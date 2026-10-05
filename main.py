import os
import re
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from dotenv import load_dotenv

load_dotenv()

from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from database import engine, Base, SessionLocal, StaffModel
from security import hash_password, limiter, generate_csrf_token
from rutas import usuarios

# =======================================================
# 1. LIFESPAN: MODERNIZACIÓN DE INICIO DE SERVIDOR
# =======================================================
def seed_staff():
    db = SessionLocal()
    try:
        master_email = os.getenv("MASTER_EMAIL")
        master_pass = os.getenv("MASTER_PASSWORD")

        if not all((master_email, master_pass)):
            raise RuntimeError("Faltan credenciales maestras en el .env.")

        if not db.query(StaffModel).filter(StaffModel.email == master_email).first():
            db.add(StaffModel(
                full_name="CEO Qxao", email=master_email,
                hashed_password=hash_password(master_pass), rol="master", is_active=True
            ))
        db.commit()
    finally:
        db.close()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Lógica de encendido
    Base.metadata.create_all(bind=engine)
    seed_staff() 
    print(">>> Servidor Qxao iniciado: Búnker Activo (Auth + Dashboard).")
    yield
    # Lógica de apagado (si fuera necesaria en el futuro)

app = FastAPI(title="Qxao Enterprise API", lifespan=lifespan)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

origenes_permitidos = [
    origen.strip().rstrip("/") 
    for origen in os.getenv("ALLOWED_ORIGINS", "http://localhost:8000").split(",") 
    if origen.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origenes_permitidos,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"], 
    allow_headers=["*"], 
)

# =======================================================
# 2. MIDDLEWARE DE SEGURIDAD ABSOLUTA (CSRF + CSP)
# =======================================================
@app.middleware("http")
async def security_and_csrf_middleware(request: Request, call_next):
    # Validación Anti-CSRF para peticiones destructivas
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        origin = request.headers.get("origin")
        if origin and origin.rstrip("/") not in origenes_permitidos:
            return Response(content="Origen de red no autorizado.", status_code=403)
        
        rutas_excluidas_csrf = ["/api/login/client", "/api/auth/staff-login", "/api/logout/client", "/api/logout/staff"]
        if request.url.path not in rutas_excluidas_csrf:
            csrf_cookie = request.cookies.get("qxao_csrf")
            csrf_header = request.headers.get("X-CSRF-Token")
            
            if not csrf_cookie or not csrf_header or csrf_cookie != csrf_header:
                return Response(content="Violación de seguridad: CSRF Token inválido o ausente.", status_code=403)

    response = await call_next(request)

    # Cabeceras de defensa en profundidad
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    
    # Política de Seguridad de Contenido (CSP)
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.tailwindcss.com https://cdnjs.cloudflare.com https://forminit.com https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: https://images.unsplash.com https://randomuser.me; "
        "connect-src 'self' https: wss:;"
    )
    response.headers["Content-Security-Policy"] = csp
    
    if os.getenv("COOKIE_SECURE", "false").lower() == "true":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"

    if request.method == "GET" and not request.cookies.get("qxao_csrf"):
        response.set_cookie(
            key="qxao_csrf",
            value=generate_csrf_token(),
            httponly=False,
            samesite="lax",
            secure=os.getenv("COOKIE_SECURE", "false").lower() == "true",
            path="/"
        )

    return response

# =======================================================
# 3. ENRUTADOR NÚCLEO (Solo clientes y staff)
# =======================================================
app.include_router(usuarios.router)

# =======================================================
# 4. DESPACHO WEB SEGURO (LA LISTA BLANCA PROTEGIDA)
# =======================================================
os.makedirs("static", exist_ok=True) 
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
@limiter.limit("60/minute")
def mostrar_inicio(request: Request): 
    return FileResponse("templates/index.html")

@app.get("/onboarding")
def mostrar_onboarding_ruta_corta(request: Request):
    return FileResponse("templates/onboarding_qxao.html")

@app.get("/{page_name}.html")
@limiter.limit("60/minute")
def mostrar_paginas(request: Request, page_name: str):
    if not re.match(r"^[a-zA-Z0-9_-]+$", page_name):
        raise HTTPException(status_code=400, detail="Estructura de petición no válida.")
        
    paginas_publicas = {"index", "demo", "soluciones", "planes", "preguntasfrecuentes", "login", "qxaomaster_88", "onboarding_qxao"}
    paginas_privadas = {"dashboard", "admin"}
    
    # BARRERA DE SEGURIDAD: Verifica la cookie antes de entregar el archivo HTML
    if page_name in paginas_privadas:
        if page_name == "dashboard" and not (request.cookies.get("qxao_client_token") or request.cookies.get("qxao_staff_token")):
            return RedirectResponse(url="/login.html", status_code=302)
        elif page_name == "admin" and not request.cookies.get("qxao_staff_token"):
            return RedirectResponse(url="/qxaomaster_88.html", status_code=302)
            
    if page_name in paginas_publicas or page_name in paginas_privadas:
        file_path = f"templates/{page_name}.html"
        if os.path.exists(file_path):
            return FileResponse(file_path)
            
    raise HTTPException(status_code=404, detail="Error 404: Sistema no encontrado.")
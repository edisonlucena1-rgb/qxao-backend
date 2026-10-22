import os
import re
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from dotenv import load_dotenv

load_dotenv()

from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from database import engine, Base, SessionLocal, StaffModel, UserModel, ensure_multitenant_columns
from security import hash_password, limiter, generate_csrf_token
from rutas import usuarios


# =======================================================
# 1. LIFESPAN: INICIALIZACIÓN DEL STAFF MASTER (los clientes entran solo por el admin)
# =======================================================
def seed_staff():
    db = SessionLocal()
    try:
        master_email = os.getenv("MASTER_EMAIL", "admin@qxao.com")
        master_pass = os.getenv("MASTER_PASSWORD", "TuContrasenaSuperSecretaAqui!")

        if master_pass == "TuContrasenaSuperSecretaAqui!":
            print("AVISO: MASTER_PASSWORD sigue con el valor de ejemplo; define una contraseña real en el entorno.")
        if master_email and master_pass:
            if not db.query(StaffModel).filter(StaffModel.email == master_email).first():
                db.add(StaffModel(
                    full_name="CEO Qxao",
                    email=master_email,
                    hashed_password=hash_password(master_pass),
                    rol="master",
                    is_active=True
                ))
                db.commit()
    except Exception as e:
        db.rollback()
        print(f"Aviso en seed_staff: {e}")
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    ensure_multitenant_columns()
    seed_staff()
    print(">>> Servidor Qxao iniciado: Búnker Multi-Tenant Activo.")
    yield


app = FastAPI(title="Qxao Enterprise API", lifespan=lifespan)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Orígenes permitidos: incluye automáticamente todos los subdominios de qxao.dpdns.org
origenes_env = [
    origen.strip().rstrip("/")
    for origen in os.getenv("ALLOWED_ORIGINS", "http://localhost:8000").split(",")
    if origen.strip()
]
origenes_qxao_default = [
    "https://qxao.dpdns.org",
    "https://app.qxao.dpdns.org",
    "https://panel.qxao.dpdns.org",
    "https://n8n.qxao.dpdns.org",
    "https://chat.qxao.dpdns.org",
    "https://crm.qxao.dpdns.org",
    "http://localhost:8000",
    "http://127.0.0.1:8000"
]
origenes_permitidos = list(dict.fromkeys(origenes_env + origenes_qxao_default))

app.add_middleware(
    CORSMiddleware,
    allow_origins=origenes_permitidos,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)


def es_origen_permitido(origin: str) -> bool:
    if not origin:
        return True
    limpio = origin.strip().rstrip("/")
    if limpio in origenes_permitidos:
        return True
    if limpio.endswith(".qxao.dpdns.org") or limpio == "https://qxao.dpdns.org":
        return True
    return False


# =======================================================
# 2. MIDDLEWARE DE SEGURIDAD (CSRF + CSP CON SOPORTE IFRAMES)
# =======================================================
@app.middleware("http")
async def security_and_csrf_middleware(request: Request, call_next):
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        path = request.url.path
        es_webhook_externo = path.startswith("/api/webhooks/")

        if not es_webhook_externo:
            origin = request.headers.get("origin")
            if origin and not es_origen_permitido(origin):
                return JSONResponse(
                    content={"success": False, "detail": f"Origen de red no autorizado ({origin})."},
                    status_code=403
                )

            rutas_excluidas_csrf = {
                "/api/login/client",
                "/api/auth/staff-login",
                "/api/logout/client",
                "/api/logout/staff"
            }
            if path not in rutas_excluidas_csrf:
                csrf_cookie = request.cookies.get("qxao_csrf")
                csrf_header = request.headers.get("X-CSRF-Token")
                tiene_sesion_jwt = bool(
                    request.cookies.get("qxao_staff_token") or request.cookies.get("qxao_client_token")
                )
                # Si el navegador envía X-CSRF-Token, validamos coincidencia; si ya tiene cookie HttpOnly
                # de sesión activa del mismo origen verificado, permitimos la operación sin bloquear el panel
                if csrf_header and csrf_cookie and csrf_cookie != csrf_header:
                    return JSONResponse(
                        content={"success": False, "detail": "CSRF Token desincronizado. Recarga la página."},
                        status_code=403
                    )
                if not tiene_sesion_jwt and (not csrf_cookie or not csrf_header):
                    return JSONResponse(
                        content={"success": False, "detail": "Sesión o CSRF Token ausente. Inicia sesión nuevamente."},
                        status_code=403
                    )

    response = await call_next(request)

    # Permitir iframes del propio ecosistema Qxao
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    # CSP actualizada con frame-src para permitir los Iframes de Chatwoot (chat.qxao.dpdns.org) y NocoDB (crm.qxao.dpdns.org)
    csp = (
        "default-src 'self' https://*.qxao.dpdns.org; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.tailwindcss.com https://cdnjs.cloudflare.com https://forminit.com https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net; "
        "font-src 'self' data: https://fonts.gstatic.com; "
        "img-src 'self' data: blob: https:; "
        "frame-src 'self' https://*.qxao.dpdns.org https:; "
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
# 3. ENRUTADOR NÚCLEO (Clientes, Staff y Webhooks n8n)
# =======================================================
app.include_router(usuarios.router)


# =======================================================
# 4. DESPACHO WEB SEGURO (SOPORTA RUTAS CON Y SIN .html)
# =======================================================
os.makedirs("static", exist_ok=True)
app.mount("/static", StaticFiles(directory="static"), name="static")

PAGINAS_PUBLICAS = {
    "index", "demo", "soluciones", "planes",
    "preguntasfrecuentes", "login", "qxaomaster_88", "onboarding_qxao"
}
PAGINAS_PRIVADAS = {"dashboard", "admin"}


def despachar_pagina_html(request: Request, page_name: str):
    limpio = page_name.strip()
    if limpio.endswith(".html"):
        limpio = limpio[:-5]

    if not re.match(r"^[a-zA-Z0-9_-]+$", limpio):
        raise HTTPException(status_code=400, detail="Estructura de petición no válida.")

    if limpio in PAGINAS_PRIVADAS:
        if limpio == "dashboard" and not (request.cookies.get("qxao_client_token") or request.cookies.get("qxao_staff_token")):
            return RedirectResponse(url="/login.html", status_code=302)
        elif limpio == "admin" and not request.cookies.get("qxao_staff_token"):
            return RedirectResponse(url="/qxaomaster_88.html", status_code=302)

    if limpio in PAGINAS_PUBLICAS or limpio in PAGINAS_PRIVADAS:
        file_path = f"templates/{limpio}.html"
        if os.path.exists(file_path):
            return FileResponse(file_path)

    raise HTTPException(status_code=404, detail="Error 404: Página no encontrada.")


@app.get("/")
@limiter.limit("60/minute")
def mostrar_inicio(request: Request):
    if os.path.exists("templates/index.html"):
        return FileResponse("templates/index.html")
    return RedirectResponse(url="/login.html", status_code=302)


@app.get("/onboarding")
def mostrar_onboarding_ruta_corta(request: Request):
    return FileResponse("templates/onboarding_qxao.html")


@app.get("/{page_name}.html")
@limiter.limit("60/minute")
def mostrar_paginas_con_ext(request: Request, page_name: str):
    return despachar_pagina_html(request, page_name)


@app.get("/{page_name}")
@limiter.limit("60/minute")
def mostrar_paginas_sin_ext(request: Request, page_name: str):
    return despachar_pagina_html(request, page_name)

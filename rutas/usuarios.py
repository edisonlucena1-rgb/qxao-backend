import os
from fastapi import APIRouter, Depends, HTTPException, Response, Request, status, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, constr
from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import datetime
from typing import Optional, List

from database import get_db, UserModel, StaffModel, ErrorLogModel
from security import (
    hash_password, verify_password, create_access_token, 
    get_master_user, get_ventas_user, get_current_client, get_current_staff, 
    ACCESS_TOKEN_EXPIRE_MINUTES, limiter
)

router = APIRouter()

class LoginRequest(BaseModel):
    email: constr(max_length=150)
    password: constr(max_length=100)

# ==========================================
# GESTIÓN DE SESIONES CON COOKIES HTTP-ONLY SEGURAS
# ==========================================
def set_auth_cookie(response: Response, token: str, cookie_name: str):
    es_produccion = os.getenv("COOKIE_SECURE", "false").lower() == "true"
    response.set_cookie(
        key=cookie_name,
        value=token,
        httponly=True,  
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        samesite="strict" if es_produccion else "lax", # Blindaje CSRF
        secure=es_produccion, # Exige HTTPS en prod
        path="/"
    )

# ==========================================
# RUTAS DE AUTENTICACIÓN (Con Anti-Fuerza Bruta)
# ==========================================
@router.post("/api/login/client")
@limiter.limit("5/minute")
def login_cliente(request: Request, credentials: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(UserModel).filter(UserModel.email == credentials.email).first()
    if not user or not verify_password(credentials.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Correo o contraseña incorrecta.")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Tu cuenta ha sido bloqueada.")

    # Inyectamos la versión del token (tv) para poder revocarlo luego
    access_token = create_access_token(data={"sub": user.email, "tipo": "cliente", "tv": user.token_version})
    
    response = JSONResponse(content={
        "success": True, 
        "user_name": user.full_name, 
        "company": user.company_name, 
        "email": user.email
    })
    set_auth_cookie(response, access_token, "qxao_client_token")
    return response

@router.post("/api/auth/staff-login")
@limiter.limit("5/minute")
def login_staff(request: Request, credentials: LoginRequest, db: Session = Depends(get_db)):
    staff = db.query(StaffModel).filter(StaffModel.email == credentials.email).first()
    if not staff or not verify_password(credentials.password, staff.hashed_password):
        raise HTTPException(status_code=400, detail="Credenciales corporativas inválidas.")
    if not staff.is_active:
        raise HTTPException(status_code=403, detail="Cuenta corporativa bloqueada.")

    access_token = create_access_token(data={"sub": staff.email, "tipo": "staff", "tv": staff.token_version})
    
    response = JSONResponse(content={
        "success": True, 
        "user_name": staff.full_name, 
        "rol": staff.rol, 
        "email": staff.email
    })
    set_auth_cookie(response, access_token, "qxao_staff_token")
    return response

# ==========================================
# RUTAS DE LOGOUT (Revocación absoluta de JWT)
# ==========================================
@router.post("/api/logout/client")
def logout_client(current_client: UserModel = Depends(get_current_client), db: Session = Depends(get_db)):
    # Al sumar 1, cualquier JWT emitido previamente queda obsoleto inmediatamente
    current_client.token_version += 1
    db.commit()
    
    response = JSONResponse(content={"success": True, "message": "Sesión de cliente cerrada"})
    response.delete_cookie("qxao_client_token", path="/")
    return response

@router.post("/api/logout/staff")
def logout_staff(current_staff: StaffModel = Depends(get_current_staff), db: Session = Depends(get_db)):
    current_staff.token_version += 1
    db.commit()
    
    response = JSONResponse(content={"success": True, "message": "Sesión de staff cerrada"})
    response.delete_cookie("qxao_staff_token", path="/")
    return response

# ==========================================
# PANEL DEL CLIENTE
# ==========================================
@router.get("/api/client/dashboard")
def get_client_dashboard(current_client: UserModel = Depends(get_current_client)):
    return {
        "success": True,
        "plan": current_client.plan,
        "mensajes_consumidos": current_client.mensajes_consumidos,
        "limite_mensajes": current_client.limite_mensajes,
        "estado_agente": current_client.estado_agente,
        "webhook_activo": current_client.webhook_activo,
        "inventario_activo": current_client.inventario_activo
    }

# ==========================================
# GESTIÓN DE CLIENTES (CRM)
# ==========================================
def obtener_limite_por_plan(plan: str):
    if plan == "Básico": return 1000
    elif plan == "Avanzado": return 5000
    elif plan == "Plus+": return 15000
    elif plan == "Enterprise": return 50000
    return 1000 

# Lectura: Accesible por Master y Ventas
@router.get("/api/admin/stats")
def get_admin_stats(db: Session = Depends(get_db), staff: StaffModel = Depends(get_ventas_user)):
    total_active = db.query(func.count(UserModel.id)).filter(UserModel.is_active.is_(True)).scalar() or 0
    total_users = db.query(func.count(UserModel.id)).scalar() or 0
    total_mensajes = db.query(func.coalesce(func.sum(UserModel.mensajes_consumidos), 0)).scalar() or 0
    success_rate = 94.5 if total_users else 0.0
    return {"total_active_clients": total_active, "conversations_today": total_mensajes, "success_rate": success_rate}

# Paginación Segura: Evita la sobrecarga de la base de datos limitando a máximo 100 registros
@router.get("/api/admin/users")
def get_all_users(
    skip: int = Query(0, ge=0), 
    limit: int = Query(100, ge=1, le=100), 
    db: Session = Depends(get_db), 
    staff: StaffModel = Depends(get_ventas_user)
):
    users_db = db.query(UserModel).order_by(UserModel.id.desc()).offset(skip).limit(limit).all()
    return [{
        "id": u.id, "full_name": u.full_name, "company_name": u.company_name,
        "email": u.email, "status": "Activo" if u.is_active else "Bloqueado",
        "is_active": u.is_active, "plan": u.plan, "rol": "cliente",
        "mensajes_consumidos": u.mensajes_consumidos, "limite_mensajes": u.limite_mensajes,
        "estado_agente": u.estado_agente, "webhook_activo": u.webhook_activo, "inventario_activo": u.inventario_activo
    } for u in users_db]

# Lectura: Accesible por Master y Ventas
@router.get("/api/admin/users/{user_id}/errors")
def get_user_errors(user_id: int, db: Session = Depends(get_db), staff: StaffModel = Depends(get_ventas_user)):
    logs = db.query(ErrorLogModel).filter(ErrorLogModel.user_id == user_id).order_by(ErrorLogModel.id.desc()).limit(5).all()
    return [{"id": l.id, "mensaje": l.mensaje, "timestamp": l.timestamp} for l in logs]

class CreateUserRequest(BaseModel):
    full_name: constr(max_length=150)
    company_name: constr(max_length=150)
    email: constr(max_length=150)
    password: constr(max_length=100)
    plan: constr(max_length=50)

# Escritura: Exclusivo de Master
@router.post("/api/admin/users")
def create_new_user(request: CreateUserRequest, db: Session = Depends(get_db), master: StaffModel = Depends(get_master_user)):
    if db.query(UserModel).filter(UserModel.email == request.email).first():
        return {"success": False, "detail": "Este correo ya está registrado."}
    
    limite = obtener_limite_por_plan(request.plan)
    new_user = UserModel(
        full_name=request.full_name, company_name=request.company_name,
        email=request.email, hashed_password=hash_password(request.password),
        plan=request.plan, limite_mensajes=limite
    )
    db.add(new_user)
    db.commit()
    db.add(ErrorLogModel(user_id=new_user.id, mensaje="Cuenta de cliente inicializada correctamente.", timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    db.commit()
    return {"success": True, "message": "Cliente creado"}

class UpdateUserRequest(BaseModel):
    full_name: constr(max_length=150)
    company_name: constr(max_length=150)
    email: constr(max_length=150)
    password: Optional[str] = None 
    plan: constr(max_length=50)

# Escritura: Exclusivo de Master
@router.put("/api/admin/users/{user_id}")
def update_user(user_id: int, request: UpdateUserRequest, db: Session = Depends(get_db), master: StaffModel = Depends(get_master_user)):
    user = db.query(UserModel).filter(UserModel.id == user_id).first()
    if not user: return {"success": False, "detail": "Cliente no encontrado"}
    user.full_name = request.full_name
    user.company_name = request.company_name
    user.email = request.email
    user.plan = request.plan
    user.limite_mensajes = obtener_limite_por_plan(request.plan)
    
    if request.password and request.password.strip() != "":
        user.hashed_password = hash_password(request.password)
        # Invalida las sesiones abiertas con la contraseña anterior
        user.token_version += 1 
        
    db.commit()
    return {"success": True, "message": "Cliente actualizado"}

# Escritura: Exclusivo de Master
@router.put("/api/admin/users/{user_id}/toggle-block")
def toggle_block_user(user_id: int, db: Session = Depends(get_db), master: StaffModel = Depends(get_master_user)):
    user = db.query(UserModel).filter(UserModel.id == user_id).first()
    if not user: raise HTTPException(status_code=404, detail="Cliente no encontrado")
    
    user.is_active = not user.is_active 
    if not user.is_active:
        # Revoca la sesión activa para expulsar al usuario al instante
        user.token_version += 1 
        
    db.commit()
    return {"success": True, "is_active": user.is_active}

# Escritura: Exclusivo de Master
@router.put("/api/admin/users/{user_id}/toggle-agent")
def toggle_agent_status(user_id: int, db: Session = Depends(get_db), master: StaffModel = Depends(get_master_user)):
    user = db.query(UserModel).filter(UserModel.id == user_id).first()
    if not user: return {"success": False, "detail": "Cliente no encontrado"}
    
    if user.estado_agente == "Activo":
        user.estado_agente = "Pausado"
        db.add(ErrorLogModel(user_id=user.id, mensaje="Agente IA pausado manualmente por Master", timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    else:
        user.estado_agente = "Activo"
        db.add(ErrorLogModel(user_id=user.id, mensaje="Agente IA reanudado por Master", timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        
    db.commit()
    return {"success": True, "estado_agente": user.estado_agente}

# ==========================================
# IMPERSONACIÓN (VER COMO CLIENTE CON AUDITORÍA)
# ==========================================
class ImpersonateRequest(BaseModel):
    email: constr(max_length=150)

# Escritura: Exclusivo de Master (Para entrar al dashboard del cliente)
@router.post("/api/admin/impersonate")
def impersonate_client(request: ImpersonateRequest, db: Session = Depends(get_db), current_staff: StaffModel = Depends(get_master_user)):
    client = db.query(UserModel).filter(UserModel.email == request.email).first()
    if not client:
        raise HTTPException(status_code=404, detail="Cliente no encontrado")
        
    # Genera un token de CLIENTE válido pero atado a este cliente específico
    impersonation_token = create_access_token(
        data={"sub": client.email, "tipo": "cliente", "tv": client.token_version}
    )
    
    # Registro de Auditoría Obligatorio
    audit_log = ErrorLogModel(
        user_id=client.id, 
        mensaje=f"AUDITORÍA: El administrador [{current_staff.email}] inició sesión en esta cuenta usando el Modo Impersonación.", 
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )
    db.add(audit_log)
    db.commit()
    
    response = JSONResponse(content={"success": True, "message": f"Acceso concedido a {client.full_name}"})
    
    # Inyecta la cookie. ¡Ahora el Master tendrá 2 cookies (Staff y Client) funcionando a la vez!
    set_auth_cookie(response, impersonation_token, "qxao_client_token")
    return response

# ==========================================
# CAMBIO DE CONTRASEÑA DEL STAFF
# ==========================================
class ChangeStaffPassword(BaseModel):
    current_password: str
    new_password: constr(min_length=8)

# Escritura: Accesible para cualquier Staff (Master o Ventas) que quiera cambiar su propia clave
@router.put("/api/admin/change-password")
def change_staff_password(request: ChangeStaffPassword, db: Session = Depends(get_db), current_staff: StaffModel = Depends(get_current_staff)):
    # 1. Verificamos que sepa su contraseña actual
    if not verify_password(request.current_password, current_staff.hashed_password):
        raise HTTPException(status_code=400, detail="La contraseña actual es incorrecta.")
        
    # 2. Encriptamos y guardamos la nueva
    current_staff.hashed_password = hash_password(request.new_password)
    
    # 3. ROTACIÓN DE SEGURIDAD: Invalidamos la sesión actual para obligarlo a loguearse con la nueva clave
    current_staff.token_version += 1 
    
    db.commit()
    
    # 4. Borramos la cookie vieja del navegador
    response = JSONResponse(content={"success": True, "message": "Contraseña actualizada. Inicia sesión nuevamente."})
    response.delete_cookie("qxao_staff_token", path="/")
    return response
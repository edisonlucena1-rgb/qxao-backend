import os
import re
import json
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Response, Request, Header, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, constr
from sqlalchemy.orm import Session
from sqlalchemy import func

from database import get_db, UserModel, StaffModel, ErrorLogModel
from security import (
    hash_password, verify_password, create_access_token,
    get_master_user, get_ventas_user, get_current_client, get_current_staff,
    ACCESS_TOKEN_EXPIRE_MINUTES, limiter
)

router = APIRouter()

# ==================================================
# VARIABLES DE ENTORNO Y DOMINIOS REALES QXAO
# ==================================================
N8N_CREATE_CLIENT_WEBHOOK_URL = os.getenv(
    "N8N_CREATE_CLIENT_WEBHOOK_URL",
    "https://n8n.qxao.dpdns.org/webhook/qxao-crear-cliente"
)
N8N_QR_WEBHOOK_URL = os.getenv(
    "N8N_QR_WEBHOOK_URL",
    "https://n8n.qxao.dpdns.org/webhook/obtener-qr-jlburger"
)
N8N_WEBHOOK_SECRET = os.getenv("N8N_WEBHOOK_SECRET", "")

DEFAULT_CHATWOOT_URL = os.getenv(
    "DEFAULT_CHATWOOT_URL",
    "https://chat.qxao.dpdns.org/app/accounts/2/dashboard"
)
DEFAULT_NOCODB_URL = os.getenv(
    "DEFAULT_NOCODB_URL",
    "https://crm.qxao.dpdns.org/wgai29by"
)


class LoginRequest(BaseModel):
    email: constr(max_length=150)
    password: constr(max_length=100)


# ==================================================
# AUTO-DETECCIÓN INTELIGENTE DE ECOSISTEMAS REALES
# ==================================================
def generar_slug_instancia(company_name: str) -> str:
    limpio = re.sub(r"[^a-zA-Z0-9]+", "_", (company_name or "cliente").strip().lower()).strip("_")
    return limpio or "cliente_qxao"


def autocompletar_ecosistema_conocido(user: UserModel, db: Optional[Session] = None) -> None:
    """
    Si un cliente existente (como JL Burger o Engranos) aún tiene vacías sus columnas
    multi-tenant en la base de datos, les asigna automáticamente sus rutas reales
    de Evolution API, Chatwoot, NocoDB y Webhook QR de n8n sin sobrescribir cambios manuales.
    """
    texto = f"{user.company_name or ''} {user.full_name or ''} {user.email or ''}".lower()
    modificado = False

    if "burger" in texto or "burguer" in texto or "jl" in texto:
        if not user.evolution_instance:
            user.evolution_instance = "JLBurguer."
            modificado = True
        if not user.chatwoot_url:
            user.chatwoot_url = "https://chat.qxao.dpdns.org/app/accounts/2/dashboard"
            modificado = True
        if not user.nocodb_url:
            user.nocodb_url = "https://crm.qxao.dpdns.org/wgai29by/pi4c3iginxwezws"
            modificado = True
        if not user.qr_webhook_url:
            user.qr_webhook_url = "https://n8n.qxao.dpdns.org/webhook/obtener-qr-jlburger"
            modificado = True

    elif "engrano" in texto or "yolanda" in texto or "pisa" in texto:
        if not user.evolution_instance:
            user.evolution_instance = "pisa62"
            modificado = True
        if not user.chatwoot_url:
            user.chatwoot_url = "https://chat.qxao.dpdns.org/app/accounts/2/dashboard"
            modificado = True
        if not user.nocodb_url:
            user.nocodb_url = "https://crm.qxao.dpdns.org/wgai29by/p96tfdcx3ish0pv"
            modificado = True
        if not user.qr_webhook_url:
            user.qr_webhook_url = "https://n8n.qxao.dpdns.org/webhook/obtener-qr-engranos"
            modificado = True

    if modificado and db is not None:
        try:
            db.commit()
        except Exception:
            db.rollback()


def llamar_webhook_n8n(url: str, payload: dict, timeout: int = 20, prefer_get: bool = False) -> Optional[dict]:
    """
    Soporta tanto Webhooks GET (como obtener-qr-jlburger y obtener-qr-engranos en n8n)
    como Webhooks POST JSON (como el Gerente General).
    """
    if not url or not url.strip():
        return None
    target_url = url.strip()
    headers = {"Accept": "application/json", "User-Agent": "QxaoBackend/2.0"}
    if N8N_WEBHOOK_SECRET:
        headers["X-Qxao-Secret"] = N8N_WEBHOOK_SECRET

    metodos = ["GET", "POST"] if prefer_get else ["POST", "GET"]

    for metodo in metodos:
        try:
            if metodo == "GET":
                query = urllib.parse.urlencode({k: v for k, v in payload.items() if v is not None})
                sep = "&" if "?" in target_url else "?"
                full_url = f"{target_url}{sep}{query}" if query else target_url
                req = urllib.request.Request(full_url, headers=headers, method="GET")
            else:
                data_bytes = json.dumps(payload).encode("utf-8")
                post_headers = {**headers, "Content-Type": "application/json"}
                req = urllib.request.Request(target_url, data=data_bytes, headers=post_headers, method="POST")

            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8").strip()
                if not raw:
                    return {"status": "ok"}
                try:
                    parsed = json.loads(raw)
                    if isinstance(parsed, list) and len(parsed) > 0 and isinstance(parsed[0], dict):
                        return parsed[0]
                    if isinstance(parsed, dict):
                        return parsed
                    return {"raw": raw}
                except Exception:
                    return {"base64": raw}
        except urllib.error.HTTPError as he:
            # Si el webhook en n8n está configurado en GET y enviamos POST (o viceversa), probamos el otro método
            if he.code in (404, 405):
                continue
            print(f"HTTPError ({he.code}) en Webhook n8n ({target_url}): {he}")
        except Exception as e:
            print(f"Error al contactar Webhook n8n ({target_url}) con {metodo}: {e}")
    return None


def obtener_limite_por_plan(plan: str) -> int:
    planes = {
        "Básico": 1000,
        "Medio": 2000,
        "Avanzado": 5000,
        "Pro": 5000,
        "Plus+": 15000,
        "Enterprise": 50000
    }
    return planes.get(plan, 1000)


# ==================================================
# GESTIÓN DE SESIONES CON COOKIES HTTP-ONLY SEGURAS
# ==================================================
def set_auth_cookie(response: Response, token: str, cookie_name: str):
    es_produccion = os.getenv("COOKIE_SECURE", "false").lower() == "true"
    response.set_cookie(
        key=cookie_name,
        value=token,
        httponly=True,
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        samesite="strict" if es_produccion else "lax",
        secure=es_produccion,
        path="/"
    )


# ==================================================
# RUTAS DE AUTENTICACIÓN
# ==================================================
@router.post("/api/login/client")
@limiter.limit("5/minute")
def login_cliente(request: Request, credentials: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(UserModel).filter(UserModel.email == credentials.email).first()
    if not user or not verify_password(credentials.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Correo o contraseña incorrecta.")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Tu cuenta ha sido bloqueada.")

    autocompletar_ecosistema_conocido(user, db)
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


@router.post("/api/logout/client")
def logout_client(current_client: UserModel = Depends(get_current_client), db: Session = Depends(get_db)):
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


# ==================================================
# PANEL DEL CLIENTE (MULTI-TENANT + IFRAMES + QR)
# ==================================================
def serializar_perfil_cliente(client: UserModel, db: Optional[Session] = None) -> dict:
    autocompletar_ecosistema_conocido(client, db)
    instancia = client.evolution_instance or generar_slug_instancia(client.company_name)
    return {
        "success": True,
        "id": client.id,
        "user_name": client.full_name,
        "full_name": client.full_name,
        "company": client.company_name,
        "company_name": client.company_name,
        "email": client.email,
        "plan": client.plan,
        "mensajes_consumidos": client.mensajes_consumidos or 0,
        "limite_mensajes": client.limite_mensajes or 1000,
        "estado_agente": client.estado_agente or "Activo",
        "webhook_activo": bool(client.webhook_activo),
        "inventario_activo": bool(client.inventario_activo),
        "evolution_instance": instancia,
        "chatwoot_url": client.chatwoot_url or DEFAULT_CHATWOOT_URL,
        "nocodb_url": client.nocodb_url or DEFAULT_NOCODB_URL,
        "qr_webhook_url": client.qr_webhook_url or "",
        "whatsapp_conectado": bool(client.whatsapp_conectado)
    }


@router.get("/api/client/dashboard")
def get_client_dashboard(current_client: UserModel = Depends(get_current_client), db: Session = Depends(get_db)):
    return serializar_perfil_cliente(current_client, db)


@router.get("/api/me")
def get_me(current_client: UserModel = Depends(get_current_client), db: Session = Depends(get_db)):
    return serializar_perfil_cliente(current_client, db)


@router.post("/api/client/toggle-agent")
@router.post("/api/toggle-agente")
def client_toggle_agent(current_client: UserModel = Depends(get_current_client), db: Session = Depends(get_db)):
    current_client.estado_agente = "Pausado" if current_client.estado_agente == "Activo" else "Activo"
    db.add(ErrorLogModel(
        user_id=current_client.id,
        mensaje=f"Estado del Agente IA cambiado a '{current_client.estado_agente}' desde el panel del cliente.",
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))
    db.commit()
    return {"success": True, "estado_agente": current_client.estado_agente}


@router.post("/api/client/toggle-webhook")
@router.post("/api/toggle-webhook")
def client_toggle_webhook(current_client: UserModel = Depends(get_current_client), db: Session = Depends(get_db)):
    current_client.webhook_activo = not bool(current_client.webhook_activo)
    db.commit()
    return {"success": True, "webhook_activo": current_client.webhook_activo}


@router.post("/api/client/toggle-inventario")
@router.post("/api/toggle-inventario")
def client_toggle_inventario(current_client: UserModel = Depends(get_current_client), db: Session = Depends(get_db)):
    current_client.inventario_activo = not bool(current_client.inventario_activo)
    db.commit()
    return {"success": True, "inventario_activo": current_client.inventario_activo}


# ==================================================
# PORTAL QR DINÁMICO (CONECTADO A N8N + EVOLUTION API)
# ==================================================
@router.post("/api/client/qr")
@router.get("/api/client/qr")
def solicitar_qr_whatsapp(current_client: UserModel = Depends(get_current_client), db: Session = Depends(get_db)):
    """
    Extrae el código QR Base64 desde el Webhook de n8n correspondiente al cliente
    (por ejemplo /webhook/obtener-qr-jlburger o /webhook/obtener-qr-engranos).
    Soporta tanto Webhooks GET como POST.
    """
    autocompletar_ecosistema_conocido(current_client, db)
    instancia = current_client.evolution_instance or generar_slug_instancia(current_client.company_name)
    if not current_client.evolution_instance:
        current_client.evolution_instance = instancia
        db.commit()

    webhook_qr = (current_client.qr_webhook_url or N8N_QR_WEBHOOK_URL or "").strip()
    if not webhook_qr:
        return {
            "success": False,
            "status": "MISSING_WEBHOOK",
            "evolution_instance": instancia,
            "detail": "Configura el Webhook QR de n8n para este cliente."
        }

    # Los workflows actuales en n8n (obtener-qr-jlburger / obtener-qr-engranos) usan método GET
    respuesta_n8n = llamar_webhook_n8n(
        webhook_qr,
        {
            "action": "get_qr",
            "client_id": current_client.id,
            "company_name": current_client.company_name,
            "email": current_client.email,
            "instance": instancia,
            "evolution_instance": instancia
        },
        timeout=25,
        prefer_get=True
    )

    if not respuesta_n8n:
        return {
            "success": False,
            "status": "WEBHOOK_ERROR",
            "evolution_instance": instancia,
            "detail": "No se recibió respuesta del Webhook QR en n8n. Verifica que el flujo esté Activo (Published)."
        }

    estado = (
        respuesta_n8n.get("status")
        or respuesta_n8n.get("state")
        or (respuesta_n8n.get("instance") if isinstance(respuesta_n8n.get("instance"), dict) else {}).get("state")
        or "QR_READY"
    )
    qr_base64 = (
        respuesta_n8n.get("base64")
        or respuesta_n8n.get("qr_base64")
        or (respuesta_n8n.get("qrcode") if isinstance(respuesta_n8n.get("qrcode"), dict) else {}).get("base64")
        or respuesta_n8n.get("qr")
        or ""
    )

    conectado = str(estado).upper() in ["CONNECTED", "OPEN", "ONLINE"]
    if conectado != bool(current_client.whatsapp_conectado):
        current_client.whatsapp_conectado = conectado
        db.commit()

    return {
        "success": True,
        "status": "CONNECTED" if conectado else estado,
        "whatsapp_conectado": conectado,
        "evolution_instance": instancia,
        "qr_base64": qr_base64
    }


# ==================================================
# GESTIÓN DE CLIENTES (PANEL ADMIN + BOTÓN "+ CREAR CLIENTE")
# ==================================================
@router.get("/api/admin/stats")
def get_admin_stats(db: Session = Depends(get_db), staff: StaffModel = Depends(get_ventas_user)):
    total_active = db.query(func.count(UserModel.id)).filter(UserModel.is_active.is_(True)).scalar() or 0
    total_users = db.query(func.count(UserModel.id)).scalar() or 0
    total_mensajes = db.query(func.coalesce(func.sum(UserModel.mensajes_consumidos), 0)).scalar() or 0
    success_rate = 94.5 if total_users else 0.0
    return {
        "total_active_clients": total_active,
        "conversations_today": total_mensajes,
        "success_rate": success_rate
    }


@router.get("/api/admin/users")
def get_all_users(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=100),
    db: Session = Depends(get_db),
    staff: StaffModel = Depends(get_ventas_user)
):
    users_db = db.query(UserModel).order_by(UserModel.id.desc()).offset(skip).limit(limit).all()
    resultado = []
    for u in users_db:
        autocompletar_ecosistema_conocido(u, db)
        resultado.append({
            "id": u.id,
            "full_name": u.full_name,
            "company_name": u.company_name,
            "email": u.email,
            "status": "Activo" if u.is_active else "Bloqueado",
            "is_active": u.is_active,
            "plan": u.plan,
            "rol": "Cliente",
            "mensajes_consumidos": u.mensajes_consumidos or 0,
            "limite_mensajes": u.limite_mensajes or 1000,
            "estado_agente": u.estado_agente or "Activo",
            "webhook_activo": bool(u.webhook_activo),
            "inventario_activo": bool(u.inventario_activo),
            "evolution_instance": u.evolution_instance or generar_slug_instancia(u.company_name),
            "chatwoot_url": u.chatwoot_url or DEFAULT_CHATWOOT_URL,
            "nocodb_url": u.nocodb_url or DEFAULT_NOCODB_URL,
            "qr_webhook_url": u.qr_webhook_url or "",
            "whatsapp_conectado": bool(u.whatsapp_conectado)
        })
    return resultado


@router.get("/api/admin/users/{user_id}/errors")
def get_user_errors(user_id: int, db: Session = Depends(get_db), staff: StaffModel = Depends(get_ventas_user)):
    logs = db.query(ErrorLogModel).filter(ErrorLogModel.user_id == user_id).order_by(ErrorLogModel.id.desc()).limit(20).all()
    return [{"id": l.id, "mensaje": l.mensaje, "timestamp": l.timestamp} for l in logs]


class CreateUserRequest(BaseModel):
    full_name: constr(max_length=150)
    company_name: constr(max_length=150)
    email: constr(max_length=150)
    password: constr(max_length=100)
    plan: constr(max_length=50)
    evolution_instance: Optional[str] = None
    chatwoot_url: Optional[str] = None
    nocodb_url: Optional[str] = None
    qr_webhook_url: Optional[str] = None
    auto_provision_n8n: Optional[bool] = True


def aprovisionar_cliente_en_n8n(user: UserModel, db: Session) -> dict:
    if not N8N_CREATE_CLIENT_WEBHOOK_URL:
        return {"provisioned": False, "reason": "N8N_CREATE_CLIENT_WEBHOOK_URL no configurada"}

    payload = {
        "event": "client.created",
        "client_id": user.id,
        "full_name": user.full_name,
        "company_name": user.company_name,
        "email": user.email,
        "plan": user.plan,
        "limite_mensajes": user.limite_mensajes,
        "evolution_instance": user.evolution_instance
    }
    resp = llamar_webhook_n8n(N8N_CREATE_CLIENT_WEBHOOK_URL, payload, timeout=20, prefer_get=False)
    if not resp:
        db.add(ErrorLogModel(
            user_id=user.id,
            mensaje="Aviso: No se obtuvo respuesta inmediata del Webhook Gerente General en n8n.",
            timestamp=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        ))
        db.commit()
        return {"provisioned": False, "reason": "Sin respuesta del webhook n8n"}

    if resp.get("evolution_instance"):
        user.evolution_instance = resp["evolution_instance"]
    if resp.get("chatwoot_url"):
        user.chatwoot_url = resp["chatwoot_url"]
    if resp.get("nocodb_url"):
        user.nocodb_url = resp["nocodb_url"]
    if resp.get("qr_webhook_url"):
        user.qr_webhook_url = resp["qr_webhook_url"]

    db.add(ErrorLogModel(
        user_id=user.id,
        mensaje=f"Ecosistema aprovisionado vía n8n (Instancia: {user.evolution_instance}).",
        timestamp=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    ))
    db.commit()
    return {"provisioned": True, "n8n_response": resp}


@router.post("/api/admin/users")
@router.post("/api/admin/create-user")
def create_new_user(request: CreateUserRequest, db: Session = Depends(get_db), master: StaffModel = Depends(get_master_user)):
    if db.query(UserModel).filter(UserModel.email == request.email).first():
        return {"success": False, "detail": "Este correo ya está registrado."}

    limite = obtener_limite_por_plan(request.plan)
    instancia = (request.evolution_instance or "").strip() or generar_slug_instancia(request.company_name)

    new_user = UserModel(
        full_name=request.full_name,
        company_name=request.company_name,
        email=request.email,
        hashed_password=hash_password(request.password),
        plan=request.plan,
        limite_mensajes=limite,
        evolution_instance=instancia,
        chatwoot_url=(request.chatwoot_url or "").strip() or DEFAULT_CHATWOOT_URL,
        nocodb_url=(request.nocodb_url or "").strip() or DEFAULT_NOCODB_URL,
        qr_webhook_url=(request.qr_webhook_url or "").strip() or None
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    autocompletar_ecosistema_conocido(new_user, db)

    db.add(ErrorLogModel(
        user_id=new_user.id,
        mensaje=f"Cuenta de cliente inicializada (Instancia Evolution: {new_user.evolution_instance}).",
        timestamp=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    ))
    db.commit()

    resultado_n8n = {"provisioned": False}
    if request.auto_provision_n8n:
        resultado_n8n = aprovisionar_cliente_en_n8n(new_user, db)

    return {
        "success": True,
        "message": "Cliente creado",
        "user_id": new_user.id,
        "evolution_instance": new_user.evolution_instance,
        "chatwoot_url": new_user.chatwoot_url,
        "nocodb_url": new_user.nocodb_url,
        "qr_webhook_url": new_user.qr_webhook_url,
        "n8n_provisioning": resultado_n8n
    }


class UpdateUserRequest(BaseModel):
    full_name: constr(max_length=150)
    company_name: constr(max_length=150)
    email: constr(max_length=150)
    password: Optional[str] = None
    plan: constr(max_length=50)
    evolution_instance: Optional[str] = None
    chatwoot_url: Optional[str] = None
    nocodb_url: Optional[str] = None
    qr_webhook_url: Optional[str] = None


@router.put("/api/admin/users/{user_id}")
def update_user(user_id: int, request: UpdateUserRequest, db: Session = Depends(get_db), master: StaffModel = Depends(get_master_user)):
    user = db.query(UserModel).filter(UserModel.id == user_id).first()
    if not user:
        return {"success": False, "detail": "Cliente no encontrado"}

    user.full_name = request.full_name
    user.company_name = request.company_name
    user.email = request.email
    user.plan = request.plan
    user.limite_mensajes = obtener_limite_por_plan(request.plan)

    if request.evolution_instance is not None:
        user.evolution_instance = request.evolution_instance.strip() or generar_slug_instancia(request.company_name)
    if request.chatwoot_url is not None:
        user.chatwoot_url = request.chatwoot_url.strip() or None
    if request.nocodb_url is not None:
        user.nocodb_url = request.nocodb_url.strip() or None
    if request.qr_webhook_url is not None:
        user.qr_webhook_url = request.qr_webhook_url.strip() or None

    if request.password and request.password.strip() != "":
        user.hashed_password = hash_password(request.password)
        user.token_version += 1

    db.commit()
    return {"success": True, "message": "Cliente actualizado"}


@router.post("/api/admin/users/{user_id}/reprovision")
def reprovision_user_n8n(user_id: int, db: Session = Depends(get_db), master: StaffModel = Depends(get_master_user)):
    user = db.query(UserModel).filter(UserModel.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Cliente no encontrado")
    resultado = aprovisionar_cliente_en_n8n(user, db)
    return {"success": True, "n8n_provisioning": resultado}


@router.put("/api/admin/users/{user_id}/toggle-block")
def toggle_block_user(user_id: int, db: Session = Depends(get_db), master: StaffModel = Depends(get_master_user)):
    user = db.query(UserModel).filter(UserModel.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Cliente no encontrado")

    user.is_active = not user.is_active
    if not user.is_active:
        user.token_version += 1

    db.commit()
    return {"success": True, "is_active": user.is_active}


@router.put("/api/admin/users/{user_id}/toggle-agent")
def toggle_agent_status(user_id: int, db: Session = Depends(get_db), master: StaffModel = Depends(get_master_user)):
    user = db.query(UserModel).filter(UserModel.id == user_id).first()
    if not user:
        return {"success": False, "detail": "Cliente no encontrado"}

    if user.estado_agente == "Activo":
        user.estado_agente = "Pausado"
        db.add(ErrorLogModel(user_id=user.id, mensaje="Agente IA pausado manualmente por Master", timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    else:
        user.estado_agente = "Activo"
        db.add(ErrorLogModel(user_id=user.id, mensaje="Agente IA reanudado por Master", timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")))

    db.commit()
    return {"success": True, "estado_agente": user.estado_agente}


# ==================================================
# WEBHOOKS ENTRANTES DESDE N8N
# ==================================================
class N8nProvisionCallback(BaseModel):
    client_id: Optional[int] = None
    email: Optional[str] = None
    evolution_instance: Optional[str] = None
    chatwoot_url: Optional[str] = None
    nocodb_url: Optional[str] = None
    qr_webhook_url: Optional[str] = None
    whatsapp_conectado: Optional[bool] = None


def verificar_secreto_n8n(x_qxao_secret: Optional[str]):
    if N8N_WEBHOOK_SECRET and x_qxao_secret != N8N_WEBHOOK_SECRET:
        raise HTTPException(status_code=401, detail="Clave de Webhook n8n inválida.")


@router.post("/api/webhooks/n8n/provision-callback")
def n8n_provision_callback(
    payload: N8nProvisionCallback,
    x_qxao_secret: Optional[str] = Header(None),
    db: Session = Depends(get_db)
):
    verificar_secreto_n8n(x_qxao_secret)

    user = None
    if payload.client_id:
        user = db.query(UserModel).filter(UserModel.id == payload.client_id).first()
    elif payload.email:
        user = db.query(UserModel).filter(UserModel.email == payload.email).first()
    elif payload.evolution_instance:
        user = db.query(UserModel).filter(UserModel.evolution_instance == payload.evolution_instance).first()

    if not user:
        raise HTTPException(status_code=404, detail="Cliente no encontrado para actualizar aprovisionamiento.")

    if payload.evolution_instance is not None:
        user.evolution_instance = payload.evolution_instance
    if payload.chatwoot_url is not None:
        user.chatwoot_url = payload.chatwoot_url
    if payload.nocodb_url is not None:
        user.nocodb_url = payload.nocodb_url
    if payload.qr_webhook_url is not None:
        user.qr_webhook_url = payload.qr_webhook_url
    if payload.whatsapp_conectado is not None:
        user.whatsapp_conectado = payload.whatsapp_conectado

    db.add(ErrorLogModel(
        user_id=user.id,
        mensaje="URLs de Chatwoot/NocoDB/Evolution actualizadas automáticamente por n8n.",
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))
    db.commit()
    return {"success": True, "user_id": user.id, "evolution_instance": user.evolution_instance}


class N8nMessageCheckRequest(BaseModel):
    evolution_instance: Optional[str] = None
    email: Optional[str] = None
    client_id: Optional[int] = None
    increment: int = 1


@router.post("/api/webhooks/n8n/check-and-consume")
def n8n_check_and_consume(
    payload: N8nMessageCheckRequest,
    x_qxao_secret: Optional[str] = Header(None),
    db: Session = Depends(get_db)
):
    verificar_secreto_n8n(x_qxao_secret)

    user = None
    if payload.client_id:
        user = db.query(UserModel).filter(UserModel.id == payload.client_id).first()
    elif payload.evolution_instance:
        user = db.query(UserModel).filter(UserModel.evolution_instance == payload.evolution_instance).first()
    elif payload.email:
        user = db.query(UserModel).filter(UserModel.email == payload.email).first()

    if not user:
        raise HTTPException(status_code=404, detail="Cliente o instancia no encontrada.")

    if not user.is_active:
        return {"allowed": False, "reason": "ACCOUNT_BLOCKED", "estado_agente": user.estado_agente}
    if not user.webhook_activo:
        return {"allowed": False, "reason": "WEBHOOK_DISABLED", "estado_agente": user.estado_agente}
    if user.estado_agente != "Activo":
        return {"allowed": False, "reason": "AGENT_PAUSED", "estado_agente": user.estado_agente}
    if (user.mensajes_consumidos or 0) >= (user.limite_mensajes or 1000):
        user.estado_agente = "Pausado"
        db.add(ErrorLogModel(
            user_id=user.id,
            mensaje="Límite de mensajes alcanzado. Agente IA pausado automáticamente.",
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))
        db.commit()
        return {"allowed": False, "reason": "LIMIT_REACHED", "estado_agente": user.estado_agente}

    if payload.increment > 0:
        user.mensajes_consumidos = (user.mensajes_consumidos or 0) + payload.increment
        db.commit()

    return {
        "allowed": True,
        "client_id": user.id,
        "company_name": user.company_name,
        "plan": user.plan,
        "mensajes_consumidos": user.mensajes_consumidos,
        "limite_mensajes": user.limite_mensajes,
        "inventario_activo": bool(user.inventario_activo),
        "estado_agente": user.estado_agente
    }


class ImpersonateRequest(BaseModel):
    email: constr(max_length=150)


@router.post("/api/admin/impersonate")
def impersonate_client(request: ImpersonateRequest, db: Session = Depends(get_db), current_staff: StaffModel = Depends(get_master_user)):
    client = db.query(UserModel).filter(UserModel.email == request.email).first()
    if not client:
        raise HTTPException(status_code=404, detail="Cliente no encontrado")

    impersonation_token = create_access_token(
        data={"sub": client.email, "tipo": "cliente", "tv": client.token_version}
    )

    audit_log = ErrorLogModel(
        user_id=client.id,
        mensaje=f"AUDITORÍA: El administrador [{current_staff.email}] inició sesión en esta cuenta usando el Modo Impersonación.",
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )
    db.add(audit_log)
    db.commit()

    response = JSONResponse(content={"success": True, "message": f"Acceso concedido a {client.full_name}"})
    set_auth_cookie(response, impersonation_token, "qxao_client_token")
    return response


class ChangeStaffPassword(BaseModel):
    current_password: str
    new_password: constr(min_length=8)


@router.put("/api/admin/change-password")
def change_staff_password(request: ChangeStaffPassword, db: Session = Depends(get_db), current_staff: StaffModel = Depends(get_current_staff)):
    if not verify_password(request.current_password, current_staff.hashed_password):
        raise HTTPException(status_code=400, detail="La contraseña actual es incorrecta.")

    current_staff.hashed_password = hash_password(request.new_password)
    current_staff.token_version += 1
    db.commit()

    response = JSONResponse(content={"success": True, "message": "Contraseña actualizada. Inicia sesión nuevamente."})
    response.delete_cookie("qxao_staff_token", path="/")
    return response

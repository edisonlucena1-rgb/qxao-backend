import os
import re
import hmac
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
# VARIABLES DE ENTORNO (NINGUNA CLAVE VA ESCRITA EN EL CÓDIGO)
# Backend -> n8n: el backend solo habla con los webhooks de n8n.
# n8n es quien habla con Evolution, Chatwoot y NocoDB.
# ==================================================
N8N_BASE_URL = os.getenv("N8N_BASE_URL", "https://n8n.qxao.dpdns.org").rstrip("/")
N8N_CREATE_CLIENT_WEBHOOK_URL = os.getenv(
    "N8N_CREATE_CLIENT_WEBHOOK_URL", f"{N8N_BASE_URL}/webhook/qxao-crear-cliente"
)
N8N_DELETE_CLIENT_WEBHOOK_URL = os.getenv(
    "N8N_DELETE_CLIENT_WEBHOOK_URL", f"{N8N_BASE_URL}/webhook/qxao-eliminar-cliente"
)
N8N_QR_WEBHOOK_URL = os.getenv(
    "N8N_QR_WEBHOOK_URL", f"{N8N_BASE_URL}/webhook/qxao-obtener-qr"
)
N8N_WEBHOOK_SECRET = os.getenv("N8N_WEBHOOK_SECRET", "")

# Sin valores por defecto: cada cliente recibe sus propias URLs desde n8n.
DEFAULT_CHATWOOT_URL = os.getenv("DEFAULT_CHATWOOT_URL", "")
DEFAULT_NOCODB_URL = os.getenv("DEFAULT_NOCODB_URL", "")


class LoginRequest(BaseModel):
    email: constr(max_length=150)
    password: constr(max_length=100)


# ==================================================
# UTILIDADES
# ==================================================
def generar_slug_instancia(company_name: str) -> str:
    limpio = re.sub(r"[^a-zA-Z0-9]+", "_", (company_name or "cliente").strip().lower()).strip("_")
    return limpio or "cliente_qxao"


def instancia_unica(db: Session, base: str, excluir_id: Optional[int] = None) -> str:
    """Devuelve un nombre de instancia que no esté usado por otro cliente."""
    candidato = base
    n = 2
    while db.query(UserModel).filter(
        UserModel.evolution_instance == candidato,
        UserModel.id != (excluir_id or 0)
    ).first():
        candidato = f"{base}_{n}"
        n += 1
    return candidato


def ahora() -> str:
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


def registrar(db: Session, user_id: int, mensaje: str) -> None:
    db.add(ErrorLogModel(user_id=user_id, mensaje=mensaje, timestamp=ahora()))


def llamar_webhook_n8n(
    url: str,
    payload: dict,
    timeout: int = 20,
    prefer_get: bool = False,
    only_post: bool = False
) -> Optional[dict]:
    """
    Llama a un webhook de n8n. Devuelve el JSON de respuesta o None si falla.
    only_post=True evita el reintento por GET (necesario para acciones que cambian datos).
    """
    if not url or not url.strip():
        return None
    target_url = url.strip()
    headers = {"Accept": "application/json", "User-Agent": "QxaoBackend/3.0"}
    if N8N_WEBHOOK_SECRET:
        headers["X-Qxao-Secret"] = N8N_WEBHOOK_SECRET

    if only_post:
        metodos = ["POST"]
    else:
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
            if he.code in (404, 405) and len(metodos) > 1:
                continue
            print(f"HTTPError ({he.code}) en Webhook n8n ({target_url}): {he}")
        except Exception as e:
            print(f"Error al contactar Webhook n8n ({target_url}) con {metodo}: {e}")
    return None


def n8n_respondio_ok(resp: Optional[dict]) -> bool:
    return isinstance(resp, dict) and resp.get("success") is not False and not resp.get("error")


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
def serializar_perfil_cliente(client: UserModel) -> dict:
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
        "evolution_instance": client.evolution_instance or "",
        "chatwoot_url": client.chatwoot_url or DEFAULT_CHATWOOT_URL,
        "nocodb_url": client.nocodb_url or DEFAULT_NOCODB_URL,
        "qr_webhook_url": client.qr_webhook_url or "",
        "whatsapp_conectado": bool(client.whatsapp_conectado)
    }


@router.get("/api/client/dashboard")
def get_client_dashboard(current_client: UserModel = Depends(get_current_client)):
    return serializar_perfil_cliente(current_client)


@router.get("/api/me")
def get_me(current_client: UserModel = Depends(get_current_client)):
    return serializar_perfil_cliente(current_client)


@router.post("/api/client/toggle-agent")
@router.post("/api/toggle-agente")
def client_toggle_agent(current_client: UserModel = Depends(get_current_client), db: Session = Depends(get_db)):
    current_client.estado_agente = "Pausado" if current_client.estado_agente == "Activo" else "Activo"
    registrar(db, current_client.id,
              f"Estado del Agente IA cambiado a '{current_client.estado_agente}' desde el panel del cliente.")
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
# PORTAL QR DINÁMICO (UN SOLO WEBHOOK DE n8n PARA TODOS LOS CLIENTES)
# ==================================================
@router.post("/api/client/qr")
@router.get("/api/client/qr")
def solicitar_qr_whatsapp(current_client: UserModel = Depends(get_current_client), db: Session = Depends(get_db)):
    instancia = (current_client.evolution_instance or "").strip()
    if not instancia:
        return {
            "success": False,
            "status": "NO_INSTANCE",
            "detail": "Este cliente aún no tiene instancia de WhatsApp. Pide al administrador que sincronice con n8n."
        }

    webhook_qr = (current_client.qr_webhook_url or N8N_QR_WEBHOOK_URL or "").strip()
    if not webhook_qr:
        return {
            "success": False,
            "status": "MISSING_WEBHOOK",
            "evolution_instance": instancia,
            "detail": "Falta configurar el Webhook QR de n8n."
        }

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
            "detail": "No se recibió respuesta del Webhook QR en n8n. Verifica que el flujo esté publicado."
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
# PANEL ADMIN: LECTURA
# ==================================================
def serializar_cliente_admin(u: UserModel) -> dict:
    return {
        "id": u.id,
        "full_name": u.full_name,
        "company_name": u.company_name,
        "email": u.email,
        "status": "Activo" if u.is_active else "Bloqueado",
        "is_active": bool(u.is_active),
        "plan": u.plan,
        "rol": "Cliente",
        "mensajes_consumidos": u.mensajes_consumidos or 0,
        "limite_mensajes": u.limite_mensajes or 1000,
        "estado_agente": u.estado_agente or "Activo",
        "webhook_activo": bool(u.webhook_activo),
        "inventario_activo": bool(u.inventario_activo),
        "evolution_instance": u.evolution_instance or "",
        "chatwoot_url": u.chatwoot_url or "",
        "nocodb_url": u.nocodb_url or "",
        "qr_webhook_url": u.qr_webhook_url or "",
        "whatsapp_conectado": bool(u.whatsapp_conectado),
        "provision_status": u.provision_status or "pendiente",
        "provision_error": u.provision_error or ""
    }


@router.get("/api/admin/stats")
def get_admin_stats(db: Session = Depends(get_db), staff: StaffModel = Depends(get_ventas_user)):
    total_active = db.query(func.count(UserModel.id)).filter(UserModel.is_active.is_(True)).scalar() or 0
    total_mensajes = db.query(func.coalesce(func.sum(UserModel.mensajes_consumidos), 0)).scalar() or 0
    paused = db.query(func.count(UserModel.id)).filter(UserModel.estado_agente != "Activo").scalar() or 0
    return {
        "total_active_clients": total_active,
        "conversations_today": total_mensajes,
        "paused_agents": paused
    }


@router.get("/api/admin/users")
def get_all_users(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=100),
    db: Session = Depends(get_db),
    staff: StaffModel = Depends(get_ventas_user)
):
    users_db = db.query(UserModel).order_by(UserModel.id.desc()).offset(skip).limit(limit).all()
    return [serializar_cliente_admin(u) for u in users_db]


@router.get("/api/admin/users/{user_id}/errors")
def get_user_errors(user_id: int, db: Session = Depends(get_db), staff: StaffModel = Depends(get_ventas_user)):
    logs = db.query(ErrorLogModel).filter(ErrorLogModel.user_id == user_id).order_by(ErrorLogModel.id.desc()).limit(50).all()
    return [{"id": l.id, "mensaje": l.mensaje, "timestamp": l.timestamp} for l in logs]


# ==================================================
# PANEL ADMIN: ALTA DE CLIENTE + APROVISIONAMIENTO (TODO VÍA n8n)
# ==================================================
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
    """Una sola llamada a n8n. n8n crea Evolution + Chatwoot + NocoDB y responde con las URLs."""
    instancia = (user.evolution_instance or "").strip()
    if not instancia or "{{" in instancia:
        instancia = instancia_unica(db, generar_slug_instancia(user.company_name), user.id)
        user.evolution_instance = instancia
        db.commit()

    payload = {
        "event": "client.created",
        "client_id": user.id,
        "full_name": user.full_name,
        "company_name": user.company_name,
        "email": user.email,
        "plan": user.plan,
        "limite_mensajes": user.limite_mensajes,
        "evolution_instance": instancia
    }

    resp = llamar_webhook_n8n(N8N_CREATE_CLIENT_WEBHOOK_URL, payload, timeout=60, only_post=True)
    ok = n8n_respondio_ok(resp)

    if ok:
        if resp.get("evolution_instance") and "{{" not in str(resp.get("evolution_instance")):
            user.evolution_instance = resp["evolution_instance"]
        if resp.get("chatwoot_url"):
            user.chatwoot_url = resp["chatwoot_url"]
        if resp.get("nocodb_url"):
            user.nocodb_url = resp["nocodb_url"]
        if resp.get("qr_webhook_url"):
            user.qr_webhook_url = resp["qr_webhook_url"]
        if isinstance(resp.get("ecosistema_ids"), dict):
            user.ecosistema_ids = json.dumps(resp["ecosistema_ids"])
        user.provision_status = "activo"
        user.provision_error = None
        registrar(db, user.id, f"Ecosistema aprovisionado por n8n (instancia: {user.evolution_instance}).")
    else:
        detalle = "n8n no respondió. Verifica que el flujo esté publicado."
        if isinstance(resp, dict):
            detalle = str(resp.get("error") or resp.get("message") or detalle)[:500]
        user.provision_status = "error"
        user.provision_error = detalle
        registrar(db, user.id, f"Fallo al aprovisionar en n8n: {detalle}")

    db.commit()
    return {"provisioned": ok, "n8n_response": resp}


@router.post("/api/admin/users")
@router.post("/api/admin/create-user")
def create_new_user(request: CreateUserRequest, db: Session = Depends(get_db), master: StaffModel = Depends(get_master_user)):
    if db.query(UserModel).filter(UserModel.email == request.email).first():
        return {"success": False, "detail": "Este correo ya está registrado."}

    limite = obtener_limite_por_plan(request.plan)
    base_instancia = (request.evolution_instance or "").strip() or generar_slug_instancia(request.company_name)
    instancia = instancia_unica(db, base_instancia)

    new_user = UserModel(
        full_name=request.full_name,
        company_name=request.company_name,
        email=request.email,
        hashed_password=hash_password(request.password),
        plan=request.plan,
        limite_mensajes=limite,
        evolution_instance=instancia,
        chatwoot_url=(request.chatwoot_url or "").strip() or None,
        nocodb_url=(request.nocodb_url or "").strip() or None,
        qr_webhook_url=(request.qr_webhook_url or "").strip() or None,
        provision_status="pendiente"
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    registrar(db, new_user.id, f"Cuenta de cliente creada por {master.email} (instancia: {new_user.evolution_instance}).")
    db.commit()

    resultado_n8n = {"provisioned": False}
    if request.auto_provision_n8n:
        resultado_n8n = aprovisionar_cliente_en_n8n(new_user, db)

    return {
        "success": True,
        "message": "Cliente creado" if resultado_n8n.get("provisioned") or not request.auto_provision_n8n
        else "Cliente creado, pero n8n no pudo aprovisionarlo. Usa 'Sync n8n' para reintentar.",
        "user_id": new_user.id,
        "provision_status": new_user.provision_status,
        "provision_error": new_user.provision_error,
        "evolution_instance": new_user.evolution_instance,
        "chatwoot_url": new_user.chatwoot_url,
        "nocodb_url": new_user.nocodb_url,
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

    duplicado = db.query(UserModel).filter(UserModel.email == request.email, UserModel.id != user_id).first()
    if duplicado:
        return {"success": False, "detail": "Ese correo ya pertenece a otro cliente."}

    user.full_name = request.full_name
    user.company_name = request.company_name
    user.email = request.email
    user.plan = request.plan
    user.limite_mensajes = obtener_limite_por_plan(request.plan)

    if request.evolution_instance is not None:
        base = request.evolution_instance.strip() or generar_slug_instancia(request.company_name)
        user.evolution_instance = instancia_unica(db, base, user.id)
    if request.chatwoot_url is not None:
        user.chatwoot_url = request.chatwoot_url.strip() or None
    if request.nocodb_url is not None:
        user.nocodb_url = request.nocodb_url.strip() or None
    if request.qr_webhook_url is not None:
        user.qr_webhook_url = request.qr_webhook_url.strip() or None

    if request.password and request.password.strip() != "":
        user.hashed_password = hash_password(request.password)
        user.token_version += 1

    registrar(db, user.id, f"Datos del cliente editados por {master.email}.")
    db.commit()
    return {"success": True, "message": "Cliente actualizado"}


@router.post("/api/admin/users/{user_id}/reprovision")
def reprovision_user_n8n(user_id: int, db: Session = Depends(get_db), master: StaffModel = Depends(get_master_user)):
    user = db.query(UserModel).filter(UserModel.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Cliente no encontrado")
    resultado = aprovisionar_cliente_en_n8n(user, db)
    return {
        "success": bool(resultado.get("provisioned")),
        "provision_status": user.provision_status,
        "detail": user.provision_error or "",
        "n8n_provisioning": resultado
    }


# ==================================================
# PANEL ADMIN: ACCIONES MASTER
# ==================================================
@router.put("/api/admin/users/{user_id}/toggle-block")
def toggle_block_user(user_id: int, db: Session = Depends(get_db), master: StaffModel = Depends(get_master_user)):
    user = db.query(UserModel).filter(UserModel.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Cliente no encontrado")

    user.is_active = not user.is_active
    if not user.is_active:
        user.token_version += 1  # cierra sus sesiones abiertas
    registrar(db, user.id, f"Acceso {'reactivado' if user.is_active else 'bloqueado'} por {master.email}.")
    db.commit()
    return {"success": True, "is_active": user.is_active}


@router.put("/api/admin/users/{user_id}/toggle-agent")
def toggle_agent_status(user_id: int, db: Session = Depends(get_db), master: StaffModel = Depends(get_master_user)):
    user = db.query(UserModel).filter(UserModel.id == user_id).first()
    if not user:
        return {"success": False, "detail": "Cliente no encontrado"}

    if user.estado_agente == "Activo":
        user.estado_agente = "Pausado"
        registrar(db, user.id, f"Agente IA pausado por {master.email}.")
    else:
        user.estado_agente = "Activo"
        registrar(db, user.id, f"Agente IA reanudado por {master.email}.")

    db.commit()
    return {"success": True, "estado_agente": user.estado_agente}


@router.post("/api/admin/users/{user_id}/reset-usage")
def reset_usage(user_id: int, db: Session = Depends(get_db), master: StaffModel = Depends(get_master_user)):
    user = db.query(UserModel).filter(UserModel.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Cliente no encontrado")

    habia_llegado_al_limite = (user.mensajes_consumidos or 0) >= (user.limite_mensajes or 1000)
    user.mensajes_consumidos = 0
    reactivado = False
    if habia_llegado_al_limite and user.estado_agente != "Activo":
        user.estado_agente = "Activo"
        reactivado = True
    registrar(db, user.id,
              f"Consumo de mensajes reiniciado a 0 por {master.email}" + (" (agente reactivado)." if reactivado else "."))
    db.commit()
    return {"success": True, "mensajes_consumidos": 0, "estado_agente": user.estado_agente}


@router.delete("/api/admin/users/{user_id}")
def delete_user(
    user_id: int,
    force: bool = Query(False),
    db: Session = Depends(get_db),
    master: StaffModel = Depends(get_master_user)
):
    """
    Elimina al cliente. Primero pide a n8n que limpie su ecosistema (instancia de WhatsApp,
    cuenta de Chatwoot y datos en NocoDB). Si n8n no confirma, no borra nada salvo que se use force=true.
    """
    user = db.query(UserModel).filter(UserModel.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Cliente no encontrado")

    payload = {
        "event": "client.deleted",
        "client_id": user.id,
        "company_name": user.company_name,
        "email": user.email,
        "evolution_instance": user.evolution_instance,
        "ecosistema_ids": json.loads(user.ecosistema_ids) if user.ecosistema_ids else {}
    }
    resp = llamar_webhook_n8n(N8N_DELETE_CLIENT_WEBHOOK_URL, payload, timeout=60, only_post=True)
    n8n_ok = n8n_respondio_ok(resp)

    if not n8n_ok and not force:
        detalle = "n8n no confirmó la limpieza del ecosistema (WhatsApp, Chatwoot, NocoDB)."
        if isinstance(resp, dict) and (resp.get("error") or resp.get("message")):
            detalle = str(resp.get("error") or resp.get("message"))[:300]
        return JSONResponse(
            status_code=409,
            content={"success": False, "needs_force": True, "detail": detalle}
        )

    print(f"[ADMIN] {master.email} eliminó al cliente {user.email} (id={user.id}, n8n_ok={n8n_ok}, force={force})")
    db.query(ErrorLogModel).filter(ErrorLogModel.user_id == user.id).delete()
    db.delete(user)
    db.commit()
    return {"success": True, "message": "Cliente eliminado", "n8n_cleanup": n8n_ok}


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
    provision_status: Optional[str] = None
    provision_error: Optional[str] = None


def verificar_secreto_n8n(x_qxao_secret: Optional[str]):
    """Falla cerrado: sin secreto configurado en el servidor, los webhooks entrantes se rechazan."""
    if not N8N_WEBHOOK_SECRET:
        raise HTTPException(status_code=503, detail="N8N_WEBHOOK_SECRET no está configurado en el servidor.")
    if not x_qxao_secret or not hmac.compare_digest(x_qxao_secret, N8N_WEBHOOK_SECRET):
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
    if payload.provision_status in ("pendiente", "activo", "error"):
        user.provision_status = payload.provision_status
        user.provision_error = (payload.provision_error or None) if payload.provision_status == "error" else None

    registrar(db, user.id, "Datos del ecosistema actualizados automáticamente por n8n.")
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
        registrar(db, user.id, "Límite de mensajes alcanzado. Agente IA pausado automáticamente.")
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

    registrar(db, client.id,
              f"AUDITORÍA: El administrador [{current_staff.email}] inició sesión en esta cuenta usando el Modo Impersonación.")
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

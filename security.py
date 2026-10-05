import os
import jwt
import bcrypt
import secrets
from datetime import datetime, timedelta
from fastapi import Request, Depends, HTTPException, status
from sqlalchemy.orm import Session
from slowapi import Limiter
from slowapi.util import get_remote_address

from database import get_db, UserModel, StaffModel

# 1. PROTECCIÓN ANTI-FUERZA BRUTA
limiter = Limiter(key_func=get_remote_address)

# 2. CONFIGURACIÓN DE CRIPTOGRAFÍA
JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY")
if not JWT_SECRET_KEY:
    raise ValueError("FATAL ERROR: JWT_SECRET_KEY no está configurada")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 480 # 8 horas

def hash_password(password: str):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str):
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

# =======================================================
# 3. GENERADOR DE TOKENS Y CSRF
# =======================================================
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=ALGORITHM)

def generate_csrf_token():
    return secrets.token_urlsafe(32)

def get_client_token(request: Request):
    token = request.cookies.get("qxao_client_token")
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Sesión no iniciada.")
    return token

def get_staff_token(request: Request):
    token = request.cookies.get("qxao_staff_token")
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Sesión corporativa no iniciada.")
    return token

# =======================================================
# 4. VERIFICADORES DE AUTENTICIDAD
# =======================================================
def get_current_client(token: str = Depends(get_client_token), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Credenciales inválidas")
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        tipo: str = payload.get("tipo")
        tv: int = payload.get("tv") # Versión del token
        
        if email is None or tipo != "cliente":
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception
        
    user = db.query(UserModel).filter(UserModel.email == email).first()
    # Si bloqueaste al usuario o le cambiaste la clave, tv ya no coincide y el token muere:
    if user is None or user.token_version != tv:
        raise credentials_exception
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Tu cuenta ha sido bloqueada.")
        
    return user

def get_current_staff(token: str = Depends(get_staff_token), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Credenciales inválidas")
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        tipo: str = payload.get("tipo")
        tv: int = payload.get("tv")
        
        if email is None or tipo != "staff":
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception
        
    staff = db.query(StaffModel).filter(StaffModel.email == email).first()
    if staff is None or staff.token_version != tv:
        raise credentials_exception
    if not staff.is_active:
        raise HTTPException(status_code=403, detail="Cuenta corporativa bloqueada.")
        
    return staff

# =======================================================
# 5. ROLES Y PERMISOS DEL PANEL
# =======================================================
def get_master_user(current_staff: StaffModel = Depends(get_current_staff)):
    """Poder absoluto: Crear, editar, bloquear."""
    if current_staff.rol != "master":
        raise HTTPException(status_code=403, detail="Acceso denegado. Operación exclusiva de Master.")
    return current_staff

def get_ventas_user(current_staff: StaffModel = Depends(get_current_staff)):
    """Solo visualización de métricas y clientes."""
    if current_staff.rol not in ["master", "ventas"]:
        raise HTTPException(status_code=403, detail="Acceso denegado. Rol insuficiente.")
    return current_staff
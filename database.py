import os
from sqlalchemy import create_engine, Column, Integer, String, Boolean
from sqlalchemy.orm import declarative_base, sessionmaker

# 1. Configuración de Base de Datos Dinámica
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./qxao.db")

# Corrección de prefijo para PostgreSQL en SQLAlchemy
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# Optimización de conexiones: Evita bloqueos en SQLite y caídas en Postgres
if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(
        DATABASE_URL, 
        connect_args={"check_same_thread": False, "timeout": 15}
    )
else:
    engine = create_engine(
        DATABASE_URL, 
        pool_pre_ping=True, 
        pool_size=20, 
        max_overflow=10, 
        pool_recycle=3600
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# =======================================================
# 2. MODELOS DE BASE DE DATOS (NÚCLEO EMPRESARIAL)
# =======================================================

class UserModel(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    full_name = Column(String, index=True)
    email = Column(String, unique=True, index=True)
    company_name = Column(String)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True) 
    plan = Column(String, default="Básico") 
    mensajes_consumidos = Column(Integer, default=0)
    limite_mensajes = Column(Integer, default=1000)
    estado_agente = Column(String, default="Activo") 
    webhook_activo = Column(Boolean, default=True) 
    inventario_activo = Column(Boolean, default=True) 
    token_version = Column(Integer, default=1) # CONTROL DE REVOCACIÓN JWT

class StaffModel(Base):
    __tablename__ = "staff"
    id = Column(Integer, primary_key=True, index=True)
    full_name = Column(String)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    rol = Column(String) 
    is_active = Column(Boolean, default=True)
    token_version = Column(Integer, default=1) # CONTROL DE REVOCACIÓN JWT

class ErrorLogModel(Base):
    __tablename__ = "error_logs"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True)
    mensaje = Column(String)
    timestamp = Column(String)

# Inicialización de tablas
Base.metadata.create_all(bind=engine)

# Inyección de dependencias para FastAPI
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
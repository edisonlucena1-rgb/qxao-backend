import os
from sqlalchemy import create_engine, Column, Integer, String, Boolean, inspect, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./qxao.db")

if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

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
    token_version = Column(Integer, default=1)

    # CAMPOS MULTI-TENANT (MARCA BLANCA POR CLIENTE)
    evolution_instance = Column(String, nullable=True, index=True)
    chatwoot_url = Column(String, nullable=True)
    nocodb_url = Column(String, nullable=True)
    qr_webhook_url = Column(String, nullable=True)
    whatsapp_conectado = Column(Boolean, default=False)
    provision_status = Column(String, default="pendiente")  # pendiente | activo | error
    provision_error = Column(String, nullable=True)
    ecosistema_ids = Column(String, nullable=True)  # JSON: ids creados por n8n (Chatwoot cuenta/usuario, base NocoDB)


class StaffModel(Base):
    __tablename__ = "staff"
    id = Column(Integer, primary_key=True, index=True)
    full_name = Column(String)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    rol = Column(String)
    is_active = Column(Boolean, default=True)
    token_version = Column(Integer, default=1)


class ErrorLogModel(Base):
    __tablename__ = "error_logs"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True)
    mensaje = Column(String)
    timestamp = Column(String)


Base.metadata.create_all(bind=engine)


def ensure_multitenant_columns():
    """
    Auto-migración segura e idempotente para PostgreSQL y SQLite.
    """
    nuevas_columnas = {
        "evolution_instance": "VARCHAR(150)",
        "chatwoot_url": "TEXT",
        "nocodb_url": "TEXT",
        "qr_webhook_url": "TEXT",
        "whatsapp_conectado": "BOOLEAN DEFAULT FALSE",
        "provision_status": "VARCHAR(20) DEFAULT 'pendiente'",
        "provision_error": "TEXT",
        "ecosistema_ids": "TEXT"
    }
    try:
        inspector = inspect(engine)
        if "users" not in inspector.get_table_names():
            return
        columnas_actuales = {col["name"] for col in inspector.get_columns("users")}
        with engine.begin() as conn:
            for col_name, col_type in nuevas_columnas.items():
                if col_name not in columnas_actuales:
                    conn.execute(text(f"ALTER TABLE users ADD COLUMN {col_name} {col_type}"))
                    print(f"Columna multi-tenant agregada: users.{col_name}")
    except Exception as e:
        print(f"Aviso al verificar columnas multi-tenant: {e}")


ensure_multitenant_columns()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

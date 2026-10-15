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
        "whatsapp_conectado": "BOOLEAN DEFAULT FALSE"
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

            cw = "https://chat.qxao.dpdns.org/app/accounts/2/dashboard"
            nc_jl = "https://crm.qxao.dpdns.org/wgai29by/pi4c3iginxwezws"
            qr_jl = "https://n8n.qxao.dpdns.org/webhook/obtener-qr-jlburger"
            nc_en = "https://crm.qxao.dpdns.org/wgai29by/p96tfdcx3ish0pv"
            qr_en = "https://n8n.qxao.dpdns.org/webhook/obtener-qr-engranos"

            conn.execute(text(
                f"UPDATE users SET evolution_instance='JLBurguer.', chatwoot_url='{cw}', nocodb_url='{nc_jl}', qr_webhook_url='{qr_jl}' "
                f"WHERE (LOWER(company_name) LIKE '%burger%' OR LOWER(company_name) LIKE '%burguer%' OR LOWER(email) LIKE '%burger%') "
                f"AND (chatwoot_url IS NULL OR chatwoot_url = '')"
            ))
            conn.execute(text(
                f"UPDATE users SET evolution_instance='pisa62', chatwoot_url='{cw}', nocodb_url='{nc_en}', qr_webhook_url='{qr_en}' "
                f"WHERE (LOWER(company_name) LIKE '%engrano%' OR LOWER(full_name) LIKE '%yolanda%' OR LOWER(email) LIKE '%engrano%') "
                f"AND (chatwoot_url IS NULL OR chatwoot_url = '')"
            ))
    except Exception as e:
        print(f"Aviso al verificar columnas multi-tenant: {e}")


ensure_multitenant_columns()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

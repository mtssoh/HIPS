import os
from sqlmodel import SQLModel, create_engine, Session
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()

# Configuración de la base de datos
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise ValueError("DB URL NOT CONFIGURED")

engine = create_engine(DATABASE_URL)

def create_db_and_tables():
    """Crea las tablas en la base de datos"""
    SQLModel.metadata.create_all(engine)

def get_session():
    """Genera una sesión de base de datos"""
    with Session(engine) as session:
        yield session

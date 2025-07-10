import os
import hashlib
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlmodel import Session

from app.database import create_db_and_tables, engine
from app.models import User, FileBaseline
from app.auth import get_password_hash
from app.utils import log_event, ALARMS_LOG_FILE, HIPS_LOG_DIR

# Importar todas las rutas
from app.routes.auth_routes import router as auth_router
from app.routes.system_routes import router as system_router
from app.routes.network_routes import router as network_router
from app.routes.log_routes import router as log_router
from app.routes.process_routes import router as process_router
from app.routes.ddos_routes import router as ddos_router

app = FastAPI(title="HIPS - Host-based Intrusion Prevention System")

# --- CORS Configuration ---
origins = [
    "http://localhost:8001",
    "http://127.0.0.1:8001",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Include Routers ---
app.include_router(auth_router, tags=["Authentication"])
app.include_router(system_router, prefix="/scan", tags=["System Scan"])
app.include_router(network_router, prefix="/system", tags=["Network Security"])
app.include_router(log_router, prefix="/system", tags=["Log Analysis"])
app.include_router(process_router, prefix="/system", tags=["Process Monitoring"])
app.include_router(ddos_router, prefix="/system", tags=["DDoS Analysis"])

# --- Startup and Shutdown Events ---
@app.on_event("startup")
def on_startup():
    create_db_and_tables()
    # Asegúrate de que el directorio de logs exista al inicio
    os.makedirs(HIPS_LOG_DIR, exist_ok=True)

    with Session(engine) as session:
        # Crear usuario admin si no existe
        if not session.query(User).filter(User.username == "admin").first():
            admin_user = User(username="admin", password_hash=get_password_hash("adminpass"))
            session.add(admin_user)
            session.commit()
            print("Admin user created.")
            log_event(ALARMS_LOG_FILE, "SYSTEM_INIT", "Admin user 'admin' created with default password.")
        
        # Set an initial baseline for /etc/passwd and /etc/shadow if it doesn't exist
        passwd_path = "/etc/passwd"
        shadow_path = "/etc/shadow"

        for file_path in [passwd_path, shadow_path]:
            if not session.query(FileBaseline).filter(FileBaseline.file_path == file_path).first():
                try:
                    with open(file_path, "rb") as f:
                        file_hash = hashlib.sha256(f.read()).hexdigest()
                    session.add(FileBaseline(file_path=file_path, baseline_hash=file_hash))
                    session.commit()
                    print(f"Initial baseline for {file_path} created.")
                    log_event(ALARMS_LOG_FILE, "BASELINE_INIT", f"Initial baseline set for {file_path}.")
                except FileNotFoundError:
                    print(f"Warning: Could not establish baseline for {file_path} (file not found).")
                    log_event(ALARMS_LOG_FILE, "BASELINE_ERROR", f"File not found for baseline: {file_path}.")
                except PermissionError:
                    print(f"Warning: Insufficient permissions to read {file_path} for baseline.")
                    log_event(ALARMS_LOG_FILE, "BASELINE_ERROR", f"Permission denied to read {file_path} for baseline. Run with appropriate permissions.")
                except Exception as e:
                    print(f"Error establishing initial baseline for {file_path}: {e}")
                    log_event(ALARMS_LOG_FILE, "BASELINE_ERROR", f"Error setting baseline for {file_path}: {e}.")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

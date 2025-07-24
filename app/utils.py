import os
import smtplib
from datetime import datetime, timezone
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional

# Directorios de logs para HIPS
HIPS_LOG_DIR = "/var/log/hips"
ALARMS_LOG_FILE = os.path.join(HIPS_LOG_DIR, "alarmas.log")
PREVENTION_LOG_FILE = os.path.join(HIPS_LOG_DIR, "prevencion.log")

# Configuración de email para alertas
ALERT_EMAIL_SENDER = os.getenv("ALERT_EMAIL_SENDER")
ALERT_EMAIL_RECEIVER = os.getenv("ALERT_EMAIL_RECEIVER")
ALERT_EMAIL_PASSWORD = os.getenv("ALERT_EMAIL_PASSWORD")
SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))

def log_event(log_file: str, event_type: str, message: str, ip: Optional[str] = None):
    """Registra un evento en el archivo de log especificado."""
    timestamp = datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M:%S")
    log_entry = f"{timestamp} :: {event_type} :: {ip if ip else 'N/A'} :: {message}\n"

    os.makedirs(HIPS_LOG_DIR, exist_ok=True)

    with open(log_file, "a") as f:
        f.write(log_entry)
    print(f"[LOG] Evento registrado en {log_file}: {log_entry.strip()}")

def send_alert_email(subject: str, body: str):
    """Envía un correo electrónico de alerta al administrador."""
    if not all([ALERT_EMAIL_SENDER, ALERT_EMAIL_RECEIVER, SMTP_SERVER]):
        print("[ADVERTENCIA] Alerta por correo no configurada. Faltan variables de entorno: SENDER, RECEIVER o SMTP_SERVER.")
        return

    msg = MIMEMultipart()
    msg['From'] = ALERT_EMAIL_SENDER
    msg['To'] = ALERT_EMAIL_RECEIVER
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            if ALERT_EMAIL_PASSWORD:
                server.login(ALERT_EMAIL_SENDER, ALERT_EMAIL_PASSWORD)
            server.send_message(msg)

        print(f"[CORREO] Alerta enviada a {ALERT_EMAIL_RECEIVER} con asunto: {subject}")
        log_event(ALARMS_LOG_FILE, "CORREO_ENVIADO", f"Alerta enviada por correo: {subject}")

    except Exception as e:
        print(f"[ERROR] No se pudo enviar la alerta por correo: {e}")
        log_event(ALARMS_LOG_FILE, "ERROR_CORREO", f"No se pudo enviar la alerta por correo: {e}")

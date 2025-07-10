import os
import re

from fastapi import APIRouter, Depends, HTTPException, status

from app.auth import get_current_user
from app.models import User
from app.utils import send_alert_email, log_event, ALARMS_LOG_FILE

router = APIRouter()

@router.post("/analyze_ddos_log")
async def analyze_ddos_log(
    request_data: dict,  # Recibe el JSON con log_file_path
    current_user: User = Depends(get_current_user)
):
    log_file_path = request_data.get("log_file_path")
    if not log_file_path:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="log_file_path is required in request body"
        )
    
    results = {
        "log_path": log_file_path,
        "detections": [],
        "message": "DDoS log analysis complete.",
        "status": "OK"
    }

    if not os.path.exists(log_file_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"DDoS log file not found at {log_file_path}"
        )
    
    # Patrones de ejemplo para DNS DDoS (ajustar según el log de muestra)
    # Ejemplo: muchas consultas DNS desde una misma IP o a un mismo dominio/tipo de registro
    # Para un ataque de reflexión/amplificación, buscarías patrones de respuestas grandes a consultas pequeñas
    ddos_patterns = [
        re.compile(r"client (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})#\d+: query: .*\s(NXDOMAIN|\d+\squeries from client)"), # Fallos repetitivos o muchas queries
        re.compile(r"client (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})#\d+: view \S+: query: \S+ IN (\S+) \S+ \((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)"), # Consultas de cierto tipo
        # Aquí irían patrones más específicos para ataques de amplificación DNS
    ]

    ip_counts = {}  # Contador de hits por IP
    
    try:
        with open(log_file_path, 'r') as f:
            for line in f:
                for pattern in ddos_patterns:
                    match = pattern.search(line)
                    if match:
                        ip = match.group(1) if len(match.groups()) >=1 else "N/A"
                        
                        if ip != "N/A":
                            ip_counts[ip] = ip_counts.get(ip, 0) + 1
                        
                        results["detections"].append({"line": line.strip(), "ip": ip, "pattern": pattern.pattern})
                        break  # Pasa a la siguiente línea una vez que un patrón coincide

        # Evaluar detecciones basadas en umbrales
        for ip, count in ip_counts.items():
            if count >= 50:  # Umbral de 50 consultas desde una IP (ajustar)
                alert_msg = f"Possible DDoS activity: IP {ip} generated {count} suspicious DNS queries."
                results["detections"].insert(0, {"summary": alert_msg, "ip": ip, "type": "ddos_ip_summary"})
                results["status"] = "ALERT"
                results["message"] = "Possible DDoS attack detected!"
                log_event(ALARMS_LOG_FILE, "DDOS_DETECTED", alert_msg, ip=ip)
                send_alert_email("HIPS Alert: Possible DDoS Attack", alert_msg)
                # PREVENCIÓN: Bloquear la IP
                # await block_ip(ip, "Possible DDoS attack source")
                # Opcional: bajar el servicio de DNS temporalmente si el ataque es muy severo
                # subprocess.run(["sudo", "systemctl", "stop", "bind9"], check=True) # Ejemplo para BIND
                # log_event(PREVENTION_LOG_FILE, "SERVICE_DOWN", "DNS service temporarily stopped due to DDoS.")

    except FileNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"DDoS log file not found at {log_file_path}"
        )
    except Exception as e:
        results["status"] = "ERROR"
        results["message"] = f"Error analyzing DDoS log: {str(e)}"
        log_event(ALARMS_LOG_FILE, "DDOS_ANALYZE_ERROR", f"Error analyzing DDoS log {log_file_path}: {str(e)}")

    return results

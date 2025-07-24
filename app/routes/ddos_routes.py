import os
import re

from fastapi import APIRouter, Depends, HTTPException, status

from app.auth import get_current_user
from app.models import User
from app.utils import send_alert_email, log_event, ALARMS_LOG_FILE
from app.prevention import block_ip

router = APIRouter()

@router.post("/analyze_ddos_log")
async def analyze_ddos_log(
    request_data: dict,  
    current_user: User = Depends(get_current_user)
):
    log_file_path = request_data.get("log_file_path")
    if not log_file_path:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Se requiere 'log_file_path' en el cuerpo de la solicitud."
        )
    
    results = {
        "ruta_log": log_file_path,
        "detecciones": [],
        "mensaje": "Análisis de DDoS completado",
        "estado": "OK"
    }

    if not os.path.exists(log_file_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No se encontró el archivo de log en la ruta: {log_file_path}"
        )
    
    ddos_patterns = [
        re.compile(r"client (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})#\d+: query: .*\s(NXDOMAIN|\d+\squeries from client)"), 
        re.compile(r'^(\d{1,3}(?:\.\d{1,3}){3}) - - \[.*?\] "(?:GET|POST|HEAD|PUT|DELETE|OPTIONS) [^"]+" ([45]\d{2})')
    ]

    ip_counts = {}  
    
    try:
        with open(log_file_path, 'r') as f:
            for line in f:
                for pattern in ddos_patterns:
                    match = pattern.search(line)
                    if match:
                        ip = match.group(1) if len(match.groups()) >= 1 else "N/A"
                        if ip != "N/A":
                            ip_counts[ip] = ip_counts.get(ip, 0) + 1
                        
                        results["detecciones"].append({
                            "linea": line.strip(),
                            "ip": ip,
                            "patron": pattern.pattern
                        })
                        break  # No buscar múltiples patrones en una misma línea

        for ip, count in ip_counts.items():
            if count >= 50: 
                mensaje_alerta = f"Posible actividad DDoS: la IP {ip} generó {count} consultas sospechosas."
                results["detecciones"].insert(0, {
                    "resumen": mensaje_alerta,
                    "ip": ip,
                    "tipo": "resumen_ddos_ip"
                })
                results["estado"] = "ALERTA"
                results["mensaje"] = "Posible actividad DDoS detectada"

                log_event(ALARMS_LOG_FILE, "DDOS_DETECTADO", mensaje_alerta, ip=ip)
                send_alert_email("ALERTA: Posible ataque DDoS detectado", mensaje_alerta)
                await block_ip(ip, "IP bloqueada por posible ataque DDoS")

    except FileNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No se encontró el archivo de log en la ruta: {log_file_path}"
        )
    except Exception as e:
        results["estado"] = "ERROR"
        results["mensaje"] = f"Error al analizar el log de DDoS: {str(e)}"
        log_event(
            ALARMS_LOG_FILE,
            "ERROR_ANALISIS_DDOS",
            f"Error al analizar el archivo {log_file_path}: {str(e)}"
        )

    return results

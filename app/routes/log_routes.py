import os
import re
import subprocess

from fastapi import APIRouter, Depends, HTTPException, status

from app.auth import get_current_user
from app.models import User
from app.utils import send_alert_email, log_event, ALARMS_LOG_FILE
from app.prevention import block_ip, change_user_password

router = APIRouter()

@router.get("/analyze_logs")
async def analyze_system_logs(
    log_type: str,  
    current_user: User = Depends(get_current_user)
):
    results = {
        "tipo_log": log_type,
        "detecciones": [],
        "mensaje": "Análisis completado.",
        "estado": "OK"
    }

    log_paths = []
    patterns = []
    
    if log_type == "auth":
        log_paths = ["/var/log/secure"] 
        patterns = [
            re.compile(r"authentication failure", re.IGNORECASE),
            re.compile(r"failed password", re.IGNORECASE)
        ]
        results["mensaje"] = "Buscando fallos de autenticación."
    elif log_type == "web":
        log_paths = ["/var/log/httpd/access.log"]
        patterns = [re.compile(r'^(\d{1,3}(?:\.\d{1,3}){3}) - - \[.*?\] "(?:GET|POST|HEAD|PUT|DELETE|OPTIONS) [^"]+" ([45]\d{2})')]
        results["mensaje"] = "Buscando errores de acceso web."
    elif log_type == "mail":
        log_paths = ["/var/log/mail.log"]
        patterns = [
            re.compile(r"relay=.*\[(\d{1,3}(?:\.\d{1,3}){3})\].*authid=.*?@.*?, mech=LOGIN", re.IGNORECASE),
            re.compile(r"from=<.*?@.*?>, size=\d+, class=\d+, nrcpts=\d+, msgid=<.*?>", re.IGNORECASE),
            re.compile(r"stat=User unknown", re.IGNORECASE)
        ]
        results["mensaje"] = "Buscando actividad sospechosa en el correo."
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Tipo de log no soportado. Valores válidos: 'auth', 'web', 'mail'."
        )

    found_events = {}  

    for log_path in log_paths:
        if os.path.exists(log_path):
            try:
                proc = subprocess.run(['tail', '-n', '1000', log_path], capture_output=True, text=True, check=True)
                lines = proc.stdout.splitlines()

                for line in lines:
                    for pattern in patterns:
                        match = pattern.search(line)
                        if match:
                            detection_info = {"linea": line, "patron": pattern.pattern}
                            ip = None
                            if log_type == "web":
                                if len(match.groups()) >= 2:
                                    ip = match.group(1)
                                    status_code = match.group(2)
                                    detection_info["ip"] = ip
                                    detection_info["codigo_http"] = status_code
                                    if ip not in found_events:
                                        found_events[ip] = {"conteo": 0, "errores": []}
                                    found_events[ip]["conteo"] += 1
                                    found_events[ip]["errores"].append(f"HTTP {status_code} desde {ip}")
                            elif log_type == "auth":
                                ip_match = re.search(r'(?:from|for)\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                                if ip_match:
                                    ip = ip_match.group(1)
                                    detection_info["ip"] = ip
                                key = ip if ip else 'origen_desconocido_auth'
                                if key not in found_events:
                                    found_events[key] = {"conteo": 0, "intentos": []}
                                found_events[key]["conteo"] += 1
                                found_events[key]["intentos"].append(line)
                            elif log_type == "mail":
                                if len(match.groups()) >= 1:
                                    if pattern == patterns[0] or pattern == patterns[1]: 
                                        ip = match.group(1)
                                    elif pattern == patterns[2]:
                                        ip = match.group(2) if len(match.groups()) >= 2 else None
                                    detection_info["origen"] = ip if ip else 'origen_desconocido'
                                    key = ip if ip else 'origen_desconocido'
                                    if key not in found_events:
                                        found_events[key] = {"conteo": 0, "detalles": []}
                                    found_events[key]["conteo"] += 1
                                    found_events[key]["detalles"].append(line)

                            results["detecciones"].append(detection_info)
                            log_event(ALARMS_LOG_FILE, f"PATRON_LOG_{log_type.upper()}", line.strip(), ip=ip)
                            break

            except FileNotFoundError:
                results["detecciones"].append({"error": f"No se encontró el log en {log_path}."})
                log_event(ALARMS_LOG_FILE, "ERROR_LOG", f"No se encontró el archivo de log: {log_path}")
            except subprocess.CalledProcessError as e:
                results["detecciones"].append({"error": f"Error al leer {log_path}: {e.stderr.strip()}"})
                log_event(ALARMS_LOG_FILE, "ERROR_LOG", f"Error al leer el log {log_path}: {e.stderr.strip()}")
            except Exception as e:
                results["detecciones"].append({"error": f"Error inesperado al procesar {log_path}: {str(e)}"})
                log_event(ALARMS_LOG_FILE, "ERROR_LOG", f"Error inesperado al procesar el log {log_path}: {str(e)}")
        else:
            results["detecciones"].append({"info": f"El archivo {log_path} no existe en este sistema."})

    if results["detecciones"]:
        results["estado"] = "ALERTA"
        results["mensaje"] = f"Se detectaron patrones en logs de tipo {log_type}. Revisión necesaria."

    if log_type == "web":
        resumen_web = []
        for ip, info in found_events.items():
            if info["conteo"] >= 5 and ip != "N/A":
                resumen = f"La IP {ip} generó {info['conteo']} errores HTTP (posible escaneo o fuerza bruta web)."
                resumen_web.append(resumen)
                results["mensaje"] = "Errores HTTP múltiples desde una misma IP detectados."
                results["estado"] = "ALERTA"
                log_event(ALARMS_LOG_FILE, "ESCANEO_WEB_DETECTADO", resumen, ip=ip)
                send_alert_email("Alerta HIPS: Escaneo Web Detectado", resumen)
                if re.match(r'\d{1,3}(\.\d{1,3}){3}', ip):
                    await block_ip(ip, reason="Escaneo o fuerza bruta detectada")
        if resumen_web:
            results["detecciones"].insert(0, {"resumen": resumen_web, "tipo": "resumen_web_ip"})

    elif log_type == "mail":
        resumen_mail = []
        for source, info in found_events.items():
            if info["conteo"] >= 10:
                resumen = f"El origen '{source}' generó {info['conteo']} eventos de correo (posible envío masivo)."
                resumen_mail.append(resumen)
                results["mensaje"] = "Posible envío masivo de correo detectado."
                results["estado"] = "ALERTA"
                log_event(ALARMS_LOG_FILE, "ENVIO_MASIVO_CORREO", resumen, ip=source if re.match(r'\d{1,3}(\.\d{1,3}){3}', source) else None)
                send_alert_email("Alerta HIPS: Envío Masivo de Correo", resumen)
                if re.match(r'\d{1,3}(\.\d{1,3}){3}', source):
                    await block_ip(source, reason="Actividad sospechosa de correo")
        if resumen_mail:
            results["detecciones"].insert(0, {"resumen": resumen_mail, "tipo": "resumen_mail_masivo"})

    elif log_type == "auth":
        resumen_auth = []
        for source, info in found_events.items():
            if info["conteo"] >= 5:
                resumen = f"El origen '{source}' generó {info['conteo']} fallos de autenticación (posible fuerza bruta)."
                resumen_auth.append(resumen)
                results["mensaje"] = "Fallos múltiples de autenticación detectados."
                results["estado"] = "ALERTA"
                log_event(ALARMS_LOG_FILE, "FUERZA_BRUTA_DETECTADA", resumen, ip=source if re.match(r'\d{1,3}(\.\d{1,3}){3}', source) else None)
                username = None
                for line in info["intentos"]:
                    username_match = re.search(r"user=([\w\d_.-]+)", line)
                    if username_match:
                        username = username_match.group(1)
                        break
                if username:
                    await change_user_password(username, "Demasiados intentos fallidos de autenticación")
        if resumen_auth:
            results["detecciones"].insert(0, {"resumen": resumen_auth, "tipo": "resumen_fuerza_bruta_auth"})

    return results

import os
import re
import subprocess
import psutil

from fastapi import APIRouter, Depends, HTTPException, status

from app.auth import get_current_user
from app.models import User
from app.utils import send_alert_email, log_event, ALARMS_LOG_FILE
from app.prevention import change_user_password

router = APIRouter()

@router.get("/connected_users")
async def get_connected_users(
    current_user: User = Depends(get_current_user)
):
    try:
        result = subprocess.run(["w", "-h"], capture_output=True, text=True, check=True)
        output_lines = result.stdout.strip().split('\n')

        connected_users = []
        for line in output_lines:
            parts = line.split()
            if len(parts) >= 3:
                user_info = {
                    "usuario": parts[0],
                    "tty": parts[1],
                    "origen": parts[2] if parts[2] != "-" else "localhost",
                    "hora_ingreso": " ".join(parts[3:5]) if len(parts) > 4 else "N/D",
                    "inactivo": parts[5] if len(parts) > 5 else "N/D",
                    "jcpu": parts[6] if len(parts) > 6 else "N/D",
                    "pcpu": parts[7] if len(parts) > 7 else "N/D",
                    "comando": " ".join(parts[8:]) if len(parts) > 8 else "N/D"
                }
                connected_users.append(user_info)

        if not connected_users:
            return {"mensaje": "No se detectaron usuarios conectados (excepto el sistema).", "usuarios": []}

        # Detectar usuarios sospechosos
        known_local = {"localhost", "127.0.0.1", "::1", ":1", os.getenv("KNOWN_LOCAL_IP", "")}
        suspicious_users = [u for u in connected_users if u["origen"] not in known_local and u["origen"] != "?"]

        if suspicious_users:
            alert_list = []
            for su in suspicious_users:
                ip = su["origen"]
                username = su["usuario"]
                try:
                    subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
                    log_event(ALARMS_LOG_FILE, "IP_BLOQUEADA", f"IP sospechosa bloqueada: {ip} (Usuario: {username})")
                    send_alert_email(
                        f"Alerta HIPS: IP bloqueada - {ip}",
                        f"La dirección IP {ip} asociada al usuario {username} fue bloqueada por inicio de sesión sospechoso."
                    )
                except subprocess.CalledProcessError as e:
                    log_event(ALARMS_LOG_FILE, "FALLO_BLOQUEO", f"No se pudo bloquear la IP {ip}: {e}")
                
                await change_user_password(username, reason=f"Inicio de sesión sospechoso desde {ip}")
                alert_list.append(f"{username} desde {ip}")

            msg = f"Se detectaron y mitigaron usuarios conectados sospechosos: {', '.join(alert_list)}"
            log_event(ALARMS_LOG_FILE, "LOGIN_SOSPECHOSO", msg)
            return {
                "usuarios_conectados": connected_users,
                "alerta": msg,
                "estado": "ALERTA",
                "usuario": current_user.username
            }

        return {
            "usuarios_conectados": connected_users,
            "mensaje": "No se encontraron usuarios sospechosos.",
            "estado": "OK",
            "usuario": current_user.username
        }

    except subprocess.CalledProcessError as e:
        log_event(ALARMS_LOG_FILE, "ERROR_CMD", f"Error al ejecutar el comando 'w': {e.stderr.strip()}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al ejecutar el comando 'w': {e.stderr.strip()}"
        )
    except Exception as e:
        log_event(ALARMS_LOG_FILE, "ERROR_INESPERADO", f"Error inesperado al obtener usuarios conectados: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error inesperado al obtener usuarios conectados: {str(e)}"
        )


@router.get("/detect_sniffers")
async def sniffer_scan(current_user: User = Depends(get_current_user)):
    resultado = {
        "interfaces_detectadas": [],
        "procesos_detectados": [],
        "estado": "OK",
        "resumen": "Inspección completada."
    }

    try:
        prom_output = subprocess.run(["ip", "-s", "link"], capture_output=True, text=True)
        entries = prom_output.stdout.splitlines()
        iface = None

        for l in entries:
            match = re.search(r'^(\d+):\s+(\S+):', l)
            if match:
                iface = match.group(2)
            elif iface and "PROMISC" in l:
                alerta = f"La interfaz '{iface}' tiene el modo promiscuo activo."
                resultado["interfaces_detectadas"].append(alerta)
                resultado["estado"] = "ALERTA"
                resultado["resumen"] = "Se detectó modo promiscuo en al menos una interfaz de red."
                log_event(ALARMS_LOG_FILE, "INTERFAZ_PROMISCUA", alerta)
                send_alert_email("Alerta HIPS: Interfaz en modo promiscuo", alerta)
                iface = None

    except Exception as e:
        mensaje_error = f"No se pudo evaluar las interfaces de red: {e}"
        resultado["interfaces_detectadas"].append(mensaje_error)
        resultado["estado"] = "ERROR"
        resultado["resumen"] = "Error al verificar interfaces de red."
        log_event(ALARMS_LOG_FILE, "FALLO_INTERFAZ", mensaje_error)

    herramientas = [
        "wireshark", "tshark", "tcpdump", "snort", "zeek", "nmap", "dumpcap",
        "ngrep", "netcat", "ettercap", "ssldump", "dsniff", "pktmon", "arpspoof"
    ]

    procesos = psutil.process_iter(["pid", "name", "cmdline", "username"])
    for proc in procesos:
        try:
            detalles = proc.info.get("cmdline", []) or [proc.info.get("name", "")]
            linea = " ".join(detalles).lower()

            for herramienta in herramientas:
                if herramienta in linea:
                    detectado = {
                        "pid": proc.info["pid"],
                        "ejecutable": proc.info["name"],
                        "comando": linea,
                        "usuario": proc.info["username"]
                    }
                    resultado["procesos_detectados"].append(detectado)
                    if resultado["estado"] != "ALERTA":
                        resultado["estado"] = "ALERTA"
                        resultado["resumen"] = "Se detectaron herramientas de análisis de red en ejecución."
                    log = f"Herramienta sospechosa activa: {detectado['ejecutable']} (PID {detectado['pid']}, usuario {detectado['usuario']})"
                    log_event(ALARMS_LOG_FILE, "HERRAMIENTA_RED_DETECTADA", log)
                    send_alert_email("Alerta HIPS: Herramienta de red detectada", log)
                    break
        except Exception:
            continue

    if resultado["estado"] == "ALERTA":
        resultado["resumen"] = "Se identificaron posibles amenazas en el sistema."

    return {"resultado": resultado, "usuario": current_user.username}

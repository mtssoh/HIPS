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
                    "user": parts[0],
                    "tty": parts[1],
                    "from": parts[2] if parts[2] != "-" else "localhost",
                    "login_time": " ".join(parts[3:5]) if len(parts) > 4 else "N/A",
                    "idle": parts[5] if len(parts) > 5 else "N/A",
                    "jcpu": parts[6] if len(parts) > 6 else "N/A",
                    "pcpu": parts[7] if len(parts) > 7 else "N/A",
                    "what": " ".join(parts[8:]) if len(parts) > 8 else "N/A"
                }
                connected_users.append(user_info)

        if not connected_users:
            return {"message": "No connected users detected (besides the system itself).", "users": []}

        # Detectar usuarios sospechosos
        known_local = {"localhost", "127.0.0.1", "::1", ":1", os.getenv("KNOWN_LOCAL_IP", "")}
        suspicious_users = [u for u in connected_users if u["from"] not in known_local and u["from"] != "?"]

        if suspicious_users:
            alert_list = []
            for su in suspicious_users:
                ip = su["from"]
                username = su["user"]
                # Bloquear la IP
                try:
                    subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
                    log_event(ALARMS_LOG_FILE, "IP_BLOCKED", f"Blocked suspicious IP: {ip} (User: {username})")
                    send_alert_email(
                        f"HIPS Alert: IP Blocked - {ip}",
                        f"The IP address {ip} associated with user {username} has been blocked due to suspicious login."
                    )
                except subprocess.CalledProcessError as e:
                    log_event(ALARMS_LOG_FILE, "BLOCK_FAILED", f"Failed to block IP {ip}: {e}")
                
                await change_user_password(username, reason=f"Suspicious login from IP {ip}")
                alert_list.append(f"{username} from {ip}")

            msg = f"Suspicious connected users detected and mitigated: {', '.join(alert_list)}"
            log_event(ALARMS_LOG_FILE, "SUSPICIOUS_LOGIN", msg)
            return {
                "connected_users": connected_users,
                "alert": msg,
                "status": "ALERT",
                "user": current_user.username
            }

        return {
            "connected_users": connected_users,
            "message": "No suspicious users found.",
            "status": "OK",
            "user": current_user.username
        }

    except subprocess.CalledProcessError as e:
        log_event(ALARMS_LOG_FILE, "CMD_ERROR", f"Error running 'w' command: {e.stderr.strip()}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error running 'w' command: {e.stderr.strip()}"
        )
    except Exception as e:
        log_event(ALARMS_LOG_FILE, "UNEXPECTED_ERROR", f"Unexpected error getting connected users: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unexpected error getting connected users: {str(e)}"
        )

@router.get("/detect_sniffers")
async def sniffer_scan(current_user: User = Depends(get_current_user)):
    outcome = {
        "interfaces_flagged": [],
        "processes_flagged": [],
        "status": "OK",
        "summary": "Inspección completada."
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
                alert_text = f"'{iface}' con modo promiscuo activo."
                outcome["interfaces_flagged"].append(alert_text)
                outcome["status"] = "ALERTA"
                outcome["summary"] = "Modo promiscuo identificado en al menos una interfaz."
                log_event(ALARMS_LOG_FILE, "PROMISC_INTERFACE", alert_text)
                send_alert_email("Alerta HIPS: Interfaz en modo promiscuo", alert_text)
                iface = None

    except Exception as problem:
        err_msg = f"Fallo al evaluar interfaces: {problem}"
        outcome["interfaces_flagged"].append(err_msg)
        outcome["status"] = "ERROR"
        outcome["summary"] = "No se pudo verificar interfaces de red."
        log_event(ALARMS_LOG_FILE, "INTERFACE_CHECK_FAIL", err_msg)

    watchlist = [
        "wireshark", "tshark", "tcpdump", "snort", "zeek", "nmap", "dumpcap",
        "ngrep", "netcat", "ettercap", "ssldump", "dsniff", "pktmon", "arpspoof"
    ]

    active = psutil.process_iter(["pid", "name", "cmdline", "username"])
    for task in active:
        try:
            details = task.info.get("cmdline", []) or [task.info.get("name", "")]
            line = " ".join(details).lower()

            for pattern in watchlist:
                if pattern in line:
                    found = {
                        "pid": task.info["pid"],
                        "exec": task.info["name"],
                        "cmd": line,
                        "owner": task.info["username"]
                    }
                    outcome["processes_flagged"].append(found)
                    if outcome["status"] != "ALERTA":
                        outcome["status"] = "ALERTA"
                        outcome["summary"] = "Actividad sospechosa detectada: herramientas de análisis presentes."
                    logtext = f"Herramienta sospechosa activa: {found['exec']} (PID {found['pid']}, usuario {found['owner']})"
                    log_event(ALARMS_LOG_FILE, "TOOL_DETECTED", logtext)
                    send_alert_email("Alerta HIPS: Herramienta de red detectada", logtext)
                    break
        except Exception:
            continue

    if outcome["status"] == "ALERTA":
        outcome["summary"] = "Se identificaron posibles amenazas en el sistema."

    return {"resultado": outcome, "usuario": current_user.username}
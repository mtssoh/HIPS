import os
import re
import subprocess
import psutil

from fastapi import APIRouter, Depends, HTTPException, status

from app.auth import get_current_user
from app.models import User
from app.utils import send_alert_email, log_event, ALARMS_LOG_FILE
from app.prevention import change_user_password, block_ip

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
async def detect_sniffers(
    current_user: User = Depends(get_current_user)
):
    detection_results = {
        "promiscuous_mode": [],
        "known_sniffers": [],
        "message": "Analysis complete.",
        "status": "OK"
    }

    # 1. Promiscuous mode detection
    try:
        promisc_output = subprocess.run(["ip", "-s", "link"], capture_output=True, text=True, check=False)
        lines = promisc_output.stdout.splitlines()
        
        current_interface = None
        for line in lines:
            if re.match(r'^\d+:\s+(\S+):', line):
                current_interface = re.match(r'^\d+:\s+(\S+):', line).group(1)
            if "PROMISC" in line and current_interface:
                msg = f"Interface '{current_interface}' is in promiscuous mode."
                detection_results["promiscuous_mode"].append(msg)
                detection_results["status"] = "ALERT"
                detection_results["message"] = "Promiscuous mode detected on one or more interfaces!"
                log_event(ALARMS_LOG_FILE, "PROMISC_MODE", msg)
                send_alert_email("HIPS Alert: Promiscuous Mode Detected", msg)
                current_interface = None 
                
    except Exception as e:
        msg = f"Error checking promiscuous mode: {str(e)}"
        detection_results["promiscuous_mode"].append(msg)
        detection_results["status"] = "ERROR"
        detection_results["message"] = "Error checking promiscuous mode."
        log_event(ALARMS_LOG_FILE, "ERROR_SNIFFER_DETECTION", msg)

    # 2. Detection of known sniffing tools
    known_sniffers_keywords = [
        "tcpdump", "wireshark", "tshark", "nmap", "netcat",
        "dumpcap", "ettercap", "ngrep", "snort", "zeek",
        "dsniff", "arpspoof", "ssldump", "pktmon"
    ]

    for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username']):
        try:
            cmdline = " ".join(proc.info['cmdline']) if proc.info['cmdline'] else proc.info['name']
            
            for keyword in known_sniffers_keywords:
                if keyword in cmdline.lower():
                    proc_info = {
                        "pid": proc.info['pid'],
                        "name": proc.info['name'],
                        "cmdline": cmdline,
                        "user": proc.info['username']
                    }
                    detection_results["known_sniffers"].append(proc_info)
                    if detection_results["status"] != "ALERT":
                        detection_results["status"] = "ALERT"
                        detection_results["message"] = "Known sniffing tools detected running!"
                    
                    msg = f"Known sniffer detected: {proc.info['name']} (PID: {proc.info['pid']}, User: {proc.info['username']})"
                    log_event(ALARMS_LOG_FILE, "SNIFFER_DETECTED", msg)
                    send_alert_email("HIPS Alert: Sniffer Tool Detected", msg)
                    break
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    if detection_results["status"] == "ALERT":
        detection_results["message"] = "Security warning: Possible threats detected!"

    return {"detection_results": detection_results, "user": current_user.username}

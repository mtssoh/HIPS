import subprocess
import psutil
import os
import re
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status

from app.auth import get_current_user
from app.models import User
from app.utils import send_alert_email, log_event, ALARMS_LOG_FILE
from app.prevention import kill_process_by_pid
router = APIRouter()

@router.get("/mail_queue_size")
async def get_mail_queue_size(
    current_user: User = Depends(get_current_user)
):
    try:
        # --- Obtener ruta absoluta del comando mailq ---
        mailq_path = "/usr/bin/mailq" 
        
        # Intenta 'mailq' (Postfix/Sendmail)
        result = subprocess.run([mailq_path], capture_output=True, text=True, check=False)
        output = result.stdout.strip()
        
        # Si mailq no encontró mensajes o el comando falló
        if not output or "empty" in output.lower() or "mail queue is empty" in output.lower() or result.returncode != 0:
            return {"queue_size": 0, "message": "Mail queue is empty or size could not be determined using mailq.", "user": current_user.username}
        
        # Si mailq sí retornó algo útil
        lines = output.splitlines()
        # Filtra líneas de cabecera/pie de página para contar mensajes reales
        queue_count = sum(1 for line in lines if not any(kw in line.lower() for kw in ["mail queue is", "queue id", "total requests", "queue is empty.", "size", "requests"]))
        
        if queue_count > 0:
            log_event(ALARMS_LOG_FILE, "MAIL_QUEUE_ALERT", f"Postfix mail queue size: {queue_count}")
            send_alert_email("HIPS Alert: Mail Queue Growing", f"The Postfix mail queue has {queue_count} items. This may indicate an issue or mass sending.")
            return {"queue_size": queue_count, "message": f"Items in mail queue (mailq): {queue_count}", "user": current_user.username}
        
        return {"queue_size": 0, "message": "Mail queue is empty or size could not be determined.", "user": current_user.username}

    except FileNotFoundError as e:
        log_event(ALARMS_LOG_FILE, "CMD_NOT_FOUND", f"Mail command not found: {e.filename}. Ensure your Mail Transfer Agent (MTA) is installed and accessible.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Command '{e.filename}' not found. Ensure your Mail Transfer Agent (MTA) is installed and accessible (e.g., Postfix which uses 'mailq')."
        )
    except Exception as e:
        log_event(ALARMS_LOG_FILE, "UNEXPECTED_ERROR", f"Unexpected error checking mail queue: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Unexpected error checking mail queue: {str(e)}"
        )

@router.get("/high_memory_processes")
async def get_high_memory_processes(
    threshold_percent: float = 10.0,
    current_user: User = Depends(get_current_user)
):
    results = {
        "processes": [],
        "message": "Process monitoring complete.",
        "status": "OK"
    }

    try:
        total_memory_mb = psutil.virtual_memory().total / (1024 * 1024)

        for proc in psutil.process_iter(['pid', 'name', 'username', 'memory_info', 'cpu_percent']):
            try:
                rss_mb = proc.memory_info().rss / (1024 * 1024)
                percentage = (rss_mb / total_memory_mb) * 100

                if percentage > threshold_percent:
                    cpu_percent_val = proc.cpu_percent(interval=0.01)

                    proc_info = {
                        "pid": proc.info['pid'],
                        "name": proc.info['name'],
                        "user": proc.info['username'],
                        "memory_percent": round(percentage, 2),
                        "memory_mb": round(rss_mb, 2),
                        "cpu_percent": round(cpu_percent_val, 2),
                        "killed": False  # agregado
                    }

                    # Acción preventiva
                    alert_msg = f"High memory usage: Process '{proc_info['name']}' (PID: {proc_info['pid']}) using {proc_info['memory_percent']}% RAM."
                    log_event(ALARMS_LOG_FILE, "HIGH_MEM_PROCESS", alert_msg)
                    send_alert_email("HIPS Alert: High Memory Usage", alert_msg)

                    killed = await kill_process_by_pid(proc_info["pid"], "HIGH_MEM_PROCESS")
                    proc_info["killed"] = killed

                    results["processes"].append(proc_info)

                    if results["status"] != "ALERT":
                        results["status"] = "ALERT"
                        results["message"] = "Processes with high memory consumption detected!"

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        results["processes"].sort(key=lambda x: x['memory_percent'], reverse=True)

    except Exception as e:
        results["status"] = "ERROR"
        results["message"] = f"Unexpected error monitoring processes: {str(e)}"
        log_event(ALARMS_LOG_FILE, "UNEXPECTED_ERROR", f"Error monitoring processes: {str(e)}")

    return results

@router.get("/check_tmp")
async def check_tmp_directory(
    current_user: User = Depends(get_current_user)
):
    results = {
        "tmp_files": [],
        "message": "TMP directory check complete.",
        "status": "OK"
    }
    tmp_path = "/tmp"
    
    if not os.path.isdir(tmp_path):
        results["status"] = "ERROR"
        results["message"] = f"Directory {tmp_path} not found."
        log_event(ALARMS_LOG_FILE, "TMP_ERROR", f"TMP directory {tmp_path} not found.")
        return results

    try:
        # Busca archivos sospechosos por extensión, nombres comunes de scripts, etc.
        suspicious_names_regex = re.compile(r'^\.|\.sh$|\.py$|\.pl$|\.php$|backdoor|shell|reverse|nc\.exe|mimikatz', re.IGNORECASE)

        for entry in os.listdir(tmp_path):
            full_path = os.path.join(tmp_path, entry)
            if os.path.islink(full_path):
                file_type = "symlink"
            elif os.path.isfile(full_path):
                file_type = "file"
            elif os.path.isdir(full_path):
                file_type = "directory"
            else:
                file_type = "unknown"

            is_suspicious = False
            message = "OK"

            if os.path.isfile(full_path):
                # Check for suspicious names or extensions
                if suspicious_names_regex.search(entry):
                    is_suspicious = True
                    message = "Suspicious name/extension detected."
                
                # Check if it's executable
                if os.access(full_path, os.X_OK):
                    is_suspicious = True
                    message = f"{message} Executable file." if is_suspicious else "Executable file."

            # Check if any running process is using this file from /tmp
            processes_using_file = []
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'exe']):
                try:
                    if proc.info['exe'] == full_path:
                        processes_using_file.append(f"PID {proc.info['pid']} ({proc.info['name']})")
                    elif proc.info['cmdline'] and full_path in " ".join(proc.info['cmdline']):
                        processes_using_file.append(f"PID {proc.info['pid']} ({proc.info['name']}) (cmdline)")
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass

            if is_suspicious or processes_using_file:
                status_entry = "ALERT"
                results["status"] = "ALERT"
                if not message:  # Si no se estableció un mensaje previo
                    message = "Suspicious activity detected in /tmp."
                if processes_using_file:
                    message = f"{message} Used by processes: {', '.join(processes_using_file)}"
                
                log_event(ALARMS_LOG_FILE, "TMP_SUSPICIOUS", f"Suspicious file/activity in {full_path}: {message}")
                send_alert_email("HIPS Alert: Suspicious /tmp Activity", f"Suspicious activity detected in /tmp: {full_path}. Details: {message}")
                
                for proc_str in processes_using_file:
                    match = re.search(r'PID (\d+)', proc_str)
                    if match:
                        pid = int(match.group(1))
                        await kill_process_by_pid(pid, f"Suspicious /tmp file used: {entry}")

            else:
                status_entry = "OK"

            results["tmp_files"].append({
                "name": entry,
                "path": full_path,
                "type": file_type,
                "is_suspicious": is_suspicious,
                "message": message,
                "status": status_entry
            })
            
    except Exception as e:
        results["status"] = "ERROR"
        results["message"] = f"Error checking /tmp directory: {str(e)}"
        log_event(ALARMS_LOG_FILE, "TMP_ERROR", f"Error checking /tmp: {str(e)}")

    return results

@router.get("/check_cron_jobs")
async def check_cron_jobs(
    current_user: User = Depends(get_current_user)
):
    results = {
        "cron_jobs": [],
        "message": "Cron job check complete.",
        "status": "OK"
    }

    # Ubicaciones comunes de archivos cron
    cron_files = [
        "/etc/crontab",
        "/etc/cron.d/",  # Directorio
        "/etc/cron.hourly/", # Directorio
        "/etc/cron.daily/",  # Directorio
        "/etc/cron.weekly/", # Directorio
        "/etc/cron.monthly/",# Directorio
        "/var/spool/cron/crontabs/" # Directorio para crontabs de usuario
    ]

    suspicious_patterns = re.compile(r'wget|curl|nc|bash -i|/dev/(tcp|udp)|base64|xxd|systemctl|chattr|chmod \+s|chmod 777', re.IGNORECASE)

    for path in cron_files:
        if os.path.isdir(path):
            try:
                for filename in os.listdir(path):
                    full_path = os.path.join(path, filename)
                    if os.path.isfile(full_path):
                        process_cron_file(full_path, results, suspicious_patterns)
            except PermissionError:
                msg = f"Permission denied to read cron directory: {path}"
                results["cron_jobs"].append({"path": path, "status": "ERROR", "message": msg})
                log_event(ALARMS_LOG_FILE, "CRON_ERROR", msg)
            except Exception as e:
                msg = f"Error listing cron directory {path}: {str(e)}"
                results["cron_jobs"].append({"path": path, "status": "ERROR", "message": msg})
                log_event(ALARMS_LOG_FILE, "CRON_ERROR", msg)
        elif os.path.isfile(path):
            process_cron_file(path, results, suspicious_patterns)

    if results["status"] == "ALERT":
        results["message"] = "Suspicious cron jobs detected!"
    
    return results

def process_cron_file(file_path, results_dict, suspicious_patterns):
    """Helper function to read and analyze a single cron file."""
    try:
        with open(file_path, 'r') as f:
            content = f.read()
            suspicious_matches = suspicious_patterns.findall(content)
            
            if suspicious_matches:
                results_dict["status"] = "ALERT"
                msg = f"Suspicious patterns found in {file_path}: {', '.join(set(suspicious_matches))}"
                results_dict["cron_jobs"].append({
                    "path": file_path,
                    "status": "ALERT",
                    "message": msg,
                    "content_preview": content[:200] + "..." if len(content) > 200 else content
                })
                log_event(ALARMS_LOG_FILE, "CRON_SUSPICIOUS", msg)
                send_alert_email("HIPS Alert: Suspicious Cron Job", msg)
            else:
                results_dict["cron_jobs"].append({
                    "path": file_path,
                    "status": "OK",
                    "message": "No suspicious patterns detected.",
                    "content_preview": content[:200] + "..." if len(content) > 200 else content
                })
    except FileNotFoundError:
        msg = f"Cron file not found: {file_path}"
        results_dict["cron_jobs"].append({"path": file_path, "status": "ERROR", "message": msg})
        log_event(ALARMS_LOG_FILE, "CRON_ERROR", msg)
    except PermissionError:
        msg = f"Permission denied to read cron file: {file_path}"
        results_dict["cron_jobs"].append({"path": file_path, "status": "ERROR", "message": msg})
        log_event(ALARMS_LOG_FILE, "CRON_ERROR", msg)
    except Exception as e:
        msg = f"Error reading cron file {file_path}: {str(e)}"
        results_dict["cron_jobs"].append({"path": file_path, "status": "ERROR", "message": msg})
        log_event(ALARMS_LOG_FILE, "CRON_ERROR", msg)

@router.get("/invalid_login_attempts")
async def get_invalid_login_attempts(
    time_window_minutes: int = 5,  # Ventana de tiempo para agrupar intentos
    max_attempts_per_ip: int = 5,  # Umbral de intentos fallidos por IP
    current_user: User = Depends(get_current_user)
):
    results = {
        "summary": [],
        "detailed_attempts": [],
        "message": "Analysis complete.",
        "status": "OK"
    }

    # Simulación de datos (reemplazar con datos reales de log)
    simulated_failed_logins = {
        "192.168.1.10": {"count": 7, "timestamps": [datetime.now() - timedelta(minutes=i) for i in range(7)]},
        "10.0.0.5": {"count": 3, "timestamps": [datetime.now() - timedelta(minutes=i) for i in range(3)]},
        "1.2.3.4": {"count": 6, "timestamps": [datetime.now() - timedelta(minutes=i) for i in range(6)]},
    }
    
    current_time = datetime.now(timezone.utc)
    
    for ip, data in simulated_failed_logins.items():
        recent_attempts = [ts for ts in data["timestamps"] if (current_time - ts).total_seconds() / 60 <= time_window_minutes]
        
        if len(recent_attempts) >= max_attempts_per_ip:
            summary_msg = f"Suspicious activity: IP {ip} has {len(recent_attempts)} failed login attempts in the last {time_window_minutes} minutes."
            results["summary"].append(summary_msg)
            results["status"] = "ALERT"
            results["message"] = "Multiple failed login attempts detected!"
            log_event(ALARMS_LOG_FILE, "MULTIPLE_FAILED_LOGINS", summary_msg, ip=ip)
            send_alert_email("HIPS Alert: Multiple Failed Logins", summary_msg)

    if not results["summary"]:
        results["message"] = "No unusual login attempt patterns detected."
    
    return results

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

@router.get("/processes_check")
async def monitor_memory_intensive_processes(
    threshold: float = 10.0,
    current_user: User = Depends(get_current_user)
):
    response = {
        "processes": [],
        "status": "OK",
        "message": "Process analysis completed successfully."
    }

    ignored_names = {"postgres", "python3", "sshd", "docker", "nginx"}

    try:
        total_mem = psutil.virtual_memory().total / 1024**2  # MB

        for process in psutil.process_iter(['pid', 'name', 'username', 'memory_info', 'cpu_percent']):
            try:
                name = process.info['name']
                if name in ignored_names:
                    continue

                mem_used = process.memory_info().rss / 1024**2  # MB
                usage_percent = (mem_used / total_mem) * 100

                if usage_percent > threshold:
                    cpu = process.cpu_percent(interval=0.01)

                    entry = {
                        "pid": process.info['pid'],
                        "name": name,
                        "user": process.info['username'],
                        "memory_percent": round(usage_percent, 2),
                        "memory_mb": round(mem_used, 2),
                        "cpu_percent": round(cpu, 2),
                        "killed": False
                    }

                    warning = f"Process '{name}' (PID {entry['pid']}) exceeding RAM usage: {entry['memory_percent']}%"
                    log_event(ALARMS_LOG_FILE, "HIGH_MEM_PROCESS", warning)
                    send_alert_email("HIPS Alert: High RAM Usage", warning)

                    entry["killed"] = await kill_process_by_pid(entry["pid"], "HIGH_MEM_PROCESS")
                    response["processes"].append(entry)

                    if response["status"] != "ALERT":
                        response["status"] = "ALERT"
                        response["message"] = "Processes over memory threshold were detected."

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        response["processes"].sort(key=lambda p: p["memory_percent"], reverse=True)

    except Exception as error:
        response["status"] = "ERROR"
        response["message"] = f"Error while checking processes: {error}"
        log_event(ALARMS_LOG_FILE, "PROCESS_MONITOR_ERROR", response["message"])

    return response

@router.get("/tmp_check")
async def inspect_tmp_contents(current_user: User = Depends(get_current_user)):
    tmp_dir = "/tmp"
    summary = {
        "tmp_files": [],
        "status": "OK",
        "message": "Inspection of /tmp completed."
    }

    if not os.path.isdir(tmp_dir):
        error_msg = f"{tmp_dir} not found."
        summary.update({"status": "ERROR", "message": error_msg})
        log_event(ALARMS_LOG_FILE, "TMP_ERROR", error_msg)
        return summary

    suspicious_pattern = re.compile(r'^\.|\.sh$|\.py$|\.pl$|\.php$|backdoor|shell|reverse|nc\.exe|mimikatz', re.IGNORECASE)

    try:
        for filename in os.listdir(tmp_dir):
            filepath = os.path.join(tmp_dir, filename)
            file_kind = (
                "symlink" if os.path.islink(filepath) else
                "file" if os.path.isfile(filepath) else
                "directory" if os.path.isdir(filepath) else
                "unknown"
            )

            flagged = False
            note = "Clean"

            if os.path.isfile(filepath):
                if suspicious_pattern.search(filename):
                    flagged = True
                    note = "Name or extension is suspicious."

                if os.access(filepath, os.X_OK):
                    flagged = True
                    note += " Executable file."

            involved_pids = []
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'exe']):
                try:
                    if proc.info['exe'] == filepath or (proc.info['cmdline'] and filepath in " ".join(proc.info['cmdline'])):
                        involved_pids.append(f"PID {proc.pid} ({proc.info['name']})")
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue

            if flagged or involved_pids:
                summary["status"] = "ALERT"
                if involved_pids:
                    note += f" Linked to: {', '.join(involved_pids)}"

                log_event(ALARMS_LOG_FILE, "TMP_SUSPICIOUS", f"{filepath}: {note}")
                send_alert_email("HIPS Alert: Suspicious File in /tmp", f"{filepath}\n{note}")

                for proc_str in involved_pids:
                    pid_match = re.search(r'PID (\d+)', proc_str)
                    if pid_match:
                        pid = int(pid_match.group(1))
                        await kill_process_by_pid(pid, f"Flagged file in /tmp: {filename}")
                try:
                    os.remove(filepath)
                except Exception as e:
                    log_event(ALARMS_LOG_FILE, "TMP_DELETE_ERROR", f"Could not remove {filepath}: {e}")

                entry_status = "ALERT"
            else:
                entry_status = "OK"

            summary["tmp_files"].append({
                "name": filename,
                "path": filepath,
                "type": file_kind,
                "is_suspicious": flagged,
                "message": note,
                "status": entry_status
            })

    except Exception as e:
        summary["status"] = "ERROR"
        summary["message"] = f"Problem scanning /tmp: {e}"
        log_event(ALARMS_LOG_FILE, "TMP_SCAN_ERROR", summary["message"])

    return summary

@router.get("/check_cron_jobs")
async def check_cron_jobs(
    current_user: User = Depends(get_current_user)
):
    results = {
        "cron_jobs": [],
        "message": "Cron job check complete.",
        "status": "OK"
    }

   
    cron_files = [
        "/etc/crontab",
        "/etc/cron.d/",  
        "/etc/cron.hourly/", 
        "/etc/cron.daily/",  
        "/etc/cron.weekly/", 
        "/etc/cron.monthly/",
        "/var/spool/cron/crontabs/" 
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

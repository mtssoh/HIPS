import os
import subprocess
from app.utils import log_event, send_alert_email, PREVENTION_LOG_FILE

async def block_ip(ip_address: str, reason: str = "HIPS Intrusion Detected") -> bool:
    """Bloquea una IP usando iptables."""
    try:
        # Asegúrate de que iptables esté disponible y tengas permisos
        # Considera usar 'ufw' en Ubuntu/Debian si está instalado: sudo ufw deny from {ip_address}
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
        log_event(PREVENTION_LOG_FILE, "IP_BLOCKED", f"IP {ip_address} blocked. Reason: {reason}", ip=ip_address)
        send_alert_email(f"HIPS Alert: IP Blocked - {ip_address}", f"The IP {ip_address} has been blocked due to: {reason}")
        return True
    except subprocess.CalledProcessError as e:
        log_event(PREVENTION_LOG_FILE, "PREVENTION_ERROR", f"Failed to block IP {ip_address}: {e.stderr.strip()}", ip=ip_address)
        print(f"Error blocking IP {ip_address}: {e.stderr.strip()}")
        return False
    except Exception as e:
        log_event(PREVENTION_LOG_FILE, "PREVENTION_ERROR", f"Unexpected error blocking IP {ip_address}: {e}", ip=ip_address)
        print(f"Unexpected error blocking IP {ip_address}: {e}")
        return False

async def change_user_password(username: str, reason: str = "Suspicious activity detected") -> bool:
    """Cambia la contraseña de un usuario a una generada aleatoriamente."""
    try:
        new_password = os.urandom(16).hex()  # Genera una contraseña aleatoria
        # El comando 'chpasswd' permite cambiar la contraseña desde stdin
        command = f'echo "{username}:{new_password}" | sudo chpasswd'
        subprocess.run(command, shell=True, check=True)  # Usar shell=True porque es un pipe
        log_event(PREVENTION_LOG_FILE, "PASSWORD_CHANGED", f"Password changed for user {username}. Reason: {reason}")
        send_alert_email(f"HIPS Alert: Password Changed - {username}", f"The password for user {username} has been changed due to: {reason}. New password: {new_password}")
        print(f"Password for user {username} changed to: {new_password}")  # Solo para depuración, NO en producción
        return True
    except subprocess.CalledProcessError as e:
        log_event(PREVENTION_LOG_FILE, "PREVENTION_ERROR", f"Failed to change password for {username}: {e.stderr.strip()}")
        print(f"Error changing password for {username}: {e.stderr.strip()}")
        return False
    except Exception as e:
        log_event(PREVENTION_LOG_FILE, "PREVENTION_ERROR", f"Unexpected error changing password for {username}: {e}")
        print(f"Unexpected error changing password for {username}: {e}")
        return False

async def kill_process_by_pid(pid: int, reason: str = "High resource usage or suspicious activity") -> bool:
    """Mata un proceso por su PID."""
    try:
        # psutil.Process(pid).terminate() # Alternativa usando psutil si el proceso es del usuario
        subprocess.run(["sudo", "kill", "-9", str(pid)], check=True)  # Usar sudo para asegurar
        log_event(PREVENTION_LOG_FILE, "PROCESS_KILLED", f"Process with PID {pid} killed. Reason: {reason}")
        send_alert_email(f"HIPS Alert: Process Killed - PID {pid}", f"Process with PID {pid} has been killed due to: {reason}")
        return True
    except subprocess.CalledProcessError as e:
        log_event(PREVENTION_LOG_FILE, "PREVENTION_ERROR", f"Failed to kill process {pid}: {e.stderr.strip()}")
        print(f"Error killing process {pid}: {e.stderr.strip()}")
        return False
    except Exception as e:
        log_event(PREVENTION_LOG_FILE, "PREVENTION_ERROR", f"Unexpected error killing process {pid}: {e}")
        print(f"Unexpected error killing process {pid}: {e}")
        return False

# Más funciones de prevención aquí: eliminar archivos, mover a cuarentena, bajar servicio, etc.

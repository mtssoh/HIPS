import os
import subprocess
from app.utils import log_event, send_alert_email, PREVENTION_LOG_FILE

async def block_ip(ip_address: str, reason: str = "Intrusión detectada por HIPS") -> bool:
    """Bloquea una IP usando iptables."""
    try:
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
        log_event(PREVENTION_LOG_FILE, "IP_BLOQUEADA", f"Se bloqueó la IP {ip_address}. Motivo: {reason}", ip=ip_address)
        send_alert_email(
            f"Alerta HIPS: IP bloqueada - {ip_address}",
            f"La dirección IP {ip_address} ha sido bloqueada.\nMotivo: {reason}"
        )
        return True
    except subprocess.CalledProcessError as e:
        log_event(PREVENTION_LOG_FILE, "ERROR_PREVENCION", f"No se pudo bloquear la IP {ip_address}: {e.stderr.strip()}", ip=ip_address)
        print(f"Error al bloquear la IP {ip_address}: {e.stderr.strip()}")
        return False
    except Exception as e:
        log_event(PREVENTION_LOG_FILE, "ERROR_PREVENCION", f"Error inesperado al bloquear la IP {ip_address}: {e}", ip=ip_address)
        print(f"Error inesperado al bloquear la IP {ip_address}: {e}")
        return False


async def change_user_password(username: str, reason: str = "Actividad sospechosa detectada") -> bool:
    """Cambia la contraseña de un usuario a una generada aleatoriamente."""
    try:
        new_password = os.urandom(16).hex()
        command = f'echo "{username}:{new_password}" | sudo chpasswd'
        subprocess.run(command, shell=True, check=True)
        log_event(PREVENTION_LOG_FILE, "CONTRASENA_CAMBIADA", f"Se cambió la contraseña del usuario {username}. Motivo: {reason}")
        send_alert_email(
            f"Alerta HIPS: Contraseña cambiada - {username}",
            f"Se cambió la contraseña del usuario {username}.\nMotivo: {reason}\nNueva contraseña: {new_password}"
        )
        print(f"Contraseña de {username} cambiada a: {new_password}")  # Solo para depuración
        return True
    except subprocess.CalledProcessError as e:
        log_event(PREVENTION_LOG_FILE, "ERROR_PREVENCION", f"No se pudo cambiar la contraseña de {username}: {e.stderr.strip()}")
        print(f"Error al cambiar la contraseña de {username}: {e.stderr.strip()}")
        return False
    except Exception as e:
        log_event(PREVENTION_LOG_FILE, "ERROR_PREVENCION", f"Error inesperado al cambiar la contraseña de {username}: {e}")
        print(f"Error inesperado al cambiar la contraseña de {username}: {e}")
        return False


async def kill_process_by_pid(pid: int, reason: str = "Uso elevado de recursos o actividad sospechosa") -> bool:
    """Finaliza un proceso por su PID."""
    try:
        subprocess.run(["sudo", "kill", "-9", str(pid)], check=True)
        log_event(PREVENTION_LOG_FILE, "PROCESO_TERMINADO", f"Se finalizó el proceso con PID {pid}. Motivo: {reason}")
        send_alert_email(
            f"Alerta HIPS: Proceso finalizado - PID {pid}",
            f"El proceso con PID {pid} fue terminado.\nMotivo: {reason}"
        )
        return True
    except subprocess.CalledProcessError as e:
        log_event(PREVENTION_LOG_FILE, "ERROR_PREVENCION", f"No se pudo finalizar el proceso {pid}: {e.stderr.strip()}")
        print(f"Error al finalizar el proceso {pid}: {e.stderr.strip()}")
        return False
    except Exception as e:
        log_event(PREVENTION_LOG_FILE, "ERROR_PREVENCION", f"Error inesperado al finalizar el proceso {pid}: {e}")
        print(f"Error inesperado al finalizar el proceso {pid}: {e}")
        return False

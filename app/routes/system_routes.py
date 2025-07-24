from fastapi import APIRouter, Depends
from sqlmodel import Session

from app.auth import get_current_user
from app.database import get_session
from app.utils import send_alert_email, log_event, ALARMS_LOG_FILE
from app.models import User, FileBaseline

import hashlib
import os

router = APIRouter()

ARCHIVOS_CRITICOS = [
    "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
    "/etc/sudoers", "/etc/hosts", "/etc/resolv.conf", "/etc/crontab", "/etc/rc.local",

    "/bin/bash", "/bin/sh", "/bin/su", "/usr/bin/sudo", "/usr/bin/passwd",
    "/bin/ls", "/bin/cp", "/bin/mv", "/bin/rm", "/bin/mkdir", "/bin/chmod", "/bin/chown",
    "/bin/kill", "/usr/bin/top", "/usr/bin/ps", "/usr/bin/w", "/usr/bin/who", "/usr/bin/uptime", "/usr/bin/killall",

    "/sbin/ifconfig", "/usr/bin/ssh", "/usr/bin/scp", "/usr/bin/curl", "/usr/bin/wget", "/usr/bin/nc", "/usr/bin/nmap",
    "/sbin/init", "/sbin/systemctl", "/bin/systemd", "/usr/sbin/cron", "/usr/sbin/sshd",

    "/usr/bin/python", "/usr/bin/python3", "/usr/bin/perl", "/usr/bin/php", "/usr/bin/ruby",
    "/bin/tar", "/usr/bin/zip", "/usr/bin/unzip", "/usr/bin/gzip", "/usr/bin/bzip2", "/usr/bin/xz",

    "/sbin/mount", "/sbin/umount", "/sbin/fdisk", "/sbin/parted",

    "/usr/bin/strace", "/usr/bin/lsof", "/usr/bin/netstat", "/usr/bin/tcpdump", "/usr/bin/journalctl"
]

@router.get("/binaries_check")
async def verificar_archivos_criticos(
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    reporte = []

    for ruta in ARCHIVOS_CRITICOS:
        try:
            with open(ruta, "rb") as archivo:
                hash_actual = hashlib.sha256(archivo.read()).hexdigest()

            referencia = session.query(FileBaseline).filter(FileBaseline.file_path == ruta).first()

            if referencia:
                if hash_actual == referencia.baseline_hash:
                    reporte.append({
                        "archivo": ruta,
                        "estado": "OK",
                        "mensaje": "Integridad verificada."
                    })
                else:
                    detalle = f"Diferencia de hash: actual = {hash_actual}, esperado = {referencia.baseline_hash}"
                    reporte.append({
                        "archivo": ruta,
                        "estado": "MODIFICADO",
                        "mensaje": detalle
                    })
                    log_event(ALARMS_LOG_FILE, "CAMBIO_ARCHIVO", f"{ruta}: {detalle}")
                    send_alert_email(
                        "Alerta HIPS: Alteración de archivo crítico",
                        f"El archivo {ruta} fue modificado.\n\nDetalles:\n{detalle}"
                    )
            else:
                mensaje = "No existe un hash de referencia para este archivo."
                reporte.append({
                    "archivo": ruta,
                    "estado": "SIN_REFERENCIA",
                    "mensaje": mensaje
                })
                log_event(ALARMS_LOG_FILE, "SIN_HASH_REFERENCIA", f"{ruta}: {mensaje}")

        except FileNotFoundError:
            mensaje_error = "Archivo inaccesible o inexistente."
            reporte.append({
                "archivo": ruta,
                "estado": "ERROR",
                "mensaje": mensaje_error
            })
            log_event(ALARMS_LOG_FILE, "ERROR_LECTURA_ARCHIVO", f"{ruta}: {mensaje_error}")

        except Exception as ex:
            mensaje_excepcion = f"Excepción inesperada: {str(ex)}"
            reporte.append({
                "archivo": ruta,
                "estado": "ERROR",
                "mensaje": mensaje_excepcion
            })
            log_event(ALARMS_LOG_FILE, "ERROR_LECTURA_ARCHIVO", f"{ruta}: {mensaje_excepcion}")

    return {
        "usuario": current_user.username,
        "resultado_escaneo": reporte
    }

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
async def cola_correo(current_user: User = Depends(get_current_user)):
    ruta = "/usr/bin/mailq"
    try:
        resultado = subprocess.run([ruta], capture_output=True, text=True)
        salida = resultado.stdout.strip()

        if resultado.returncode != 0 or not salida or "empty" in salida.lower():
            return {
                "cantidad": 0,
                "mensaje": "No hay correos en cola o no se pudo obtener la información.",
                "usuario": current_user.username
            }

        fragmentos = salida.split("\n")
        cantidad_en_cola = sum(
            1 for fragmento in fragmentos
            if not any(x in fragmento.lower() for x in ["mail queue is", "queue id", "total requests", "queue is empty.", "size", "requests"])
        )

        if cantidad_en_cola > 0:
            aviso = f"Se detectaron {cantidad_en_cola} elementos en la cola de correos."
            log_event(ALARMS_LOG_FILE, "COLA_CORREO", aviso)
            send_alert_email("Alerta HIPS: Cola de correo activa", aviso)
            return {
                "cantidad": cantidad_en_cola,
                "mensaje": aviso,
                "usuario": current_user.username
            }

        return {
            "cantidad": 0,
            "mensaje": "Cola vacía o no accesible.",
            "usuario": current_user.username
        }

    except FileNotFoundError as err:
        log_event(ALARMS_LOG_FILE, "FALTA_COMANDO", f"No se encontró: {err.filename}")
        raise HTTPException(
            status_code=500,
            detail=f"No se localizó el ejecutable '{err.filename}'. Verificá que el MTA esté instalado (ej. Postfix)."
        )
    except Exception as ex:
        log_event(ALARMS_LOG_FILE, "FALLO_DESCONOCIDO", f"Error al revisar la cola: {str(ex)}")
        raise HTTPException(
            status_code=500,
            detail=f"Error al revisar la cola de correos: {str(ex)}"
        )


@router.get("/processes_check")
async def monitor_memoria(
    threshold: float = 10.0,
    current_user: User = Depends(get_current_user)
):
    respuesta = {
        "procesos": [],
        "estado": "OK",
        "mensaje": "Análisis de procesos completado exitosamente."
    }

    ignorar = {"postgres", "python3", "sshd", "docker", "nginx"}

    try:
        total_mem = psutil.virtual_memory().total / 1024**2

        for proc in psutil.process_iter(['pid', 'name', 'username', 'memory_info', 'cpu_percent']):
            try:
                nombre = proc.info['name']
                if nombre in ignorar:
                    continue

                mem_usada = proc.memory_info().rss / 1024**2
                porcentaje = (mem_usada / total_mem) * 100

                if porcentaje > threshold:
                    cpu = proc.cpu_percent(interval=0.01)

                    entrada = {
                        "pid": proc.info['pid'],
                        "nombre": nombre,
                        "usuario": proc.info['username'],
                        "memoria_porcentaje": round(porcentaje, 2),
                        "memoria_mb": round(mem_usada, 2),
                        "cpu_porcentaje": round(cpu, 2),
                        "terminado": False
                    }

                    aviso = f"Proceso '{nombre}' (PID {entrada['pid']}) excede el uso de RAM: {entrada['memoria_porcentaje']}%"
                    log_event(ALARMS_LOG_FILE, "PROCESO_RAM_ALTA", aviso)
                    send_alert_email("Alerta HIPS: Consumo alto de RAM", aviso)

                    entrada["terminado"] = await kill_process_by_pid(entrada["pid"], "PROCESO_RAM_ALTA")
                    respuesta["procesos"].append(entrada)

                    if respuesta["estado"] != "ALERTA":
                        respuesta["estado"] = "ALERTA"
                        respuesta["mensaje"] = "Se detectaron procesos que superan el umbral de memoria."

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        respuesta["procesos"].sort(key=lambda p: p["memoria_porcentaje"], reverse=True)

    except Exception as error:
        respuesta["estado"] = "ERROR"
        respuesta["mensaje"] = f"Error al verificar procesos: {error}"
        log_event(ALARMS_LOG_FILE, "ERROR_PROCESOS", respuesta["mensaje"])

    return respuesta


@router.get("/tmp_check")
async def verificar_tmp(current_user: User = Depends(get_current_user)):
    tmp_dir = "/tmp"
    resumen = {
        "archivos_tmp": [],
        "estado": "OK",
        "mensaje": "Inspección de /tmp completada."
    }

    if not os.path.isdir(tmp_dir):
        mensaje = f"No se encontró el directorio {tmp_dir}."
        resumen.update({"estado": "ERROR", "mensaje": mensaje})
        log_event(ALARMS_LOG_FILE, "TMP_ERROR", mensaje)
        return resumen

    patron_sospechoso = re.compile(r'^\.|\.sh$|\.py$|\.pl$|\.php$|backdoor|shell|reverse|nc\.exe|mimikatz', re.IGNORECASE)

    try:
        for archivo in os.listdir(tmp_dir):
            ruta = os.path.join(tmp_dir, archivo)
            tipo = (
                "enlace simbólico" if os.path.islink(ruta) else
                "archivo" if os.path.isfile(ruta) else
                "directorio" if os.path.isdir(ruta) else
                "desconocido"
            )

            sospechoso = False
            nota = "Limpio"

            if os.path.isfile(ruta):
                if patron_sospechoso.search(archivo):
                    sospechoso = True
                    nota = "Nombre o extensión sospechosa."

                if os.access(ruta, os.X_OK):
                    sospechoso = True
                    nota += " Archivo ejecutable."

            procesos_relacionados = []
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'exe']):
                try:
                    if proc.info['exe'] == ruta or (proc.info['cmdline'] and ruta in " ".join(proc.info['cmdline'])):
                        procesos_relacionados.append(f"PID {proc.pid} ({proc.info['name']})")
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue

            if sospechoso or procesos_relacionados:
                resumen["estado"] = "ALERTA"
                if procesos_relacionados:
                    nota += f" Relacionado a: {', '.join(procesos_relacionados)}"

                log_event(ALARMS_LOG_FILE, "TMP_SOSPECHOSO", f"{ruta}: {nota}")
                send_alert_email("Alerta HIPS: Archivo sospechoso en /tmp", f"{ruta}\n{nota}")

                for pid_texto in procesos_relacionados:
                    pid_match = re.search(r'PID (\d+)', pid_texto)
                    if pid_match:
                        pid = int(pid_match.group(1))
                        await kill_process_by_pid(pid, f"Archivo marcado en /tmp: {archivo}")
                try:
                    os.remove(ruta)
                except Exception as e:
                    log_event(ALARMS_LOG_FILE, "TMP_DELETE_ERROR", f"No se pudo eliminar {ruta}: {e}")

                estado_archivo = "ALERTA"
            else:
                estado_archivo = "OK"

            resumen["archivos_tmp"].append({
                "nombre": archivo,
                "ruta": ruta,
                "tipo": tipo,
                "sospechoso": sospechoso,
                "mensaje": nota,
                "estado": estado_archivo
            })

    except Exception as e:
        resumen["estado"] = "ERROR"
        resumen["mensaje"] = f"Problema al escanear /tmp: {e}"
        log_event(ALARMS_LOG_FILE, "TMP_SCAN_ERROR", resumen["mensaje"])

    return resumen


@router.get("/check_cron_jobs")
async def verificar_cron(current_user: User = Depends(get_current_user)):
    resultados = {
        "tareas_cron": [],
        "mensaje": "Verificación de cron completada.",
        "estado": "OK"
    }

    rutas = [
        "/etc/crontab",
        "/etc/cron.d/",
        "/etc/cron.hourly/",
        "/etc/cron.daily/",
        "/etc/cron.weekly/",
        "/etc/cron.monthly/",
        "/var/spool/cron/crontabs/"
    ]

    patron = re.compile(r'wget|curl|nc|bash -i|/dev/(tcp|udp)|base64|xxd|systemctl|chattr|chmod \+s|chmod 777', re.IGNORECASE)

    for path in rutas:
        if os.path.isdir(path):
            try:
                for archivo in os.listdir(path):
                    ruta_completa = os.path.join(path, archivo)
                    if os.path.isfile(ruta_completa):
                        procesar_cron(ruta_completa, resultados, patron)
            except PermissionError:
                msg = f"Permiso denegado al leer el directorio cron: {path}"
                resultados["tareas_cron"].append({"ruta": path, "estado": "ERROR", "mensaje": msg})
                log_event(ALARMS_LOG_FILE, "CRON_ERROR", msg)
            except Exception as e:
                msg = f"Error al listar cron {path}: {str(e)}"
                resultados["tareas_cron"].append({"ruta": path, "estado": "ERROR", "mensaje": msg})
                log_event(ALARMS_LOG_FILE, "CRON_ERROR", msg)
        elif os.path.isfile(path):
            procesar_cron(path, resultados, patron)

    if resultados["estado"] == "ALERTA":
        resultados["mensaje"] = "¡Se detectaron tareas cron sospechosas!"

    return resultados


def procesar_cron(ruta, resultados, patron):
    try:
        with open(ruta, 'r') as f:
            contenido = f.read()
            hallazgos = patron.findall(contenido)

            if hallazgos:
                resultados["estado"] = "ALERTA"
                resumen = f"Patrones sospechosos en {ruta}: {', '.join(set(hallazgos))}"
                resultados["tareas_cron"].append({
                    "ruta": ruta,
                    "estado": "ALERTA",
                    "mensaje": resumen,
                    "contenido": contenido[:200] + "..." if len(contenido) > 200 else contenido
                })
                log_event(ALARMS_LOG_FILE, "CRON_SOSPECHOSO", resumen)
                send_alert_email("Alerta HIPS: Cron sospechoso", resumen)
            else:
                resultados["tareas_cron"].append({
                    "ruta": ruta,
                    "estado": "OK",
                    "mensaje": "Sin patrones sospechosos.",
                    "contenido": contenido[:200] + "..." if len(contenido) > 200 else contenido
                })
    except FileNotFoundError:
        msg = f"No se encontró el archivo cron: {ruta}"
        resultados["tareas_cron"].append({"ruta": ruta, "estado": "ERROR", "mensaje": msg})
        log_event(ALARMS_LOG_FILE, "CRON_ERROR", msg)
    except PermissionError:
        msg = f"Permiso denegado al leer el archivo cron: {ruta}"
        resultados["tareas_cron"].append({"ruta": ruta, "estado": "ERROR", "mensaje": msg})
        log_event(ALARMS_LOG_FILE, "CRON_ERROR", msg)
    except Exception as e:
        msg = f"Error al leer el archivo cron {ruta}: {str(e)}"
        resultados["tareas_cron"].append({"ruta": ruta, "estado": "ERROR", "mensaje": msg})
        log_event(ALARMS_LOG_FILE, "CRON_ERROR", msg)


@router.get("/invalid_login_attempts")
async def intentos_invalidos(
    ventana_minutos: int = 5,
    max_por_ip: int = 5,
    current_user: User = Depends(get_current_user)
):
    resultado = {
        "resumen": [],
        "intentos_detallados": [],
        "mensaje": "Análisis completado.",
        "estado": "OK"
    }

    simulados = {
        "192.168.1.10": {"conteo": 7, "timestamps": [datetime.now() - timedelta(minutes=i) for i in range(7)]},
        "10.0.0.5": {"conteo": 3, "timestamps": [datetime.now() - timedelta(minutes=i) for i in range(3)]},
        "1.2.3.4": {"conteo": 6, "timestamps": [datetime.now() - timedelta(minutes=i) for i in range(6)]},
    }

    ahora = datetime.now(timezone.utc)

    for ip, data in simulados.items():
        recientes = [ts for ts in data["timestamps"] if (ahora - ts).total_seconds() / 60 <= ventana_minutos]

        if len(recientes) >= max_por_ip:
            resumen = f"Actividad sospechosa: La IP {ip} realizó {len(recientes)} intentos fallidos en los últimos {ventana_minutos} minutos."
            resultado["resumen"].append(resumen)
            resultado["estado"] = "ALERTA"
            resultado["mensaje"] = "¡Se detectaron múltiples intentos de acceso fallidos!"
            log_event(ALARMS_LOG_FILE, "INTENTOS_FALLIDOS", resumen, ip=ip)
            send_alert_email("Alerta HIPS: Múltiples accesos fallidos", resumen)

    if not resultado["resumen"]:
        resultado["mensaje"] = "No se detectaron patrones anómalos de acceso."

    return resultado

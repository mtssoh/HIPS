from fastapi import APIRouter, Depends
from sqlmodel import Session

from app.auth import get_current_user
from app.database import get_session
from app.utils import send_alert_email, log_event, ALARMS_LOG_FILE
from app.models import User, FileBaseline

import hashlib
import os

router = APIRouter()

CRITICAL_FILES = [
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

@router.get("/system_files")
async def scan_system_files(
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    results = []

    for file_path in CRITICAL_FILES:
        try:
            with open(file_path, "rb") as f:
                current_hash = hashlib.sha256(f.read()).hexdigest()

            baseline = session.query(FileBaseline).filter(FileBaseline.file_path == file_path).first()

            if baseline:
                if current_hash == baseline.baseline_hash:
                    results.append({
                        "file": file_path,
                        "status": "OK",
                        "message": "No changes detected."
                    })
                else:
                    message = f"CHANGE DETECTED: Current hash: {current_hash}, Baseline hash: {baseline.baseline_hash}"
                    results.append({
                        "file": file_path,
                        "status": "CHANGE DETECTED",
                        "message": message
                    })
                    log_event(ALARMS_LOG_FILE, "FILE_CHANGE", message)
                    send_alert_email("HIPS Alert: System File Modified!",
                                     f"File {file_path} has been modified.\n{message}")
            else:
                message = "File has no registered baseline. Consider creating one."
                results.append({
                    "file": file_path,
                    "status": "NO BASELINE",
                    "message": message
                })
                log_event(ALARMS_LOG_FILE, "NO_BASELINE", f"No baseline for {file_path}. {message}")

        except FileNotFoundError:
            message = "File not found or insufficient permissions."
            results.append({
                "file": file_path,
                "status": "ERROR",
                "message": message
            })
            log_event(ALARMS_LOG_FILE, "FILE_SCAN_ERROR", f"{file_path}: {message}")

        except Exception as e:
            message = f"Error processing: {str(e)}"
            results.append({
                "file": file_path,
                "status": "ERROR",
                "message": message
            })
            log_event(ALARMS_LOG_FILE, "FILE_SCAN_ERROR", f"{file_path}: {str(e)}")

    return {"user": current_user.username, "scan_results": results}

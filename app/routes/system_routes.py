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

@router.get("/binaries_check")
async def verify_critical_files(
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    report = []

    for path in CRITICAL_FILES:
        try:
            with open(path, "rb") as file_data:
                checksum = hashlib.sha256(file_data.read()).hexdigest()

            reference = session.query(FileBaseline).filter(FileBaseline.file_path == path).first()

            if reference:
                if checksum == reference.baseline_hash:
                    report.append({
                        "file": path,
                        "status": "OK",
                        "message": "Integrity verified."
                    })
                else:
                    diff_msg = (
                        f"Hash mismatch: current = {checksum}, expected = {reference.baseline_hash}"
                    )
                    report.append({
                        "file": path,
                        "status": "MODIFIED",
                        "message": diff_msg
                    })
                    log_event(ALARMS_LOG_FILE, "FILE_CHANGE", f"{path}: {diff_msg}")
                    send_alert_email(
                        "HIPS Alert: File Integrity Breach",
                        f"The file {path} has been altered.\n\nDetails:\n{diff_msg}"
                    )
            else:
                warn_msg = "No baseline hash recorded for this file."
                report.append({
                    "file": path,
                    "status": "MISSING_BASELINE",
                    "message": warn_msg
                })
                log_event(ALARMS_LOG_FILE, "NO_BASELINE", f"{path}: {warn_msg}")

        except FileNotFoundError:
            error_msg = "File not accessible or missing."
            report.append({
                "file": path,
                "status": "ERROR",
                "message": error_msg
            })
            log_event(ALARMS_LOG_FILE, "FILE_SCAN_ERROR", f"{path}: {error_msg}")

        except Exception as ex:
            exception_msg = f"Unexpected exception: {str(ex)}"
            report.append({
                "file": path,
                "status": "ERROR",
                "message": exception_msg
            })
            log_event(ALARMS_LOG_FILE, "FILE_SCAN_ERROR", f"{path}: {exception_msg}")

    return {
        "user": current_user.username,
        "scan_results": report
    }
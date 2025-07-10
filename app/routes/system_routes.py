from fastapi import APIRouter, Depends
from sqlmodel import Session

from app.auth import get_current_user
from app.database import get_session
from app.utils import send_alert_email, log_event, ALARMS_LOG_FILE
from app.models import User, FileBaseline
import hashlib
import os

router = APIRouter()

@router.get("/system_files")
async def scan_system_files(
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session)
):
    results = []
    files_to_check = ["/etc/passwd", "/etc/shadow"]

    for file_path in files_to_check:
        try:
            with open(file_path, "rb") as f:
                current_hash = hashlib.sha256(f.read()).hexdigest()

            baseline_entry = session.query(FileBaseline).filter(FileBaseline.file_path == file_path).first()

            if baseline_entry:
                if current_hash == baseline_entry.baseline_hash:
                    results.append({"file": file_path, "status": "OK", "message": "No changes detected."})
                else:
                    message = f"CHANGE DETECTED: Current hash: {current_hash}, Baseline hash: {baseline_entry.baseline_hash}"
                    results.append({"file": file_path, "status": "CHANGE DETECTED", "message": message})
                    log_event(ALARMS_LOG_FILE, "FILE_CHANGE", message)
                    send_alert_email("HIPS Alert: System File Modified!", f"File {file_path} has been modified.\n{message}")
            else:
                message = "File has no registered baseline. Consider creating one."
                results.append({"file": file_path, "status": "NO BASELINE", "message": message})
                log_event(ALARMS_LOG_FILE, "NO_BASELINE", f"No baseline for {file_path}. {message}")

        except FileNotFoundError:
            message = "File not found or insufficient permissions."
            results.append({"file": file_path, "status": "ERROR", "message": message})
            log_event(ALARMS_LOG_FILE, "FILE_SCAN_ERROR", f"Error scanning {file_path}: {message}")
        except Exception as e:
            message = f"Error processing: {e}"
            results.append({"file": file_path, "status": "ERROR", "message": message})
            log_event(ALARMS_LOG_FILE, "FILE_SCAN_ERROR", f"Unexpected error scanning {file_path}: {e}")

    return {"scan_results": results, "user": current_user.username}


import os
import re
import subprocess

from fastapi import APIRouter, Depends, HTTPException, status

from app.auth import get_current_user
from app.models import User
from app.utils import send_alert_email, log_event, ALARMS_LOG_FILE
from app.prevention import block_ip, change_user_password

router = APIRouter()

@router.get("/analyze_logs")
async def analyze_system_logs(
    log_type: str,  
    current_user: User = Depends(get_current_user)
):
    results = {
        "log_type": log_type,
        "detections": [],
        "message": "Analysis complete.",
        "status": "OK"
    }

    log_paths = []
    patterns = []
    
    if log_type == "auth":
       
        log_paths = ["/var/log/secure"] 
        patterns = [
            re.compile(r"authentication failure", re.IGNORECASE),
            re.compile(r"failed password", re.IGNORECASE)
        ]
        results["message"] = "Searching for authentication failures."
    elif log_type == "web":
       
        log_paths = ["/var/log/httpd/access.log"]
       
        patterns = [re.compile(r'^(\d{1,3}(?:\.\d{1,3}){3}) - - \[.*?\] "(?:GET|POST|HEAD|PUT|DELETE|OPTIONS) [^"]+" ([45]\d{2})')]
        results["message"] = "Searching for web page errors."
    elif log_type == "mail":
     
        log_paths = ["/var/log/mail.log"]
   
        patterns = [
                re.compile(r"relay=.*\[(\d{1,3}(?:\.\d{1,3}){3})\].*authid=.*?@.*?, mech=LOGIN", re.IGNORECASE),
                re.compile(r"from=<.*?@.*?>, size=\d+, class=\d+, nrcpts=\d+, msgid=<.*?>", re.IGNORECASE),
                re.compile(r"stat=User unknown", re.IGNORECASE)
                ]

        results["message"] = "Searching for suspicious mail activity."
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported log type. Valid types: 'auth', 'web', 'mail'."
        )

    found_events = {}  

    for log_path in log_paths:
        if os.path.exists(log_path):
            try:
               
                proc = subprocess.run(['tail', '-n', '1000', log_path], capture_output=True, text=True, check=True)
                lines = proc.stdout.splitlines()

                for line in lines:
                    for pattern in patterns:
                        match = pattern.search(line)
                        if match:
                            detection_info = {"line": line, "pattern": pattern.pattern}
                            ip = None  
                            if log_type == "web":
                                if len(match.groups()) >= 2:
                                    ip = match.group(1)
                                    status_code = match.group(2)
                                    detection_info["ip"] = ip
                                    detection_info["status_code"] = status_code
                                    if ip not in found_events:
                                        found_events[ip] = {"count": 0, "errors": []}
                                    found_events[ip]["count"] += 1
                                    found_events[ip]["errors"].append(f"HTTP {status_code} from {ip}")
                            elif log_type == "auth":
                               
                                ip_match = re.search(r'(?:from|for)\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                                if ip_match:
                                    ip = ip_match.group(1)
                                    detection_info["ip"] = ip
                                key = ip if ip else 'unknown_auth'
                                if key not in found_events:
                                    found_events[key] = {"count": 0, "attempts": []}
                                found_events[key]["count"] += 1
                                found_events[key]["attempts"].append(line)
                            elif log_type == "mail":
                                if len(match.groups()) >= 1:
                                    
                                    if pattern == patterns[0] or pattern == patterns[1]: 
                                        ip = match.group(1) if len(match.groups()) >= 1 else None
                                    elif pattern == patterns[2]:  # Reject pattern
                                        ip = match.group(2) if len(match.groups()) >= 2 else None
                                        
                                    detection_info["source"] = ip if ip else 'unknown_source'
                                    key = ip if ip else 'unknown_source'
                                    if key not in found_events:
                                        found_events[key] = {"count": 0, "details": []}
                                    found_events[key]["count"] += 1
                                    found_events[key]["details"].append(line)
                            
                            results["detections"].append(detection_info)
                            log_event(ALARMS_LOG_FILE, f"LOG_PATTERN_{log_type.upper()}", line.strip(), ip=ip)
                            break  #

            except FileNotFoundError:
                results["detections"].append({"error": f"Log {log_path} not found."})
                log_event(ALARMS_LOG_FILE, "LOG_ERROR", f"Log file not found: {log_path}")
            except subprocess.CalledProcessError as e:
                results["detections"].append({"error": f"Error reading {log_path}: {e.stderr.strip()}"})
                log_event(ALARMS_LOG_FILE, "LOG_ERROR", f"Error reading log {log_path}: {e.stderr.strip()}")
            except Exception as e:
                results["detections"].append({"error": f"Unexpected error processing {log_path}: {str(e)}"})
                log_event(ALARMS_LOG_FILE, "LOG_ERROR", f"Unexpected error processing log {log_path}: {str(e)}")
        else:
            results["detections"].append({"info": f"Log file {log_path} does not exist on this system."})

   
    if results["detections"]:
        results["status"] = "ALERT"
        results["message"] = f"{log_type} patterns detected. Review required."
    

    if log_type == "web":
        ip_summary = []
        for ip, info in found_events.items():
            if info["count"] >= 5 and ip != "N/A":
                summary_msg = f"IP {ip} generated {info['count']} HTTP errors (possible web scan/bruteforce)."
                ip_summary.append(summary_msg)
                results["message"] = "Multiple HTTP errors from the same IP detected."
                results["status"] = "ALERT"
                log_event(ALARMS_LOG_FILE, "WEB_SCAN_DETECTED", summary_msg, ip=ip)
                send_alert_email("HIPS Alert: Web Scan Detected", summary_msg)
                if re.match(r'\d{1,3}(\.\d{1,3}){3}', ip):
                    await block_ip(ip, reason="Web scan/bruteforce detected")
        if ip_summary:
            results["detections"].insert(0, {"summary": ip_summary, "type": "web_ip_summary"})
    

    elif log_type == "mail":
        mail_summary = []
        for source, info in found_events.items():
            if info["count"] >= 10:  
                summary_msg = f"Source '{source}' generated {info['count']} mail events (possible mass sending)."
                mail_summary.append(summary_msg)
                results["message"] = "Possible mass mail sending detected."
                results["status"] = "ALERT"
                log_event(ALARMS_LOG_FILE, "MASS_MAIL_DETECTED", summary_msg, ip=source if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', source) else None)
                send_alert_email("HIPS Alert: Mass Mail Sending Detected", summary_msg)
                if re.match(r'\d{1,3}(\.\d{1,3}){3}', source):
                    await block_ip(source, reason="Mass mail activity detected")


        if mail_summary:
            results["detections"].insert(0, {"summary": mail_summary, "type": "mail_mass_summary"})


    elif log_type == "auth":
        auth_summary = []
        for source, info in found_events.items():
            if info["count"] >= 5:
                summary_msg = f"Source '{source}' generated {info['count']} authentication failures (possible bruteforce)."
                auth_summary.append(summary_msg)
                results["message"] = "Multiple authentication failures detected."
                results["status"] = "ALERT"
                log_event(ALARMS_LOG_FILE, "BRUTEFORCE_DETECTED", summary_msg, ip=source if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', source) else None)
                username = None
                for line in info["attempts"]:
                    username_match = re.search(r"user=([\w\d_.-]+)", line)
                    if username_match:
                        username = username_match.group(1)
                        break
                if username:
                    await change_user_password(username, "Too many authentication failures")
        if auth_summary:
            results["detections"].insert(0, {"summary": auth_summary, "type": "auth_bruteforce_summary"})

    return results

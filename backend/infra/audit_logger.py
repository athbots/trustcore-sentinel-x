import json
import os
from datetime import datetime

AUDIT_LOG_FILE = os.path.join(os.path.dirname(__file__), "..", "logs", "audit.json")

# Ensure logs dir exists
os.makedirs(os.path.dirname(AUDIT_LOG_FILE), exist_ok=True)

def log_audit_event(request_id: str, endpoint: str, ip: str, method: str, threat_level: str, risk_score: int, action: str, response_time_ms: float):
    entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "request_id": request_id,
        "client_ip": ip,
        "method": method,
        "endpoint": endpoint,
        "threat_level": threat_level,
        "risk_score": risk_score,
        "action_taken": action,
        "processing_time_ms": round(response_time_ms, 2)
    }
    
    with open(AUDIT_LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")

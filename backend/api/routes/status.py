"""
TrustCore Sentinel X — System Status Route
GET /system_status
"""
import time
from fastapi import APIRouter, Depends
from services.response_engine import get_recent_actions, get_action_stats
from infra.config import SYSTEM_NAME, SYSTEM_VERSION
from infra.security import verify_api_key, rate_limit
from schemas.system import SystemStatusResponse
from api.utils import get_safe_response, standardize_response

router = APIRouter()
_START_TIME = time.time()

@router.get("/system_status", dependencies=[Depends(verify_api_key), Depends(rate_limit)])
async def system_status():
    """Return live system status in standardized format."""
    try:
        import state
        from core.process_monitor import ProcessMonitor
        pm = ProcessMonitor()
        os_metrics = pm.get_system_metrics()
        
        # Merge with last result if available
        res = state.last_result if state.last_result else {}
        
        standard_data = {
            "trust_score": float(res.get("risk_score", 100)),
            "risk_level": str(res.get("risk", {}).get("threat_level", "SAFE")),
            "decision": str(res.get("response", {}).get("action", "ALLOW")),
            "cpu": float(os_metrics.get("cpu_percent", 0.0)),
            "memory": float(os_metrics.get("memory_percent", 0.0)),
            "process_count": int(len(pm.get_running_processes())),
            "status": "System Operational"
        }
        
        return standardize_response(standard_data)
    except Exception as e:
        return get_safe_response("/system_status", e)

def _fmt_uptime(s: int) -> str:
    h, rem = divmod(s, 3600)
    m, sec = divmod(rem, 60)
    return f"{h}h {m}m {sec}s"

"""
TrustCore Sentinel X — System Status Route
GET /system_status
"""
import time
from fastapi import APIRouter, Depends
from services.response_engine import get_recent_actions, get_action_stats
from infra.config import SYSTEM_NAME, SYSTEM_VERSION
from infra.security import verify_api_key, rate_limit

router = APIRouter()
_START_TIME = time.time()


@router.get("/system_status", dependencies=[Depends(verify_api_key), Depends(rate_limit)])
async def system_status():
    """Return live system uptime, event counts, and recent response actions."""
    uptime_seconds = int(time.time() - _START_TIME)
    stats = get_action_stats()
    recent = get_recent_actions(limit=10)

    import state

    response = {
        "system": SYSTEM_NAME,
        "version": SYSTEM_VERSION,
        "status": "OPERATIONAL",
        "uptime_seconds": uptime_seconds,
        "uptime_human": _fmt_uptime(uptime_seconds),
        "event_stats": stats,
        "recent_actions": recent,
    }

    if state.last_result:
        response["risk_score"] = state.last_result["risk"]["risk_score"]
        response["threat_level"] = state.last_result["risk"]["threat_level"]
        response["action"] = state.last_result["response"]["action"]
        response["timestamp"] = state.last_result["timestamp"]

    return response


def _fmt_uptime(s: int) -> str:
    h, rem = divmod(s, 3600)
    m, sec = divmod(rem, 60)
    return f"{h}h {m}m {sec}s"

"""
TrustCore Sentinel X — System Status Route
GET /system_status
"""
import time
from fastapi import APIRouter
from services.response_engine import get_recent_actions, get_action_stats
from config import SYSTEM_NAME, SYSTEM_VERSION

router = APIRouter()
_START_TIME = time.time()


@router.get("/system_status")
async def system_status():
    """Return live system uptime, event counts, and recent response actions."""
    uptime_seconds = int(time.time() - _START_TIME)
    stats = get_action_stats()
    recent = get_recent_actions(limit=10)

    return {
        "system": SYSTEM_NAME,
        "version": SYSTEM_VERSION,
        "status": "OPERATIONAL",
        "uptime_seconds": uptime_seconds,
        "uptime_human": _fmt_uptime(uptime_seconds),
        "event_stats": stats,
        "recent_actions": recent,
    }


def _fmt_uptime(s: int) -> str:
    h, rem = divmod(s, 3600)
    m, sec = divmod(rem, 60)
    return f"{h}h {m}m {sec}s"

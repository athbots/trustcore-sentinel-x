"""
TrustCore Sentinel X — Status & System Routes (Production)
"""
import time
from fastapi import APIRouter
from sentinel.config import SYSTEM_NAME, SYSTEM_VERSION
from sentinel.core.response_engine import get_recent_actions, get_action_stats
from sentinel.storage.database import db
from sentinel.pipeline import last_result

router = APIRouter()

_start_time = time.time()


def _uptime_human(seconds: int) -> str:
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    return f"{h}h {m}m {s}s"


@router.get("/status", summary="System health check")
async def system_status() -> dict:
    uptime = int(time.time() - _start_time)
    return {
        "system": SYSTEM_NAME,
        "version": SYSTEM_VERSION,
        "status": "OPERATIONAL",
        "uptime_seconds": uptime,
        "uptime_human": _uptime_human(uptime),
        "event_stats": get_action_stats(),
        "recent_actions": get_recent_actions(10),
    }


@router.get("/system_status", summary="Live system status with latest result")
async def live_system_status() -> dict:
    uptime = int(time.time() - _start_time)
    result = last_result or {}
    return {
        "system": SYSTEM_NAME,
        "version": SYSTEM_VERSION,
        "status": "OPERATIONAL",
        "uptime_seconds": uptime,
        "uptime_human": _uptime_human(uptime),
        "risk_score": result.get("risk", {}).get("risk_score"),
        "threat_level": result.get("risk", {}).get("threat_level"),
        "action": result.get("response", {}).get("action"),
        "event_stats": get_action_stats(),
        "recent_actions": get_recent_actions(10),
    }


@router.get("/events", summary="Recent stored events")
async def get_events(limit: int = 50) -> dict:
    events = db.get_recent_events(limit)
    stats = db.get_event_stats()
    return {
        "events": events,
        "stats": stats,
    }

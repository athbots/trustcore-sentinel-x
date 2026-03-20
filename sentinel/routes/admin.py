"""
TrustCore Sentinel X — Settings, Logs, and Admin API Routes
"""
from fastapi import APIRouter
from sentinel.core import settings as cfg
from sentinel.core.response_engine import get_status as response_status, set_safe_mode, unblock_ip
from sentinel.utils.logger import export_logs, export_audit
from sentinel.utils.watchdog import watchdog, breaker

router = APIRouter()


# ── Settings ─────────────────────────────────────────────────────────────────

@router.get("/settings", summary="Get current settings")
async def get_settings():
    return cfg.get_all()


@router.post("/settings", summary="Update settings")
async def update_settings(changes: dict):
    return cfg.update(changes)


@router.post("/settings/reset", summary="Reset settings to defaults")
async def reset_settings():
    return cfg.reset()


# ── Response Engine Controls ─────────────────────────────────────────────────

@router.get("/response/status", summary="Response engine status")
async def get_response_status():
    return response_status()


@router.post("/response/safe_mode", summary="Toggle safe mode")
async def toggle_safe_mode(enabled: bool = True):
    return {"result": set_safe_mode(enabled)}


@router.post("/response/unblock", summary="Unblock a previously blocked IP")
async def do_unblock(ip: str):
    return {"result": unblock_ip(ip)}


# ── Logs ─────────────────────────────────────────────────────────────────────

@router.get("/logs", summary="Export recent application logs")
async def get_logs(limit: int = 200):
    return {"logs": export_logs(limit)}


@router.get("/logs/audit", summary="Export audit trail")
async def get_audit(limit: int = 200):
    return {"audit": export_audit(limit)}


# ── Health ───────────────────────────────────────────────────────────────────

@router.get("/health", summary="System health check")
async def health_check():
    return {
        "status": "ok",
        "collectors": watchdog.health(),
        "circuit_breaker": breaker.status(),
        "response": response_status(),
    }

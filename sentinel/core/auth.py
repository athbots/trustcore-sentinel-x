"""
TrustCore Sentinel X — API Key Authentication Middleware

Lightweight token-based protection for admin routes.
Public routes (/, /status, /ws/feed, /analyze, /docs) are open.
Admin routes (/settings, /response, /logs, /health) require X-API-Key header.

The API key is auto-generated on first run and stored in config.json.
"""
import secrets
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware

from sentinel.utils.logger import get_logger, audit

logger = get_logger("auth")

# Routes that do NOT require authentication
PUBLIC_PATHS = {
    "/", "/status", "/system_status", "/analyze", "/simulate_attack",
    "/simulate_normal", "/health",
    "/docs", "/redoc", "/openapi.json",
    "/ws/feed", "/static",
}

# Prefixes that are public
PUBLIC_PREFIXES = ("/static/", "/docs", "/redoc")

_api_key: str | None = None


def init_api_key() -> str:
    """Load or generate the API key."""
    global _api_key
    from sentinel.core.settings import get, update

    existing = get("api_key")
    if existing:
        _api_key = existing
    else:
        _api_key = secrets.token_urlsafe(32)
        update({"api_key": _api_key})
        logger.info(f"Generated new API key: {_api_key[:8]}…")

    return _api_key


def get_api_key() -> str | None:
    return _api_key


class APIKeyMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Allow public routes
        if path in PUBLIC_PATHS or any(path.startswith(p) for p in PUBLIC_PREFIXES):
            return await call_next(request)

        # Allow WebSocket upgrade (auth handled separately if needed)
        if request.headers.get("upgrade", "").lower() == "websocket":
            return await call_next(request)

        # Check API key
        provided = request.headers.get("X-API-Key") or request.query_params.get("api_key")

        if not _api_key:
            # Auth not initialized yet — allow
            return await call_next(request)

        if provided != _api_key:
            audit("AUTH_DENIED", f"Unauthorized access to {path}", ip=request.client.host if request.client else "?")
            raise HTTPException(status_code=401, detail="Invalid or missing API key")

        return await call_next(request)

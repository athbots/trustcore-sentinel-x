"""
TrustCore Sentinel X — Production FastAPI Application (v2.2)

Integrates: collectors, pipeline, watchdog, settings, auth, intelligence.

Run with:
    python -m sentinel
    uvicorn sentinel.app:app --host 127.0.0.1 --port 8321

Dashboard: http://127.0.0.1:8321
API Docs:  http://127.0.0.1:8321/docs
"""
import asyncio
import os

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from sentinel.config import SYSTEM_NAME, SYSTEM_VERSION, API_HOST, API_PORT
from sentinel.utils.logger import get_logger, audit
from sentinel.storage.database import db
from sentinel.pipeline import event_queue, pipeline_consumer
from sentinel.routes.analyze import router as analyze_router
from sentinel.routes.status import router as status_router
from sentinel.routes.simulate import router as simulate_router
from sentinel.routes.websocket import router as ws_router
from sentinel.routes.admin import router as admin_router

logger = get_logger("app")

# ── State ────────────────────────────────────────────────────────────────────
_collectors = []
_pipeline_task = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _pipeline_task

    logger.info("=" * 60)
    logger.info(f"  {SYSTEM_NAME} v{SYSTEM_VERSION} — STARTING")
    logger.info(f"  Dashboard: http://{API_HOST}:{API_PORT}")
    logger.info(f"  API Docs:  http://{API_HOST}:{API_PORT}/docs")
    logger.info("=" * 60)
    audit("SYSTEM_START", f"{SYSTEM_NAME} v{SYSTEM_VERSION}")

    # 1. Load config + auth
    from sentinel.core import settings as cfg
    cfg.load()
    from sentinel.core.auth import init_api_key
    api_key = init_api_key()
    logger.info(f"✓ Config loaded | API key: {api_key[:8]}…")

    # 2. Initialize database
    db.initialize()
    db.prune_old_events(max_age_days=cfg.get("log_retention_days", 30))
    logger.info("✓ Database ready")

    # 3. Warm up ML models
    from sentinel.detectors.phishing import analyze_phishing
    from sentinel.detectors.network_anomaly import analyze_anomaly
    analyze_phishing("warm-up")
    analyze_anomaly([500, 10, 0.4, 60, 0])
    logger.info("✓ ML models loaded")

    # 4. Start pipeline consumer
    _pipeline_task = asyncio.create_task(pipeline_consumer())
    logger.info("✓ Pipeline consumer started")

    # 5. Start collectors with watchdog
    loop = asyncio.get_event_loop()
    _start_collectors(loop, cfg)

    logger.info("=" * 60)
    logger.info(f"  {SYSTEM_NAME} v{SYSTEM_VERSION} — ONLINE")
    logger.info("=" * 60)

    yield  # ── App is running ──

    # Shutdown
    logger.info("Shutting down...")
    audit("SYSTEM_STOP", "Graceful shutdown")

    from sentinel.utils.watchdog import watchdog
    watchdog.stop()
    for c in _collectors:
        try:
            c.stop()
        except Exception:
            pass
    if _pipeline_task:
        _pipeline_task.cancel()
        try:
            await _pipeline_task
        except asyncio.CancelledError:
            pass
    db.close()
    logger.info("Shutdown complete")


def _start_collectors(loop: asyncio.AbstractEventLoop, cfg) -> None:
    global _collectors
    from sentinel.utils.watchdog import watchdog

    collectors_started = 0

    if cfg.get("enable_process_collector", True):
        try:
            from sentinel.collectors.process import ProcessCollector
            c = ProcessCollector(event_queue)
            c.start(loop)
            _collectors.append(c)
            watchdog.register(c, loop)
            collectors_started += 1
            logger.info("✓ Process collector started")
        except Exception as e:
            logger.warning(f"Process collector failed: {e}")

    if cfg.get("enable_network_collector", True):
        try:
            from sentinel.collectors.network import NetworkCollector
            c = NetworkCollector(event_queue)
            c.start(loop)
            _collectors.append(c)
            watchdog.register(c, loop)
            collectors_started += 1
            logger.info("✓ Network collector started")
        except Exception as e:
            logger.warning(f"Network collector failed: {e}")

    if cfg.get("enable_login_collector", True):
        try:
            from sentinel.collectors.login import LoginCollector
            c = LoginCollector(event_queue)
            c.start(loop)
            _collectors.append(c)
            watchdog.register(c, loop)
            collectors_started += 1
            logger.info("✓ Login collector started")
        except Exception as e:
            logger.warning(f"Login collector failed: {e}")

    watchdog.start()
    logger.info(f"{collectors_started} collector(s) active with watchdog")


# ── App ──────────────────────────────────────────────────────────────────────
app = FastAPI(
    title=SYSTEM_NAME,
    version=SYSTEM_VERSION,
    description=(
        "AI-powered autonomous cyber defense system. "
        "Real-time monitoring, phishing NLP, anomaly detection, "
        "risk scoring (0–100), and automated response."
    ),
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# API key auth (added after CORS so CORS headers are set before auth check)
from sentinel.core.auth import APIKeyMiddleware
app.add_middleware(APIKeyMiddleware)

# Routes
app.include_router(analyze_router, tags=["Analysis"])
app.include_router(status_router, tags=["System"])
app.include_router(simulate_router, tags=["Simulation"])
app.include_router(ws_router, tags=["WebSocket"])
app.include_router(admin_router, tags=["Admin"])

# ── Static Frontend ──────────────────────────────────────────────────────────
_frontend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend"))

if os.path.isdir(_frontend_dir):
    app.mount("/static", StaticFiles(directory=_frontend_dir), name="static")

    @app.get("/", include_in_schema=False)
    async def serve_dashboard():
        return FileResponse(os.path.join(_frontend_dir, "index.html"))
else:
    @app.get("/", include_in_schema=False)
    async def root():
        return {"message": f"{SYSTEM_NAME} v{SYSTEM_VERSION} — API running. Visit /docs"}


# ── Health Check ─────────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {"status": "ok"}


# ── CLI Entry Point ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("sentinel.app:app", host=API_HOST, port=API_PORT, reload=False, log_level="info")

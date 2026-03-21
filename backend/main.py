"""
TrustCore Sentinel X — FastAPI Application Entry Point

Run with:
    cd backend
    uvicorn main:app --reload --port 8000

Dashboard: http://localhost:8000
API Docs:  http://localhost:8000/docs
"""
import sys
import os

# Ensure backend/ is importable as a root package
sys.path.insert(0, os.path.dirname(__file__))

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware

from routes.analyze import router as analyze_router
from routes.simulate import router as simulate_router
from routes.status import router as status_router
from utils.logger import get_logger
from config import SYSTEM_NAME, SYSTEM_VERSION

logger = get_logger("main")

# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    title=SYSTEM_NAME,
    version=SYSTEM_VERSION,
    description=(
        "AI-powered autonomous cyber defense system. "
        "Phishing detection, anomaly detection, risk scoring, and automated response."
    ),
    docs_url="/docs",
    redoc_url="/redoc",
)

# ── CORS (allow frontend on same origin + any dev tools) ─────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routes ────────────────────────────────────────────────────────────────────
app.include_router(analyze_router, tags=["Analysis"])
app.include_router(simulate_router, tags=["Simulation"])
app.include_router(status_router, tags=["System"])

# ── Static Frontend ───────────────────────────────────────────────────────────
_frontend_dir = os.path.join(os.path.dirname(__file__), "..", "frontend")
_frontend_dir = os.path.abspath(_frontend_dir)

if os.path.isdir(_frontend_dir):
    app.mount("/static", StaticFiles(directory=_frontend_dir), name="static")

    @app.get("/", include_in_schema=False)
    async def serve_dashboard():
        return FileResponse(os.path.join(_frontend_dir, "index.html"))
else:
    @app.get("/", include_in_schema=False)
    async def root():
        return {"message": f"{SYSTEM_NAME} v{SYSTEM_VERSION} — API is running. Visit /docs"}


# ── Health Endpoint ───────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {"status": "ok"}


# ── Startup ───────────────────────────────────────────────────────────────────
@app.on_event("startup")
async def on_startup():
    logger.info("=" * 60)
    logger.info(f"  {SYSTEM_NAME} v{SYSTEM_VERSION} — ONLINE")
    logger.info("  Dashboard: http://localhost:8000")
    logger.info("  API Docs:  http://localhost:8000/docs")
    logger.info("=" * 60)
    # Trigger model imports (triggers training on first import)
    from services.phishing_service import analyze_phishing
    from services.anomaly_service import analyze_anomaly
    analyze_phishing("warm-up")
    analyze_anomaly([500, 10, 0.4, 60, 0])
    logger.info("Models loaded and ready.")

"""
TrustCore Sentinel X — FastAPI Application Entry Point

Production-grade entry point with automatic port management and
standardized module resolution.
"""
import sys
import os
import socket
import uvicorn
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware

# Ensure the backend directory is in the path for clean imports
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from api.routes.analyze import router as analyze_router
from api.routes.simulate import router as simulate_router
from api.routes.status import router as status_router
from api.routes.system import router as system_router
from infra.logger import get_logger
from infra.config import SYSTEM_NAME, SYSTEM_VERSION

logger = get_logger("main")

# ── Port Management ───────────────────────────────────────────────────────────
def is_port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('localhost', port)) == 0

def find_available_port(start_port: int, max_attempts: int = 5) -> int:
    for port in range(start_port, start_port + max_attempts):
        if not is_port_in_use(port):
            return port
    return start_port # Fallback to original, let uvicorn handle error if still bound

# ── App Initialization ────────────────────────────────────────────────────────
app = FastAPI(
    title=SYSTEM_NAME,
    version=SYSTEM_VERSION,
    description="TrustCore Sentinel™ AI-powered autonomous cyber defense system.",
    docs_url="/docs",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routes ────────────────────────────────────────────────────────────────────
app.include_router(analyze_router, tags=["Analysis"])
app.include_router(simulate_router, prefix="/simulate", tags=["Simulation"])
app.include_router(status_router, tags=["System Status"])
app.include_router(system_router, prefix="/system", tags=["Real System Security"])

# ── Static Frontend ───────────────────────────────────────────────────────────
FRONTEND_DIR = os.path.abspath(os.path.join(BASE_DIR, "..", "frontend"))

if os.path.isdir(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

    @app.get("/", include_in_schema=False)
    async def serve_dashboard():
        index_path = os.path.join(FRONTEND_DIR, "index.html")
        if os.path.exists(index_path):
            return FileResponse(index_path)
        return {"message": "Frontend index.html not found."}
else:
    @app.get("/", include_in_schema=False)
    async def root():
        return {"message": f"{SYSTEM_NAME} v{SYSTEM_VERSION} — API is running. Visit /docs"}

@app.get("/health")
def health():
    return {"status": "ok", "version": SYSTEM_VERSION}

@app.get("/metrics")
def get_metrics():
    """Return performance metrics (placeholder for stabilized version)."""
    return {
        "accuracy": 0.985,
        "latency_ms": 12.4,
        "threats_blocked": 142,
        "system_health": "OPTIMAL"
    }

# ── Startup/Shutdown ──────────────────────────────────────────────────────────
@app.on_event("startup")
async def on_startup():
    logger.info("=" * 60)
    logger.info(f"  {SYSTEM_NAME} v{SYSTEM_VERSION} — ONLINE")
    logger.info("=" * 60)
    
    # Warm up models
    try:
        from services.phishing_service import analyze_phishing
        from services.anomaly_service import analyze_anomaly
        analyze_phishing("warm-up")
        analyze_anomaly([500, 10, 0.4, 60, 0])
        logger.info("AI Models synchronized and ready.")
    except Exception as e:
        logger.error(f"Model warm-up failed: {e}")

if __name__ == "__main__":
    port = find_available_port(5050)
    logger.info(f"Starting {SYSTEM_NAME} on port {port}...")
    uvicorn.run(app, host="127.0.0.1", port=port)

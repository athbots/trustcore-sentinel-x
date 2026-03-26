from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import time
import logging

try:
    from prometheus_fastapi_instrumentator import Instrumentator
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False

from trust_engine.models.schemas import EngineRequest
from trust_engine.core.trust_engine import TrustCoreEngine
from trust_engine.storage.db import init_db
from trust_engine.pipeline.kafka_stream import event_stream
from trust_engine.pipeline.stream_processor import StreamIntelligence
from trust_engine.storage.graph import neo4j_graph
from trust_engine.api.middleware import enterprise_firewall_middleware

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
log = logging.getLogger("trust_engine.api")

engine: TrustCoreEngine = None
stream_intelligence = StreamIntelligence()

@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("Initializing Enterprise Storage layer...")
    await init_db()
    
    log.info("Starting Event Streams & Message Bus...")
    await event_stream.initialize()
    await stream_intelligence.start()
    
    log.info("Provisioning TrustCore Enterprise Engine...")
    global engine
    engine = TrustCoreEngine()
    
    yield
    
    log.info("Shutting down Event Pipeline and Connections...")
    await stream_intelligence.stop()
    await event_stream.shutdown()
    await neo4j_graph.close()

app = FastAPI(title="TrustCore Sentinel Enterprise API", lifespan=lifespan)

# Add Security Firewall Middleware
app.middleware("http")(enterprise_firewall_middleware)

# Enable CORS for UI Dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

if PROMETHEUS_AVAILABLE:
    Instrumentator().instrument(app).expose(app)
    log.info("Prometheus metrics endpoint exposed at /metrics")

@app.get("/health")
async def health_check():
    return {"status": "enterprise_ok", "version": "3.0.0-ENTERPRISE"}

@app.post("/api/v1/evaluate")
async def evaluate_endpoint(request: Request, body_req: EngineRequest):
    """
    Enterprise API endpoint. Evaluates risk with correlation, executes autonomous blocking, 
    and returns explanatory UI matrix. Supports multi-tenancy.
    """
    if not engine:
        raise HTTPException(status_code=503, detail="Enterprise cluster initializing")
        
    start_time = time.perf_counter()
    tenant_id = getattr(request.state, "tenant_id", "default")
    
    result = await engine.evaluate_trust(body_req, tenant_id=tenant_id)
    latency_ms = (time.perf_counter() - start_time) * 1000
    
    evaluation = result["evaluation"].model_dump() if hasattr(result["evaluation"], "model_dump") else result["evaluation"].dict()
    
    return {
        "evaluation": evaluation,
        "explainer_matrix": result["explainer_matrix"],
        "metadata": {
            "tenant_id": tenant_id,
            "latency_ms": round(latency_ms, 2)
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("trust_engine.api.main:app", host="0.0.0.0", port=8080, workers=4)

"""
TrustCore Sentinel X — Unified Analysis Route
POST /analyze

Thin HTTP boundary that delegates to the analysis controller.
Uses deferred (lazy) import of the controller to avoid import-order
issues when uvicorn hot-reloads from the routes/ subdirectory.
"""

from fastapi import APIRouter, Depends, Request
from domain.models.core import ThreatEvent
from infra.security import verify_api_key, rate_limit
import time
import uuid
from datetime import datetime

router = APIRouter()

@router.post(
    "/analyze",
    summary="Full AI threat analysis",
    dependencies=[Depends(verify_api_key), Depends(rate_limit)],
    description=(
        "Run the complete pipeline: phishing NLP + anomaly Isolation Forest "
        "+ weighted risk scoring (0–100) + autonomous response action."
    ),
)
async def analyze_event(req: ThreatEvent, request: Request) -> dict:
    """Analyze a security event through the full TrustCore AI pipeline."""
    start_time = time.time()
    request_id = str(uuid.uuid4())
    
    from services.analysis_service import run_full_analysis
    import state

    # Domain conversion and pipeline trigger
    result = run_full_analysis(req.model_dump())
    
    # Timing and identity additions
    process_time_ms = (time.time() - start_time) * 1000
    result["request_id"] = request_id
    result["processing_time_ms"] = round(process_time_ms, 2)
    result["timestamp"] = datetime.utcnow().isoformat() + "Z"
    
    state.last_result = result
    
    # Audit log sink
    from infra.audit_logger import log_audit_event
    client_ip = request.client.host if request.client else "unknown"
    log_audit_event(
        request_id=request_id,
        endpoint="/analyze",
        ip=req.source_ip or client_ip,
        method="POST",
        threat_level=result.get("risk", {}).get("threat_level", "SAFE"),
        risk_score=result.get("risk_score", 0),
        action=result.get("response", {}).get("action", "LOG"),
        response_time_ms=process_time_ms
    )
    
    return result

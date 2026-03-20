"""
TrustCore Sentinel X — Analysis Route (Production)
POST /analyze — manual event submission through the full AI pipeline.
"""
from fastapi import APIRouter
from sentinel.core.schemas import EventRequest
from sentinel.pipeline import process_event

router = APIRouter()


@router.post(
    "/analyze",
    summary="Full AI threat analysis",
    description=(
        "Run the complete pipeline: phishing NLP + network anomaly detection "
        "+ process analysis + risk scoring (0–100) + autonomous response."
    ),
)
async def analyze_event(req: EventRequest) -> dict:
    """Analyze a manually submitted security event."""
    event = req.model_dump()
    result = await process_event(event)
    return result

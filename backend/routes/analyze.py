"""
TrustCore Sentinel X — Unified Analysis Route
POST /analyze

Thin HTTP boundary — delegates all business logic to the analysis controller.
Schema validation is handled by Pydantic (core/schemas.py).
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from fastapi import APIRouter
from core.schemas import EventRequest, AnalysisResponse
from controllers.analysis_controller import run_full_analysis

router = APIRouter()


@router.post(
    "/analyze",
    response_model=AnalysisResponse,
    summary="Analyze a security event",
    description=(
        "Run the full AI pipeline: phishing detection (NLP) + "
        "anomaly detection (Isolation Forest) + risk scoring (0–100) + "
        "autonomous response (LOG/ALERT/BLOCK/ISOLATE)."
    ),
)
async def analyze_event(req: EventRequest) -> dict:
    """
    Analyze a security event through the full TrustCore AI pipeline.

    Returns a complete threat assessment with:
    - Phishing verdict + score
    - Anomaly verdict + score
    - Unified risk score (0–100)
    - Autonomous response action taken
    """
    return run_full_analysis(req.model_dump())

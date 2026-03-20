"""
TrustCore Sentinel X — Unified Analysis Route
POST /analyze

Thin HTTP boundary that delegates to the analysis controller.
Uses deferred (lazy) import of the controller to avoid import-order
issues when uvicorn hot-reloads from the routes/ subdirectory.
"""
import sys
import os

# Prepend backend root before anything else — must happen at module level
# so subsequent imports in this file work correctly.
_here = os.path.dirname(os.path.abspath(__file__))          # routes/
_backend = os.path.dirname(_here)                           # backend/
if _backend not in sys.path:
    sys.path.insert(0, _backend)

from fastapi import APIRouter
from pydantic import BaseModel, Field
from typing import List, Optional

router = APIRouter()


class EventRequest(BaseModel):
    """Security event payload for full AI pipeline analysis."""

    text: str = Field(
        default="",
        description="Email body, log message, or any text to scan for phishing signals",
        examples=["Verify your PayPal account immediately or it will be suspended"],
    )
    features: List[float] = Field(
        default=[500.0, 10.0, 0.45, 60.0, 0],
        description=(
            "Network telemetry vector (5 values): "
            "[bytes_per_second, request_rate, payload_entropy, session_duration, port_risk(0|1)]"
        ),
    )
    source_ip: Optional[str] = Field(default=None, description="Source IPv4 address")
    target: Optional[str]    = Field(default=None, description="Target host/system name")
    event_type: Optional[str]= Field(default=None, description="Attack class hint (DDOS, PHISHING, …)")
    repeat_offender: bool    = Field(default=False, description="Source flagged in prior events")

    model_config = {
        "json_schema_extra": {
            "example": {
                "text": "Verify your PayPal account immediately or it will be suspended",
                "features": [800, 12, 0.52, 45, 0],
                "source_ip": "203.0.113.45",
                "target": "finance-gateway",
                "event_type": "PHISHING",
                "repeat_offender": False,
            }
        }
    }


@router.post(
    "/analyze",
    summary="Full AI threat analysis",
    description=(
        "Run the complete pipeline: phishing NLP + anomaly Isolation Forest "
        "+ weighted risk scoring (0–100) + autonomous response action."
    ),
)
async def analyze_event(req: EventRequest) -> dict:
    """
    Analyze a security event through the full TrustCore AI pipeline.

    Returns a complete threat assessment with phishing result, anomaly result,
    risk score (0–100), threat level, and the autonomous response action taken.
    """
    # Lazy import: guarantees sys.path is set before the controller loads its
    # own service imports (services.*, utils.*, config) — safe under --reload.
    from controllers.analysis_controller import run_full_analysis
    return run_full_analysis(req.model_dump())

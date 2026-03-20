"""
TrustCore Sentinel X — Unified Analysis Route
POST /analyze
Runs phishing + anomaly + risk scoring + autonomous response in one call.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from fastapi import APIRouter
from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime, timezone

from services.phishing_service import analyze_phishing
from services.anomaly_service import analyze_anomaly
from services.risk_engine import compute_risk
from services.response_engine import execute_response
from utils.logger import get_logger

router = APIRouter()
logger = get_logger("route.analyze")


class EventRequest(BaseModel):
    text: str = Field("", description="Email body or log text to analyze for phishing")
    features: List[float] = Field(
        default=[500.0, 10.0, 0.45, 60.0, 0],
        description="Network feature vector: [bytes/s, req_rate, entropy, duration, port_risk]"
    )
    source_ip: Optional[str] = Field(None, description="Source IP address")
    target: Optional[str] = Field(None, description="Target system name")
    event_type: Optional[str] = Field(None, description="Event type hint")
    repeat_offender: bool = Field(False, description="Is this a known repeat source?")


@router.post("/analyze")
async def analyze_event(req: EventRequest):
    """
    Unified threat analysis endpoint.
    Runs all AI models and returns a complete threat verdict with auto-response.
    """
    event_dict = req.model_dump()

    # ── Step 1: Phishing Detection ──────────────────────────────────────────
    phishing_result = analyze_phishing(req.text)

    # ── Step 2: Anomaly Detection ───────────────────────────────────────────
    anomaly_result = analyze_anomaly(req.features)

    # ── Step 3: Risk Scoring ────────────────────────────────────────────────
    risk_result = compute_risk(
        phishing_score=phishing_result["score"],
        anomaly_score=anomaly_result["score"],
        event=event_dict,
    )

    # ── Step 4: Autonomous Response ─────────────────────────────────────────
    response_record = execute_response(
        threat_level=risk_result["threat_level"],
        risk_score=risk_result["risk_score"],
        action=risk_result["response"]["action"],
        description=risk_result["response"]["description"],
        event=event_dict,
    )

    logger.info(
        f"ANALYZE | RISK={risk_result['risk_score']}/100 | "
        f"THREAT={risk_result['threat_level']} | ACTION={risk_result['response']['action']}"
    )

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "phishing": phishing_result,
        "anomaly": anomaly_result,
        "risk": risk_result,
        "response": response_record,
    }

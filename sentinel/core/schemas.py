"""
TrustCore Sentinel X — Pydantic Schemas (Production)
"""
from pydantic import BaseModel, Field
from typing import List, Optional, Any


# ── Request Models ────────────────────────────────────────────────────────────

class EventRequest(BaseModel):
    """Unified event submission schema for the /analyze endpoint."""
    text: str = Field(
        default="",
        description="Email body, log message, or text to scan for phishing",
    )
    features: List[float] = Field(
        default=[500.0, 10.0, 0.45, 60.0, 0],
        description="Network telemetry: [bytes/s, req_rate, entropy, duration, port_risk]",
    )
    source_ip: Optional[str] = Field(default=None)
    target: Optional[str] = Field(default=None)
    event_type: Optional[str] = Field(default=None)
    repeat_offender: bool = Field(default=False)

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


# ── Response Models ───────────────────────────────────────────────────────────

class PhishingResult(BaseModel):
    score: float
    verdict: str
    confidence: str
    signals: List[str]


class AnomalyResult(BaseModel):
    score: float
    verdict: str
    anomalous_features: List[str]
    raw_if_score: float


class ComponentScores(BaseModel):
    phishing: float
    network_anomaly: float
    process_anomaly: float
    context: float


class ResponseAction(BaseModel):
    action: str
    description: str


class RiskResult(BaseModel):
    risk_score: int
    threat_level: str
    component_scores: ComponentScores
    response: ResponseAction


class ExplanationResult(BaseModel):
    summary: str
    narrative: str
    recommendation: str
    severity_icon: str


class ResponseRecord(BaseModel):
    timestamp: str
    action: str
    threat_level: str
    risk_score: int
    event_type: str
    source_ip: str
    target: str
    description: str
    outcome: str
    icon: str


class AnalysisResponse(BaseModel):
    """Full analysis result returned by POST /analyze."""
    timestamp: str
    phishing: PhishingResult
    anomaly: AnomalyResult
    risk: RiskResult
    response: ResponseRecord
    explanation: ExplanationResult


class SystemStatusResponse(BaseModel):
    system: str
    version: str
    status: str
    uptime_seconds: int
    uptime_human: str
    collectors: dict
    event_stats: dict
    recent_actions: List[Any]

"""
TrustCore Sentinel X — Core Pydantic Schemas
=============================================
Single source of truth for all request/response models.
Imported by both routes (HTTP boundary) and controllers (business logic).
"""

from pydantic import BaseModel, Field
from typing import List, Optional, Any


# ── Request Models ────────────────────────────────────────────────────────────

class EventRequest(BaseModel):
    """
    Unified event submission schema.
    All fields except text and features are optional metadata
    that enriches the context scoring component.
    """
    text: str = Field(
        default="",
        description="Email body, log message, or any text to analyze for phishing",
        examples=["Verify your PayPal account immediately or it will be suspended"],
    )
    features: List[float] = Field(
        default=[500.0, 10.0, 0.45, 60.0, 0],
        description=(
            "Network telemetry vector: "
            "[bytes/s, request_rate, payload_entropy, session_duration, port_risk(0/1)]"
        ),
        min_length=1,
        max_length=5,
    )
    source_ip: Optional[str] = Field(
        default=None,
        description="IPv4 source address of the event origin",
        examples=["203.0.113.45"],
    )
    target: Optional[str] = Field(
        default=None,
        description="Target system or hostname",
        examples=["finance-gateway"],
    )
    event_type: Optional[str] = Field(
        default=None,
        description="Hint about the attack class (PHISHING, DDOS, PORT_SCAN, ...)",
        examples=["PHISHING"],
    )
    repeat_offender: bool = Field(
        default=False,
        description="True if the source IP has been flagged in prior events",
    )

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


# ── Sub-response Models ────────────────────────────────────────────────────────

class PhishingResult(BaseModel):
    score:      float
    verdict:    str   # PHISHING | SUSPICIOUS | LEGITIMATE
    confidence: str   # LOW | MEDIUM | HIGH
    signals:    List[str]


class AnomalyResult(BaseModel):
    score:               float
    verdict:             str   # NORMAL | SUSPICIOUS | ANOMALY
    anomalous_features:  List[str]
    raw_if_score:        float


class ComponentScores(BaseModel):
    phishing: float
    anomaly:  float
    context:  float


class ResponseAction(BaseModel):
    action:      str   # LOG | ALERT | BLOCK | ISOLATE
    description: str


class RiskResult(BaseModel):
    risk_score:       int          # 0–100
    threat_level:     str          # SAFE | LOW | MEDIUM | HIGH | CRITICAL
    component_scores: ComponentScores
    response:         ResponseAction


class ResponseRecord(BaseModel):
    timestamp:    str
    action:       str
    threat_level: str
    risk_score:   int
    event_type:   str
    source_ip:    str
    target:       str
    description:  str
    outcome:      str
    icon:         str


# ── Top-level Response Model ───────────────────────────────────────────────────

class AnalysisResponse(BaseModel):
    """Full analysis result returned by POST /analyze."""
    timestamp: str
    phishing:  PhishingResult
    anomaly:   AnomalyResult
    risk:      RiskResult
    response:  ResponseRecord


# ── System Status ──────────────────────────────────────────────────────────────

class ActionStats(BaseModel):
    total_actions: int
    by_action:     dict
    by_threat_level: dict


class SystemStatusResponse(BaseModel):
    system:        str
    version:       str
    status:        str
    uptime_seconds: int
    uptime_human:  str
    event_stats:   ActionStats
    recent_actions: List[Any]

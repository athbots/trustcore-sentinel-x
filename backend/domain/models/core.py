"""
TrustCore Sentinel X — Core Domain Models
=========================================
Centralized Pydantic schemas representing the internal language 
of the system. These models are free of any framework-specific
(FastAPI) encumbrances.
"""

from typing import List, Optional
from pydantic import BaseModel, Field, field_validator
import re

class ThreatEvent(BaseModel):
    """Canonical representation of an inbound security event."""
    text: str = Field(
        default="",
        description="Text payload to scan for phishing signals (e.g. Email body)",
    )

    @field_validator("text")
    @classmethod
    def sanitize_text(cls, v: str) -> str:
        """Strip null bytes and non-printable control characters for injection safety."""
        return re.sub(r'[\x00-\x1F\x7F]', '', v).strip()

    features: List[float] = Field(
        default=[500.0, 10.0, 0.45, 60.0, 0.0],
        description="Network telemetry vector: [bytes_per_sec, req_rate, entropy, duration, port_risk]",
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


class EntityProfile(BaseModel):
    """Historical risk footprint tied to a specific actor (IP)."""
    entity_id: str
    risk_multiplier: float
    reputation: str
    is_repeat_offender: bool
    high_risk_events: int
    avg_risk: float

class AttackChain(BaseModel):
    """Correlated multi-stage attack sequence."""
    chain_detected: bool
    matched_chains: List[dict] = Field(default_factory=list)
    stages_observed: int = 0

class ExplainabilityProfile(BaseModel):
    """Transparent AI decision explanations."""
    summary: str
    narrative: str
    recommendation: str
    factors: List[dict] = Field(default_factory=list)

class RiskScore(BaseModel):
    """Discrete mathematical output representing system danger."""
    risk_score: int
    threat_level: str
    confidence: float
    reason: str

class DetectionResult(BaseModel):
    """Unified system analysis output containing all layer results."""
    request_id: Optional[str] = None
    timestamp: str
    processing_time_ms: Optional[float] = None
    risk_score: int
    confidence: float
    reason: str
    signals: List[str]
    
    explanation: dict  # Alternatively use ExplainabilityProfile
    attack_chain: dict # Alternatively use AttackChain
    entity_profile: dict # Alternatively use EntityProfile
    
    phishing: dict
    anomaly: dict
    risk: dict
    response: dict

"""
TrustCore Sentinel X — Pydantic Schemas
"""

from pydantic import BaseModel, Field
from typing import Optional, List
from enum import Enum


class ThreatLevel(str, Enum):
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AutomatedResponse(str, Enum):
    MONITOR = "MONITOR"
    FLAG_FOR_REVIEW = "FLAG_FOR_REVIEW"
    THROTTLE = "THROTTLE"
    BLOCK = "BLOCK"
    ISOLATE_AND_ALERT = "ISOLATE_AND_ALERT"


# ── Request Schemas ──────────────────────────────────────────────────────────

class EmailScanRequest(BaseModel):
    subject: str = Field(..., example="Urgent: Verify your account now!")
    body: str = Field(..., example="Click here to verify your account or it will be suspended.")
    sender: str = Field(..., example="support@paypa1-secure.com")
    recipient: Optional[str] = Field(None, example="victim@company.com")


class NetworkEventRequest(BaseModel):
    source_ip: str = Field(..., example="192.168.1.55")
    destination_ip: str = Field(..., example="10.0.0.1")
    port: int = Field(..., example=22)
    bytes_sent: float = Field(..., example=15000)
    bytes_received: float = Field(..., example=200)
    duration_seconds: float = Field(..., example=0.5)
    protocol: str = Field(..., example="TCP")
    failed_logins: int = Field(default=0, example=8)
    packet_count: int = Field(default=1, example=150)


class BulkScanRequest(BaseModel):
    emails: Optional[List[EmailScanRequest]] = []
    network_events: Optional[List[NetworkEventRequest]] = []


# ── Response Schemas ─────────────────────────────────────────────────────────

class ThreatDetail(BaseModel):
    category: str
    confidence: float
    indicators: List[str]


class SentinelResponse(BaseModel):
    risk_score: float = Field(..., description="0–100 risk score")
    threat_level: ThreatLevel
    automated_response: AutomatedResponse
    threats_detected: List[ThreatDetail]
    summary: str
    timestamp: str
    entity_id: Optional[str] = None


class BulkScanResponse(BaseModel):
    total_analyzed: int
    high_risk_count: int
    results: List[SentinelResponse]
    overall_threat_level: ThreatLevel

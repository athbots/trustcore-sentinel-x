from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from enum import Enum
import time

class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

class Decision(str, Enum):
    ALLOW = "ALLOW"
    CHALLENGE = "CHALLENGE"
    BLOCK = "BLOCK"

class EngineRequest(BaseModel):
    user_id: str
    session_id: str
    device_id: str
    ip_address: str
    action: str  # e.g., "login", "transfer", "upload"
    content: Optional[str] = None
    timestamp: float = Field(default_factory=time.time)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
class EngineResponse(BaseModel):
    trust_score: int  # 0 to 100
    risk_level: RiskLevel
    decision: Decision
    confidence: float  # 0.0 to 1.0
    explanation: List[str]

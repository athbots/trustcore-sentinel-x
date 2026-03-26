from pydantic import BaseModel
from typing import List, Dict, Any, Optional

class OsMetrics(BaseModel):
    cpu_percent: float
    memory_percent: float
    disk_percent: float
    network_connections: int

class SystemMetrics(BaseModel):
    malicious_files: int
    suspicious_processes: int
    high_risk_events: int

class ProcessThreat(BaseModel):
    path: str
    risk_score: float
    reasons: List[str]
    threat_level: str
    decision: str
    confidence: float
    explanation: str

class FullSystemStatus(BaseModel):
    trust_score: float
    risk_level: str
    status_message: str
    decision: str
    cpu_usage: float
    memory_usage: float
    process_count: int
    anomaly_score: float
    explanations: List[str]

class ProcessStatusResponse(BaseModel):
    trust_score: float
    risk_level: str
    decision: str
    confidence: float
    explanation: str
    explanations: List[str]
    metrics: SystemMetrics
    os_metrics: OsMetrics
    threats: List[ProcessThreat]

class SystemStatusResponse(BaseModel):
    system: str
    version: str
    status: str
    uptime_seconds: int
    uptime_human: str
    event_stats: Dict[str, int]
    recent_actions: List[Dict[str, Any]]
    risk_score: Optional[float] = None
    threat_level: Optional[str] = None
    action: Optional[str] = None
    timestamp: Optional[str] = None

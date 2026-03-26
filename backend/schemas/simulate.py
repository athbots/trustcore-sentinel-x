from pydantic import BaseModel
from typing import Optional, Dict, Any

class AttackSimulationRequest(BaseModel):
    scenario: str
    duration: int = 10

class AttackSimulationResponse(BaseModel):
    scenario: str
    status: str
    duration_seconds: int
    expected_effect: str
    cleanup_status: str

class AttackSimulationStatus(BaseModel):
    active_scenario: Optional[str]
    elapsed_seconds: float
    remaining_seconds: float
    is_running: bool
    simulated_signals: Dict[str, Any]

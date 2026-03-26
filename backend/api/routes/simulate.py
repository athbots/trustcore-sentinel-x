from fastapi import APIRouter, Depends, HTTPException
from core.attack_simulator import AttackSimulator
from schemas.simulate import AttackSimulationRequest, AttackSimulationResponse, AttackSimulationStatus
from infra.security import verify_api_key, rate_limit
from typing import Dict, Any

router = APIRouter()
simulator = AttackSimulator()

@router.post("/attack", response_model=AttackSimulationResponse)
async def start_attack_simulation(request: AttackSimulationRequest):
    """
    Trigger a safe, controlled attack simulation.
    Scenarios: cpu_spike, memory_pressure, process_burst, file_churn, mixed_attack
    """
    result = simulator.start_scenario(request.scenario, request.duration)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    
    return AttackSimulationResponse(
        scenario=request.scenario,
        status="started",
        duration_seconds=request.duration,
        expected_effect=result["expected_effect"],
        cleanup_status="pending"
    )

@router.get("/attack/status", response_model=AttackSimulationStatus)
async def get_attack_status():
    """Get the current state of the attack simulation."""
    status = simulator.get_status()
    return AttackSimulationStatus(**status)

@router.post("/attack/stop")
async def stop_attack_simulation():
    """Manually terminate any active attack simulation."""
    simulator.stop_all()
    return {"status": "stopped", "message": "All simulations terminated and cleaned up."}

# Legacy endpoints for backward compatibility if needed by old mock scripts
@router.get("/simulate_attack")
async def legacy_simulate_attack():
    return {"message": "Use POST /simulate/attack for the new hardened simulation engine."}

@router.get("/simulate_normal")
async def legacy_simulate_normal():
    return {"message": "System is operating normally. Telemetry is 100% real-time."}

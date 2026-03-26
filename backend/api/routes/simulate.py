from fastapi import APIRouter, Depends, HTTPException
from core.attack_simulator import AttackSimulator
from api.utils import get_safe_response, standardize_response
from core.process_monitor import ProcessMonitor
from typing import Dict, Any, List
from schemas.simulate import AttackSimulationRequest
from infra.security import verify_api_key, rate_limit

router = APIRouter()
simulator = AttackSimulator()
pm = ProcessMonitor()

@router.post("/attack")
async def start_attack_simulation(request: AttackSimulationRequest):
    """Trigger a safe, controlled attack simulation."""
    try:
        result = simulator.start_scenario(request.scenario, request.duration)
        metrics = pm.get_system_metrics()
        
        status_msg = f"Simulating {request.scenario}"
        if "error" in result:
             status_msg = f"Sim Start Error: {result['error']}"

        return standardize_response({
            "trust_score": 55.0, # Simulation trigger score
            "risk_level": "MONITOR",
            "decision": "MONITOR",
            "cpu": float(metrics.get("cpu_percent", 0.0)),
            "memory": float(metrics.get("memory_percent", 0.0)),
            "process_count": int(len(pm.get_running_processes())),
            "status": status_msg
        })
    except Exception as e:
        return get_safe_response("/simulate/attack", e)

@router.get("/attack/status")
async def get_attack_status():
    """Get the current state of the attack simulation."""
    try:
        status = simulator.get_status()
        metrics = pm.get_system_metrics()
        return standardize_response({
            "trust_score": 100.0 if not status.get("is_running") else 50.0,
            "risk_level": "SAFE" if not status.get("is_running") else "HIGH",
            "decision": "ALLOW" if not status.get("is_running") else "CHALLENGE",
            "cpu": float(metrics.get("cpu_percent", 0.0)),
            "memory": float(metrics.get("memory_percent", 0.0)),
            "process_count": int(len(pm.get_running_processes())),
            "status": f"Simulation Status: {'ACTIVE' if status.get('is_running') else 'IDLE'}"
        })
    except Exception as e:
        return get_safe_response("/simulate/status", e)

@router.post("/attack/stop")
async def stop_attack_simulation():
    """Manually terminate any active attack simulation."""
    try:
        simulator.stop_all()
        metrics = pm.get_system_metrics()
        return standardize_response({
            "trust_score": 100.0,
            "risk_level": "SAFE",
            "decision": "ALLOW",
            "cpu": float(metrics.get("cpu_percent", 0.0)),
            "memory": float(metrics.get("memory_percent", 0.0)),
            "process_count": int(len(pm.get_running_processes())),
            "status": "Simulation Stopped"
        })
    except Exception as e:
        return get_safe_response("/simulate/stop", e)

# Legacy endpoints - also standardized
@router.get("/simulate_attack")
async def legacy_simulate_attack():
    return standardize_response({"status": "Legacy Attack Requested", "trust_score": 40.0})

@router.get("/simulate_normal")
async def legacy_simulate_normal():
    return standardize_response({"status": "Legacy Normal Requested", "trust_score": 95.0})

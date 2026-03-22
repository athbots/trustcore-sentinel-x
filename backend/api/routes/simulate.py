"""
TrustCore Sentinel X — Attack Simulation Route
GET /simulate_attack  — returns a randomly generated attack event
GET /simulate_normal  — returns a benign event for baseline comparison
"""
from fastapi import APIRouter, Depends
from services.attack_simulator import generate_attack_event, generate_normal_event
from infra.security import verify_api_key, rate_limit

router = APIRouter()


@router.get("/simulate_attack", dependencies=[Depends(verify_api_key), Depends(rate_limit)])
async def simulate_attack():
    """Generate a realistic simulated cyber attack event payload."""
    return generate_attack_event()


@router.get("/simulate_normal", dependencies=[Depends(verify_api_key), Depends(rate_limit)])
async def simulate_normal():
    """Generate a benign baseline event for comparison."""
    return generate_normal_event()

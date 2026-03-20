"""
TrustCore Sentinel X — Attack Simulation Route
GET /simulate_attack  — returns a randomly generated attack event
GET /simulate_normal  — returns a benign event for baseline comparison
"""
from fastapi import APIRouter
from services.attack_simulator import generate_attack_event, generate_normal_event

router = APIRouter()


@router.get("/simulate_attack")
async def simulate_attack():
    """Generate a realistic simulated cyber attack event payload."""
    return generate_attack_event()


@router.get("/simulate_normal")
async def simulate_normal():
    """Generate a benign baseline event for comparison."""
    return generate_normal_event()

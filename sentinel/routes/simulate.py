"""
TrustCore Sentinel X — Attack Simulation Route (Production)

Generates realistic simulated attack events for demo and testing.
"""
import random
from fastapi import APIRouter

router = APIRouter()

_ATTACK_SCENARIOS = [
    {
        "text": "Verify your PayPal account immediately or it will be suspended",
        "features": [45000, 500, 0.92, 0.3, 1],
        "source_ip": "203.0.113.45",
        "target": "finance-gateway",
        "event_type": "PHISHING",
    },
    {
        "text": "",
        "features": [95000, 2000, 0.15, 0.1, 1],
        "source_ip": "198.51.100.77",
        "target": "web-server-01",
        "event_type": "DDOS",
    },
    {
        "text": "Your Apple ID has been locked. Click to unlock now",
        "features": [1200, 5, 0.85, 120, 0],
        "source_ip": "192.0.2.200",
        "target": "mail-server",
        "event_type": "PHISHING",
    },
    {
        "text": "",
        "features": [500, 300, 0.45, 0.2, 1],
        "source_ip": "10.0.0.55",
        "target": "admin-panel",
        "event_type": "PORT_SCAN",
    },
    {
        "text": "Wire transfer request: Please approve $25,000 to vendor account",
        "features": [8000, 15, 0.95, 3, 1],
        "source_ip": "203.0.113.100",
        "target": "finance-gateway",
        "event_type": "DATA_EXFIL",
        "repeat_offender": True,
    },
    {
        "text": "",
        "features": [75000, 1500, 0.1, 600, 1],
        "source_ip": "198.51.100.33",
        "target": "database-primary",
        "event_type": "RANSOMWARE",
    },
]


@router.get("/simulate_attack", summary="Generate a random attack event")
async def simulate_attack() -> dict:
    """Return a randomly selected attack scenario for testing."""
    return random.choice(_ATTACK_SCENARIOS)

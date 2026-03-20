"""
TrustCore Sentinel X — Attack Simulator

Generates realistic simulated cyber attack events for demo and testing.
All events are 100% synthetic — no real network traffic is used.
"""
import random
import time
from datetime import datetime, timezone

# ── Attack templates ──────────────────────────────────────────────────────────

_PHISHING_TEXTS = [
    "URGENT: Your Microsoft 365 account will be suspended. Verify credentials now.",
    "Click to confirm your PayPal payment of $499.99 or dispute within 24 hours",
    "Your Apple ID has been locked due to suspicious activity. Unlock now.",
    "Congratulations! You have been selected for a free gift card. Claim today.",
    "IT Alert: Your VPN password expires today. Reset immediately to maintain access.",
    "Wire transfer required: Please approve $18,500 to supplier account urgently.",
    "DHL Notice: Your parcel is on hold. Pay customs fee to release shipment.",
    "Security alert: Unauthorized login from Russia. Verify your identity now.",
    "HR Update: Your salary adjustment requires immediate confirmation. Click here.",
    "Zoom invitation: Your account will be closed. Reactivate with one click.",
]

_EVENT_TYPES = [
    "PHISHING",
    "PORT_SCAN",
    "DDOS",
    "LATERAL_MOVEMENT",
    "DATA_EXFIL",
    "RANSOMWARE",
    "BRUTE_FORCE",
    "SQL_INJECTION",
    "PRIVILEGE_ESCALATION",
    "ZERO_DAY_EXPLOIT",
]

_SOURCE_IPS = [
    "203.0.113.45",   # suspicious range
    "198.51.100.12",  # suspicious range
    "192.0.2.88",     # suspicious range
    "10.0.0.254",     # internal suspicious
    "172.16.99.1",    # internal lateral movement
    "45.33.32.156",   # known scanner IP (nmap.org, public)
    "91.108.4.200",   # Eastern Europe range
    "185.220.101.5",  # Tor exit node range
]

_TARGETS = [
    "admin-portal.internal",
    "database-server-01",
    "finance-gateway",
    "vpn-concentrator",
    "root-ca-server",
    "email-gateway",
    "firewall-mgmt",
    "user-workstation-042",
    "api-server-prod",
    "backup-storage",
]


def _anomaly_features_for(event_type: str) -> list:
    """Generate realistic anomaly feature vectors per attack type."""
    rng = random.Random()
    if event_type == "DDOS":
        return [
            round(rng.uniform(80000, 200000), 1),   # bytes/s — massive
            round(rng.uniform(500, 2000), 1),         # request_rate — huge
            round(rng.uniform(0.3, 0.5), 3),          # entropy — low (repetitive)
            round(rng.uniform(0.1, 2), 2),            # session_duration — very short
            1,                                         # port_risk_score
        ]
    elif event_type == "PORT_SCAN":
        return [
            round(rng.uniform(50, 200), 1),           # bytes/s — tiny packets
            round(rng.uniform(200, 800), 1),           # request_rate — rapid
            round(rng.uniform(0.1, 0.3), 3),           # entropy — very low
            round(rng.uniform(0.01, 0.5), 3),          # duration — instant probes
            1,
        ]
    elif event_type in ("DATA_EXFIL", "RANSOMWARE"):
        return [
            round(rng.uniform(30000, 90000), 1),       # bytes/s — large outbound
            round(rng.uniform(1, 5), 1),               # request_rate — low (stealth)
            round(rng.uniform(0.88, 0.99), 3),         # entropy — encrypted/compressed
            round(rng.uniform(300, 3600), 1),          # duration — long session
            rng.choice([0, 1]),
        ]
    elif event_type == "BRUTE_FORCE":
        return [
            round(rng.uniform(500, 3000), 1),
            round(rng.uniform(50, 300), 1),            # rapid repeated auth attempts
            round(rng.uniform(0.4, 0.6), 3),
            round(rng.uniform(1, 30), 2),
            1,
        ]
    else:  # lateral movement, privilege escalation, etc.
        return [
            round(rng.uniform(1000, 15000), 1),
            round(rng.uniform(5, 40), 1),
            round(rng.uniform(0.65, 0.85), 3),
            round(rng.uniform(10, 120), 1),
            rng.choice([0, 1]),
        ]


def generate_attack_event() -> dict:
    """
    Generate a single realistic simulated cyber attack event.

    Returns a dict ready to POST to /analyze.
    """
    event_type = random.choice(_EVENT_TYPES)
    is_phishing_type = event_type == "PHISHING"

    return {
        "event_type": event_type,
        "text": random.choice(_PHISHING_TEXTS) if is_phishing_type else f"[{event_type}] Anomalous network activity detected from source",
        "features": _anomaly_features_for(event_type),
        "source_ip": random.choice(_SOURCE_IPS),
        "target": random.choice(_TARGETS),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "repeat_offender": random.random() < 0.3,
        "severity_hint": random.choice(["low", "medium", "high", "critical"]),
    }


def generate_normal_event() -> dict:
    """Generate a benign baseline event for comparison."""
    rng = random.Random()
    return {
        "event_type": "NORMAL",
        "text": random.choice([
            "User logged in successfully from known IP",
            "Routine DNS lookup from workstation",
            "Scheduled backup completed successfully",
            "Software update downloaded and applied",
        ]),
        "features": [
            round(rng.uniform(100, 4000), 1),
            round(rng.uniform(1, 15), 1),
            round(rng.uniform(0.3, 0.65), 3),
            round(rng.uniform(10, 250), 1),
            0,
        ],
        "source_ip": f"192.168.1.{rng.randint(2, 200)}",
        "target": "user-workstation",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "repeat_offender": False,
        "severity_hint": "low",
    }

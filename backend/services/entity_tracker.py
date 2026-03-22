"""
TrustCore Sentinel X — Adaptive Entity Intelligence
=====================================================
Maintains per-entity (IP / user / session) risk profiles that evolve
over time. Repeat offenders receive escalating risk multipliers,
creating a memory-driven adaptive defense posture.
"""

import time
from collections import defaultdict
from typing import Any


# ── Entity Profile Store ──────────────────────────────────────────────────────
# { entity_key: { "events": [...], "total_risk": int, "flags": int, ... } }

_entity_store: dict[str, dict[str, Any]] = defaultdict(lambda: {
    "events": [],
    "total_risk_accumulated": 0,
    "high_risk_count": 0,
    "first_seen": None,
    "last_seen": None,
})

_MAX_EVENTS_PER_ENTITY = 50
_DECAY_SECONDS = 3600  # 1 hour — risk decays after inactivity


def _entity_key(event: dict[str, Any]) -> str:
    """Derive a unique entity key from event metadata."""
    ip = event.get("source_ip") or "unknown"
    return ip  # Can be extended to include user / session


def _compute_multiplier(profile: dict[str, Any]) -> float:
    """
    Calculate risk multiplier based on entity history.
    - First offense: 1.0x
    - 2 high-risk events: 1.15x
    - 3+: 1.3x
    - 5+: 1.5x (repeat offender ceiling)
    """
    high = profile["high_risk_count"]
    if high >= 5:
        return 1.5
    elif high >= 3:
        return 1.3
    elif high >= 2:
        return 1.15
    return 1.0


def _compute_reputation(profile: dict[str, Any]) -> str:
    """Assign a reputation label based on accumulated behavior."""
    high = profile["high_risk_count"]
    total = len(profile["events"])
    if total == 0:
        return "UNKNOWN"
    ratio = high / max(total, 1)
    if high >= 5 or ratio > 0.6:
        return "MALICIOUS"
    elif high >= 2 or ratio > 0.3:
        return "SUSPICIOUS"
    elif total >= 3 and ratio < 0.1:
        return "TRUSTED"
    return "NEUTRAL"


def track_entity(
    event: dict[str, Any],
    risk_score: int,
    threat_level: str,
) -> dict[str, Any]:
    """
    Update entity profile and return adaptive intelligence.

    Returns:
        entity_id:          The entity key (IP address).
        risk_multiplier:    Adaptive multiplier (1.0–1.5x).
        reputation:         UNKNOWN | NEUTRAL | TRUSTED | SUSPICIOUS | MALICIOUS.
        is_repeat_offender: True if entity has 2+ high-risk events.
        total_events:       Total events recorded for this entity.
        high_risk_events:   Count of events that scored HIGH or CRITICAL.
        first_seen:         ISO timestamp of first observed event.
        last_seen:          ISO timestamp of latest event.
    """
    key = _entity_key(event)
    profile = _entity_store[key]
    now = time.time()

    # Update profile
    if profile["first_seen"] is None:
        profile["first_seen"] = now
    profile["last_seen"] = now
    profile["total_risk_accumulated"] += risk_score

    is_high = threat_level in ("HIGH", "CRITICAL")
    if is_high:
        profile["high_risk_count"] += 1

    profile["events"].append({
        "timestamp": now,
        "risk_score": risk_score,
        "threat_level": threat_level,
        "event_type": event.get("event_type", "UNKNOWN"),
    })

    # Cap event history
    if len(profile["events"]) > _MAX_EVENTS_PER_ENTITY:
        profile["events"] = profile["events"][-_MAX_EVENTS_PER_ENTITY:]

    multiplier = _compute_multiplier(profile)
    reputation = _compute_reputation(profile)

    return {
        "entity_id": key,
        "risk_multiplier": multiplier,
        "reputation": reputation,
        "is_repeat_offender": profile["high_risk_count"] >= 2,
        "total_events": len(profile["events"]),
        "high_risk_events": profile["high_risk_count"],
        "avg_risk": round(profile["total_risk_accumulated"] / max(len(profile["events"]), 1), 1),
        "first_seen_ago_seconds": round(now - profile["first_seen"], 1),
    }

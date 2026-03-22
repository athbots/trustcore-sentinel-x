"""
TrustCore Sentinel X — Autonomous Response Engine

Determines and logs the automated defensive action based on risk score.
All actions are SIMULATED — no real network changes are made.
"""
import time
from datetime import datetime, timezone
from infra.logger import get_logger

logger = get_logger("response_engine")

# Action history (in-memory, resets on restart)
_action_log: list[dict] = []

_ACTION_ICONS = {
    "LOG":      "📋",
    "ALERT":    "🔔",
    "BLOCK":    "🚫",
    "ISOLATE":  "☢️",
}


def execute_response(
    threat_level: str,
    risk_score: int,
    action: str,
    description: str,
    event: dict | None = None,
) -> dict:
    """
    Execute (simulate) an automated security response.

    Args:
        threat_level: SAFE | LOW | MEDIUM | HIGH | CRITICAL
        risk_score:   0–100
        action:       LOG | ALERT | BLOCK | ISOLATE
        description:  Human-readable action description
        event:        Original event context

    Returns:
        response record with timestamp, action taken, and simulated outcome.
    """
    source_ip = (event or {}).get("source_ip", "UNKNOWN")
    target = (event or {}).get("target", "UNKNOWN")
    event_type = (event or {}).get("event_type", "UNKNOWN")

    icon = _ACTION_ICONS.get(action, "⚡")
    timestamp = datetime.now(timezone.utc).isoformat()

    # Simulate action-specific outcomes
    outcome = _simulate_action(action, source_ip, target, risk_score)

    record = {
        "timestamp": timestamp,
        "action": action,
        "threat_level": threat_level,
        "risk_score": risk_score,
        "event_type": event_type,
        "source_ip": source_ip,
        "target": target,
        "description": description,
        "outcome": outcome,
        "icon": icon,
    }

    _action_log.append(record)
    if len(_action_log) > 200:  # keep last 200 actions
        _action_log.pop(0)

    logger.info(
        f"{icon} ACTION={action} | THREAT={threat_level} | RISK={risk_score}/100 | "
        f"SRC={source_ip} | TGT={target} | {outcome}"
    )

    return record


def _simulate_action(action: str, source_ip: str, target: str, risk_score: int) -> str:
    """Return a realistic simulated outcome string for each action type."""
    if action == "LOG":
        return f"Event recorded in SIEM. Risk {risk_score}/100 — monitoring continues."
    elif action == "ALERT":
        return f"Alert dispatched to SOC dashboard. Analyst assigned. Source {source_ip} flagged."
    elif action == "BLOCK":
        return (
            f"[SIMULATED] iptables DROP rule applied for {source_ip}. "
            f"Session terminated. Firewall updated. Threat contained."
        )
    elif action == "ISOLATE":
        return (
            f"[SIMULATED] Host {target} quarantined — VLAN isolation enacted. "
            f"All traffic from {source_ip} null-routed. Incident ticket #INC-{int(time.time()) % 100000} created."
        )
    return "Action executed."


def get_recent_actions(limit: int = 20) -> list[dict]:
    """Return last N response actions."""
    return list(reversed(_action_log[-limit:]))


def get_action_stats() -> dict:
    """Aggregate stats over all recorded actions."""
    counts = {"LOG": 0, "ALERT": 0, "BLOCK": 0, "ISOLATE": 0}
    for r in _action_log:
        counts[r["action"]] = counts.get(r["action"], 0) + 1

    threat_counts = {}
    for r in _action_log:
        threat_counts[r["threat_level"]] = threat_counts.get(r["threat_level"], 0) + 1

    return {
        "total_actions": len(_action_log),
        "by_action": counts,
        "by_threat_level": threat_counts,
    }

"""
TrustCore Sentinel X — Attack Chain Tracker
============================================
Correlates sequential events from the same source to detect multi-stage
attack progressions (e.g. Recon → Exploit → Exfil).

Maintains an in-memory sliding window per source IP and matches events
against known kill-chain patterns inspired by the MITRE ATT&CK framework.
"""

import time
from collections import defaultdict
from typing import Any


# ── Kill-Chain Stage Definitions ──────────────────────────────────────────────
# Each stage maps an event_type (or detected signal) to a kill-chain phase.

STAGE_MAP: dict[str, str] = {
    # Reconnaissance
    "RECON":              "1_RECON",
    "PORT_SCAN":          "1_RECON",
    "NETWORK_FLOW":       "1_RECON",
    # Initial Access
    "PHISHING":           "2_INITIAL_ACCESS",
    "EMAIL_RECEIVED":     "2_INITIAL_ACCESS",
    "SPEAR_PHISHING":     "2_INITIAL_ACCESS",
    # Credential Abuse
    "BRUTE_FORCE":        "3_CREDENTIAL_ABUSE",
    "CREDENTIAL_STUFFING":"3_CREDENTIAL_ABUSE",
    "LOGIN_ANOMALY":      "3_CREDENTIAL_ABUSE",
    # Lateral Movement
    "LATERAL_MOVEMENT":   "4_LATERAL_MOVEMENT",
    "PRIVILEGE_ESCALATION":"4_LATERAL_MOVEMENT",
    # Command & Control
    "C2_BEACON":          "5_COMMAND_CONTROL",
    "C2":                 "5_COMMAND_CONTROL",
    # Exfiltration
    "DATA_EXFIL":         "6_EXFILTRATION",
    "EXFILTRATION":       "6_EXFILTRATION",
    "RANSOMWARE":         "6_EXFILTRATION",
}

# Known multi-stage chains and their descriptions
KNOWN_CHAINS = [
    {
        "name": "Credential Compromise Chain",
        "stages": ["2_INITIAL_ACCESS", "3_CREDENTIAL_ABUSE"],
        "description": "Phishing email led to credential abuse attempt.",
    },
    {
        "name": "Full Kill Chain",
        "stages": ["1_RECON", "2_INITIAL_ACCESS", "3_CREDENTIAL_ABUSE", "6_EXFILTRATION"],
        "description": "Complete attack lifecycle: reconnaissance through data exfiltration.",
    },
    {
        "name": "Lateral Breach",
        "stages": ["3_CREDENTIAL_ABUSE", "4_LATERAL_MOVEMENT"],
        "description": "Compromised credentials used for lateral movement across network segments.",
    },
    {
        "name": "Recon-to-Exploit",
        "stages": ["1_RECON", "2_INITIAL_ACCESS"],
        "description": "Reconnaissance activity followed by initial exploitation attempt.",
    },
    {
        "name": "C2 Exfiltration",
        "stages": ["5_COMMAND_CONTROL", "6_EXFILTRATION"],
        "description": "Command-and-control communication followed by data exfiltration.",
    },
]

# Per-IP event history: { ip: [ (timestamp, stage, event_type, risk_score) ] }
_event_history: dict[str, list[tuple[float, str, str, int]]] = defaultdict(list)

# Sliding window: only correlate events within this many seconds
_WINDOW_SECONDS = 600  # 10 minutes


def _classify_event(event: dict[str, Any], risk_score: int) -> str | None:
    """Map an event to a kill-chain stage. Returns None if unmappable."""
    event_type = (event.get("event_type") or "").upper()
    if event_type in STAGE_MAP:
        return STAGE_MAP[event_type]

    # Infer from risk indicators
    if risk_score >= 70 and event.get("text"):
        return "2_INITIAL_ACCESS"
    return None


def _prune_old_events(ip: str) -> None:
    """Remove events outside the sliding window."""
    cutoff = time.time() - _WINDOW_SECONDS
    _event_history[ip] = [e for e in _event_history[ip] if e[0] >= cutoff]


def _match_chains(stages: list[str]) -> list[dict[str, Any]]:
    """Check observed stages against known kill-chain patterns."""
    matched = []
    stage_set = set(stages)
    for chain in KNOWN_CHAINS:
        if all(s in stage_set for s in chain["stages"]):
            coverage = len(chain["stages"]) / 6.0  # 6 possible stages
            matched.append({
                "chain_name": chain["name"],
                "description": chain["description"],
                "matched_stages": chain["stages"],
                "confidence": round(min(0.5 + coverage, 0.95), 2),
            })
    # Sort by most stages matched (most complete chain first)
    matched.sort(key=lambda c: len(c["matched_stages"]), reverse=True)
    return matched


def track_event(
    event: dict[str, Any],
    risk_score: int,
) -> dict[str, Any]:
    """
    Record an event and check for multi-stage attack correlation.

    Returns:
        chain_detected (bool):  Whether a known chain was matched.
        matched_chains (list):  Chains that matched, with confidence.
        attack_timeline (list): Ordered timeline of stages for this source.
        stages_observed (int):  Number of distinct kill-chain stages seen.
    """
    source_ip = event.get("source_ip") or "unknown"
    _prune_old_events(source_ip)

    stage = _classify_event(event, risk_score)
    event_type = (event.get("event_type") or "UNKNOWN").upper()

    if stage:
        _event_history[source_ip].append((time.time(), stage, event_type, risk_score))

    # Build timeline
    history = _event_history[source_ip]
    observed_stages = list(dict.fromkeys(e[1] for e in history))  # preserve order, dedupe

    timeline = [
        {
            "stage": e[1],
            "event_type": e[2],
            "risk_score": e[3],
            "seconds_ago": round(time.time() - e[0], 1),
        }
        for e in history
    ]

    matched = _match_chains(observed_stages)

    return {
        "chain_detected": len(matched) > 0,
        "matched_chains": matched[:3],  # top 3
        "attack_timeline": timeline[-10:],  # last 10 events
        "stages_observed": len(observed_stages),
    }

"""
TrustCore Sentinel X — Event Correlation Engine

Detects multi-step attack patterns by correlating events across time:
  - Brute-force → lateral movement → exfiltration chains
  - Port scan → exploit → privilege escalation
  - Phishing → credential theft → internal pivot

Uses a sliding-window per entity to match against known kill-chain patterns.
"""
import time
from sentinel.utils.logger import get_logger

logger = get_logger("intelligence.correlation")

# ── Kill Chain Patterns ──────────────────────────────────────────────────────
# Each pattern is a sequence of event_types that, when seen from the same
# entity within the time window, indicate a multi-step attack.

ATTACK_CHAINS = [
    {
        "name": "Credential Compromise Chain",
        "stages": ["BRUTE_FORCE_DETECTED", "SUSPICIOUS_PROCESS", "DATA_EXFIL"],
        "window_seconds": 600,
        "risk_boost": 30,
        "description": "Brute-force login followed by suspicious process and data exfiltration.",
    },
    {
        "name": "Phishing to Lateral Movement",
        "stages": ["PHISHING", "SUSPICIOUS_PROCESS", "LATERAL_MOVEMENT"],
        "window_seconds": 900,
        "risk_boost": 35,
        "description": "Phishing payload executed, spawned malicious process, then lateral pivot.",
    },
    {
        "name": "Reconnaissance to Exploit",
        "stages": ["PORT_SCAN", "NETWORK_ANOMALY", "PRIVILEGE_ESCALATION"],
        "window_seconds": 300,
        "risk_boost": 25,
        "description": "Port scan followed by network exploit and privilege escalation.",
    },
    {
        "name": "Ransomware Kill Chain",
        "stages": ["PHISHING", "SUSPICIOUS_PROCESS", "HIGH_CPU_PROCESS"],
        "window_seconds": 600,
        "risk_boost": 40,
        "description": "Phishing delivery → payload execution → encryption activity detected.",
    },
    {
        "name": "Insider Threat Pattern",
        "stages": ["BRUTE_FORCE_DETECTED", "PRIVILEGE_ESCALATION", "DATA_EXFIL"],
        "window_seconds": 1800,
        "risk_boost": 30,
        "description": "Repeated login attempts, privilege escalation, then data exfiltration.",
    },
]

# ── Event History per Entity ─────────────────────────────────────────────────
_event_history: dict[str, list[dict]] = {}
_MAX_HISTORY = 100


def record_event(entity_id: str, event_type: str) -> None:
    """Record an event for correlation analysis."""
    if entity_id not in _event_history:
        _event_history[entity_id] = []

    _event_history[entity_id].append({
        "type": event_type.upper(),
        "ts": time.time(),
    })

    # Trim
    if len(_event_history[entity_id]) > _MAX_HISTORY:
        _event_history[entity_id] = _event_history[entity_id][-_MAX_HISTORY:]


def correlate(entity_id: str) -> dict:
    """
    Check if the entity's recent event history matches any attack chain.

    Returns:
        {
            "matched": bool,
            "chain_name": str | None,
            "risk_boost": int,
            "description": str,
            "stages_matched": list[str],
            "confidence": float,   # 0.0 – 1.0
        }
    """
    history = _event_history.get(entity_id, [])
    if not history:
        return _no_match()

    now = time.time()
    best_match = None
    best_confidence = 0.0

    for chain in ATTACK_CHAINS:
        window = chain["window_seconds"]
        recent = [e for e in history if now - e["ts"] <= window]
        types_seen = [e["type"] for e in recent]

        # Check if all stages appear in order
        matched_stages = []
        idx = 0
        for stage in chain["stages"]:
            for i in range(idx, len(types_seen)):
                if types_seen[i] == stage:
                    matched_stages.append(stage)
                    idx = i + 1
                    break

        stages_needed = len(chain["stages"])
        stages_found = len(matched_stages)

        if stages_found >= 2:  # At least 2 stages matched
            confidence = stages_found / stages_needed
            if confidence > best_confidence:
                best_confidence = confidence
                best_match = {
                    "matched": True,
                    "chain_name": chain["name"],
                    "risk_boost": int(chain["risk_boost"] * confidence),
                    "description": chain["description"],
                    "stages_matched": matched_stages,
                    "stages_total": stages_needed,
                    "confidence": round(confidence, 2),
                }

    if best_match:
        logger.warning(
            f"⚡ Attack chain detected: {best_match['chain_name']} "
            f"({best_match['stages_matched']}) confidence={best_match['confidence']}"
        )
        return best_match

    return _no_match()


def _no_match() -> dict:
    return {
        "matched": False,
        "chain_name": None,
        "risk_boost": 0,
        "description": "",
        "stages_matched": [],
        "confidence": 0.0,
    }


def get_entity_timeline(entity_id: str, limit: int = 20) -> list[dict]:
    """Return recent event timeline for an entity."""
    history = _event_history.get(entity_id, [])
    return history[-limit:]

"""
TrustCore Sentinel X — Risk Scoring Engine v2 (Multi-Signal Fusion)

Combines 7 signal sources into a unified risk score with confidence:
  1. Phishing detector
  2. Network anomaly detector
  3. Process anomaly detector
  4. Context analysis
  5. Threat intelligence
  6. Behavior profiling
  7. Entity history (adaptive)
  + Event correlation (risk boost)
"""
from sentinel.config import (
    WEIGHT_PHISHING, WEIGHT_NETWORK, WEIGHT_PROCESS, WEIGHT_CONTEXT,
    RISK_LOW_THRESHOLD, RISK_MEDIUM_THRESHOLD, RISK_HIGH_THRESHOLD,
    RISK_CRITICAL_THRESHOLD, RESPONSE_RULES,
)
from sentinel.utils.logger import get_logger

logger = get_logger("core.risk_scorer")


def _context_score(event: dict) -> float:
    """Derive a 0.0–1.0 context risk score from event metadata."""
    score = 0.0
    source_ip = event.get("source_ip") or ""
    suspicious_prefixes = ("10.0.0.", "192.0.2.", "203.0.113.", "198.51.100.")
    if any(source_ip.startswith(p) for p in suspicious_prefixes):
        score += 0.3

    target = (event.get("target") or "").lower()
    if any(k in target for k in ("admin", "root", "finance", "database", "vpn", "firewall")):
        score += 0.3

    if event.get("repeat_offender", False):
        score += 0.25

    event_type = (event.get("event_type") or "").upper()
    high_risk_types = {
        "RANSOMWARE", "LATERAL_MOVEMENT", "DATA_EXFIL",
        "PRIVILEGE_ESCALATION", "BRUTE_FORCE_DETECTED",
        "SUSPICIOUS_PROCESS", "HIGH_CPU_PROCESS",
    }
    if event_type in high_risk_types:
        score += 0.25

    return min(score, 1.0)


def _compute_confidence(scores: dict, correlation_matched: bool) -> float:
    """
    Compute 0.0–1.0 confidence based on signal agreement.
    High confidence = multiple independent signals agree.
    """
    active_signals = sum(1 for v in scores.values() if v > 0.1)
    total_signals = len(scores)

    # More agreeing signals → higher confidence
    agreement = active_signals / max(total_signals, 1)

    # Correlation match boosts confidence
    if correlation_matched:
        agreement = min(agreement + 0.2, 1.0)

    # Clamp
    return round(max(0.3, min(agreement, 0.99)), 2)


def compute_risk(
    phishing_score: float = 0.0,
    network_anomaly_score: float = 0.0,
    process_anomaly_score: float = 0.0,
    event: dict | None = None,
    # New v2 signals (injected by pipeline)
    threat_intel_score: float = 0.0,
    behavior_score: float = 0.0,
    entity_multiplier: float = 1.0,
    correlation_boost: int = 0,
    correlation_info: dict | None = None,
    behavior_signals: list | None = None,
    threat_indicators: list | None = None,
) -> dict:
    """
    Compute unified risk score with multi-signal fusion.

    Returns dict with:
        risk_score (0–100), confidence, threat_level, component_scores,
        correlation, response, reason
    """
    event = event or {}
    ctx = _context_score(event)

    # Build signal dict for confidence calculation
    signals = {
        "phishing": phishing_score,
        "network": network_anomaly_score,
        "process": process_anomaly_score,
        "context": ctx,
        "threat_intel": threat_intel_score,
        "behavior": behavior_score,
    }

    # Weighted fusion (original 4 signals: 80% weight, new signals: 20%)
    base_weighted = (
        WEIGHT_PHISHING * phishing_score
        + WEIGHT_NETWORK * network_anomaly_score
        + WEIGHT_PROCESS * process_anomaly_score
        + WEIGHT_CONTEXT * ctx
    )

    # Intelligence signals (add 10% each)
    intel_weighted = (
        0.10 * threat_intel_score
        + 0.10 * behavior_score
    )

    raw_score = (base_weighted + intel_weighted) * 100

    # Apply entity multiplier (repeat offenders get escalated)
    raw_score *= entity_multiplier

    # Apply correlation boost (multi-step attack detected)
    raw_score += correlation_boost

    risk_score = min(round(raw_score), 100)

    # Confidence
    correlation_matched = bool(correlation_info and correlation_info.get("matched"))
    confidence = _compute_confidence(signals, correlation_matched)

    # Threat level
    if risk_score >= RISK_CRITICAL_THRESHOLD:
        threat_level = "CRITICAL"
    elif risk_score >= RISK_HIGH_THRESHOLD:
        threat_level = "HIGH"
    elif risk_score >= RISK_MEDIUM_THRESHOLD:
        threat_level = "MEDIUM"
    elif risk_score >= RISK_LOW_THRESHOLD:
        threat_level = "LOW"
    else:
        threat_level = "SAFE"

    response_key = threat_level if threat_level in RESPONSE_RULES else "SAFE"

    # Build reason string
    reason = _build_reason(
        threat_level, signals, correlation_info,
        behavior_signals or [], threat_indicators or [],
    )

    return {
        "risk_score": risk_score,
        "confidence": confidence,
        "threat_level": threat_level,
        "reason": reason,
        "component_scores": {
            "phishing": round(phishing_score * 100, 1),
            "network_anomaly": round(network_anomaly_score * 100, 1),
            "process_anomaly": round(process_anomaly_score * 100, 1),
            "context": round(ctx * 100, 1),
            "threat_intel": round(threat_intel_score * 100, 1),
            "behavior": round(behavior_score * 100, 1),
        },
        "entity_multiplier": entity_multiplier,
        "correlation": correlation_info or {"matched": False},
        "response": RESPONSE_RULES[response_key],
    }


def _build_reason(
    threat_level: str, signals: dict,
    correlation: dict | None,
    behavior_signals: list, threat_indicators: list,
) -> str:
    """Build a concise human-readable reason string."""
    if threat_level == "SAFE":
        return "No significant threat indicators detected."

    parts = []
    top = sorted(signals.items(), key=lambda x: x[1], reverse=True)
    for name, val in top[:3]:
        if val >= 0.3:
            parts.append(f"{name} signal elevated ({val:.0%})")

    if correlation and correlation.get("matched"):
        parts.append(f"Attack chain: {correlation['chain_name']}")

    if behavior_signals:
        parts.append(behavior_signals[0])

    if threat_indicators:
        parts.append(threat_indicators[0])

    return ". ".join(parts) + "." if parts else f"Threat level: {threat_level}."

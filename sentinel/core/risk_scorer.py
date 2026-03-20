"""
TrustCore Sentinel X — Risk Scoring Engine (Production)

Combines phishing, network anomaly, process anomaly, and contextual signals
into a unified 0–100 risk score with threat level classification.
"""
from sentinel.config import (
    WEIGHT_PHISHING, WEIGHT_NETWORK, WEIGHT_PROCESS, WEIGHT_CONTEXT,
    RISK_LOW_THRESHOLD, RISK_MEDIUM_THRESHOLD, RISK_HIGH_THRESHOLD,
    RISK_CRITICAL_THRESHOLD, RESPONSE_RULES,
)
from sentinel.utils.logger import get_logger

logger = get_logger("core.risk_scorer")


def _context_score(event: dict) -> float:
    """
    Derive a 0.0–1.0 context risk score from event metadata.
    Considers: source reputation, target sensitivity, repeat offender, event type.
    """
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


def compute_risk(
    phishing_score: float = 0.0,
    network_anomaly_score: float = 0.0,
    process_anomaly_score: float = 0.0,
    event: dict | None = None,
) -> dict:
    """
    Compute the unified risk score.

    Args:
        phishing_score: 0.0–1.0 from phishing detector
        network_anomaly_score: 0.0–1.0 from network anomaly detector
        process_anomaly_score: 0.0–1.0 from process anomaly detector
        event: raw event dict for contextual scoring

    Returns dict with:
        risk_score (0–100), threat_level, component_scores, response
    """
    ctx = _context_score(event or {})

    weighted = (
        WEIGHT_PHISHING * phishing_score
        + WEIGHT_NETWORK * network_anomaly_score
        + WEIGHT_PROCESS * process_anomaly_score
        + WEIGHT_CONTEXT * ctx
    )

    risk_score = round(weighted * 100)

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

    return {
        "risk_score": risk_score,
        "threat_level": threat_level,
        "component_scores": {
            "phishing": round(phishing_score * 100, 1),
            "network_anomaly": round(network_anomaly_score * 100, 1),
            "process_anomaly": round(process_anomaly_score * 100, 1),
            "context": round(ctx * 100, 1),
        },
        "response": RESPONSE_RULES[response_key],
    }

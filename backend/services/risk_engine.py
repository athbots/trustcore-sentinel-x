"""
TrustCore Sentinel X — Risk Scoring Engine

Combines phishing score + anomaly score + contextual factors into a
single 0–100 risk score with an overall threat level.

Weights (configurable in config.py):
  - Phishing:  40%
  - Anomaly:   40%
  - Context:   20%
"""
from config import (
    WEIGHT_PHISHING, WEIGHT_ANOMALY, WEIGHT_CONTEXT,
    RISK_LOW_THRESHOLD, RISK_MEDIUM_THRESHOLD, RISK_CRITICAL_THRESHOLD,
    RESPONSE_RULES,
)


def _context_score(event: dict) -> float:
    """
    Derive a 0.0–1.0 context risk score from event metadata.
    Considers: source reputation, target sensitivity, time-of-day, repeat offender flag.
    """
    score = 0.0

    # Known-bad source IP ranges (RFC 5737 TEST-NET used as stand-ins)
    source_ip = event.get("source_ip", "")
    suspicious_prefixes = ("10.0.0.", "192.0.2.", "203.0.113.", "198.51.100.")
    if any(source_ip.startswith(p) for p in suspicious_prefixes):
        score += 0.3

    # Targeting high-value assets
    target = event.get("target", "").lower()
    if any(k in target for k in ("admin", "root", "finance", "database", "vpn", "firewall")):
        score += 0.3

    # Repeat offender flag
    if event.get("repeat_offender", False):
        score += 0.25

    # High-risk event type
    event_type = event.get("event_type", "").upper()
    high_risk_types = {"RANSOMWARE", "LATERAL_MOVEMENT", "DATA_EXFIL", "PRIVILEGE_ESCALATION"}
    if event_type in high_risk_types:
        score += 0.25

    return min(score, 1.0)


def compute_risk(
    phishing_score: float,
    anomaly_score: float,
    event: dict | None = None,
) -> dict:
    """
    Compute the unified risk score.

    Args:
        phishing_score: 0.0–1.0 from phishing service
        anomaly_score:  0.0–1.0 from anomaly service
        event:          Raw event dict for contextual scoring (optional)

    Returns:
        risk_score (int):      0–100
        threat_level (str):    SAFE | LOW | MEDIUM | HIGH | CRITICAL
        component_scores (dict): breakdown of each component
        response (dict):        recommended automated action
    """
    ctx = _context_score(event or {})

    # Weighted combination → 0.0–1.0
    weighted = (
        WEIGHT_PHISHING * phishing_score +
        WEIGHT_ANOMALY  * anomaly_score +
        WEIGHT_CONTEXT  * ctx
    )

    # Scale to 0–100
    risk_score = round(weighted * 100)

    # Threat level
    if risk_score >= RISK_CRITICAL_THRESHOLD:
        threat_level = "CRITICAL"
        response_key = "CRITICAL"
    elif risk_score >= RISK_MEDIUM_THRESHOLD:
        threat_level = "HIGH"
        response_key = "HIGH"
    elif risk_score >= RISK_LOW_THRESHOLD:
        threat_level = "MEDIUM"
        response_key = "MEDIUM"
    else:
        threat_level = "LOW" if risk_score > 10 else "SAFE"
        response_key = "LOW"

    return {
        "risk_score": risk_score,
        "threat_level": threat_level,
        "component_scores": {
            "phishing": round(phishing_score * 100, 1),
            "anomaly":  round(anomaly_score * 100, 1),
            "context":  round(ctx * 100, 1),
        },
        "response": RESPONSE_RULES[response_key],
    }

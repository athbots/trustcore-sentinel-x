"""
TrustCore Sentinel X — Explanation Engine

Generates human-readable narratives from detection results.
Turns raw scores and signal lists into clear, actionable text
that non-technical users can understand.
"""
from sentinel.utils.logger import get_logger

logger = get_logger("core.explainer")

_LEVEL_ICONS = {
    "SAFE": "🟢",
    "LOW": "🔵",
    "MEDIUM": "🟡",
    "HIGH": "🟠",
    "CRITICAL": "🔴",
}

_ACTION_VERBS = {
    "LOG": "logged for review",
    "ALERT": "triggered a security alert",
    "BLOCK": "blocked at the firewall",
    "ISOLATE": "quarantined from the network",
}


def explain(
    risk_result: dict,
    phishing_result: dict | None = None,
    network_result: dict | None = None,
    process_result: dict | None = None,
    event: dict | None = None,
) -> dict:
    """
    Generate a human-readable explanation of a threat assessment.

    Returns dict with:
        summary (str): one-line headline
        narrative (str): detailed multi-sentence explanation
        recommendation (str): what the user should do
        severity_icon (str): emoji indicator
    """
    risk_score = risk_result.get("risk_score", 0)
    threat_level = risk_result.get("threat_level", "SAFE")
    action = risk_result.get("response", {}).get("action", "LOG")
    icon = _LEVEL_ICONS.get(threat_level, "⚪")
    components = risk_result.get("component_scores", {})

    event = event or {}
    source_ip = event.get("source_ip", "unknown source")
    event_type = event.get("event_type", "event")

    # ── Summary line ─────────────────────────────────────────────────────────
    summary = f"{icon} {threat_level} RISK (score {risk_score}/100)"

    # ── Narrative ────────────────────────────────────────────────────────────
    parts = []

    # What happened
    parts.append(f"A {event_type.lower().replace('_', ' ')} was detected from {source_ip}.")

    # Phishing detail
    if phishing_result and phishing_result.get("score", 0) > 0.3:
        verdict = phishing_result["verdict"]
        signals = phishing_result.get("signals", [])
        parts.append(
            f"Phishing analysis: {verdict} "
            f"(score {components.get('phishing', 0):.0f}/100). "
            + (f"Triggered patterns: {', '.join(s[:25] for s in signals[:2])}." if signals else "")
        )

    # Network anomaly detail
    if network_result and network_result.get("score", 0) > 0.3:
        verdict = network_result["verdict"]
        features = network_result.get("anomalous_features", [])
        parts.append(
            f"Network anomaly: {verdict} "
            f"(score {components.get('network_anomaly', 0):.0f}/100). "
            + (f"Anomalous features: {', '.join(features[:3])}." if features else "")
        )

    # Process anomaly detail
    if process_result and process_result.get("score", 0) > 0.2:
        proc_signals = process_result.get("signals", [])
        parts.append(
            f"Process anomaly detected: "
            + ". ".join(proc_signals[:2]) + "."
        )

    # Action taken
    action_verb = _ACTION_VERBS.get(action, "processed")
    parts.append(f"Response: event has been {action_verb}.")

    narrative = " ".join(parts)

    # ── Recommendation ───────────────────────────────────────────────────────
    if threat_level in ("CRITICAL", "HIGH"):
        recommendation = (
            "Immediate investigation recommended. Review the flagged process/connection "
            "and consider terminating the suspicious activity manually if automated "
            "blocking has not resolved it."
        )
    elif threat_level == "MEDIUM":
        recommendation = (
            "Monitor this activity closely. If it repeats, consider blocking the "
            "source IP or investigating the associated process."
        )
    elif threat_level == "LOW":
        recommendation = (
            "No immediate action required. This event has been logged for "
            "trend analysis."
        )
    else:
        recommendation = "No action needed. System is operating normally."

    return {
        "summary": summary,
        "narrative": narrative,
        "recommendation": recommendation,
        "severity_icon": icon,
    }

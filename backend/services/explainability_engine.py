"""
TrustCore Sentinel X — Explainability Engine
=============================================
Generates ranked, feature-level explanations for every detection decision.
Provides transparency into WHY the AI flagged (or cleared) a given event.
"""

from typing import Any


def generate_explanation(
    phishing_result: dict[str, Any],
    anomaly_result: dict[str, Any],
    risk_result: dict[str, Any],
    event: dict[str, Any],
) -> dict[str, Any]:
    """
    Build a structured explanation object that ranks every contributing
    factor and provides a human-readable narrative for the decision.

    Returns:
        summary:        One-line natural-language verdict.
        narrative:      Multi-sentence explanation of the decision chain.
        recommendation: Suggested analyst action.
        factors:        Ranked list of contributing features with weights.
    """
    risk_score = risk_result.get("risk_score", 0)
    threat_level = risk_result.get("threat_level", "SAFE")
    comp = risk_result.get("component_scores", {})

    # ── Build ranked factor list ──────────────────────────────────────────
    factors = []

    # Phishing contribution
    phish_score = comp.get("phishing", 0)
    phish_verdict = phishing_result.get("verdict", "LEGITIMATE")
    factors.append({
        "feature": "Phishing NLP (TF-IDF + Logistic Regression)",
        "contribution": round(phish_score, 1),
        "weight": "40%",
        "detail": f"Verdict: {phish_verdict} — ML probability combined with heuristic pattern matching.",
    })

    # Anomaly contribution
    anom_score = comp.get("anomaly", 0)
    anom_verdict = anomaly_result.get("verdict", "NORMAL")
    anomalous_features = anomaly_result.get("anomalous_features", [])
    anom_detail = f"Verdict: {anom_verdict}"
    if anomalous_features:
        anom_detail += f" — deviating features: {', '.join(anomalous_features)}"
    factors.append({
        "feature": "Network Anomaly (Isolation Forest)",
        "contribution": round(anom_score, 1),
        "weight": "40%",
        "detail": anom_detail,
    })

    # Context contribution
    ctx_score = comp.get("context", 0)
    ctx_reasons = []
    if event.get("source_ip", "").startswith(("10.0.0.", "192.0.2.", "203.0.113.")):
        ctx_reasons.append("suspicious source IP range")
    target = (event.get("target") or "").lower()
    if any(k in target for k in ("admin", "root", "finance", "database", "vpn")):
        ctx_reasons.append(f"high-value target: {event.get('target')}")
    if event.get("repeat_offender"):
        ctx_reasons.append("repeat offender flag active")
    factors.append({
        "feature": "Contextual Risk Signals",
        "contribution": round(ctx_score, 1),
        "weight": "20%",
        "detail": f"Factors: {', '.join(ctx_reasons)}" if ctx_reasons else "No elevated context signals.",
    })

    # Sort by contribution descending
    factors.sort(key=lambda f: f["contribution"], reverse=True)

    # ── Natural-language narrative ────────────────────────────────────────
    top_factor = factors[0]["feature"] if factors else "Unknown"
    summary = f"Risk {risk_score}/100 ({threat_level}) — primary driver: {top_factor}."

    parts = []
    if phish_score > 30:
        parts.append(
            f"The phishing classifier identified strong social-engineering indicators "
            f"(score {phish_score:.0f}/100), suggesting credential harvesting or deceptive intent."
        )
    if anom_score > 30:
        feat_str = ", ".join(anomalous_features) if anomalous_features else "multiple dimensions"
        parts.append(
            f"The Isolation Forest flagged anomalous network behavior across {feat_str} "
            f"(score {anom_score:.0f}/100), deviating significantly from the trained baseline."
        )
    if ctx_score > 20:
        parts.append(
            f"Contextual signals elevated the risk: {', '.join(ctx_reasons)}."
        )
    if not parts:
        parts.append("No significant threat indicators were detected across any analysis layer.")

    narrative = " ".join(parts)

    # ── Recommendation ────────────────────────────────────────────────────
    if risk_score >= 85:
        recommendation = "Immediate incident response recommended. Isolate affected endpoints and preserve forensic evidence."
    elif risk_score >= 50:
        recommendation = "Escalate to SOC analyst for manual review. Consider preemptive containment of source."
    elif risk_score >= 25:
        recommendation = "Monitor the entity for further activity. No immediate action required."
    else:
        recommendation = "No action needed. Event appears benign."

    return {
        "summary": summary,
        "narrative": narrative,
        "recommendation": recommendation,
        "factors": factors,
    }

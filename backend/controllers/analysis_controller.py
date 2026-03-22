"""
TrustCore Sentinel X — Analysis Controller
==========================================
Orchestrates the full detection + intelligence pipeline:
  phishing → anomaly → risk → explainability → attack chain → entity → response

The controller is the business logic layer — routes delegate to this.
Routes stay thin (HTTP concern only); this module owns the pipeline logic.
"""


from datetime import datetime, timezone
from typing import Any

from services.phishing_service       import analyze_phishing
from services.anomaly_service        import analyze_anomaly
from services.risk_engine            import compute_risk
from services.response_engine        import execute_response
from services.explainability_engine  import generate_explanation
from services.attack_chain_tracker   import track_event
from services.entity_tracker         import track_entity
from utils.logger                    import get_logger

logger = get_logger("controller.analysis")


def run_full_analysis(event: dict[str, Any]) -> dict[str, Any]:
    """
    Execute the complete threat analysis + intelligence pipeline.

    Pipeline:
      1. Phishing NLP    (TF-IDF + classifier + heuristics)
      2. Anomaly IF      (Isolation Forest on feature vector)
      3. Risk Engine     (weighted combination → 0–100 score)
      4. Explainability  (ranked feature contributions + narrative)
      5. Attack Chain    (multi-stage MITRE-style correlation)
      6. Entity Intel    (adaptive per-IP risk memory)
      7. Response        (autonomous action based on risk level)
    """
    text     = event.get("text", "")
    features = event.get("features", [500.0, 10.0, 0.45, 60.0, 0])

    # ── Step 1: Phishing Detection ────────────────────────────────────────
    phishing_result = analyze_phishing(text)

    # ── Step 2: Anomaly Detection ─────────────────────────────────────────
    anomaly_result  = analyze_anomaly(features)

    # ── Step 3: Risk Scoring ──────────────────────────────────────────────
    risk_result     = compute_risk(
        phishing_score=phishing_result["score"],
        anomaly_score=anomaly_result["score"],
        event=event,
    )

    # ── Step 4: Explainability ────────────────────────────────────────────
    explanation = generate_explanation(
        phishing_result=phishing_result,
        anomaly_result=anomaly_result,
        risk_result=risk_result,
        event=event,
    )

    # ── Step 5: Attack Chain Correlation ──────────────────────────────────
    attack_chain = track_event(event=event, risk_score=risk_result["risk_score"])

    # ── Step 6: Entity Intelligence ───────────────────────────────────────
    entity_profile = track_entity(
        event=event,
        risk_score=risk_result["risk_score"],
        threat_level=risk_result["threat_level"],
    )

    # Apply entity multiplier to risk score (cap at 100)
    multiplier = entity_profile.get("risk_multiplier", 1.0)
    adjusted_risk = min(round(risk_result["risk_score"] * multiplier), 100)

    # Recalculate threat level if multiplier pushed score up
    if adjusted_risk != risk_result["risk_score"]:
        risk_result["risk_score"] = adjusted_risk
        if adjusted_risk >= 85:
            risk_result["threat_level"] = "CRITICAL"
        elif adjusted_risk >= 50:
            risk_result["threat_level"] = "HIGH"
        elif adjusted_risk >= 25:
            risk_result["threat_level"] = "MEDIUM"
        else:
            risk_result["threat_level"] = "LOW" if adjusted_risk > 10 else "SAFE"

    # ── Step 7: Autonomous Response ───────────────────────────────────────
    response_record = execute_response(
        threat_level=risk_result["threat_level"],
        risk_score=risk_result["risk_score"],
        action=risk_result["response"]["action"],
        description=risk_result["response"]["description"],
        event=event,
    )

    logger.info(
        "ANALYSIS COMPLETE | risk=%d/100 | level=%s | action=%s | entity=%s (x%.2f) | chain=%s",
        risk_result["risk_score"],
        risk_result["threat_level"],
        risk_result["response"]["action"],
        entity_profile.get("entity_id", "?"),
        multiplier,
        "YES" if attack_chain.get("chain_detected") else "NO",
    )

    # Build combined signals list
    signals = phishing_result.get("signals", []) + anomaly_result.get("anomalous_features", [])
    if entity_profile.get("is_repeat_offender"):
        signals.append(f"⚠ Repeat offender: {entity_profile['high_risk_events']} prior high-risk events")
    if attack_chain.get("chain_detected"):
        top_chain = attack_chain["matched_chains"][0]
        signals.append(f"🔗 Attack chain: {top_chain['chain_name']} ({top_chain['confidence']:.0%} confidence)")

    # Build reason string
    reason_parts = [f"Threat Level: {risk_result['threat_level']}"]
    if entity_profile.get("is_repeat_offender"):
        reason_parts.append(f"repeat offender (x{multiplier})")
    if attack_chain.get("chain_detected"):
        reason_parts.append(f"attack chain: {attack_chain['matched_chains'][0]['chain_name']}")
    reason = " — ".join(reason_parts)

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),

        # ── Top-level unified output ──────────────────────────────────────
        "risk_score":     risk_result["risk_score"],
        "confidence":     max(phishing_result.get("confidence", 0.0) if isinstance(phishing_result.get("confidence"), (int, float)) else 0.0,
                              anomaly_result.get("score", 0.0)),
        "reason":         reason,
        "signals":        signals,
        "explanation":    explanation,
        "attack_chain":   attack_chain,
        "entity_profile": entity_profile,

        # ── Preserved nested fields for frontend UI ───────────────────────
        "phishing":  phishing_result,
        "anomaly":   anomaly_result,
        "risk":      risk_result,
        "response":  response_record,
    }


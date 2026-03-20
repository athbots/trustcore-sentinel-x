"""
TrustCore Sentinel X — Analysis Controller
==========================================
Orchestrates the full detection pipeline:
  phishing detection -> anomaly detection -> risk scoring -> autonomous response

The controller is the business logic layer — routes delegate to this.
Routes stay thin (HTTP concern only); this module owns the pipeline logic.
"""
import sys
import os

# Make backend/ root importable regardless of invocation context
_backend_root = os.path.dirname(os.path.abspath(__file__))
# controllers/ is one level inside backend/, so go up one more
_backend_root = os.path.dirname(_backend_root)
if _backend_root not in sys.path:
    sys.path.insert(0, _backend_root)


from datetime import datetime, timezone
from typing import Any

from services.phishing_service import analyze_phishing
from services.anomaly_service   import analyze_anomaly
from services.risk_engine       import compute_risk
from services.response_engine   import execute_response
from utils.logger               import get_logger

logger = get_logger("controller.analysis")


def run_full_analysis(event: dict[str, Any]) -> dict[str, Any]:
    """
    Execute the complete threat analysis pipeline on a single event.

    Pipeline:
      1. Phishing NLP  (TF-IDF + Naive Bayes + heuristics)
      2. Anomaly IF    (Isolation Forest on feature vector)
      3. Risk Engine   (weighted combination → 0–100 score)
      4. Response      (autonomous action based on risk level)

    Args:
        event: Dictionary matching EventRequest schema fields.

    Returns:
        Full analysis result dict with phishing, anomaly, risk, and response keys.
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

    # ── Step 4: Autonomous Response ───────────────────────────────────────
    response_record = execute_response(
        threat_level=risk_result["threat_level"],
        risk_score=risk_result["risk_score"],
        action=risk_result["response"]["action"],
        description=risk_result["response"]["description"],
        event=event,
    )

    logger.info(
        "ANALYSIS COMPLETE | risk=%d/100 | level=%s | action=%s | src=%s | tgt=%s",
        risk_result["risk_score"],
        risk_result["threat_level"],
        risk_result["response"]["action"],
        event.get("source_ip", "—"),
        event.get("target", "—"),
    )

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "phishing":  phishing_result,
        "anomaly":   anomaly_result,
        "risk":      risk_result,
        "response":  response_record,
    }

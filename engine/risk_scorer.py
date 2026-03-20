"""
TrustCore Sentinel X — Risk Scorer
Converts raw detector scores into a normalized 0–100 risk score,
threat level, and recommended automated response.
"""

from models.schemas import ThreatLevel, AutomatedResponse
from typing import Tuple


# ── Risk Bands ─────────────────────────────────────────────────────────────────

RISK_BANDS = [
    # (min_score, max_score, ThreatLevel, AutomatedResponse, description)
    (0,  20,  ThreatLevel.SAFE,     AutomatedResponse.MONITOR,            "No significant threat detected."),
    (20, 40,  ThreatLevel.LOW,      AutomatedResponse.FLAG_FOR_REVIEW,    "Minor anomalies detected; flagged for analyst review."),
    (40, 60,  ThreatLevel.MEDIUM,   AutomatedResponse.THROTTLE,           "Moderate threat indicators; connection throttled pending review."),
    (60, 80,  ThreatLevel.HIGH,     AutomatedResponse.BLOCK,              "High-confidence threat detected; connection blocked automatically."),
    (80, 101, ThreatLevel.CRITICAL, AutomatedResponse.ISOLATE_AND_ALERT,  "Critical threat! Asset isolated and SOC team alerted immediately."),
]


def score_to_threat(risk_score: float) -> Tuple[ThreatLevel, AutomatedResponse, str]:
    """Maps a 0–100 risk score to threat level, action, and a human-readable summary."""
    for low, high, level, action, desc in RISK_BANDS:
        if low <= risk_score < high:
            return level, action, desc
    # Fallback (score == 100)
    return ThreatLevel.CRITICAL, AutomatedResponse.ISOLATE_AND_ALERT, RISK_BANDS[-1][4]


def compute_composite_score(scores: list[float], weights: list[float] = None) -> float:
    """
    Computes a weighted composite risk score from multiple detector scores.
    Uses max-of-components boosting to ensure any single critical signal
    elevates the overall score.
    """
    if not scores:
        return 0.0

    if weights is None:
        weights = [1.0] * len(scores)

    total_weight = sum(weights)
    weighted_avg = sum(s * w for s, w in zip(scores, weights)) / total_weight

    # Max-component boost: if any single score is very high, pull the composite up
    max_score = max(scores)
    composite = weighted_avg * 0.65 + max_score * 0.35

    return round(min(composite, 100.0), 2)

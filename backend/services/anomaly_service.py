"""
TrustCore Sentinel X — Anomaly Detection Service

Uses Isolation Forest trained on simulated normal network traffic at startup.
Detects deviations in: packet size, request rate, entropy, duration, port risk.

Anomaly score: 0.0 (normal) → 1.0 (highly anomalous)
"""
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from typing import List

from infra.config import ANOMALY_CONTAMINATION, ANOMALY_TRAINING_SAMPLES

# ---------------------------------------------------------------------------
# Feature schema (order matters):
#   [0] bytes_per_second   — Normal: 100–5000, Attack: 50000+
#   [1] request_rate       — Normal: 1–20 req/s, DDoS: 500+
#   [2] payload_entropy    — Normal: 0.3–0.7, Encrypted/exfil: 0.9+
#   [3] session_duration   — Normal: 5–300s, Scanners: <0.5
#   [4] port_risk_score    — 0=known safe, 1=high-risk port
# ---------------------------------------------------------------------------
FEATURE_NAMES = [
    "bytes_per_second",
    "request_rate",
    "payload_entropy",
    "session_duration",
    "port_risk_score",
]

N_FEATURES = len(FEATURE_NAMES)


def _generate_normal_traffic(n: int) -> np.ndarray:
    """Generate synthetic normal network traffic feature vectors."""
    rng = np.random.RandomState(42)
    return np.column_stack([
        rng.uniform(100, 5000, n),       # bytes_per_second
        rng.uniform(1, 20, n),            # request_rate
        rng.uniform(0.3, 0.7, n),         # payload_entropy
        rng.uniform(5, 300, n),           # session_duration
        rng.choice([0, 0, 0, 0, 1], n),   # port_risk_score (mostly safe)
    ])


# ---------------------------------------------------------------------------
# Train model on startup (instant — no I/O)
# ---------------------------------------------------------------------------
_X_normal = _generate_normal_traffic(ANOMALY_TRAINING_SAMPLES)
_scaler = StandardScaler()
_X_scaled = _scaler.fit_transform(_X_normal)

_model = IsolationForest(
    n_estimators=100,
    contamination=ANOMALY_CONTAMINATION,
    random_state=42,
    n_jobs=-1,
)
_model.fit(_X_scaled)

# Score range calibration: map raw IF scores to [0, 1]
_raw_scores = _model.score_samples(_X_scaled)
_score_min = _raw_scores.min()
_score_max = _raw_scores.max()


def _calibrate(raw_score: float) -> float:
    """Map Isolation Forest raw score to [0, 1] anomaly probability."""
    # IF returns negative scores; more negative = more anomalous
    normalized = (raw_score - _score_max) / (_score_min - _score_max + 1e-9)
    return float(np.clip(normalized, 0.0, 1.0))


def analyze_anomaly(features: List[float]) -> dict:
    """
    Analyze a feature vector for network anomalies.

    Args:
        features: List of 5 floats [bytes/s, req_rate, entropy, duration, port_risk]
                  Missing values are filled with normal-range defaults.

    Returns:
        score (float): 0.0 (normal) – 1.0 (highly anomalous)
        verdict (str): NORMAL | SUSPICIOUS | ANOMALY
        anomalous_features (list): feature names that deviate most
        raw_if_score (float): raw Isolation Forest score
    """
    # Pad or truncate to N_FEATURES
    padded = list(features) + [0.0] * N_FEATURES
    padded = padded[:N_FEATURES]
    x = np.array(padded, dtype=float).reshape(1, -1)

    # Scale and predict
    x_scaled = _scaler.transform(x)
    raw_score = float(_model.score_samples(x_scaled)[0])
    anomaly_score = _calibrate(raw_score)

    # Identify which individual features deviate (vs training mean/std)
    means = _scaler.mean_
    stds = np.sqrt(_scaler.var_)
    z_scores = np.abs((padded - means) / (stds + 1e-9))
    anomalous = [FEATURE_NAMES[i] for i in np.argsort(z_scores)[::-1] if z_scores[i] > 2.0][:3]

    # Verdict
    if anomaly_score >= 0.70:
        verdict = "ANOMALY"
    elif anomaly_score >= 0.40:
        verdict = "SUSPICIOUS"
    else:
        verdict = "NORMAL"

    return {
        "score": round(anomaly_score, 4),
        "verdict": verdict,
        "anomalous_features": anomalous,
        "raw_if_score": round(raw_score, 4),
    }

"""
TrustCore Sentinel X — Network Anomaly Detector (Production)

Uses Isolation Forest trained on synthetic normal traffic at startup.
Can optionally load a pre-trained model from disk (trained on CICIDS2017).

Feature schema (5 values):
    [bytes_per_second, request_rate, payload_entropy, session_duration, port_risk_score]
"""
import numpy as np
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from typing import List

from sentinel.config import ANOMALY_CONTAMINATION, ANOMALY_TRAINING_SAMPLES, MODEL_DIR
from sentinel.utils.logger import get_logger

logger = get_logger("detector.network_anomaly")

FEATURE_NAMES = [
    "bytes_per_second",
    "request_rate",
    "payload_entropy",
    "session_duration",
    "port_risk_score",
]
N_FEATURES = len(FEATURE_NAMES)

# ── Synthetic Training Data ──────────────────────────────────────────────────

def _generate_normal_traffic(n: int) -> np.ndarray:
    """Generate synthetic normal network traffic feature vectors."""
    rng = np.random.RandomState(42)
    return np.column_stack([
        rng.uniform(100, 5000, n),       # bytes_per_second
        rng.uniform(1, 20, n),           # request_rate
        rng.uniform(0.3, 0.7, n),        # payload_entropy
        rng.uniform(5, 300, n),          # session_duration
        rng.choice([0, 0, 0, 0, 1], n),  # port_risk_score (mostly safe)
    ])

# ── Model Training ───────────────────────────────────────────────────────────

def _load_or_train() -> tuple[IsolationForest, StandardScaler, float, float]:
    """Load pre-trained model if available, otherwise train on synthetic data."""
    model_path = MODEL_DIR / "anomaly_if.joblib"
    scaler_path = MODEL_DIR / "anomaly_scaler.joblib"

    if model_path.exists() and scaler_path.exists():
        try:
            import joblib
            model = joblib.load(model_path)
            scaler = joblib.load(scaler_path)
            # Get calibration bounds
            X_cal = _generate_normal_traffic(200)
            X_cal_scaled = scaler.transform(X_cal)
            raw_scores = model.score_samples(X_cal_scaled)
            logger.info("Loaded pre-trained anomaly model from disk")
            return model, scaler, raw_scores.min(), raw_scores.max()
        except Exception as e:
            logger.warning(f"Failed to load pre-trained model: {e}. Training fresh.")

    # Train on synthetic data
    X = _generate_normal_traffic(ANOMALY_TRAINING_SAMPLES)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(
        n_estimators=100,
        contamination=ANOMALY_CONTAMINATION,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_scaled)

    raw_scores = model.score_samples(X_scaled)
    logger.info(f"Anomaly model trained on {ANOMALY_TRAINING_SAMPLES} synthetic samples")

    return model, scaler, raw_scores.min(), raw_scores.max()


_model, _scaler, _score_min, _score_max = _load_or_train()


def _calibrate(raw_score: float) -> float:
    """Map Isolation Forest raw score to [0, 1] anomaly probability."""
    normalized = (raw_score - _score_max) / (_score_min - _score_max + 1e-9)
    return float(np.clip(normalized, 0.0, 1.0))


def analyze_anomaly(features: List[float]) -> dict:
    """
    Analyze a feature vector for network anomalies.

    Args:
        features: list of 5 floats [bytes/s, req_rate, entropy, duration, port_risk]

    Returns dict with:
        score, verdict, anomalous_features, raw_if_score
    """
    padded = list(features) + [0.0] * N_FEATURES
    padded = padded[:N_FEATURES]
    x = np.array(padded, dtype=float).reshape(1, -1)

    x_scaled = _scaler.transform(x)
    raw_score = float(_model.score_samples(x_scaled)[0])
    anomaly_score = _calibrate(raw_score)

    means = _scaler.mean_
    stds = np.sqrt(_scaler.var_)
    z_scores = np.abs((np.array(padded) - means) / (stds + 1e-9))
    anomalous = [FEATURE_NAMES[i] for i in np.argsort(z_scores)[::-1] if z_scores[i] > 2.0][:3]

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

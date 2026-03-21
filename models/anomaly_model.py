"""
TrustCore Sentinel X — Anomaly Detection Model
===============================================
Standalone module. Can be imported or run directly.

Architecture:
  StandardScaler → Isolation Forest (100 estimators)
  Trained on 500 synthetic normal-traffic feature vectors.
  Detects deviations in 5 network telemetry features.

Feature Vector:
  [0] bytes_per_second   — traffic volume
  [1] request_rate       — requests per second
  [2] payload_entropy    — Shannon entropy of packet payloads
  [3] session_duration   — seconds the session lasted
  [4] port_risk_score    — 0=safe port, 1=high-risk port

Usage (standalone):
  python anomaly_model.py

Usage (import):
  from models.anomaly_model import AnomalyModel
  model = AnomalyModel()
  result = model.predict([150000, 1200, 0.35, 0.5, 1])
"""

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from typing import List

FEATURE_NAMES = [
    "bytes_per_second",
    "request_rate",
    "payload_entropy",
    "session_duration",
    "port_risk_score",
]

N_FEATURES     = len(FEATURE_NAMES)
N_TRAIN        = 500
CONTAMINATION  = 0.10   # Expected fraction of anomalies in real traffic


def _generate_normal_traffic(n: int, seed: int = 42) -> np.ndarray:
    """
    Synthesize normal network traffic feature vectors.
    Distributions are based on typical enterprise LAN baselines.
    """
    rng = np.random.RandomState(seed)
    return np.column_stack([
        rng.uniform(100,  5_000, n),           # bytes_per_second
        rng.uniform(1,       20, n),            # request_rate
        rng.uniform(0.3,    0.7, n),            # payload_entropy
        rng.uniform(5,      300, n),            # session_duration
        rng.choice([0, 0, 0, 0, 1], n),         # port_risk_score (mostly safe)
    ])


class AnomalyModel:
    """
    Network traffic anomaly detector.

    Attributes:
        model:      Fitted IsolationForest
        scaler:     Fitted StandardScaler
        score_min:  Minimum raw IF score seen during training (for calibration)
        score_max:  Maximum raw IF score seen during training
    """

    def __init__(self, n_train: int = N_TRAIN, contamination: float = CONTAMINATION):
        X = _generate_normal_traffic(n_train)

        self.scaler = StandardScaler()
        X_scaled    = self.scaler.fit_transform(X)

        self.model = IsolationForest(
            n_estimators=100,
            contamination=contamination,
            random_state=42,
            n_jobs=-1,
        )
        self.model.fit(X_scaled)

        raw_scores      = self.model.score_samples(X_scaled)
        self.score_min  = float(raw_scores.min())
        self.score_max  = float(raw_scores.max())

    def _calibrate(self, raw: float) -> float:
        """Map IF raw score to [0.0, 1.0] (0=normal, 1=anomalous)."""
        norm = (raw - self.score_max) / (self.score_min - self.score_max + 1e-9)
        return float(np.clip(norm, 0.0, 1.0))

    def predict(self, features: List[float]) -> dict:
        """
        Score a single feature vector.

        Args:
            features: List of floats, length 1–5.
                      Missing values default to mid-range baselines.

        Returns:
            score (float):             0.0 (normal) – 1.0 (anomalous)
            verdict (str):             NORMAL | SUSPICIOUS | ANOMALY
            anomalous_features (list): Feature names with z-score > 2.0
            raw_if_score (float):      Raw Isolation Forest score
        """
        padded = (list(features) + [0.0] * N_FEATURES)[:N_FEATURES]
        x      = np.array(padded, dtype=float).reshape(1, -1)
        xs     = self.scaler.transform(x)
        raw    = float(self.model.score_samples(xs)[0])
        score  = self._calibrate(raw)

        means  = self.scaler.mean_
        stds   = np.sqrt(self.scaler.var_)
        z      = np.abs((np.array(padded) - means) / (stds + 1e-9))
        anom_f = [FEATURE_NAMES[i] for i in np.argsort(z)[::-1] if z[i] > 2.0][:3]

        verdict = "ANOMALY" if score >= 0.70 else ("SUSPICIOUS" if score >= 0.40 else "NORMAL")

        return {
            "score":               round(score, 4),
            "verdict":             verdict,
            "anomalous_features":  anom_f,
            "raw_if_score":        round(raw, 4),
            "feature_values":      dict(zip(FEATURE_NAMES, padded)),
        }

    def model_info(self) -> dict:
        return {
            "model_type":       "Isolation Forest",
            "n_estimators":     100,
            "contamination":    CONTAMINATION,
            "training_samples": N_TRAIN,
            "features":         FEATURE_NAMES,
            "score_range":      "calibrated [0.0, 1.0]",
        }


# ── Standalone Demo ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    model = AnomalyModel()
    info  = model.model_info()

    print("\n" + "=" * 65)
    print("  TrustCore Sentinel X — Network Anomaly Detection Model")
    print("=" * 65)
    print(f"  Model       : {info['model_type']} ({info['n_estimators']} estimators)")
    print(f"  Training    : {info['training_samples']} synthetic normal-traffic vectors")
    print(f"  Features    : {', '.join(info['features'])}")
    print("=" * 65)

    test_cases = [
        ("Normal web browsing",  [2000,   8,  0.45,  90,  0]),
        ("Normal file download", [4500,   3,  0.55, 240,  0]),
        ("DDoS flood",           [150000, 1200, 0.35, 0.5, 1]),
        ("Port scan",            [120,    450,  0.18, 0.2, 1]),
        ("Data exfiltration",    [75000,  2,    0.97, 1800, 0]),
        ("Ransomware",           [50000,  3,    0.99, 600,  1]),
        ("Brute force",          [1500,   180,  0.50, 15,   1]),
        ("Low-traffic stealth",  [80,     1,    0.92, 3600, 0]),
    ]

    print()
    for name, features in test_cases:
        r = model.predict(features)
        icon = "🚨" if r["verdict"] == "ANOMALY" else ("⚠️ " if r["verdict"] == "SUSPICIOUS" else "✅")
        anom_str = f"  [{', '.join(r['anomalous_features'])}]" if r["anomalous_features"] else ""
        print(f"  {icon} [{r['verdict']:10s}] Score={r['score']:.3f} | {name}{anom_str}")
    print()

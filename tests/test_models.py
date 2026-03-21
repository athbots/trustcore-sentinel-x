"""
TrustCore Sentinel X — CI Smoke Tests
======================================
Pytest-compatible tests that verify all AI models work correctly.
These run in CI without needing a running server.
"""

from models.phishing_model import PhishingModel
from models.anomaly_model import AnomalyModel


# ── Phishing Model Tests ─────────────────────────────────────────────────────


class TestPhishingModel:
    """Verify the phishing detection model loads and produces correct results."""

    def setup_method(self):
        self.model = PhishingModel()

    def test_model_loads(self):
        info = self.model.model_info()
        assert info["training_samples"] > 0
        assert float(info["cv5_accuracy"].rstrip("%")) > 50

    def test_detects_phishing(self):
        result = self.model.predict(
            "Verify your PayPal account immediately or it will be suspended"
        )
        assert result["score"] > 0.5
        assert result["verdict"] in ("PHISHING", "SUSPICIOUS")

    def test_detects_legitimate(self):
        result = self.model.predict(
            "Team meeting scheduled for Monday at 3pm in conference room B"
        )
        assert result["score"] < 0.5
        assert result["verdict"] == "LEGITIMATE"

    def test_empty_input(self):
        result = self.model.predict("")
        assert result["score"] == 0.0
        assert result["verdict"] == "LEGITIMATE"

    def test_batch_predict(self):
        texts = [
            "Verify your account now!",
            "Team meeting at 3pm",
        ]
        results = self.model.batch_predict(texts)
        assert len(results) == 2
        assert results[0]["score"] > results[1]["score"]


# ── Anomaly Model Tests ──────────────────────────────────────────────────────


class TestAnomalyModel:
    """Verify the anomaly detection model loads and scores correctly."""

    def setup_method(self):
        self.model = AnomalyModel()

    def test_model_loads(self):
        info = self.model.model_info()
        assert info["model_type"] == "Isolation Forest"
        assert info["training_samples"] == 500

    def test_normal_traffic(self):
        result = self.model.predict([2000, 8, 0.45, 90, 0])
        assert result["score"] < 0.5
        assert result["verdict"] == "NORMAL"

    def test_ddos_attack(self):
        result = self.model.predict([150000, 1200, 0.35, 0.5, 1])
        assert result["score"] > 0.4
        assert result["verdict"] in ("SUSPICIOUS", "ANOMALY")

    def test_data_exfiltration(self):
        result = self.model.predict([75000, 2, 0.97, 1800, 0])
        assert result["score"] > 0.3
        assert result["verdict"] in ("SUSPICIOUS", "ANOMALY")

    def test_partial_features(self):
        """Model should handle fewer than 5 features by padding."""
        result = self.model.predict([5000, 10])
        assert "score" in result
        assert "verdict" in result


# ── Backend Services Tests (import validation) ───────────────────────────────


class TestBackendImports:
    """Verify backend services can be imported when sys.path includes backend/."""

    def test_phishing_service_import(self):
        import sys
        import os
        backend_path = os.path.join(
            os.path.dirname(__file__), "..", "backend"
        )
        if backend_path not in sys.path:
            sys.path.insert(0, os.path.abspath(backend_path))

        from services.phishing_service import analyze_phishing
        result = analyze_phishing("Test email for CI validation")
        assert "score" in result
        assert "verdict" in result

    def test_anomaly_service_import(self):
        from services.anomaly_service import analyze_anomaly
        result = analyze_anomaly([500, 10, 0.45, 60, 0])
        assert "score" in result
        assert "verdict" in result

    def test_risk_engine_import(self):
        from services.risk_engine import compute_risk
        result = compute_risk(0.5, 0.5, {"source_ip": "10.0.0.1"})
        assert "risk_score" in result
        assert "threat_level" in result

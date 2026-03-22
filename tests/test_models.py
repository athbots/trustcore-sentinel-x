"""
TrustCore Sentinel X — Model Verification Tests
==============================================
Pytest-compatible tests that verify all AI/ML models work correctly.
These run in CI without needing a running server.
"""

from backend.services.phishing_service import analyze_phishing
from backend.services.anomaly_service import analyze_anomaly
from backend.services.risk_engine import compute_risk


# ── Phishing Service Verification ──────────────────────────────────────────


def test_phishing_service_loads():
    """Verify the phishing detection service produces valid structured results."""
    result = analyze_phishing("Test warm-up")
    assert "score" in result
    assert "verdict" in result
    assert "confidence" in result


def test_detects_phishing_indicator():
    """Verify explicit phishing patterns trigger higher scores."""
    result = analyze_phishing("Verify your PayPal account immediately or it will be suspended")
    assert result["score"] >= 0.70
    assert result["verdict"] == "PHISHING"


def test_detects_legitimate_indicator():
    """Verify representative business communication is scored as legitimate."""
    result = analyze_phishing("Team meeting scheduled for Monday at 3pm in conference room B")
    assert result["score"] < 0.30
    assert result["verdict"] == "LEGITIMATE"


# ── Anomaly Service Verification ───────────────────────────────────────────


def test_anomaly_service_loads():
    """Verify the anomaly detection service produces valid structured results."""
    result = analyze_anomaly([500, 10, 0.4, 60, 0])
    assert "score" in result
    assert "verdict" in result
    assert "anomalous_features" in result


def test_normal_traffic_behavior():
    """Verify baseline network behavior maps to CLEAN anomaly verdicts."""
    result = analyze_anomaly([2000, 8, 0.45, 90, 0])
    assert result["score"] < 0.40
    assert result["verdict"] == "NORMAL"


def test_ddos_attack_behavior():
    """Verify massive data spikes trigger ANOMALY verdicts."""
    result = analyze_anomaly([150000, 1200, 0.35, 0.5, 1])
    assert result["score"] > 0.70
    assert result["verdict"] == "ANOMALY"


# ── Risk Engine Integration ────────────────────────────────────────────────


def test_risk_scoring_matrix():
    """Verify the risk engine integrates ML outcomes into a final threat score."""
    # Simulate a suspicious phishing email + suspicious network anomaly
    result = compute_risk(0.5, 0.45, {"source_ip": "10.0.0.1"})
    
    assert "risk_score" in result
    assert "threat_level" in result
    assert "response" in result
    assert result["risk_score"] > 40

from backend.services.phishing_service import analyze_phishing
from backend.services.anomaly_service import analyze_anomaly

def test_phishing_detection_clean():
    """Verify clean benign text is classified safely with low probability."""
    text = "Hey team, this is the agenda for the weekly all-hands meeting. See you there!"
    result = analyze_phishing(text)
    
    assert result["verdict"] == "LEGITIMATE"
    assert result["score"] < 0.40
    assert len(result["signals"]) == 0

def test_phishing_detection_malicious():
    """Verify explicit credential harvesting indicators trigger HIGH probability and signals."""
    text = "URGENT: Your PayPal account has been compromised. Please verify your billing details immediately by clicking here."
    result = analyze_phishing(text)
    
    assert result["verdict"] == "PHISHING"
    assert result["score"] > 0.60
    assert any("verify" in signal.lower() or "urgent" in signal.lower() or "account" in signal.lower() for signal in result["signals"])

def test_anomaly_detection_normal():
    """Verify baseline network behavior maps to CLEAN anomaly verdicts."""
    # [bytes_per_sec, req_rate, entropy, duration, port_risk]
    normal_vector = [500.0, 10.0, 0.4, 60.0, 0.0]
    result = analyze_anomaly(normal_vector)
    
    assert result["verdict"] == "NORMAL"
    assert result["score"] < 0.50

def test_anomaly_detection_outlier():
    """Verify massive data spikes map to ANOMALOUS network verdicts."""
    ddos_vector = [50000.0, 1000.0, 0.95, 3600.0, 1.0]
    result = analyze_anomaly(ddos_vector)
    
    assert result["verdict"] == "ANOMALY"
    assert result["score"] > 0.50

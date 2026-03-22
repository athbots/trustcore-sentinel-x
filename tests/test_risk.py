from backend.services.risk_engine import compute_risk

def test_risk_engine_weighting_low():
    """Assert minimum outputs return SAFE threat levels safely under 35."""
    event_data = {
        "text": "Hello world",
        "features": [500, 10, 0.4, 60, 0],
        "source_ip": "127.0.0.1",
        "repeat_offender": False
    }
    
    phishing_result = 0.10
    anomaly_result = 0.10
    
    risk_output = compute_risk(phishing_result, anomaly_result, event_data)
    
    assert risk_output["risk_score"] < 35
    assert risk_output["threat_level"] in ["SAFE", "LOW"]
    assert "LOG" in risk_output["response"]["action"] or "SAFE" in risk_output["response"]["action"]

def test_risk_engine_weighting_critical():
    """Assert high probability models correctly trigger CRITICAL scalar logic."""
    event_data = {
        "text": "paypal urgently verify",
        "features": [50000, 1000, 0.95, 3600, 1],
        "source_ip": "192.168.1.100",
        "repeat_offender": True
    }
    
    phishing_result = 0.95
    anomaly_result = 0.95
    
    risk_output = compute_risk(phishing_result, anomaly_result, event_data)
    
    assert risk_output["risk_score"] > 75
    assert risk_output["threat_level"] in ["HIGH", "CRITICAL"]
    assert risk_output["response"]["action"] in ["BLOCK", "ISOLATE"]


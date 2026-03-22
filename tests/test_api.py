from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)
VALID_API_KEY = "trustcore-super-secret-key-2026"
HEADERS = {"X-API-Key": VALID_API_KEY}

def test_missing_api_key_rejection():
    """Verify endpoints block requests lacking the explicit API signature."""
    response = client.get("/system_status")
    assert response.status_code == 403
    assert "Not authenticated" in response.text

def test_input_validation_failure():
    """Verify Pydantic models reject incorrectly typed metric variables."""
    payload = {
        "text": "Valid text string",
        "features": "This should be a list of floats, not a string",
        "source_ip": "10.0.0.1"
    }
    response = client.post("/analyze", json=payload, headers=HEADERS)
    assert response.status_code == 422 # Standard Unprocessable Entity

def test_analyze_attack_simulation():
    """Verify simulated attacks trigger a high-risk system response correctly."""
    payload = {
        "text": "URGENT: Verify your account immediately to prevent locking.",
        "features": [50000, 1000, 0.95, 3600, 1], # Anomalous vector
        "source_ip": "198.51.100.22"
    }
    response = client.post("/analyze", json=payload, headers=HEADERS)
    assert response.status_code == 200
    
    data = response.json()
    assert data["risk_score"] > 60
    assert data["risk"]["threat_level"] in ["HIGH", "CRITICAL"]

def test_consistency_check():
    """Verify passing the exact same deterministic payload twice yields symmetric risk analysis."""
    payload = {
        "text": "This is a benign clean data vector.",
        "features": [500, 10, 0.45, 60, 0],
        "source_ip": "10.0.0.5"
    }
    
    response_1 = client.post("/analyze", json=payload, headers=HEADERS).json()
    response_2 = client.post("/analyze", json=payload, headers=HEADERS).json()
    
    # Asserting symmetrical outcome scoring
    assert response_1["risk_score"] == response_2["risk_score"]
    assert response_1["phishing"]["score"] == response_2["phishing"]["score"]

def test_rate_limiter_overflow():
    """Verify rapid API polling correctly intercepts and bounces via HTTP 429."""
    for _ in range(35):
        client.get("/system_status", headers=HEADERS)
        
    final_response = client.get("/system_status", headers=HEADERS)
    assert final_response.status_code == 429
    assert "Too Many Requests" in final_response.text

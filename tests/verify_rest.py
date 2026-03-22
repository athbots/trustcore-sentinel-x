import requests
import time

BASE_URL = "http://localhost:8000"
API_KEY = "trustcore-super-secret-key-2026"
HEADERS = {"X-API-Key": API_KEY}

def test_health():
    print("Testing /health...")
    try:
        res = requests.get(f"{BASE_URL}/health")
        print(f"Status: {res.status_code}, Body: {res.json()}")
        return res.status_code == 200
    except Exception as e:
        print(f"Error: {e}")
        return False

def test_status():
    print("Testing /system_status...")
    try:
        res = requests.get(f"{BASE_URL}/system_status", headers=HEADERS)
        print(f"Status: {res.status_code}, Body: {res.json().get('status')}")
        return res.status_code == 200
    except Exception as e:
        print(f"Error: {e}")
        return False

def test_analyze():
    print("Testing /analyze...")
    payload = {"text": "Safe test message", "features": [0, 0, 0, 0, 0]}
    try:
        res = requests.post(f"{BASE_URL}/analyze", json=payload, headers=HEADERS)
        print(f"Status: {res.status_code}, Risk: {res.json().get('risk_score')}")
        return res.status_code == 200
    except Exception as e:
        print(f"Error: {e}")
        return False

if __name__ == "__main__":
    h = test_health()
    s = test_status()
    a = test_analyze()
    
    if all([h, s, a]):
        print("\n✅ All REST endpoints functional!")
    else:
        print("\n❌ Endpoint verification failed!")

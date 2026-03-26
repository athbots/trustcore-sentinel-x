import requests
import json

BASE_URL = "http://127.0.0.1:5050"
API_KEY = "trustcore-super-secret-key-2026"
HEADERS = {"X-API-Key": API_KEY}

REQUIRED_FIELDS = {
    "trust_score": (int, float),
    "risk_level": str,
    "decision": str,
    "cpu": (int, float),
    "memory": (int, float),
    "process_count": int,
    "status": str
}

def verify_endpoint(endpoint, method="GET", payload=None):
    print(f"Verifying {method} {endpoint}...")
    try:
        if method == "GET":
            response = requests.get(f"{BASE_URL}{endpoint}", headers=HEADERS)
        else:
            response = requests.post(f"{BASE_URL}{endpoint}", headers=HEADERS, json=payload)
        
        if response.status_code != 200:
            print(f"  [FAIL] Status code: {response.status_code}")
            print(f"  Response: {response.text}")
            return False
        
        data = response.json()
        missing = []
        wrong_type = []
        
        for field, expected_type in REQUIRED_FIELDS.items():
            if field not in data:
                missing.append(field)
            elif not isinstance(data[field], expected_type):
                wrong_type.append(f"{field} (expected {expected_type}, got {type(data[field])})")
        
        if missing or wrong_type:
            if missing:
                print(f"  [FAIL] Missing fields: {missing}")
            if wrong_type:
                print(f"  [FAIL] Wrong types: {wrong_type}")
            print(f"  Actual JSON: {json.dumps(data, indent=2)}")
            return False
        
        # Check clamping
        if not (0 <= data["trust_score"] <= 100):
            print(f"  [FAIL] trust_score out of range: {data['trust_score']}")
            return False
        if not (0 <= data["cpu"] <= 100):
            print(f"  [FAIL] cpu out of range: {data['cpu']}")
            return False
        if not (0 <= data["memory"] <= 100):
            print(f"  [FAIL] memory out of range: {data['memory']}")
            return False
            
        print(f"  [PASS] All 7 fields present and valid.")
        return True
    except Exception as e:
        print(f"  [ERROR] {str(e)}")
        return False

def main():
    endpoints = [
        ("/system/status", "GET", None),
        ("/system/processes", "GET", None),
        ("/system_status", "GET", None),
        ("/analyze", "POST", {
            "text": "Check your bank account",
            "features": [500, 10, 0.4, 60, 0],
            "source_ip": "1.2.3.4"
        }),
        ("/simulate/attack", "POST", {"scenario": "cpu_spike", "duration": 30}),
        ("/simulate/attack/status", "GET", None),
        ("/simulate/attack/stop", "POST", None),
    ]
    
    all_pass = True
    for endpoint, method, payload in endpoints:
        if not verify_endpoint(endpoint, method, payload):
            all_pass = False
            
    if all_pass:
        print("\nOVERALL VERIFICATION: PASSED")
    else:
        print("\nOVERALL VERIFICATION: FAILED")

if __name__ == "__main__":
    main()

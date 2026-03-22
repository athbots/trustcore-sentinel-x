import json
import time
import requests
import colorama
from data.loader import load_phishing_data, load_network_data

API_URL = "http://127.0.0.1:8000/analyze"

colorama.init(autoreset=True)

def print_hdr(title):
    print(f"\n{colorama.Fore.CYAN}{'='*60}")
    print(f"{colorama.Fore.CYAN}{title.center(60)}")
    print(f"{colorama.Fore.CYAN}{'='*60}")

def analyze_event(payload, event_title):
    print_hdr(f"Testing: {event_title}")
    print(f"{colorama.Fore.YELLOW}Payload sent:{colorama.Style.RESET_ALL}")
    print(json.dumps(payload, indent=2))
    
    try:
        resp = requests.post(API_URL, json=payload, headers={"X-API-Key": "trustcore-super-secret-key-2026"}, timeout=5)
        resp.raise_for_status()
        data = resp.json()
        
        print(f"\n{colorama.Fore.GREEN}Analysis Result:{colorama.Style.RESET_ALL}")
        # Extract required fields conceptually to demonstrate integration
        out = {
            "risk_score": data.get("risk_score"),
            "confidence": data.get("confidence"),
            "reason": data.get("reason"),
            "signals": data.get("signals", [])
        }
        print(json.dumps(out, indent=2))
        
        action = data.get("response", {}).get("action")
        print(f"\n{colorama.Fore.MAGENTA}Autonomous Action taken: {action}{colorama.Style.RESET_ALL}")
        
    except requests.exceptions.ConnectionError:
        print(f"{colorama.Fore.RED}Error: Could not connect to API. Is the backend running?{colorama.Style.RESET_ALL}")
    except Exception as e:
        print(f"{colorama.Fore.RED}Error analyzing event: {e}{colorama.Style.RESET_ALL}")

def main():
    print(f"{colorama.Fore.GREEN}Loading datasets...{colorama.Style.RESET_ALL}")
    phishing_data = load_phishing_data()
    network_data = load_network_data()

    if not phishing_data or not network_data:
        print("ERROR: Datasets not found. Did you create them in data/?")
        return

    # 1. Benign Email
    benign_email = next((x for x in phishing_data if x.get("label") == 0), None)
    if benign_email:
        analyze_event({
            "text": benign_email["text"],
            "features": [500, 10, 0.45, 60, 0],
            "event_type": "EMAIL_RECEIVED"
        }, "Real Benign Email (Dataset)")
        time.sleep(1.5)

    # 2. Phishing Email
    phish_email = next((x for x in phishing_data if x.get("label") == 1), None)
    if phish_email:
        analyze_event({
            "text": phish_email["text"],
            "features": [600, 12, 0.50, 45, 0],
            "event_type": "EMAIL_RECEIVED"
        }, "Real Phishing Email (Dataset)")
        time.sleep(1.5)

    # 3. Benign Network Event
    benign_net = next((x for x in network_data if x.get("label") == 0), None)
    if benign_net:
        analyze_event({
            "text": "",
            "features": [
                benign_net.get("bytes_sent", 0),
                benign_net.get("bytes_received", 0),
                benign_net.get("duration", 1),
                benign_net.get("failed_logins", 0),
                benign_net.get("packet_count", 1),
                0 if benign_net.get("port", 443) not in [22, 3389, 445, 1433, 4444] else 1
            ],
            "event_type": "NETWORK_FLOW"
        }, "Real Normal Network Traffic (Dataset)")
        time.sleep(1.5)

    # 4. Anomalous Network Event
    anom_net = next((x for x in network_data if x.get("label") == 1), None)
    if anom_net:
        analyze_event({
            "text": "",
            "features": [
                anom_net.get("bytes_sent", 0),
                anom_net.get("bytes_received", 0),
                anom_net.get("duration", 1),
                anom_net.get("failed_logins", 0),
                anom_net.get("packet_count", 1),
                0 if anom_net.get("port", 443) not in [22, 3389, 445, 1433, 4444] else 1
            ],
            "event_type": "NETWORK_FLOW"
        }, "Real Anomalous Network Traffic (Dataset)")

    print(f"\n{colorama.Fore.GREEN}Simulation complete! ML models successfully ingested dataset records.{colorama.Style.RESET_ALL}")

if __name__ == "__main__":
    main()

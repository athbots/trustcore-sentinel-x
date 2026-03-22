"""
TrustCore Sentinel X — Attack Simulation Lab

Validates that the system detects robust, multi-stage, real-world
attack scenarios. It feeds custom event streams into the backend
and dynamically monitors risk escalation and chain mapping.

Usage:
  python simulation/attack_scenarios.py
"""

import sys
import time
import requests
import json
import logging

# Disable standard python requests logging
logging.getLogger("urllib3").setLevel(logging.WARNING)

API_URL = "http://127.0.0.1:8000/analyze"

# Colors for cinematic output
C = {
    "red": "\033[91m", "green": "\033[92m", "yellow": "\033[93m",
    "blue": "\033[94m", "magenta": "\033[95m", "cyan": "\033[96m",
    "white": "\033[97m", "reset": "\033[0m", "bold": "\033[1m"
}

# ── SCENARIOS ─────────────────────────────────────────────────────────────────

SCENARIOS = {
    "1": {
        "name": "Targeted Phishing Attack",
        "description": "A suspicious credential-harvesting email followed by a direct credential attempt.",
        "ip": "203.0.113.10",
        "stages": [
            {
                "desc": "Suspicious email delivery",
                "payload": {
                    "event_type": "PHISHING",
                    "text": "URGENT ACTION REQUIRED: Your Office365 password expires in 2 hours. Click here to verify your identity: http://update-secure-auth.xyz/login",
                    "features": [1200, 20, 0.6, 443, 0],
                    "target": "finance@company.local"
                }
            },
            {
                "desc": "Credential attempt via VPN",
                "payload": {
                    "event_type": "LOGIN_ANOMALY",
                    "text": "",
                    "features": [5000, 50, 0.9, 443, 1],
                    "target": "vpn.company.local"
                }
            }
        ]
    },
    "2": {
        "name": "Brute Force Attack",
        "description": "Repeated login attempts resulting in an anomaly spike.",
        "ip": "198.51.100.44",
        "stages": [
            {
                "desc": "Initial SSH connection",
                "payload": {
                    "event_type": "NETWORK_FLOW",
                    "text": "",
                    "features": [200, 5, 0.4, 22, 1],
                    "target": "10.0.0.50"
                }
            },
            {
                "desc": "Repeated login failures (brute force)",
                "payload": {
                    "event_type": "BRUTE_FORCE",
                    "text": "",
                    "features": [8500, 450, 0.95, 22, 1],
                    "target": "10.0.0.50"
                }
            }
        ]
    },
    "3": {
        "name": "Data Exfiltration",
        "description": "Abnormal outbound traffic bypassing normal thresholds.",
        "ip": "10.0.0.12",  # Internal compromised host
        "stages": [
            {
                "desc": "Massive outbound HTTPS transfer",
                "payload": {
                    "event_type": "DATA_EXFIL",
                    "text": "Large unstructured byte stream detected",
                    "features": [150000, 3000, 0.99, 443, 1],
                    "target": "unknown-external-ip.net"
                }
            }
        ]
    },
    "4": {
        "name": "Multi-Stage APT (Chained Sequence)",
        "description": "Phishing → Credential Abuse → Brute Force → Exfiltration",
        "ip": "66.249.64.12",
        "stages": [
            {
                "desc": "Targeted Spear-Phishing",
                "payload": {
                    "event_type": "PHISHING",
                    "text": "HR Department: Please review the updated Q4 holiday schedule attached. Requires immediate acknowledgement.",
                    "features": [800, 10, 0.4, 443, 0],
                    "target": "employee@company.local"
                }
            },
            {
                "desc": "Credential Abuse (Login Anomaly)",
                "payload": {
                    "event_type": "CREDENTIAL_STUFFING",
                    "text": "Unusual login time from new geographic region",
                    "features": [150, 5, 0.8, 443, 1],
                    "target": "portal.company.local"
                }
            },
            {
                "desc": "Internal Brute Force (Lateral Movement)",
                "payload": {
                    "event_type": "BRUTE_FORCE",
                    "text": "",
                    "features": [9000, 500, 0.95, 3389, 1],
                    "target": "dc01.company.local"
                }
            },
            {
                "desc": "Data Exfiltration Tracker",
                "payload": {
                    "event_type": "DATA_EXFIL",
                    "text": "Database dump exfiltrated via FTP",
                    "features": [250000, 5000, 1.0, 21, 1],
                    "target": "malicious-drop.ru"
                }
            }
        ]
    }
}


def print_header(title):
    print(f"\n{C['cyan']}{C['bold']}{'═' * 60}")
    print(f"  {title}")
    print(f"{'═' * 60}{C['reset']}\n")

def run_scenario(scenario_id: str):
    scenario = SCENARIOS.get(scenario_id)
    if not scenario:
        return

    print_header(f"▶ SCENARIO {scenario_id}: {scenario['name']}")
    print(f"{C['magenta']}Description:{C['reset']} {scenario['description']}")
    print(f"{C['magenta']}Attacker IP:{C['reset']} {scenario['ip']}\n")

    history = []
    final_result = None

    print(f"{C['bold']}=== ATTACK SIMULATION TIMELINE ==={C['reset']}")
    
    for idx, stage in enumerate(scenario["stages"], 1):
        payload = stage["payload"]
        payload["source_ip"] = scenario["ip"]

        try:
            time.sleep(1) # Dramatic pause relative to attack execution
            headers = {"X-API-Key": "trustcore-super-secret-key-2026"}
            res = requests.post(API_URL, json=payload, headers=headers, timeout=5)
            res.raise_for_status()
            data = res.json()
            final_result = data
            
            risk = data.get("risk_score", 0)
            level = data.get("risk", {}).get("threat_level", "SAFE")
            
            color = C['red'] if risk >= 70 else C['yellow'] if risk >= 40 else C['green']
            
            print(f"Stage {idx}: {C['cyan']}{stage['desc']:<40}{C['reset']} "
                  f"(Risk: {color}{risk:02d} - {level}{C['reset']})")
            
            history.append(data)
            
        except Exception as e:
            print(f"{C['red']}Connection Error: {e}{C['reset']}")
            return

    # Process Final Results
    if not final_result: return

    chain = final_result.get("attack_chain", {})
    entity = final_result.get("entity_profile", {})
    explanation = final_result.get("explanation", {})

    print()
    if chain.get("chain_detected"):
        chain_name = chain['matched_chains'][0]['chain_name']
        print(f" {C['red']}→ Attack Chain Confirmed: [{chain_name}]{C['reset']}")
    else:
        print(f" {C['cyan']}→ No multi-stage attack chain correlated.{C['reset']}")

    print(f"\n{C['bold']}=== SYSTEM INTELLIGENCE ==={C['reset']}")
    
    conf_pct = int(final_result.get("confidence", 0.0) * 100)
    risk_score = final_result.get("risk_score", 0)
    print(f"\n{C['magenta']}MODEL CONFIDENCE: {C['reset']}{conf_pct}%")
    print(f"{C['magenta']}DETECTION PROBABILITY: {C['reset']}{risk_score}%")
    
    # ── Explainability ──
    print(f"\n{C['yellow']}WHY FLAGGED:{C['reset']}")
    print(f"  {explanation.get('narrative', 'No narrative provided.')}")
    if explanation.get("factors"):
        print(f"  {C['bold']}Top Factors:{C['reset']}")
        for f in explanation["factors"][:2]:
            print(f"    - {f['feature']} ({f['contribution']}/100)")
            
    # ── Attack Chain ──
    if chain.get("chain_detected"):
        print(f"\n{C['magenta']}🔗 ATTACK CHAIN:{C['reset']}")
        for ch in chain.get("matched_chains", [])[:1]:
            print(f"  Pattern: {ch['chain_name']} ({ch['confidence']:.0%} match)")
            print(f"  Details: {ch['description']}")
            print(f"  Stages observed: {chain.get('stages_observed')}")

    # ── Entity Profile ──
    print(f"\n{C['blue']}👤 ENTITY PROFILE ({scenario['ip']}):{C['reset']}")
    print(f"  Reputation: {entity.get('reputation', 'UNKNOWN')}")
    print(f"  Risk Multiplier: {entity.get('risk_multiplier', 1.0)}x")
    print(f"  Repeat Offender: {'YES' if entity.get('is_repeat_offender') else 'NO'}")
    
    print(f"\n{C['green']}✔ Scenario execution complete.{C['reset']}\n")


def menu():
    while True:
        print_header("TrustCore Sentinel X — Attack Simulation Lab")
        for key, sc in SCENARIOS.items():
            print(f"  [{key}] {sc['name']}")
        print(f"  [A] Run All Scenarios Sequentially")
        print(f"  [Q] Quit")
        
        choice = input(f"\n{C['bold']}Select scenario > {C['reset']}").strip().upper()
        
        if choice == 'Q':
            break
        elif choice == 'A':
            for k in SCENARIOS.keys():
                run_scenario(k)
                time.sleep(2)
        elif choice in SCENARIOS:
            run_scenario(choice)
        else:
            print(f"{C['red']}Invalid choice.{C['reset']}")

if __name__ == "__main__":
    try:
        requests.get("http://127.0.0.1:8000/health", timeout=2)
    except:
        print(f"{C['red']}❌ Error: Backend API is not running. Please start it on port 8000.{C['reset']}")
        sys.exit(1)
        
    if len(sys.argv) > 1 and sys.argv[1] == "--all":
        # Used for fast automation/testing
        for k in SCENARIOS.keys():
            run_scenario(k)
    else:
        menu()

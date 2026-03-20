"""
TrustCore Sentinel X — Advanced Demo Simulation (v2.1 Cinematic)

Runs a realistic 2-minute attack progression:
    1. SAFE — normal traffic
    2. ALERT — phishing detected
    3. BLOCK — repeated attacks, entity escalation
    4. ISOLATE — kill chain triggered, full quarantine
"""
import requests
import time
import sys

API = "http://127.0.0.1:8321"

# ANSI colors & formatting
C = {
    "r": "\033[91m", "g": "\033[92m", "y": "\033[93m", "c": "\033[96m",
    "m": "\033[95m", "w": "\033[97m", "d": "\033[90m", "0": "\033[0m",
    "bold": "\033[1m", "bg_red": "\033[41m\033[97m", "blink": "\033[5m"
}

STAGES = [
    {
        "name": "RECONNAISSANCE",
        "delay": 4,
        "events": [
            {
                "text": "Weekly team meeting agenda shared on Slack",
                "features": [500, 10, 0.3, 80, 0],
                "source_ip": "10.0.1.15",
                "event_type": "NORMAL_TRAFFIC",
                "target": "slack.com",
            },
            {
                "text": "Monthly server maintenance notification from IT",
                "features": [200, 5, 0.1, 443, 0],
                "source_ip": "10.0.1.20",
                "event_type": "NORMAL_TRAFFIC",
                "target": "internal-it.company.com",
            },
        ],
    },
    {
        "name": "PHISHING ATTACK",
        "delay": 5,
        "events": [
            {
                "text": "URGENT: Your PayPal account has been suspended! Click here to verify your identity immediately: http://paypa1-verify.evil-phishing.com/login",
                "features": [1500, 50, 0.9, 4444, 1],
                "source_ip": "203.0.113.66",
                "event_type": "PHISHING",
                "target": "admin@company.com",
            },
        ],
    },
    {
        "name": "BRUTE FORCE",
        "delay": 5,
        "events": [
            {
                "text": "",
                "features": [5000, 200, 0.95, 22, 1],
                "source_ip": "203.0.113.66",
                "event_type": "BRUTE_FORCE_DETECTED",
                "target": "ssh://admin-server",
            },
            {
                "text": "",
                "features": [6000, 300, 0.98, 22, 1],
                "source_ip": "203.0.113.66",
                "event_type": "BRUTE_FORCE_DETECTED",
                "target": "ssh://admin-server",
            },
        ],
    },
    {
        "name": "PAYLOAD EXECUTION",
        "delay": 5,
        "events": [
            {
                "text": "powershell.exe -enc SQBFAHgAIAAoAE4AZQB3AC0ATwBiAGoA",
                "features": [8000, 500, 0.99, 4444, 1],
                "source_ip": "203.0.113.66",
                "event_type": "SUSPICIOUS_PROCESS",
                "target": "workstation-07",
                "process_name": "powershell.exe",
            },
        ],
    },
    {
        "name": "DATA EXFILTRATION",
        "delay": 6,
        "events": [
            {
                "text": "Large outbound transfer detected to external IP",
                "features": [50000, 1000, 1.0, 443, 1],
                "source_ip": "203.0.113.66",
                "event_type": "DATA_EXFIL",
                "target": "198.51.100.77",
            },
        ],
    },
    {
        "name": "LATERAL MOVEMENT",
        "delay": 5,
        "events": [
            {
                "text": "Internal pivot detected — RDP to domain controller",
                "features": [30000, 800, 0.97, 3389, 1],
                "source_ip": "203.0.113.66",
                "event_type": "LATERAL_MOVEMENT",
                "target": "dc01.company.local",
            },
        ],
    },
]


def banner():
    print("\033[2J\033[H")  # Clear screen and move to top
    print(f"\n{C['c']}{C['bold']}{'═' * 70}")
    print(f"  🛡️  TrustCore Sentinel X — Autonomous Defense Simulation")
    print(f"  {'─' * 64}")
    print(f"  Demonstrating: Entity Tracking · Correlation · Autonomous Response")
    print(f"{'═' * 70}{C['0']}\n")


def print_dramatic_typing(text, color=C['w'], bold=False, delay=0.03):
    """Simulates a super computer typing out intelligence."""
    prefix = f"{color}{C['bold'] if bold else ''}"
    sys.stdout.write(prefix)
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print(C["0"])


def print_result(result: dict, stage_name: str):
    risk = result.get("risk", {})
    resp = result.get("response", {})
    intel = result.get("intelligence", {})
    corr = intel.get("correlation", {})

    score = risk.get("risk_score", 0)
    conf = risk.get("confidence", 0)
    level = risk.get("threat_level", "SAFE")
    reason = risk.get("reason", "")
    action = resp.get("action", "LOG")
    mult = intel.get("entity_multiplier", 1.0)

    # Color mapping
    lc = {"SAFE": C["g"], "LOW": C["c"], "MEDIUM": C["y"], "HIGH": C["y"], "CRITICAL": C["r"]}
    box_col = lc.get(level, C["w"])

    print()
    if score >= 70:
        print(f"  {C['bg_red']}{C['bold']} ⚠️  UNDER ATTACK: CRITICAL THREAT DETECTED {' ' * 23}{C['0']}")
        print(f"  {C['r']}│{C['0']}")

    # Main stats block
    stat_line = f"RISK SCORE: {score}/100"
    if score >= 70: stat_line = f"{C['r']}{stat_line}{box_col}"

    print(f"  {box_col}┌─ {stat_line}  │  CONFIDENCE: {conf:.0%}  │  {level}")
    print(f"  │  ACTION TAKEN: {C['bold']}{action}{C['0']}{box_col}  │  ENTITY MULTIPLIER: {mult:.1f}x")

    if corr.get("matched"):
        print(f"  │  {C['m']}⚡ KILL CHAIN: {corr['chain_name']} (match={corr['confidence']:.0%}){box_col}")

    if reason:
        print(f"  │")
        sys.stdout.write(f"  │  {C['c']}💡 INTELLIGENCE: {C['0']}")
        sys.stdout.flush()
        print_dramatic_typing(reason[:100], color=C['y'], bold=True, delay=0.01)

    print(f"  {box_col}└{'─' * 66}{C['0']}")


def run():
    banner()

    try:
        r = requests.get(f"{API}/status", timeout=3)
        r.raise_for_status()
    except Exception:
        print(f"{C['r']}  ❌ Server offline. Run `python -m sentinel` first.{C['0']}")
        sys.exit(1)

    for i, stage in enumerate(STAGES, 1):
        print(f"\n{C['c']}  ▶ STAGE {i}/{len(STAGES)}: {stage['name']}{C['0']}")
        print(f"  {C['d']}{'─' * 66}{C['0']}")

        for event in stage["events"]:
            try:
                # Add dramatic pause for submission
                sys.stdout.write(f"  {C['d']}Analyzing new network event... ")
                sys.stdout.flush()
                time.sleep(0.5)

                r = requests.post(f"{API}/analyze", json=event, timeout=10)
                result = r.json()

                sys.stdout.write(f"{C['g']}Analyzed.{C['0']}\n")
                sys.stdout.flush()
                time.sleep(0.5)

                print_result(result, stage["name"])
            except Exception as e:
                print(f"  {C['r']}Error: {e}{C['0']}")

            time.sleep(stage["delay"])

    # Final status
    print(f"\n{C['c']}{'═' * 70}")
    print(f"  {C['bold']}SYSTEM QUARANTINE COMPLETE{C['0']}")
    try:
        status = requests.get(f"{API}/system_status", timeout=3).json()
        sys_status = status.get('system_status', '?')
        col = C['r'] if sys_status == 'UNDER ATTACK' else C['g']

        print(f"  Status: {col}{C['bold']}{sys_status}{C['0']}")
        top = status.get("top_threats", [])
        if top:
            print(f"  Neutralized Target: {C['m']}{top[0].get('entity_id')}{C['0']} (Risk Profile: {top[0].get('avg_risk')})")
    except Exception:
        pass
    print(f"{C['c']}{'═' * 70}{C['0']}\n")


if __name__ == "__main__":
    run()

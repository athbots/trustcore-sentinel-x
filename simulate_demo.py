"""
TrustCore Sentinel X — Advanced Demo Simulation (v3.0)

Runs a realistic multi-stage attack progression showcasing:
  - AI-driven detection (Phishing NLP + Anomaly IF)
  - Explainability engine (ranked feature contributions)
  - Attack chain correlation (MITRE-style kill chain)
  - Adaptive entity intelligence (repeat offender escalation)
  - Autonomous response escalation (LOG → ALERT → BLOCK → ISOLATE)

Usage:
    1. Start backend:  cd backend && uvicorn main:app --port 8000
    2. Run this:       python simulate_demo.py
"""
import requests
import time
import sys
import json

API = "http://127.0.0.1:8000"

# ANSI colors
C = {
    "r": "\033[91m", "g": "\033[92m", "y": "\033[93m", "c": "\033[96m",
    "m": "\033[95m", "w": "\033[97m", "d": "\033[90m", "0": "\033[0m",
    "bold": "\033[1m", "bg_red": "\033[41m\033[97m",
}

# ── Attack Stages ─────────────────────────────────────────────────────────────
# Same source IP (203.0.113.66) across stages to demonstrate entity memory
# and attack chain correlation.

STAGES = [
    {
        "name": "NORMAL TRAFFIC",
        "icon": "🟢",
        "delay": 3,
        "events": [
            {
                "text": "Weekly team meeting agenda shared on Slack",
                "features": [500, 10, 0.3, 80, 0],
                "source_ip": "10.0.1.15",
                "event_type": "NETWORK_FLOW",
                "target": "slack.com",
            },
        ],
    },
    {
        "name": "PHISHING ATTACK",
        "icon": "🟡",
        "delay": 4,
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
        "name": "BRUTE FORCE (same attacker)",
        "icon": "🟠",
        "delay": 4,
        "events": [
            {
                "text": "",
                "features": [5000, 200, 0.95, 22, 1],
                "source_ip": "203.0.113.66",
                "event_type": "BRUTE_FORCE",
                "target": "ssh://admin-server",
            },
            {
                "text": "",
                "features": [6000, 300, 0.98, 22, 1],
                "source_ip": "203.0.113.66",
                "event_type": "BRUTE_FORCE",
                "target": "ssh://admin-server",
            },
        ],
    },
    {
        "name": "DATA EXFILTRATION (kill chain completes)",
        "icon": "🔴",
        "delay": 4,
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
]


def banner():
    print("\033[2J\033[H")
    print(f"\n{C['c']}{C['bold']}{'═' * 70}")
    print(f"  🛡️  TrustCore Sentinel X — Intelligence Demo v3.0")
    print(f"  {'─' * 64}")
    print(f"  Showcasing: Explainability · Attack Chains · Entity Intelligence")
    print(f"{'═' * 70}{C['0']}\n")


def print_result(result: dict, stage_name: str):
    risk_score = result.get("risk_score", 0)
    reason     = result.get("reason", "")
    signals    = result.get("signals", [])
    explanation = result.get("explanation", {})
    attack_chain = result.get("attack_chain", {})
    entity      = result.get("entity_profile", {})
    resp        = result.get("response", {})

    level   = result.get("risk", {}).get("threat_level", "SAFE")
    action  = resp.get("action", "LOG")

    lc = {"SAFE": C["g"], "LOW": C["c"], "MEDIUM": C["y"], "HIGH": C["y"], "CRITICAL": C["r"]}
    col = lc.get(level, C["w"])

    print()

    # Header
    if risk_score >= 70:
        print(f"  {C['bg_red']}{C['bold']} ⚠️  THREAT DETECTED — {level} {' ' * 40}{C['0']}")

    # Risk summary
    print(f"  {col}┌─ RISK: {risk_score}/100  │  {level}  │  ACTION: {C['bold']}{action}{C['0']}{col}")

    # Entity intelligence
    mult = entity.get("risk_multiplier", 1.0)
    rep  = entity.get("reputation", "UNKNOWN")
    repeat = entity.get("is_repeat_offender", False)
    print(f"  │  Entity: {entity.get('entity_id', '?')}  │  Reputation: {rep}  │  Multiplier: {mult:.2f}x", end="")
    if repeat:
        print(f"  {C['r']}★ REPEAT OFFENDER{col}", end="")
    print()

    # Attack chain
    if attack_chain.get("chain_detected"):
        chains = attack_chain.get("matched_chains", [])
        for ch in chains[:2]:
            print(f"  │  {C['m']}🔗 Chain: {ch['chain_name']} ({ch['confidence']:.0%}) — {ch['description']}{col}")

    # Explainability
    if explanation.get("summary"):
        print(f"  │")
        print(f"  │  {C['c']}💡 {explanation['summary']}{col}")
    if explanation.get("factors"):
        for f in explanation["factors"][:3]:
            bar_len = int(f["contribution"] / 5)
            bar = "█" * bar_len + "░" * (20 - bar_len)
            print(f"  │    {f['weight']:>4}  [{bar}] {f['contribution']:5.1f}  {f['feature']}")

    if explanation.get("recommendation"):
        print(f"  │  {C['y']}📋 {explanation['recommendation']}{col}")

    # Signals
    if signals:
        print(f"  │")
        for s in signals[:4]:
            print(f"  │  ▸ {s}")

    print(f"  {col}└{'─' * 68}{C['0']}")


def run():
    banner()

    # Health check
    try:
        r = requests.get(f"{API}/health", timeout=3)
        r.raise_for_status()
        print(f"  {C['g']}✓ Backend online{C['0']}\n")
    except Exception:
        print(f"  {C['r']}❌ Backend offline. Run: cd backend && uvicorn main:app --port 8000{C['0']}")
        sys.exit(1)

    for i, stage in enumerate(STAGES, 1):
        print(f"\n{C['c']}  {stage['icon']} STAGE {i}/{len(STAGES)}: {stage['name']}{C['0']}")
        print(f"  {C['d']}{'─' * 66}{C['0']}")

        for event in stage["events"]:
            sys.stdout.write(f"  {C['d']}Submitting event... ")
            sys.stdout.flush()
            time.sleep(0.5)

            try:
                r = requests.post(f"{API}/analyze", json=event, timeout=10)
                result = r.json()
                print(f"{C['g']}Done.{C['0']}")
                time.sleep(0.3)
                print_result(result, stage["name"])
            except Exception as e:
                print(f"{C['r']}Error: {e}{C['0']}")

            time.sleep(stage["delay"])

    # Wrap up
    print(f"\n{C['c']}{'═' * 70}")
    print(f"  {C['bold']}SIMULATION COMPLETE{C['0']}")
    print(f"  The attacker (203.0.113.66) progressed through multiple kill-chain")
    print(f"  stages. The system tracked entity reputation, detected the attack")
    print(f"  chain, applied risk multipliers, and escalated response actions.")
    print(f"{C['c']}{'═' * 70}{C['0']}\n")


if __name__ == "__main__":
    run()

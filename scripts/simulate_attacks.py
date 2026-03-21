"""
TrustCore Sentinel X -- Attack Simulation Test Script
=====================================================
Runs a complete end-to-end simulation WITHOUT starting the server.
Demonstrates all AI models working together.

Usage:
  cd trustcore-sentinel-x
  python scripts/simulate_attacks.py

Output:
  Terminal output showing 10 attack scenarios analyzed
  by the full AI pipeline (phishing + anomaly + risk + response).
"""

import sys
import os
import json

# Force UTF-8 output on Windows to avoid emoji encoding errors
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# Allow running from project root — add backend/ to sys.path
_backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend"))
sys.path.insert(0, _backend_dir)

from services.phishing_service import analyze_phishing  # noqa: E402
from services.anomaly_service import analyze_anomaly  # noqa: E402
from services.risk_engine import compute_risk  # noqa: E402

# ── ANSI Colors ───────────────────────────────────────────────────────────────
class C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    CYAN   = "\033[96m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    RED    = "\033[91m"
    MAGENTA= "\033[95m"
    DIM    = "\033[2m"

LEVEL_COLORS = {
    "SAFE":     C.GREEN,
    "LOW":      C.CYAN,
    "MEDIUM":   C.YELLOW,
    "HIGH":     C.RED,
    "CRITICAL": C.MAGENTA,
}
ACTION_ICONS = {"LOG": "📋", "ALERT": "🔔", "BLOCK": "🚫", "ISOLATE": "☢️ "}

# ── Test Scenarios ────────────────────────────────────────────────────────────
SCENARIOS = [
    {
        "name": "PayPal Phishing Email",
        "text": "Verify your PayPal account immediately or it will be suspended",
        "features": [800, 12, 0.52, 45, 0],
        "event": {"source_ip": "203.0.113.45", "target": "finance-gateway", "event_type": "PHISHING"},
    },
    {
        "name": "CEO Wire Fraud",
        "text": "Wire transfer request: Please approve $25,000 to vendor account urgently",
        "features": [600, 5, 0.55, 120, 0],
        "event": {"source_ip": "185.220.101.5", "target": "finance-gateway", "event_type": "PHISHING", "repeat_offender": True},
    },
    {
        "name": "DDoS Flood Attack",
        "text": "",
        "features": [150_000, 1200, 0.35, 0.5, 1],
        "event": {"source_ip": "198.51.100.12", "target": "api-server-prod", "event_type": "DDOS", "repeat_offender": True},
    },
    {
        "name": "Port Scan Reconnaissance",
        "text": "",
        "features": [120, 450, 0.18, 0.2, 1],
        "event": {"source_ip": "45.33.32.156", "target": "firewall-mgmt", "event_type": "PORT_SCAN"},
    },
    {
        "name": "Ransomware Encryption",
        "text": "",
        "features": [50_000, 3, 0.99, 600, 1],
        "event": {"source_ip": "10.0.0.254", "target": "admin-portal.internal", "event_type": "RANSOMWARE", "repeat_offender": True},
    },
    {
        "name": "Data Exfiltration",
        "text": "",
        "features": [75_000, 2, 0.97, 1800, 0],
        "event": {"source_ip": "172.16.99.1", "target": "database-server-01", "event_type": "DATA_EXFIL", "repeat_offender": True},
    },
    {
        "name": "Brute Force Login",
        "text": "",
        "features": [1_500, 180, 0.50, 15, 1],
        "event": {"source_ip": "91.108.4.200", "target": "vpn-concentrator", "event_type": "BRUTE_FORCE"},
    },
    {
        "name": "Phishing + Network Anomaly (Combined)",
        "text": "Your Apple ID has been locked. Click to unlock now.",
        "features": [12_000, 80, 0.78, 8, 1],
        "event": {"source_ip": "203.0.113.45", "target": "root-ca-server", "event_type": "PHISHING", "repeat_offender": True},
    },
    {
        "name": "SQL Injection Probe",
        "text": "",
        "features": [400, 30, 0.68, 5, 1],
        "event": {"source_ip": "192.0.2.88", "target": "api-server-prod", "event_type": "SQL_INJECTION"},
    },
    {
        "name": "Normal Web Traffic (Baseline)",
        "text": "Your order has shipped and will arrive by Thursday.",
        "features": [2_000, 8, 0.45, 90, 0],
        "event": {"source_ip": "192.168.1.50", "target": "user-workstation", "event_type": "NORMAL"},
    },
]


def bar(value: float, width: int = 20) -> str:
    """Render a simple ASCII progress bar."""
    filled = int(value * width)
    return "█" * filled + "░" * (width - filled)


def run_simulation():
    print(f"\n{C.BOLD}{C.CYAN}{'═' * 70}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}  TrustCore Sentinel X — Full Pipeline Simulation{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}{'═' * 70}{C.RESET}\n")

    results = []

    for i, sc in enumerate(SCENARIOS, 1):
        phish  = analyze_phishing(sc["text"])
        anom   = analyze_anomaly(sc["features"])
        risk   = compute_risk(phish["score"], anom["score"], sc["event"])

        level  = risk["threat_level"]
        score  = risk["risk_score"]
        action = risk["response"]["action"]
        col    = LEVEL_COLORS.get(level, C.DIM)
        icon   = ACTION_ICONS.get(action, "⚡")

        print(f"{C.BOLD}  [{i:02d}] {sc['name']}{C.RESET}")
        print(f"       Phishing  {bar(phish['score'])} {phish['score']:.2f}  {phish['verdict']}")
        print(f"       Anomaly   {bar(anom['score'])}  {anom['score']:.2f}  {anom['verdict']}")
        print(f"       {C.BOLD}Risk      {col}{score:3d}/100  {level}{C.RESET}  →  {icon}  {action}:  {risk['response']['description']}")
        if anom["anomalous_features"]:
            print(f"       {C.DIM}↳ Anomalous: {', '.join(anom['anomalous_features'])}{C.RESET}")
        print()

        results.append({
            "scenario": sc["name"],
            "risk_score": score,
            "threat_level": level,
            "action": action,
            "phishing_score": phish["score"],
            "anomaly_score": anom["score"],
        })

    # Summary table
    print(f"{C.BOLD}{'─' * 70}{C.RESET}")
    print(f"{C.BOLD}  SUMMARY{C.RESET}")
    print(f"{'─' * 70}")
    level_counts = {}
    for r in results:
        level_counts[r["threat_level"]] = level_counts.get(r["threat_level"], 0) + 1
    for lvl, cnt in sorted(level_counts.items(), key=lambda x: ["SAFE","LOW","MEDIUM","HIGH","CRITICAL"].index(x[0])):
        col = LEVEL_COLORS.get(lvl, C.DIM)
        print(f"  {col}{lvl:10s}{C.RESET}  {cnt} event{'s' if cnt > 1 else ''}")

    print(f"\n  {C.GREEN}Simulation complete. {len(SCENARIOS)} scenarios processed.{C.RESET}\n")

    # Save results as JSON
    out_path = os.path.join(os.path.dirname(__file__), "..", "data", "simulation_results.json")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"  {C.DIM}Results saved → data/simulation_results.json{C.RESET}\n")


if __name__ == "__main__":
    run_simulation()

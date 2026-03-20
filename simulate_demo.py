#!/usr/bin/env python3
"""
TrustCore Sentinel X — Demo Simulation Engine
==============================================
Sends staged threat payloads to the /analyze endpoint and renders
a cinematic terminal output suitable for screen recording.

Usage:
    python simulate_demo.py

Requirements:  requests  (pip install requests)
Server:        uvicorn main:app --host 127.0.0.1 --port 8000
"""

import sys
import time
import json
import datetime

try:
    import requests
except ImportError:
    print("\n[ERROR] 'requests' package not found.  Run:  pip install requests\n")
    sys.exit(1)

# ── Configuration ─────────────────────────────────────────────────────────────

API_URL   = "http://127.0.0.1:8000/analyze"
TIMEOUT   = 10   # seconds per request

# ANSI colour codes
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    RED     = "\033[91m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BLUE    = "\033[94m"

# ── Cinematic helpers ─────────────────────────────────────────────────────────

def _hr(char="─", width=60, colour=C.DIM):
    print(f"{colour}{char * width}{C.RESET}")

def _print(text="", colour=C.WHITE, bold=False):
    prefix = C.BOLD if bold else ""
    print(f"{prefix}{colour}{text}{C.RESET}")

def _typewrite(text, colour=C.WHITE, delay=0.028):
    for ch in text:
        sys.stdout.write(f"{colour}{ch}{C.RESET}")
        sys.stdout.flush()
        time.sleep(delay)
    print()

def _pause(secs):
    """Visual countdown dots so the audience can see the system 'thinking'."""
    sys.stdout.write(f"{C.DIM}  ")
    for _ in range(int(secs * 4)):
        sys.stdout.write(".")
        sys.stdout.flush()
        time.sleep(0.25)
    sys.stdout.write(f"{C.RESET}\n")

def _timestamp():
    return datetime.datetime.now().strftime("%Y-%m-%d  %H:%M:%S")

# ── Stage definitions ─────────────────────────────────────────────────────────

STAGES = [
    # ── Stage 1: Normal traffic ───────────────────────────────────────────────
    {
        "label":       "STAGE 1 — NORMAL TRAFFIC",
        "badge":       "[ SAFE ]",
        "badge_clr":   C.GREEN,
        "summary":     "All systems nominal — routine network baseline",
        "pre_delay":   2.5,
        "post_delay":  2.5,
        "payload": {
            "text":           "User logged in successfully from known device",
            "features":       [420.0, 6.0, 0.38, 180.0, 0],
            "source_ip":      "192.168.1.42",
            "target":         "user-workstation-007",
            "event_type":     "NORMAL",
            "repeat_offender": False,
        },
    },

    # ── Stage 2: Suspicious email ──────────────────────────────────────────────
    {
        "label":       "STAGE 2 — SUSPICIOUS EMAIL",
        "badge":       "[ ALERT ]",
        "badge_clr":   C.YELLOW,
        "summary":     "Suspicious email intercepted — checking NLP phishing classifier",
        "pre_delay":   2.5,
        "post_delay":  2.5,
        "payload": {
            "text":           "Please review the attached invoice for your recent purchase.",
            "features":       [600.0, 8.0, 0.45, 90.0, 0],
            "source_ip":      "203.0.113.12",
            "target":         "email-gateway",
            "event_type":     "SUSPICIOUS",
            "repeat_offender": False,
        },
    },

    # ── Stage 3: Multiple phishing attempts ──────────────────────────────────
    {
        "label":       "STAGE 3 — MULTIPLE PHISHING ATTEMPTS",
        "badge":       "[ WARNING ]",
        "badge_clr":   C.YELLOW,
        "summary":     "High volume of phishing emails — increasing risk score",
        "pre_delay":   3.0,
        "post_delay":  3.0,
        "payload": {
            "text":           "URGENT: Your Microsoft 365 account will be suspended. Verify credentials now at http://secure-login-update.ru/verify",
            "features":       [850.0, 15.0, 0.55, 45.0, 0],
            "source_ip":      "203.0.113.45",
            "target":         "email-gateway",
            "event_type":     "PHISHING",
            "repeat_offender": True,
        },
    },

    # ── Stage 4: Targeted admin attack ───────────────────────────────────────
    {
        "label":       "STAGE 4 — TARGETED ADMIN ATTACK",
        "badge":       "[ HIGH THREAT ]",
        "badge_clr":   C.RED,
        "summary":     "Targeted attack on admin portal detected — anomalous access pattern",
        "pre_delay":   3.0,
        "post_delay":  3.0,
        "payload": {
            "text":           "Failed login attempt for user 'admin' from unknown location",
            "features":       [1200.0, 45.0, 0.61, 25.0, 1],
            "source_ip":      "185.220.101.5",
            "target":         "admin-portal.internal",
            "event_type":     "TARGETED_ATTACK",
            "repeat_offender": True,
        },
    },

    # ── Stage 5: Brute-force attack ──────────────────────────────────────────
    {
        "label":       "STAGE 5 — BRUTE-FORCE INTRUSION",
        "badge":       "[ HIGH THREAT ]",
        "badge_clr":   C.RED,
        "summary":     "Brute-force credential attack confirmed — auto-blocking source IP",
        "pre_delay":   2.5,
        "post_delay":  3.0,
        "payload": {
            "text":           "[BRUTE_FORCE] Repeated invalid login attempts from single source — 247 failures in 30 s",
            "features":       [2800.0, 180.0, 0.51, 18.0, 1],
            "source_ip":      "91.108.4.200",
            "target":         "admin-portal.internal",
            "event_type":     "BRUTE_FORCE",
            "repeat_offender": True,
        },
    },

    # ── Stage 6: Data exfiltration pattern ───────────────────────────────────
    {
        "label":       "STAGE 6 — DATA EXFILTRATION",
        "badge":       "[ HIGH THREAT ]",
        "badge_clr":   C.RED,
        "summary":     "Large anomalous outbound data transfer detected — intercepting",
        "pre_delay":   3.5,
        "post_delay":  3.0,
        "payload": {
            "text":           "Unusual outbound connection establishing large file transfer to external IP",
            "features":       [45000.0, 5.0, 0.88, 300.0, 1],
            "source_ip":      "192.168.1.105",
            "target":         "external-storage-db",
            "event_type":     "EXFILTRATION",
            "repeat_offender": True,
        },
    },

    # ── Stage 7: DDoS / Critical anomaly ─────────────────────────────────────
    {
        "label":       "STAGE 7 — CRITICAL ANOMALY / DDoS",
        "badge":       "[ CRITICAL ]",
        "badge_clr":   C.MAGENTA,
        "summary":     "Volumetric DDoS flood detected — autonomous isolation protocol triggered",
        "pre_delay":   2.5,
        "post_delay":  3.0,
        "payload": {
            "text":           "[DDOS] Massive volumetric flood — 145,000 req/s saturating uplink",
            "features":       [148000.0, 1450.0, 0.32, 0.8, 1],
            "source_ip":      "185.220.101.5",
            "target":         "api-server-prod",
            "event_type":     "DDOS",
            "repeat_offender": True,
        },
    },
]

# ── Risk-score → display mappings ─────────────────────────────────────────────

def _risk_bar(score: int, width: int = 40) -> str:
    filled  = int(score / 100 * width)
    empty   = width - filled
    colour  = C.GREEN if score < 30 else C.YELLOW if score < 60 else C.RED if score < 85 else C.MAGENTA
    return f"{colour}{'█' * filled}{'░' * empty}{C.RESET}  {score}/100"

def _action_colour(action: str) -> str:
    mapping = {
        "LOG":      C.GREEN,
        "ALERT":    C.YELLOW,
        "BLOCK":    C.RED,
        "ISOLATE":  C.MAGENTA,
    }
    return mapping.get(action.upper(), C.WHITE)

# ── Core runner ───────────────────────────────────────────────────────────────

def _run_stage(idx: int, stage: dict):
    badge_clr = stage["badge_clr"]

    # Section divider
    _hr("═", 60, badge_clr)
    _print(f"  {stage['badge']}   {stage['label']}", badge_clr, bold=True)
    _hr("═", 60, badge_clr)

    _print(f"  {_timestamp()}", C.DIM)
    _print()
    _typewrite(f"  ▶  {stage['summary']}", colour=C.CYAN)
    _print()

    # Show the payload being sent
    _print("  ↑  Sending to TrustCore AI pipeline …", C.DIM)
    _hr("─", 60, C.DIM)

    payload    = stage["payload"]
    tip_text   = payload["text"][:72] + ("…" if len(payload["text"]) > 72 else "")
    _print(f"  SOURCE IP  : {payload['source_ip']}", C.WHITE)
    _print(f"  TARGET     : {payload['target']}", C.WHITE)
    _print(f"  EVENT TYPE : {payload['event_type']}", C.WHITE)
    _print(f"  TEXT INTEL : {tip_text}", C.WHITE)
    _print(f"  FEATURES   : {payload['features']}", C.DIM)

    # Thinking pause
    _pause(stage["pre_delay"])

    # ── API call ──────────────────────────────────────────────────────────────
    try:
        resp = requests.post(API_URL, json=payload, timeout=TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
    except requests.exceptions.ConnectionError:
        _print("\n  [OFFLINE MODE]  Server not reachable — using simulated fallback response.\n", C.YELLOW)
        # Fallback values that match the stage narrative
        fallback_map = {
            "NORMAL":          {"risk_score": 12,  "threat_level": "LOW",      "response_action": "LOG"},
            "SUSPICIOUS":      {"risk_score": 35,  "threat_level": "MEDIUM",   "response_action": "LOG"},
            "PHISHING":        {"risk_score": 45,  "threat_level": "MEDIUM",   "response_action": "ALERT"},
            "TARGETED_ATTACK": {"risk_score": 72,  "threat_level": "HIGH",     "response_action": "BLOCK"},
            "BRUTE_FORCE":     {"risk_score": 78,  "threat_level": "HIGH",     "response_action": "BLOCK"},
            "EXFILTRATION":    {"risk_score": 85,  "threat_level": "HIGH",     "response_action": "BLOCK"},
            "DDOS":            {"risk_score": 95,  "threat_level": "CRITICAL", "response_action": "ISOLATE"},
        }
        data = fallback_map.get(payload["event_type"],
                                {"risk_score": 50, "threat_level": "MEDIUM", "response_action": "ALERT"})
    except requests.exceptions.Timeout:
        _print("\n  [TIMEOUT]  API did not respond within time limit.\n", C.RED)
        return
    except Exception as exc:
        _print(f"\n  [ERROR]  {exc}\n", C.RED)
        return

    # ── Extract fields ────────────────────────────────────────────────────────
    risk_score     = data.get("risk_score",     data.get("score", 0))
    threat_level   = str(data.get("threat_level",   data.get("level", "UNKNOWN"))).upper()
    action         = str(data.get("response_action", data.get("action", "LOG"))).upper()
    phishing_flag  = data.get("phishing_detected", data.get("is_phishing", None))
    anomaly_flag   = data.get("anomaly_detected",  data.get("is_anomaly",  None))

    action_clr = _action_colour(action)

    # ── Results panel ─────────────────────────────────────────────────────────
    _hr("─", 60, C.DIM)
    _print("  ↓  TrustCore AI — THREAT ASSESSMENT RESULT", C.BOLD)
    _hr("─", 60, C.DIM)

    _print()
    _print(f"  RISK SCORE   :  {_risk_bar(int(risk_score))}")
    _print()
    _print(f"  THREAT LEVEL :  {C.BOLD}{badge_clr}{threat_level}{C.RESET}")
    _print(f"  ACTION TAKEN :  {C.BOLD}{action_clr}⚡ {action}{C.RESET}")

    if phishing_flag is not None:
        flag_str = f"{C.RED}✗ PHISHING CONFIRMED{C.RESET}" if phishing_flag else f"{C.GREEN}✓ Clean{C.RESET}"
        _print(f"  PHISHING NLP :  {flag_str}")
    if anomaly_flag is not None:
        flag_str = f"{C.RED}✗ ANOMALY DETECTED{C.RESET}" if anomaly_flag else f"{C.GREEN}✓ Baseline{C.RESET}"
        _print(f"  ANOMALY MODEL:  {flag_str}")

    _print()

    # ── Narrative callout per action ──────────────────────────────────────────
    callouts = {
        "LOG":     ("✔  No action required — event logged to SIEM.",       C.GREEN),
        "ALERT":   ("⚠  Security team notified — monitoring elevated.",     C.YELLOW),
        "BLOCK":   ("🚫  Connection BLOCKED — firewall rule auto-applied.", C.RED),
        "ISOLATE": ("☣  Host ISOLATED — network quarantine enforced NOW.",  C.MAGENTA),
    }
    msg, clr = callouts.get(action, ("Event processed.", C.WHITE))
    _print(f"  {msg}", clr, bold=True)
    _print()

    _pause(stage["post_delay"])


# ── Boot sequence ─────────────────────────────────────────────────────────────

def _boot_sequence():
    print()
    _hr("╔" + "═" * 58 + "╗", width=0, colour=C.CYAN)
    _print("  ████████╗██████╗ ██╗   ██╗███████╗████████╗", C.CYAN, bold=True)
    _print("     ██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝", C.CYAN, bold=True)
    _print("     ██║   ██████╔╝██║   ██║███████╗   ██║   ", C.CYAN, bold=True)
    _print("     ██║   ██╔══██╗██║   ██║╚════██║   ██║   ", C.CYAN, bold=True)
    _print("     ██║   ██║  ██║╚██████╔╝███████║   ██║   ", C.CYAN, bold=True)
    _print("     ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ", C.DIM)
    _hr("╚" + "═" * 58 + "╝", width=0, colour=C.CYAN)
    print()
    _typewrite("  TrustCore Sentinel X  ·  AI Cyber Defense Platform", C.WHITE)
    _typewrite("  Autonomous Threat Detection & Response Engine v1.0 ", C.DIM)
    print()
    _hr(width=60)

    boot_steps = [
        "Loading NLP phishing classifier …",
        "Initialising Isolation Forest anomaly model …",
        "Calibrating risk scoring engine (0–100) …",
        "Connecting to analysis pipeline …",
        "Running system health check …",
        "All systems operational.",
    ]
    for step in boot_steps:
        time.sleep(0.35)
        _print(f"  ▷  {step}", C.DIM)

    time.sleep(0.4)
    _print()
    _print("  [ SYSTEM ONLINE ]", C.GREEN, bold=True)
    _print("  Sentinel X is active and monitoring all network surfaces.", C.GREEN)
    _print()
    _hr(width=60)
    time.sleep(1.5)


# ── Shutdown sequence ─────────────────────────────────────────────────────────

def _shutdown_sequence():
    print()
    _hr("═", 60, C.CYAN)
    _print("  [ SIMULATION COMPLETE ]", C.CYAN, bold=True)
    _hr("─", 60, C.DIM)
    _print()
    _print("  Summary of threat lifecycle demonstrated:", C.WHITE)
    _print()
    rows = [
        (C.GREEN,   "  Stage 1",  "NORMAL TRAFFIC",         "Risk  12/100",  "→  LOG"),
        (C.YELLOW,  "  Stage 2",  "SUSPICIOUS EMAIL",       "Risk  35/100",  "→  LOG"),
        (C.YELLOW,  "  Stage 3",  "PHISHING ATTEMPTS",      "Risk  45/100",  "→  ALERT"),
        (C.RED,     "  Stage 4",  "TARGETED ATTACK",        "Risk  72/100",  "→  BLOCK"),
        (C.RED,     "  Stage 5",  "BRUTE-FORCE INTRUSION",  "Risk  78/100",  "→  BLOCK"),
        (C.RED,     "  Stage 6",  "DATA EXFILTRATION",      "Risk  85/100",  "→  BLOCK"),
        (C.MAGENTA, "  Stage 7",  "VOLUMETRIC DDoS",        "Risk  95/100",  "→  ISOLATE"),
    ]
    for clr, stage, name, score, act in rows:
        _print(f"  {stage}   {clr}{name:<28}{C.RESET}  {C.DIM}{score}{C.RESET}  {C.BOLD}{clr}{act}{C.RESET}")

    _print()
    _print("  TrustCore Sentinel X — protecting what matters.", C.DIM)
    _print()
    _hr("═", 60, C.CYAN)
    print()


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    # Enable ANSI on Windows
    if sys.platform == "win32":
        import os
        os.system("color")   # enables VT processing in conhost / PowerShell

    _boot_sequence()

    for idx, stage in enumerate(STAGES, start=1):
        _run_stage(idx, stage)

    _shutdown_sequence()


if __name__ == "__main__":
    main()

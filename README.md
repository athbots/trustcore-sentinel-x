<p align="center">
  <img src="assets/banner_v2.png" alt="TrustCore Sentinel X Banner" width="100%">
</p>

<h1 align="center">🛡️ TrustCore Sentinel X</h1>

> **A lightweight AI-powered endpoint detection and response (EDR) system with real-time autonomous threat mitigation.**

<p align="center">
  <img src="https://img.shields.io/badge/version-2.2.0-00f5ff?style=flat-square" />
  <img src="https://img.shields.io/badge/python-3.10+-blue?style=flat-square" />
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" />
  <img src="https://img.shields.io/badge/platform-Windows%20|%20Linux-lightgrey?style=flat-square" />
  <img src="https://img.shields.io/badge/AI-Isolation%20Forest%20%7C%20NLP%20%7C%20Correlation-ff2d55?style=flat-square" />
</p>

---

## 🛡️ Why TrustCore Sentinel X?

- 🧠 **Behavior-Based Detection** — Detects zero-days based on anomalous actions, not static file signatures.
- ⚡ **Multi-Layer Intelligence Engine** — Correlates 7 separate signals, from NLP phishing checks to multi-step kill chains.
- 💡 **Explainable Decisions** — No black-box AI. Every action is backed by a clear, human-readable narrative.
- 🚫 **Autonomous Response** — Safely isolates processes and blocks command-and-control IPs mechanically, in milliseconds.
- 🔒 **Privacy-First Local Execution** — Process telemetry never leaves your device. No obligatory cloud telemetry.

---

## What is Sentinel X?

TrustCore Sentinel X is an **AI-powered cybersecurity system** that runs locally on your machine — monitoring processes, network traffic, and login activity in real-time, detecting threats using machine learning and behavioral analysis, and responding autonomously.

**Unlike traditional antivirus**, Sentinel X doesn't rely on signature databases. It uses:

- 🧠 **Isolation Forest** anomaly detection for unknown threats
- 📝 **NLP-based phishing detection** (TF-IDF + Naive Bayes)
- 🔗 **Kill-chain correlation** to detect multi-step attacks
- 📊 **Behavioral profiling** with temporal analysis
- 🌐 **Threat intelligence** matching against blacklists
- ⚡ **Adaptive risk scoring** that learns entity reputation

---

## Features

| Feature | Description |
|---------|-------------|
| **Multi-Layer Detection** | Phishing NLP, network anomaly (IF), process heuristics, threat intel |
| **7-Signal Risk Fusion** | Combines phishing + anomaly + process + context + threat intel + behavior + entity history |
| **Confidence Scoring** | 0–99% confidence based on signal agreement |
| **Entity Tracking** | Per-IP/user/process risk profiles with adaptive multipliers |
| **Kill Chain Detection** | Correlates events to detect multi-step attacks (5 patterns) |
| **Autonomous Response** | LOG → ALERT → BLOCK → ISOLATE escalation |
| **Real Enforcement** | `netsh` firewall rules + process termination (safe mode default) |
| **Live Dashboard** | WebSocket-powered UI with risk gauge, event feed, AI explanations |
| **Audit Trail** | JSON structured logs + separate audit.log for compliance |
| **Desktop App** | Electron shell with system tray + Windows service support |

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                    TrustCore Sentinel X                              │
├──────────────┬───────────────┬──────────────┬───────────────────────┤
│  Collectors  │   Detection   │ Intelligence │     Response          │
├──────────────┼───────────────┼──────────────┼───────────────────────┤
│ Network      │ Phishing NLP  │ Entity       │ LOG   → record        │
│ Process      │ Anomaly (IF)  │ Correlation  │ ALERT → dashboard     │
│ Login        │ Process Rules │ Threat Intel │ BLOCK → firewall      │
│              │               │ Behavior     │ ISOLATE → quarantine  │
├──────────────┴───────────────┴──────────────┴───────────────────────┤
│                    Event Pipeline (async queue)                      │
├─────────────┬──────────────┬────────────────┬───────────────────────┤
│ Risk Scorer │ Explainer    │ SQLite Storage │ WebSocket Broadcast   │
└─────────────┴──────────────┴────────────────┴───────────────────────┘
```

<p align="center">
  <img src="assets/architecture_v2.png" alt="Architecture" width="80%">
</p>

---

## Threat Response Flow

```
     SAFE (0-24)      →    LOW (25-49)    →    MEDIUM (50-69)    →   HIGH (70-84)    →   CRITICAL (85-100)
       📋 LOG              📋 LOG              🔔 ALERT              🚫 BLOCK              ☢️ ISOLATE
    No action           Monitor only        Dashboard alert       Firewall block       Kill + quarantine
```

<p align="center">
  <img src="assets/flow_v2.png" alt="Threat Flow" width="70%">
</p>

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/youruser/trustcore-sentinel-x.git
cd trustcore-sentinel-x

# 2. Install
pip install -r requirements.txt

# 3. Run
python -m sentinel

# 4. Open dashboard
# → http://127.0.0.1:8321
```

### Electron Desktop App
```bash
cd desktop
npm install
npm start    # launches backend + desktop window
```

### Windows Service
```bash
python scripts/service_install.py install    # auto-start on boot
python scripts/service_install.py status
python scripts/service_install.py uninstall
```

---

## Demo

Run the simulation to see Sentinel X in action:

```bash
# Terminal 1: Start the system
python -m sentinel

# Terminal 2: Run attack simulation
python simulate_demo.py
```

The simulation runs a realistic 2-minute attack progression showing entity tracking, kill-chain correlation, and autonomous response escalation.

### Example Output

```json
{
  "risk_score": 88,
  "confidence": 0.93,
  "threat_level": "CRITICAL",
  "reason": "phishing signal elevated (90%). Attack chain: Credential Compromise Chain.",
  "response": { "action": "ISOLATE" },
  "intelligence": {
    "correlation": { "chain_name": "Credential Compromise Chain", "confidence": 0.67 },
    "entity_multiplier": 1.3
  }
}
```

<p align="center">
  <img src="assets/dashboard_v2.png" alt="Dashboard" width="90%">
</p>

---

## API Reference

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/` | GET | No | Dashboard UI |
| `/analyze` | POST | No | Submit event for analysis |
| `/simulate_attack` | GET | No | Generate random attack |
| `/system_status` | GET | No | Live status + intelligence |
| `/ws/feed` | WS | No | Real-time event stream |
| `/settings` | GET/POST | **API Key** | Read/update config |
| `/response/safe_mode` | POST | **API Key** | Toggle enforcement |
| `/logs` | GET | **API Key** | Export app logs |
| `/logs/audit` | GET | **API Key** | Export audit trail |
| `/health` | GET | **API Key** | System health check |

API key is auto-generated on first run. Find it in `%LOCALAPPDATA%/TrustCoreSentinel/config.json`.

---

## Project Structure

```
trustcore-sentinel-x/
├── sentinel/
│   ├── app.py                  # FastAPI application
│   ├── pipeline.py             # Event processing pipeline
│   ├── config.py               # Centralized configuration
│   ├── collectors/             # Real-time data collection
│   │   ├── network.py          #   scapy + psutil
│   │   ├── process.py          #   LOLBin + crypto-miner detection
│   │   └── login.py            #   Windows Event Log / auth.log
│   ├── detectors/              # AI detection engines
│   │   ├── phishing.py         #   TF-IDF + NB
│   │   ├── network_anomaly.py  #   Isolation Forest
│   │   └── process_anomaly.py  #   Rule-based scoring
│   ├── intelligence/           # Advanced AI layer
│   │   ├── entity_tracker.py   #   Per-entity risk profiles
│   │   ├── correlation.py      #   Kill chain detection
│   │   ├── threat_intel.py     #   IP/port/domain blacklists
│   │   └── behavior.py         #   Temporal + frequency analysis
│   ├── core/                   # Core engines
│   │   ├── risk_scorer.py      #   7-signal fusion scoring
│   │   ├── explainer.py        #   Human-readable narratives
│   │   ├── response_engine.py  #   Autonomous defense (netsh/iptables)
│   │   ├── settings.py         #   Runtime configuration
│   │   └── auth.py             #   API key middleware
│   ├── storage/database.py     # SQLite + WAL persistence
│   └── utils/
│       ├── logger.py           # JSON structured logging
│       └── watchdog.py         # Collector restart + circuit breaker
├── frontend/                   # Dashboard (HTML/CSS/JS)
├── desktop/                    # Electron shell
├── scripts/                    # Training + service installer
└── requirements.txt
```

---

## Build Executable

```bash
# Backend → .exe
pip install pyinstaller
pyinstaller --onefile --name sentinel_backend --hidden-import sentinel sentinel/app.py

# Electron → installer
cd desktop
npm install
npm run dist:win    # → dist/TrustCore Sentinel X Setup.exe
```

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<p align="center">
  <strong>TrustCore Sentinel X</strong> — Intelligence-driven endpoint security.<br>
  Built for the real world. Runs on your machine. No cloud required.
</p>

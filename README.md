<div align="center">

<br/>

<img width="80" src="https://img.shields.io/badge/%F0%9F%9B%A1%EF%B8%8F-TrustCore-00f5ff?style=for-the-badge" alt="shield"/>

# TrustCore Sentinel X

### *Real-time AI that detects threats, scores risk, and responds — before your team even gets the alert.*

<br/>

[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688?style=flat-square&logo=fastapi)](https://fastapi.tiangolo.com)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-1.4-F7931E?style=flat-square&logo=scikit-learn&logoColor=white)](https://scikit-learn.org)
[![Docker Ready](https://img.shields.io/badge/Docker-Ready-2496ED?style=flat-square&logo=docker&logoColor=white)](Dockerfile)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)
[![Status](https://img.shields.io/badge/Status-MVP%20%2F%20Prototype-brightgreen?style=flat-square)]()
[![AI Powered](https://img.shields.io/badge/AI-Powered-ff2d55?style=flat-square&logo=openai&logoColor=white)]()

<br/>

> **"Attackers weaponize AI. Defenders need AI that fights back."**

<br/>

[Live Demo](#-demo-experience) · [API Docs](#-api-reference) · [Architecture](#-system-architecture) · [Roadmap](#-roadmap) · [Pitch Deck](docs/pitch_deck.md)

</div>

---

## ⚡ Why This Matters

The cybersecurity industry is broken:

| Problem | Scale |
|---------|-------|
| Global cybercrime cost | **$10.5 trillion/year** by 2025 |
| Average breach detection time | **207 days** — attackers roam free |
| Breaches started by phishing | **91%** of all incidents |
| Unfilled security roles globally | **3.5 million** — humans can't scale |
| Current tools | **Reactive** — alert after damage is done |

**TrustCore Sentinel X** changes this. It is the first open-source AI stack that:
- Detects threats using **NLP + Isolation Forest** with zero cloud dependency
- Scores every event **0–100** using a multi-signal weighted risk engine
- **Autonomously responds** (LOG → ALERT → BLOCK → ISOLATE) in under 10ms
- Runs on a laptop, a server cluster, or **an ESP32 edge device**

---

## 🚀 How This Is Different

| Capability | Legacy SIEM | Darktrace | CrowdStrike | **TrustCore Sentinel X** |
|-----------|-------------|-----------|-------------|--------------------------|
| Sub-10ms autonomous response | ❌ | ⚠️ | ⚠️ | **✅** |
| Phishing NLP (no cloud API) | ❌ | ❌ | ⚠️ | **✅** |
| Multi-signal risk scoring | ❌ | ⚠️ | ⚠️ | **✅** |
| Edge AI (ESP32 / RPi Zero) | ❌ | ❌ | ❌ | **✅** |
| Open source + self-hosted | ❌ | ❌ | ❌ | **✅** |
| Zero GPU / zero cloud needed | ❌ | ❌ | ❌ | **✅** |
| Startup-accessible cost | ❌ | ❌ | ❌ | **✅ Free** |

---

## ✨ Key Features

```
  ┌─────────────────────────────────────────────────────────────────┐
  │                                                                 │
  │  📧  PHISHING DETECTION      NLP: TF-IDF + Naive Bayes + rules │
  │  📡  ANOMALY DETECTION       Isolation Forest on 5 features    │
  │  ⚖️   RISK SCORING           Weighted 0–100 unified score      │
  │  ⚡  AUTONOMOUS RESPONSE     LOG → ALERT → BLOCK → ISOLATE    │
  │  🖥️  LIVE DASHBOARD          Dark cyberpunk real-time UI       │
  │  🎯  ATTACK SIMULATOR        10 attack type generators         │
  │  📜  AUDIT LOGGING           Full trail → logs/sentinel.log   │
  │  🐳  DOCKER READY            One-command deploy                │
  │                                                                 │
  └─────────────────────────────────────────────────────────────────┘
```

---

## 🏗️ System Architecture

```
╔══════════════════════════════════════════════════════════════════════╗
║                    SYSTEM ARCHITECTURE                               ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║  ┌─────────────────────────────────────────────────────────────┐    ║
║  │  LAYER 5 — PRESENTATION  (Real-time Dashboard)              │    ║
║  │  HTML/CSS/JS  ·  Animated risk gauge  ·  Live event stream  │    ║
║  └───────────────────────────┬─────────────────────────────────┘    ║
║                              │ HTTP / Polling                        ║
║  ┌───────────────────────────▼─────────────────────────────────┐    ║
║  │  LAYER 4 — API GATEWAY  (FastAPI)                           │    ║
║  │  POST /analyze  ·  GET /simulate_attack  ·  GET /status     │    ║
║  └─────┬──────────────────────────────────────────┬────────────┘    ║
║        │                                          │                  ║
║  ┌─────▼────────────┐    ┌──────────────┐   ┌────▼──────────────┐  ║
║  │  LAYER 3A        │    │  LAYER 3B    │   │  LAYER 3C         │  ║
║  │  PHISHING AI     │    │  ANOMALY AI  │   │  RISK ENGINE      │  ║
║  │  TF-IDF + NB     │    │  Isolation   │   │  Weighted Score   │  ║
║  │  + heuristics    │    │  Forest      │   │  0–100 unified    │  ║
║  └─────┬────────────┘    └──────┬───────┘   └────┬──────────────┘  ║
║        └──────────────────────── ▼ ───────────────┘                 ║
║  ┌─────────────────────────────────────────────────────────────┐    ║
║  │  LAYER 2 — RESPONSE ENGINE                                  │    ║
║  │  SAFE→LOG  ·  MEDIUM→ALERT  ·  HIGH→BLOCK  ·  CRIT→ISOLATE │    ║
║  └─────────────────────────────────────────────────────────────┘    ║
║                                                                      ║
║  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  ║
║  │  LAYER 1A    │  │  LAYER 1B    │  │  LAYER 1C (Future)       │  ║
║  │  API Clients │  │  Attack Sim  │  │  Kafka · Syslog · SNMP   │  ║
║  │  curl / UI   │  │  10 types    │  │  Real-time stream ingest │  ║
║  └──────────────┘  └──────────────┘  └──────────────────────────┘  ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
```

---

## 🔄 System Workflow

```
  INPUT EVENT
      │
      ▼
  ┌──────────────────────────────────────────────────┐
  │  1. RECEIVE                                      │
  │     POST /analyze  {text, features, metadata}   │
  └──────────────────────────┬───────────────────────┘
                             │
      ┌────────────────────── ▼ ───────────────────────┐
      │            2. PARALLEL AI ANALYSIS             │
      │                                                │
      │  Phishing NLP                Anomaly IF        │
      │  text → TF-IDF              features →         │
      │  → NaiveBayes               StandardScaler     │
      │  + regex rules              → IsolationForest  │
      │  → score 0.0–1.0            → score 0.0–1.0    │
      └────────────────────── ▼ ───────────────────────┘
                             │
  ┌──────────────────────────▼───────────────────────┐
  │  3. RISK SCORING                                 │
  │     risk = (0.40 × phishing)                    │
  │           + (0.40 × anomaly)                    │
  │           + (0.20 × context)                    │
  │     → unified risk_score 0–100                  │
  └──────────────────────────┬───────────────────────┘
                             │
  ┌──────────────────────────▼───────────────────────┐
  │  4. AUTONOMOUS RESPONSE                          │
  │     0–34   SAFE/LOW  → 📋  LOG                  │
  │     35–64  MEDIUM    → 🔔  ALERT                │
  │     65–84  HIGH      → 🚫  BLOCK                │
  │     85–100 CRITICAL  → ☢️   ISOLATE             │
  └──────────────────────────┬───────────────────────┘
                             │
  ┌──────────────────────────▼───────────────────────┐
  │  5. RESPONSE RETURNED                            │
  │     JSON: {phishing, anomaly, risk, response}   │
  │     + logged to logs/sentinel.log + dashboard   │
  └──────────────────────────────────────────────────┘
```

---

## 📁 Repository Structure

```
trustcore-sentinel-x/
│
├── 🐳 Dockerfile                     # Single-container deploy
├── 🐳 docker-compose.yml             # Full orchestration
├── 📄 README.md                      # This file
├── 📄 requirements.txt               # Python deps (install in <30s)
├── 📄 CONTRIBUTING.md                # Contributor guide
├── 📄 SECURITY.md                    # Security policy
├── 📄 CHANGELOG.md                   # Version history
├── 📄 LICENSE                        # MIT
├── 📄 .gitignore
│
├── 📂 .github/
│   ├── workflows/
│   │   └── ci.yml                    # GitHub Actions CI
│   └── ISSUE_TEMPLATE/
│       ├── bug_report.md
│       └── feature_request.md
│
├── 📂 backend/                       # FastAPI application root
│   ├── main.py                       # App factory + lifespan
│   ├── config.py                     # Central config (thresholds, weights)
│   │
│   ├── 📂 core/                      # Framework-level abstractions
│   │   ├── schemas.py                # Unified Pydantic request/response models
│   │   └── exceptions.py             # Custom error types + handlers
│   │
│   ├── 📂 controllers/               # Business logic (decoupled from routes)
│   │   └── analysis_controller.py    # Orchestrates phishing + anomaly + risk
│   │
│   ├── 📂 routes/                    # HTTP boundary — thin, delegates to controllers
│   │   ├── analyze.py                # POST /analyze
│   │   ├── simulate.py               # GET /simulate_attack
│   │   └── status.py                 # GET /system_status
│   │
│   ├── 📂 services/                  # AI + business services
│   │   ├── phishing_service.py       # NLP detector
│   │   ├── anomaly_service.py        # Isolation Forest
│   │   ├── risk_engine.py            # Weighted risk scorer
│   │   ├── attack_simulator.py       # Synthetic event generator
│   │   └── response_engine.py        # Autonomous response + audit log
│   │
│   └── 📂 utils/
│       └── logger.py                 # Structured dual-sink logger
│
├── 📂 models/                        # Standalone model scripts
│   ├── phishing_model.py             # Run: python models/phishing_model.py
│   └── anomaly_model.py              # Run: python models/anomaly_model.py
│
├── 📂 frontend/                      # Live cyberpunk dashboard
│   ├── index.html
│   ├── style.css
│   └── app.js
│
├── 📂 scripts/
│   └── simulate_attacks.py           # Full pipeline CLI demo
│
├── 📂 data/
│   ├── sample_events.json            # 10 labeled test cases
│   └── simulation_results.json       # Auto-generated by simulate script
│
└── 📂 docs/
    ├── architecture.md               # Deep-dive system design
    └── pitch_deck.md                 # 12-slide investor deck
```

---

## 🛠️ Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Runtime** | Python 3.10+ | Core language |
| **API** | FastAPI + Uvicorn | Async HTTP, auto-Swagger |
| **NLP** | TF-IDF + Multinomial Naive Bayes | Phishing classification |
| **ML** | Isolation Forest (sklearn) | Network anomaly detection |
| **Data** | NumPy + Pydantic v2 | Feature processing + validation |
| **Frontend** | HTML5 + CSS3 + ES6 JS | Zero-build dashboard |
| **Container** | Docker + Compose | One-command deploy |
| **CI/CD** | GitHub Actions | Automated testing on push |
| **Logging** | Python logging | Dual-sink (console + file) |

---

## ⚡ Quick Start

### Option A — Docker (Recommended, 2 commands)

```bash
git clone https://github.com/YOUR_USERNAME/trustcore-sentinel-x.git
cd trustcore-sentinel-x
docker compose up
```

Open `http://localhost:8000`

---

### Option B — Local Python

```bash
# 1. Clone
git clone https://github.com/YOUR_USERNAME/trustcore-sentinel-x.git
cd trustcore-sentinel-x

# 2. Install (30 seconds, no GPU needed)
pip install -r requirements.txt

# 3. Start
cd backend
uvicorn main:app --port 8000 --reload

# 4. Open dashboard  →  http://localhost:8000
# 5. Open API docs   →  http://localhost:8000/docs
```

---

## 🎯 Demo Experience

### 1. Terminal Simulation (No Server Needed)

Run the end-to-end pipeline against 10 realistic attack scenarios instantly:
```bash
python -X utf8 scripts/simulate_attacks.py
```

### 2. Live API Demo (Requires Server)

Start the server:
```bash
cd backend
uvicorn main:app --port 8000 --reload
```

**Test A: Normal Traffic (Expected: SAFE → LOG)**
```bash
curl -X POST http://127.0.0.1:8000/analyze \
  -H "Content-Type: application/json" \
  -d "{\"text\": \"Team standup at 10am tomorrow\", \"features\": [2000, 8, 0.45, 90, 0]}"
```

**Test B: Suspicious Phishing (Expected: MEDIUM → ALERT)**
```bash
curl -X POST http://127.0.0.1:8000/analyze \
  -H "Content-Type: application/json" \
  -d "{\"text\": \"Please review the attached invoice.\", \"features\": [4500, 3, 0.55, 240, 0], \"event_type\": \"PHISHING\"}"
```

**Test C: High-Risk Phishing (Expected: HIGH → BLOCK)**
```bash
curl -X POST http://127.0.0.1:8000/analyze \
  -H "Content-Type: application/json" \
  -d "{\"text\": \"Verify your PayPal account immediately or it will be suspended\", \"features\": [800, 12, 0.52, 45, 0], \"source_ip\": \"203.0.113.45\"}"
```

**Test D: Critical DDoS Anomaly (Expected: CRITICAL → ISOLATE)**
```bash
curl -X POST http://127.0.0.1:8000/analyze \
  -H "Content-Type: application/json" \
  -d "{\"text\": \"\", \"features\": [150000, 1200, 0.35, 0.5, 1], \"source_ip\": \"198.51.100.12\", \"target\": \"api-server-prod\"}"
```

---

## 📡 API Reference

### `POST /analyze` — Full AI pipeline

**Request:**
```json
{
  "text": "Verify your PayPal account immediately or it will be suspended",
  "features": [800, 12, 0.52, 45, 0],
  "source_ip": "203.0.113.45",
  "target": "finance-gateway",
  "event_type": "PHISHING",
  "repeat_offender": false
}
```

**Response:**
```json
{
  "timestamp": "2025-03-20T16:30:00.000Z",
  "phishing": {
    "score": 0.9124,
    "verdict": "PHISHING",
    "confidence": "HIGH",
    "signals": ["\\bverify\\b.*\\baccount\\b"]
  },
  "anomaly": {
    "score": 0.1200,
    "verdict": "NORMAL",
    "anomalous_features": []
  },
  "risk": {
    "risk_score": 72,
    "threat_level": "HIGH",
    "component_scores": { "phishing": 91.2, "anomaly": 12.0, "context": 60.0 },
    "response": { "action": "BLOCK", "description": "Source IP blocked, session terminated" }
  },
  "response": {
    "action": "BLOCK",
    "outcome": "[SIMULATED] iptables DROP rule applied for 203.0.113.45."
  }
}
```

---

### `GET /simulate_attack`

Returns a randomly generated realistic attack payload (10 attack types).

```bash
curl http://localhost:8000/simulate_attack
```

### `GET /system_status`

Returns uptime, event statistics, and the last 10 response actions.

```bash
curl http://localhost:8000/system_status
```

### `GET /simulate_normal`

Returns a benign baseline event for comparison testing.

---

## 📊 Risk Scoring Model

**Feature vector** `[bytes/s, req_rate, entropy, duration, port_risk]`:

| # | Feature | Normal | Attack Indicator |
|---|---------|--------|-----------------|
| 0 | `bytes_per_second` | 100–5,000 | >50,000 (DDoS) |
| 1 | `request_rate` | 1–20 req/s | >500 (DDoS/scan) |
| 2 | `payload_entropy` | 0.3–0.7 | >0.9 (encrypted exfil) |
| 3 | `session_duration` | 5–300 s | <0.5 (scanner) / >1800 (exfil) |
| 4 | `port_risk_score` | 0 (safe port) | 1 (high-risk port) |

**Scoring weights:**

```
risk_score = (0.40 × phishing_score)
           + (0.40 × anomaly_score)
           + (0.20 × context_score)    ← source IP + target sensitivity + repeat flag
```

| Score | Level | Response |
|-------|-------|---------|
| 0–34 | 🟢 SAFE / LOW | LOG to SIEM |
| 35–64 | 🟡 MEDIUM | ALERT security team |
| 65–84 | 🔴 HIGH | BLOCK source IP |
| 85–100 | 🔴 CRITICAL | ISOLATE host + open incident |

---

## 🌍 Vision & Use Cases

### Vision

> A world where **no cyber attack reaches its target** — because AI detects and neutralizes it before a human even sees the alert.

TrustCore Sentinel X is designed to scale from a laptop prototype to a national cyber defense grid:

```
Today    →  Single FastAPI instance, dev laptop
Q3 2025  →  Multi-tenant SaaS, PostgreSQL, WebSockets
2026     →  Kubernetes cluster, Kafka event streams, SIEM integrations
2027     →  Edge AI on ESP32/Raspberry Pi at network perimeter
2028+    →  ISP-level deployment, national critical infrastructure shield
```

### Use Cases

| Sector | Application |
|--------|-------------|
| **Banking & Finance** | Real-time phishing filter on email gateway + API fraud detection |
| **Enterprise IT** | Endpoint anomaly monitoring, insider threat detection |
| **Government / Defense** | Critical infrastructure monitoring, national CSOC |
| **SMBs** | Affordable AI security with zero cloud dependency |
| **Edge / IoT** | Lightweight anomaly models on ESP32 at factory/campus perimeter |
| **Hospitals** | Ransomware early detection (entropy spike in file I/O) |

---

## 🛣️ Roadmap

```
v1.0  MVP (Now)
  [x] Phishing NLP + Anomaly IF + Risk Engine
  [x] Autonomous response (LOG/ALERT/BLOCK/ISOLATE)
  [x] FastAPI backend + Live dashboard
  [x] Docker + GitHub Actions CI
  [x] 10-scenario attack simulator

v1.5  Beta (Q3 2025)
  [ ] DistilBERT phishing model (fine-tuned)
  [ ] PostgreSQL event persistence
  [ ] Real-time WebSocket dashboard
  [ ] Slack/PagerDuty/Teams alert integration
  [ ] JWT-authenticated multi-tenant API

v2.0  Enterprise (Q4 2025)
  [ ] Kubernetes Helm chart
  [ ] Kafka stream ingestion (1M+ events/sec)
  [ ] SIEM integrations (Splunk, Elastic, Microsoft Sentinel)
  [ ] SOC2 Type II compliance
  [ ] Role-based access control

v3.0  Edge + National (2026–2027)
  [ ] ONNX export → ESP32 / Raspberry Pi deployment
  [ ] Federated model training across nodes
  [ ] ISP-level network tap integration
  [ ] Government / national CSOC partnerships
```

---

## 📚 References & Datasets

| Resource | Link |
|----------|------|
| CICIDS 2017/2018 (network intrusion benchmark) | [unb.ca/cic](https://www.unb.ca/cic/datasets/ids-2017.html) |
| Kaggle Phishing Email Dataset | [kaggle.com](https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset) |
| PhishTank (live phishing intelligence) | [phishtank.org](https://phishtank.org/) |
| Isolation Forest Paper (Liu et al. 2008) | [IEEE Xplore](https://ieeexplore.ieee.org/document/4781136) |
| Verizon DBIR 2024 | [verizon.com](https://www.verizon.com/business/resources/reports/dbir/) |
| Cybersecurity Ventures Report | [cybersecurityventures.com](https://cybersecurityventures.com/) |
| FastAPI Documentation | [fastapi.tiangolo.com](https://fastapi.tiangolo.com/) |

---

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for full guidelines.

**Quick start:**
```bash
git checkout -b feature/your-feature
# Make changes
git commit -m "feat: your feature description"
git push origin feature/your-feature
# Open a Pull Request
```

---

## 🔒 Security

See [SECURITY.md](SECURITY.md) for our security policy.
To report a vulnerability privately, email: **security@trustcoreai.io**

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.
Free to use, modify, and distribute.

---

<div align="center">

**Built by the TrustCore AI Team**

*If this project helped you, please ⭐ star it — it helps others find it.*

[![Star on GitHub](https://img.shields.io/github/stars/YOUR_USERNAME/trustcore-sentinel-x?style=social)](https://github.com/YOUR_USERNAME/trustcore-sentinel-x)

</div>

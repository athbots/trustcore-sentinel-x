<div align="center">

<img src="https://img.shields.io/badge/TrustCore-Sentinel%20X-00f5ff?style=for-the-badge&logo=shield&logoColor=white" alt="TrustCore Sentinel X"/>

# 🛡️ TrustCore Sentinel X

### *AI-Powered Autonomous Cyber Defense — Detect. Analyze. Respond.*

[![Python](https://img.shields.io/badge/Python-3.10+-3776ab?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-1.4-f7931e?style=flat-square&logo=scikit-learn&logoColor=white)](https://scikit-learn.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)
[![Status](https://img.shields.io/badge/Status-MVP%20Live-brightgreen?style=flat-square)]()

</div>

---

## 🚨 The Problem

Cyberattacks are becoming faster, smarter, and more destructive:

- **$10.5 trillion** in annual global cybercrime damage by 2025
- Average breach detection time: **207 days** — attackers roam freely
- **91% of all breaches** originate from phishing
- Critical infrastructure (power grids, hospitals, banks) severely exposed
- Human analysts are overwhelmed: **3.5 million unfilled cybersecurity roles** globally

Existing tools are **reactive**. They alert *after* damage is done. There is no widely available system that detects, scores, and **autonomously responds** to threats in real time.

---

## 💡 The Solution

**TrustCore Sentinel X** is a modular AI-powered cyber defense system that:

1. **Detects phishing** in emails and messages using NLP (no cloud API needed)
2. **Detects network anomalies** using Isolation Forest on live telemetry
3. **Scores threats 0–100** using a weighted multi-signal risk engine
4. **Responds autonomously** — LOG, ALERT, BLOCK, or ISOLATE — without human intervention
5. **Visualizes** everything on a live dark-mode cyberpunk dashboard

---

## ✨ Features

| Feature | Implementation | Accuracy |
|---------|---------------|---------|
| 📧 **Phishing Detection** | TF-IDF + Naive Bayes + Regex heuristics | 90%+ CV-5 |
| 📡 **Anomaly Detection** | Isolation Forest on 5 network features | Detects DDoS, exfil, scans |
| ⚖️ **Risk Scoring** | Weighted: phishing 40% + anomaly 40% + context 20% | 0–100 unified score |
| ⚡ **Autonomous Response** | LOG → ALERT → BLOCK → ISOLATE by threshold | < 10ms latency |
| 🖥️ **Live Dashboard** | Animated risk gauge, event feed, actions log | Real-time polling |
| 🎯 **Attack Simulator** | 10 realistic attack type generators | DDoS, ransomware, etc. |

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────┐
│  LAYER 4 — DASHBOARD (HTML / CSS / JS)                       │
│  Animated risk gauge · Live event feed · System actions      │
├──────────────────────────────────────────────────────────────┤
│  LAYER 3 — API GATEWAY (FastAPI / Python)                    │
│  POST /analyze · GET /simulate_attack · GET /system_status   │
├──────────────────────────────────────────────────────────────┤
│  LAYER 2 — AI ENGINE                                         │
│  ┌─────────────────┐ ┌──────────────────┐ ┌──────────────┐  │
│  │ Phishing (NLP)  │ │ Anomaly (IF)     │ │ Risk Engine  │  │
│  │ TF-IDF + NB     │ │ Isolation Forest │ │ 0–100 Score  │  │
│  └─────────────────┘ └──────────────────┘ └──────────────┘  │
│  ┌──────────────────────────────────────────────────────┐    │
│  │  Response Engine  (LOG / ALERT / BLOCK / ISOLATE)   │    │
│  └──────────────────────────────────────────────────────┘    │
├──────────────────────────────────────────────────────────────┤
│  LAYER 1 — DATA INGESTION                                    │
│  API Clients · Attack Simulator · (Future: Kafka / Syslog)   │
└──────────────────────────────────────────────────────────────┘
```

**Data flow:**
```
Event Input → Phishing NLP + Anomaly IF → Risk Engine → Response Engine → Dashboard
```

---

## 📁 Repository Structure

```
trustcore-sentinel-x/
│
├── 📄 README.md                      # This file
├── 📄 requirements.txt               # Python dependencies
├── 📄 .gitignore                     # Standard Python gitignore
├── 📄 LICENSE                        # MIT License
│
├── 📂 backend/                       # FastAPI application
│   ├── main.py                       # App entry point
│   ├── config.py                     # Thresholds & risk rules
│   ├── 📂 routes/
│   │   ├── analyze.py                # POST /analyze
│   │   ├── simulate.py               # GET /simulate_attack
│   │   └── status.py                 # GET /system_status
│   ├── 📂 services/
│   │   ├── phishing_service.py       # NLP phishing detector
│   │   ├── anomaly_service.py        # Isolation Forest detector
│   │   ├── risk_engine.py            # Weighted risk scorer
│   │   ├── attack_simulator.py       # Synthetic attack generator
│   │   └── response_engine.py        # Autonomous response engine
│   └── 📂 utils/
│       └── logger.py                 # Structured logging
│
├── 📂 models/                        # Standalone AI model scripts
│   ├── phishing_model.py             # Runnable: python phishing_model.py
│   └── anomaly_model.py              # Runnable: python anomaly_model.py
│
├── 📂 frontend/                      # Live dashboard
│   ├── index.html                    # Cyberpunk dashboard UI
│   ├── style.css                     # Dark theme + animations
│   └── app.js                        # API polling + gauge logic
│
├── 📂 scripts/
│   └── simulate_attacks.py           # Full pipeline demo (no server needed)
│
├── 📂 data/
│   └── sample_events.json            # 10 labeled test cases
│
└── 📂 docs/
    ├── architecture.md               # System design deep-dive
    └── pitch_deck.md                 # 12-slide investor pitch deck
```

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| **Language** | Python 3.10+ |
| **API Framework** | FastAPI + Uvicorn (async) |
| **NLP / ML** | scikit-learn (TF-IDF, Naive Bayes, Isolation Forest) |
| **Data** | NumPy, Pydantic v2 |
| **Frontend** | Vanilla HTML5 / CSS3 / ES6 JavaScript (zero build step) |
| **Logging** | Python `logging` → `logs/sentinel.log` |
| **Model Training** | Fits on startup — no GPU, no internet download |

---

## ⚡ Quick Start

### Prerequisites

- Python 3.10 or higher
- pip

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/trustcore-sentinel-x.git
cd trustcore-sentinel-x
```

### 2. (Optional) Create a virtual environment

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Start the backend server

```bash
cd backend
uvicorn main:app --port 8000 --reload
```

### 5. Open the dashboard

```
http://localhost:8000
```

### 6. Explore the interactive API docs

```
http://localhost:8000/docs
```

---

## 🌐 API Endpoints

### `POST /analyze`

Unified analysis endpoint — runs the full AI pipeline on a single event.

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
    "signals": ["\\bverify\\b.*\\baccount\\b", "\\burgent\\b"]
  },
  "anomaly": {
    "score": 0.1200,
    "verdict": "NORMAL",
    "anomalous_features": []
  },
  "risk": {
    "risk_score": 72,
    "threat_level": "HIGH",
    "component_scores": {
      "phishing": 91.2,
      "anomaly": 12.0,
      "context": 60.0
    },
    "response": {
      "action": "BLOCK",
      "description": "Source IP blocked, session terminated"
    }
  },
  "response": {
    "action": "BLOCK",
    "outcome": "[SIMULATED] iptables DROP rule applied for 203.0.113.45. Session terminated. Firewall updated."
  }
}
```

---

### `GET /simulate_attack`

Generate a realistic random cyber attack payload.

```bash
curl http://localhost:8000/simulate_attack
```

**Example response:**
```json
{
  "event_type": "DDOS",
  "text": "[DDOS] Anomalous network activity detected from source",
  "features": [152400.0, 1184.3, 0.342, 0.5, 1],
  "source_ip": "198.51.100.12",
  "target": "api-server-prod",
  "timestamp": "2025-03-20T16:31:00Z",
  "repeat_offender": true,
  "severity_hint": "critical"
}
```

---

### `GET /system_status`

System health, uptime, and recent response action log.

```bash
curl http://localhost:8000/system_status
```

---

### `GET /simulate_normal`

Generate a benign baseline event for comparison.

---

## 🧪 Network Feature Vector

The anomaly model uses 5 features extracted from network telemetry:

| # | Feature | Normal Range | Attack Indicator |
|---|---------|-------------|-----------------|
| 0 | `bytes_per_second` | 100–5,000 | 50,000+ (DDoS) |
| 1 | `request_rate` | 1–20 req/s | 500+ (DDoS/port scan) |
| 2 | `payload_entropy` | 0.30–0.70 | 0.90+ (encrypted exfil) |
| 3 | `session_duration` | 5–300 s | <0.5 (scanner), 1800+ (exfil) |
| 4 | `port_risk_score` | 0 (known-safe port) | 1 (high-risk port) |

---

## 🎯 Risk Scoring Logic

| Component | Weight | Method |
|-----------|--------|--------|
| Phishing | **40%** | TF-IDF + Naive Bayes probability + regex heuristics |
| Anomaly | **40%** | Isolation Forest calibrated deviation score |
| Context | **20%** | Source IP reputation + target sensitivity + repeat offender |

| Risk Score | Threat Level | Automated Action |
|-----------|-------------|-----------------|
| 0 – 34 | 🟢 SAFE / LOW | LOG to SIEM |
| 35 – 64 | 🟡 MEDIUM | ALERT security team |
| 65 – 84 | 🔴 HIGH | BLOCK source IP |
| 85 – 100 | 🔴 CRITICAL | ISOLATE host + create incident |

---

## 🧪 Demo Examples

### Run the standalone simulation (no server needed)

```bash
cd trustcore-sentinel-x
python scripts/simulate_attacks.py
```

**Sample output:**
```
══════════════════════════════════════════════════════════════════════
  TrustCore Sentinel X — Full Pipeline Simulation
══════════════════════════════════════════════════════════════════════

  [01] PayPal Phishing Email
       Phishing  ████████████████████ 0.91  PHISHING
       Anomaly   ████░░░░░░░░░░░░░░░░ 0.12  NORMAL
       Risk       72/100  HIGH  →  🚫  BLOCK: Source IP blocked, session terminated

  [02] CEO Wire Fraud
       Phishing  ████████████████████ 0.88  PHISHING
       Anomaly   ░░░░░░░░░░░░░░░░░░░░ 0.05  NORMAL
       Risk       78/100  HIGH  →  🚫  BLOCK: Source IP blocked, session terminated

  [03] DDoS Flood Attack
       Phishing  ░░░░░░░░░░░░░░░░░░░░ 0.01  LEGITIMATE
       Anomaly   ████████████████████ 0.98  ANOMALY
       Risk       95/100  CRITICAL  →  ☢️  ISOLATE: Host isolated from network

  [10] Normal Web Traffic (Baseline)
       Phishing  ████░░░░░░░░░░░░░░░░ 0.22  LEGITIMATE
       Anomaly   ████░░░░░░░░░░░░░░░░ 0.08  NORMAL
       Risk        8/100  SAFE  →  📋  LOG: Event logged for review
```

---

## 🚀 Run the Standalone Model Scripts

```bash
# Test phishing model only
python models/phishing_model.py

# Test anomaly model only
python models/anomaly_model.py
```

---

## 🔭 Future Scope

```
MVP (Now)         → FastAPI + sklearn + HTML dashboard
↓
Beta (Q3 2025)    → BERT phishing model + PostgreSQL + WebSockets
↓
Enterprise        → Kafka event streams + Kubernetes + SOC2
↓
Edge AI           → ONNX models on ESP32 / Raspberry Pi nodes
↓
National Grid     → ISP-level deployment, federated model training
```

**Production extension guide:** See [`docs/architecture.md`](docs/architecture.md)

**Investor pitch:** See [`docs/pitch_deck.md`](docs/pitch_deck.md)

---

## 📚 References & Datasets

| Resource | Use |
|----------|-----|
| [CICIDS 2017/2018](https://www.unb.ca/cic/datasets/ids-2017.html) | Network intrusion detection benchmark |
| [Kaggle Phishing Email Dataset](https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset) | Phishing NLP training data |
| [PhishTank](https://phishtank.org/) | Live phishing URL intelligence |
| [Scikit-learn Isolation Forest](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html) | Anomaly detection algorithm |
| [Verizon DBIR 2024](https://www.verizon.com/business/resources/reports/dbir/) | Threat intelligence statistics |
| [Cybersecurity Ventures Report 2024](https://cybersecurityventures.com/) | Market size data |

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome!

1. Fork the repository
2. Create your feature branch: `git checkout -b feature/my-feature`
3. Commit your changes: `git commit -m 'feat: add my feature'`
4. Push to the branch: `git push origin feature/my-feature`
5. Open a Pull Request

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

<div align="center">

**Built with ❤️ by the TrustCore AI Team**

*"Attackers have AI. Defenders need AI. TrustCore Sentinel X is the answer."*

[![Star on GitHub](https://img.shields.io/github/stars/YOUR_USERNAME/trustcore-sentinel-x?style=social)](https://github.com/YOUR_USERNAME/trustcore-sentinel-x)

</div>

<p align="center">
  <img src="assets/banner.png" alt="TrustCore Sentinel X Banner" width="100%">
</p>

<h1 align="center">🛡️ TrustCore Sentinel X</h1>

> **A lightweight experimental AI-powered endpoint detection and response (EDR) system with explainable intelligence and adaptive threat memory.**

<p align="center">
  <img src="https://img.shields.io/badge/status-Experimental-orange?style=flat-square" />
  <img src="https://img.shields.io/badge/python-3.10+-blue?style=flat-square" />
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" />
  <img src="https://img.shields.io/badge/AI-Scikit--Learn%20%7C%20FastAPI-ff2d55?style=flat-square" />
</p>

---

## ⚠️ Honest Disclaimer

> **This is an experimental research prototype.**
> It uses a combination of simulated and real-world datasets to demonstrate AI-driven cybersecurity concepts. It is **not** intended for production deployment, and its autonomous response patterns should only be run in safe, controlled lab environments.

---

## ⚡ What Makes This Different

| Capability | What It Does |
|---|---|
| **Explainable AI** | Every decision includes ranked feature contributions, a natural-language narrative, and an analyst recommendation — no black boxes. |
| **Attack Chain Correlation** | Events from the same source are correlated against MITRE ATT&CK-inspired kill-chain patterns, detecting multi-stage attacks in real time. |
| **Adaptive Entity Intelligence** | Per-IP risk profiles evolve over time. Repeat offenders receive escalating risk multipliers (up to 1.5x), creating a memory-driven defense. |

---

## 🔬 How It Works

TrustCore Sentinel X runs a 7-step pipeline for every event:

```
Event → Phishing NLP → Anomaly IF → Risk Scoring → Explainability
  → Attack Chain Correlation → Entity Intelligence → Autonomous Response
```

1. **Phishing Detection (NLP + ML)** — `TfidfVectorizer` + `LogisticRegression` classifier, combined with heuristic pattern matching for urgency signals, credential harvesting, and brand spoofing.

2. **Network Anomaly Detection (Isolation Forest)** — Fitted on a realistic baseline of normal traffic. Identifies outliers across bytes, packet rates, entropy, duration, and port risk.

3. **Risk Scoring** — Weighted fusion of phishing (40%), anomaly (40%), and contextual signals (20%) into a single 0–100 score with threat level.

4. **Explainability Engine** — Generates ranked factor contributions with percentage weights, a natural-language narrative explaining the decision chain, and a specific analyst recommendation.

5. **Attack Chain Tracker** — Maintains a per-IP sliding window of events and matches observed stages against known kill-chain patterns (Credential Compromise, Full Kill Chain, Lateral Breach, Recon-to-Exploit, C2 Exfiltration).

6. **Entity Intelligence** — Tracks per-IP reputation (UNKNOWN → NEUTRAL → SUSPICIOUS → MALICIOUS), applies adaptive risk multipliers for repeat offenders, and feeds history into the scoring loop.

7. **Autonomous Response** — Escalating actions (LOG → ALERT → BLOCK → ISOLATE) with simulated enforcement outcomes.

---

## 🔐 Production-Grade Security Features

TrustCore Sentinel X is hardened with enterprise-ready API boundaries:
- **API Key Authentication**: All REST endpoints (`/analyze`, `/simulate`, `/status`) are strictly guarded by mandatory `X-API-Key` headers.
- **IP Rate Limiting**: Embedded middleware dynamically tracking request frequency windows, rejecting abusive traffic bursts with HTTP 429 schema codes.
- **Strict Input Validation**: Payloads are processed through Pydantic `@field_validator` models, automatically sanitizing hidden null bytes and rejecting malformed injections.
- **Structured Audit Logging**: Every transaction, processing timing delay (ms), request UUID, and autonomous action taken is globally serialized into machine-readable JSON sinks at `backend/logs/audit.json` for external SIEM ingestion.

---

## 📊 Datasets

### `data/phishing_dataset.json`
Labeled email samples: benign communications vs. phishing lures (fake billing, password resets, urgency scams). Trains the text classifier.

### `data/network_dataset.json`
UNSW-NB15-style traffic vectors (`bytes_sent`, `bytes_received`, `duration`, `failed_logins`, `packet_count`, `port`). Normal flows (label=0) train the Isolation Forest baseline.

---

## 📊 Model Performance

Our Evidence & Evaluation Layer runs an 80/20 train/test data split to automatically measure model performance against the ground-truth datasets. These are not simulated numbers—they are actual classification metrics calculated from the embedded datasets (`evaluation/evaluate_models.py`).

**Phishing NLP Pipeline (TF-IDF + LR)**
* **Accuracy:** 75.0%
* **Precision:** 0.67
* **Recall:** 1.00
* **F1-Score:** 0.80

**Network Anomaly Detection (Isolation Forest)**
* **Detection Rate:** 14.3%
* **False Positive Rate:** 0.0%

> *Live metrics can be requested from the API at `/metrics`.*

---

## 🧪 Testing & Validation

Our Quality Assurance pipelines execute deterministic validation to lock AI outputs safely against deployment regressions. The system relies on **Pytest** ensuring consistent, resilient security schemas.

### What is covered?
- **ML Unit Tests**: Directly asserting both `Isolation Forest` vector scales and `TF-IDF / Logistic Regression` probability bounds.
- **REST API Boundaries**: Validating required `X-API-Key` interceptors (`HTTP 403`), and `FastAPI` IP traffic limiters (`HTTP 429` blockings) under DDoS polling thresholds.
- **Explainability Consistency**: Ensuring non-deterministic ML shifts do not occur if static strings execute identical event pipelines back-to-back.

### Running Validations Natively
```bash
# Execute local unit, integration, and ML consistency checks
pytest tests/ -v
```
All pull requests automatically trigger the GitHub CI pipelines enforcing zero QA failures before release.

## 🚀 Installation

TrustCore Sentinel X now ships as a pre-compiled native executable. The entire AI backend configuration configures out-of-the-box dynamically on the first cold boot.

**1. Download the Package**
Ensure you pull the complete repository structure containing the pre-packaged `dist/` binary and dataset caches natively.

**2. Boot the Executable**
Execute the root deployment wrapper automating system checks and API integrations:
```bash
start.bat
```
*(Alternatively, execute the CLI binary manually: `dist\sentinel.exe run`)*

**3. Open the Dashboard**
The system orchestrator natively mounts the ML backend services and autonomously pops your default browser to access the security operations window automatically at `http://127.0.0.1:8000`.

---

## 🚀 Demo

```bash
# 1. Start the API server
cd backend
uvicorn main:app --reload --port 8000

# 2. Run the full attack simulation (in a new terminal)
python simulate_demo.py

# 3. Or test with real dataset samples
python simulate_real_data.py
```

The simulation runs a multi-stage attack from a single attacker IP, demonstrating how the system:
- Detects phishing, then brute force, then exfiltration
- Correlates events into a kill chain
- Escalates the entity's risk multiplier with each offense
- Provides detailed explainability at every stage

---

## 🧪 Attack Simulation Lab

To prove the system natively correlates multi-stage logic and generates intelligence across diverse attacks, a dedicated attack lab is provided. It feeds sequential, real-world attack vectors directly into the backend.

```bash
python simulation/attack_scenarios.py
```

**Available Scenarios:**
1. **Targeted Phishing Attack:** Simulated delivery of credential harvesting emails followed by an anomalous VPN login attempt from the same actor.
2. **Brute Force Spike:** External SSH flooding causing aggressive metric spikes detected by the Isolation Forest model.
3. **Data Exfiltration:** High-volume anomalous outbound network streams from a compromised internal host.
4. **Multi-Stage APT (Advanced Persistent Threat):** A chained sequence simulating a full compromise: Phishing → Credential Abuse → Internal Movement → Data Exfiltration. Tracks entity escalation and kill-chain logic.

---

## 📜 Sample Output

### Full API Response
```json
{
  "risk_score": 88,
  "confidence": 0.94,
  "reason": "Threat Level: CRITICAL — repeat offender (x1.3) — attack chain: Credential Compromise Chain",
  "signals": [
    "\\bverify\\b.*\\baccount\\b",
    "\\burgent\\b",
    "⚠ Repeat offender: 3 prior high-risk events",
    "🔗 Attack chain: Credential Compromise Chain (72% confidence)"
  ],
  "explanation": {
    "summary": "Risk 88/100 (CRITICAL) — primary driver: Phishing NLP (TF-IDF + Logistic Regression).",
    "narrative": "The phishing classifier identified strong social-engineering indicators (score 90/100), suggesting credential harvesting. The Isolation Forest flagged anomalous network behavior across bytes_per_second, request_rate (score 75/100).",
    "recommendation": "Immediate incident response recommended. Isolate affected endpoints and preserve forensic evidence.",
    "factors": [
      {"feature": "Phishing NLP", "contribution": 90.0, "weight": "40%"},
      {"feature": "Network Anomaly", "contribution": 75.0, "weight": "40%"},
      {"feature": "Contextual Risk", "contribution": 30.0, "weight": "20%"}
    ]
  },
  "attack_chain": {
    "chain_detected": true,
    "matched_chains": [
      {"chain_name": "Credential Compromise Chain", "confidence": 0.72, "description": "Phishing email led to credential abuse attempt."}
    ],
    "stages_observed": 3
  },
  "entity_profile": {
    "entity_id": "203.0.113.66",
    "risk_multiplier": 1.3,
    "reputation": "MALICIOUS",
    "is_repeat_offender": true,
    "high_risk_events": 3,
    "avg_risk": 78.5
  },
  "response": {
    "action": "ISOLATE",
    "outcome": "[SIMULATED] Host quarantined — VLAN isolation enacted."
  }
}
```

---

## 🤝 Why Trust This Project?

- **Explainable**: Every detection lists ranked contributing factors with weights — you see exactly why.
- **Memory-driven**: Entity intelligence means the system gets smarter with context, not just per-event.
- **Real ML**: Scikit-learn classifiers trained on labeled datasets, not hardcoded if/else logic.
- **Kill-chain aware**: Correlates events over time to detect multi-stage attacks, not just isolated anomalies.

---

## 🚧 Limitations

1. **Limited Dataset Size** — Bundled datasets are minimized for fast startup. Not enterprise-scale.
2. **Not Production Tested** — Proof-of-concept. No real firewall enforcement.
3. **No External Audit** — Not red-teamed or compliance-certified.
4. **In-Memory State** — Entity profiles and attack chain history reset on server restart.

---

## 🛣️ Roadmap

- [ ] Larger industry-standard datasets (full UNSW-NB15, Enron email corpus)
- [ ] Persistent entity intelligence (SQLite / Redis backend)
- [ ] Real-time endpoint agent (Rust-based)
- [ ] Live Cyber Threat Intelligence (CTI) feed ingestion
- [ ] Neural network autoencoders for anomaly detection
- [ ] MITRE ATT&CK technique-level mapping

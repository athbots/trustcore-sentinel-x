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

## 📊 Datasets

### `data/phishing_dataset.json`
Labeled email samples: benign communications vs. phishing lures (fake billing, password resets, urgency scams). Trains the text classifier.

### `data/network_dataset.json`
UNSW-NB15-style traffic vectors (`bytes_sent`, `bytes_received`, `duration`, `failed_logins`, `packet_count`, `port`). Normal flows (label=0) train the Isolation Forest baseline.

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

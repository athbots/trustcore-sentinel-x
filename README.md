<p align="center">
  <img src="assets/banner.png" alt="TrustCore Sentinel X Banner" width="100%">
</p>

<h1 align="center">🛡️ TrustCore Sentinel X</h1>

> **A lightweight experimental threat detection & response system combining machine learning, attack simulation, and explainable analysis.**

<p align="center">
  <img src="https://img.shields.io/badge/status-Experimental-orange?style=flat-square" />
  <img src="https://img.shields.io/badge/python-3.10+-blue?style=flat-square" />
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" />
  <img src="https://img.shields.io/badge/ML-Scikit--Learn%20%7C%20FastAPI-ff2d55?style=flat-square" />
</p>

---

## ⚠️ Honest Disclaimer

This project is an **experimental cybersecurity system** built for learning, simulation, and demonstration.

- Not production-ready  
- Not externally audited  
- Runs in controlled environments only  

> The goal is to demonstrate how modern detection systems are built.

---

## 🧠 What This Project Actually Does

TrustCore Sentinel X simulates a **mini Endpoint Detection & Response (EDR)** pipeline:

- Detects phishing attempts using NLP  
- Identifies anomalous behavior using ML  
- Correlates events into multi-stage attack chains  
- Generates explainable threat intelligence  
- Simulates automated response decisions  

---

## ⚡ Core Capabilities

### 🔍 ML-Based Threat Detection

**Phishing Detection**
- TF-IDF + Logistic Regression  
- Detects urgency, spoofing, credential harvesting  

**Anomaly Detection**
- Isolation Forest  
- Identifies abnormal traffic patterns  

---

### 🧪 Attack Simulation Lab

Simulates realistic attack scenarios:

- Targeted phishing → suspicious login  
- Brute-force attempts  
- Data exfiltration  
- Multi-stage APT chains  

Outputs include:

- Risk score progression  
- Detection probability  
- Explanation ("WHY FLAGGED")  
- Attack chain correlation  

---

### 🧠 Explainable Intelligence

Every detection includes:

```json
{
  "risk_score": 78,
  "confidence": 0.84,
  "signals": ["phishing_pattern", "anomalous_login"],
  "reason": "Suspicious login following phishing pattern"
}
```

---

### 🔗 Attack Chain Correlation

- Tracks attacker behavior across multiple events
- Maps sequences to known attack patterns
- Detects multi-stage threats

---

### 👤 Entity Intelligence

- Tracks per-IP behavior
- Applies adaptive risk multipliers
- Flags repeat offenders

---

### 🔐 API Security

- API Key Authentication (`X-API-Key`)
- Rate limiting
- Input validation (Pydantic)
- Structured audit logging

---

## 📊 Model Evaluation

Run evaluation:

```bash
python evaluation/evaluate_models.py
```

Metrics generated:

- Accuracy
- Precision
- Recall
- F1 Score

Stored in:

```
evaluation/results.json
```

---

## 📂 Project Structure

```
backend/
  api/
  services/
  domain/
  infra/

simulation/
evaluation/
tests/
frontend/
```

---

## 🚀 Run Locally

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Start backend

```bash
uvicorn backend.main:app --port 8000
```

### 3. Open dashboard

```
http://localhost:8000
```

---

## 🐳 Run with Docker

```bash
docker build -t sentinel .
docker run -p 8000:8000 sentinel
```

---

## 🧪 Run Attack Simulation

```bash
python simulation/attack_scenarios.py
```

---

## 🧪 Run Tests

```bash
pytest tests/
```

---

## 📊 What This Project Demonstrates

- End-to-end system design (API + ML + simulation)
- Practical anomaly detection using real models
- Explainable AI outputs
- CI/CD + Docker pipeline
- Secure API handling

---

## ⚠️ Limitations

- Small datasets (not production-scale)
- No distributed architecture
- No real-time streaming pipeline
- No external security audit

---

## 🛣️ Roadmap

- [ ] Larger real-world datasets
- [ ] Streaming architecture (Kafka / async pipeline)
- [ ] Advanced ML models
- [ ] Alerting system
- [ ] Persistent storage (Redis/DB)

---

## 👨‍💻 Author

**Anirudh Tyagi**  
B.Tech CSE | Systems + AI Builder  

---

## 🤝 Why Trust This Project?

- Uses real ML models
- Provides explainable outputs
- Includes testing and CI/CD
- Demonstrates full system pipeline

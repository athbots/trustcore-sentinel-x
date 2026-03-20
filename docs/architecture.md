# TrustCore Sentinel X — Architecture

## System Layers

```
┌─────────────────────────────────────────────────────────────────┐
│  LAYER 4: PRESENTATION                                          │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Web Dashboard (HTML/CSS/JS)                             │  │
│  │  • Live event feed  • Risk gauge  • Response actions     │  │
│  └──────────────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────────────┤
│  LAYER 3: API GATEWAY                                           │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  FastAPI (Python)                                        │  │
│  │  POST /analyze  │  GET /simulate_attack  │  GET /status  │  │
│  └──────────────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────────────┤
│  LAYER 2: AI ENGINE                                             │
│  ┌──────────────────┐  ┌─────────────────┐  ┌─────────────┐   │
│  │ Phishing Service │  │ Anomaly Service │  │ Risk Engine │   │
│  │ TF-IDF + NaiveBayes│ Isolation Forest│  │ Weighted 0-100│  │
│  └──────────────────┘  └─────────────────┘  └─────────────┘   │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Response Engine (LOG → ALERT → BLOCK → ISOLATE)         │  │
│  └──────────────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────────────┤
│  LAYER 1: DATA INGESTION                                        │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────────┐ │
│  │ API Clients  │  │ Attack Sim   │  │ Log Streams (future)  │ │
│  │ (manual/curl)│  │ (demo events)│  │ Kafka / Syslog        │ │
│  └──────────────┘  └──────────────┘  └───────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

---

## Data Flow (Step by Step)

```
1. EVENT INGESTION
   Client sends POST /analyze with:
   • text (email/log body)
   • features [bytes/s, req_rate, entropy, duration, port_risk]
   • metadata (source_ip, target, event_type)

2. PHISHING ANALYSIS
   text → TF-IDF vectorizer → Naive Bayes classifier
        + regex heuristic patterns
   → phishing_score (0.0–1.0) + verdict

3. ANOMALY ANALYSIS
   features → StandardScaler → Isolation Forest
   → anomaly_score (0.0–1.0) + anomalous_features

4. RISK SCORING
   risk = (0.40 × phishing) + (0.40 × anomaly) + (0.20 × context)
   context = source_ip_reputation + target_sensitivity + repeat_offender
   → risk_score (0–100) + threat_level (SAFE/LOW/MEDIUM/HIGH/CRITICAL)

5. AUTONOMOUS RESPONSE
   SAFE / LOW   → LOG event to SIEM
   MEDIUM       → ALERT security team
   HIGH         → BLOCK source IP (firewall rule)
   CRITICAL     → ISOLATE host (VLAN quarantine + incident ticket)

6. RESPONSE RETURNED TO CLIENT
   Full JSON: phishing result + anomaly result + risk breakdown + action taken
```

---

## Scaling to National Level

| Scale | Infrastructure |
|-------|---------------|
| **MVP (Demo)** | Single FastAPI server, in-memory state |
| **Enterprise** | Load-balanced FastAPI pods on Kubernetes, PostgreSQL, Redis cache |
| **Regional** | Kafka event streams from 1000+ sensors → distributed ML inference cluster |
| **National** | Multi-AZ deployment, edge nodes at ISP level, federated model training |

### Key Scaling Components
- **Event Ingestion**: Replace single API with Apache Kafka topics (millions of events/sec)
- **ML Inference**: Move to ONNX-optimized models on GPU inference servers (NVIDIA Triton)
- **Storage**: Timescale DB for time-series events, Elasticsearch for log search
- **Orchestration**: Kubernetes + Istio service mesh
- **Dashboard**: Grafana + custom React SPA with WebSocket live updates

---

## Edge Device Integration (ESP32/Raspberry Pi)

```
Edge Node (ESP32 / RPi Zero)
        │
        │  Local: lightweight anomaly model (ONNX)
        │  Detects: packet burst, unusual entropy
        │  Sends: pre-filtered events to central API
        ▼
Regional Aggregator (RPi 4 / Jetson Nano)
        │  Runs: phishing + anomaly + risk scoring locally
        │  Sends: only HIGH/CRITICAL events upstream
        ▼
TrustCore Central API (Cloud)
        │  Global threat correlation
        │  Model retraining on new threat patterns
        ▼
National SOC Dashboard
```

### Why Edge AI Matters
- **Latency**: Detect and block threats in <10ms at the device level
- **Bandwidth**: Only high-confidence threats sent to cloud (10x bandwidth reduction)
- **Resilience**: Works offline — no cloud dependency for local defense
- **Scale**: 1M+ edge nodes possible at national ISP/router level

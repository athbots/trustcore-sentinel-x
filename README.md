# 🛡️ TrustCore Sentinel™
### Enterprise AI Trust Infrastructure & Endpoint Intelligence

TrustCore Sentinel™ is a production-grade, 100% data-driven cybersecurity platform designed for high-fidelity endpoint monitoring, stateful anomaly detection, and autonomous trust evaluation.

---

## 🚀 Quick Start (Production Boot)

Transform your machine into a monitored asset in less than 30 seconds.

1. **Initialize Environment**:
   Double-click `run.bat` (Windows) or execute `pip install -r requirements.txt`.
2. **Launch Console**:
   The `run.bat` script will automatically start the server on **Port 5050**.
3. **Access Intelligence**:
   Open [http://127.0.0.1:5050](http://127.0.0.1:5050) in your browser.

---

## 🏛️ System Architecture

### 🧠 Stateful Anomaly Engine
Uses a rolling telemetry window (40 samples) and kernel-level observation to detect sudden architectural spikes in CPU, RAM, and Process entropy.

### ⚖️ Technical Trust Fabric
Enforces a 4-tier decision model mapping physical signals to authoritative security states:
- **ALLOW (>75)**: Optimal security posture.
- **MONITOR (50-75)**: Preemptive resource observation.
- **CHALLENGE (25-50)**: Behavioral verification required.
- **BLOCK (<25)**: Infrastructure breach mitigation triggered.

### 📊 Real-Time Telemetry
100% data-driven visuals sourcing live data from the host machine via `psutil` and the internal Heuristics Engine. No mock data or random generators are present in this infrastructure.
safe 
<img width="2559" height="1476" alt="image" src="https://github.com/user-attachments/assets/5e48e8dc-1bd4-4bec-b024-9a8b4db73991" />
a mixed attack deployed 
<img width="2559" height="1478" alt="image" src="https://github.com/user-attachments/assets/da7ddc31-e207-436f-bf52-3b7132ffdb55" />

---

## 🛠️ Deployment & Execution

### Local Production
```powershell
./run.bat
```

### Manual Backend Execution
```bash
uvicorn backend.main:app --host 127.0.0.1 --port 5050
```

### Packaging (Portable Executable)
To build a standalone `.exe`:
```bash
pyinstaller --onefile --add-data "frontend;frontend" backend/main.py
```

---

## 📂 Infrastructure Map
- `backend/`: High-concurrency FastAPI kernel.
- `frontend/`: Real-time SOC dashboard (HTML5/CSS3/Vanilla JS).
- `run.bat`: Automated production bootstrap.
- `requirements.txt`: Unified dependency manifest.

---

## 👨‍💻 Author
**Anirudh Tyagi**  
Principal Systems Engineer | AI Trust Infrastructure Architect

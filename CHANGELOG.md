# Changelog

All notable changes to TrustCore Sentinel X are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.1.0] — 2025-03-20

### Added
- `backend/core/` module — unified Pydantic schemas (`schemas.py`) and custom exception hierarchy (`exceptions.py`)
- `backend/controllers/analysis_controller.py` — decouples pipeline orchestration from HTTP routes
- `Dockerfile` (multi-stage, non-root, health-checked) and `docker-compose.yml`
- `.github/workflows/ci.yml` — GitHub Actions CI (lint + model tests + Docker build)
- `CONTRIBUTING.md` — contributor guide with conventional commit conventions
- `SECURITY.md` — private vulnerability disclosure policy
- `CHANGELOG.md` — this file
- `.github/ISSUE_TEMPLATE/` — bug report and feature request templates
- Elite `README.md` rewrite — competitive matrix, ASCII architecture, workflow diagram, vision, use cases, full roadmap

### Changed
- `routes/analyze.py` now delegates to `analysis_controller.run_full_analysis()` — routes are now thin HTTP wrappers
- `models/phishing_model.py` and `models/anomaly_model.py` — standalone class-based API with cross-validation reporting

---

## [1.0.0] — 2025-03-20

### Added
- **Phishing detection** — TF-IDF + Multinomial Naive Bayes + 14 regex heuristic patterns
- **Anomaly detection** — Isolation Forest trained on 500 synthetic normal-traffic vectors
- **Risk scoring engine** — weighted combination (phishing 40% + anomaly 40% + context 20%) → 0–100 score
- **Autonomous response engine** — LOG / ALERT / BLOCK / ISOLATE with in-memory audit trail
- **Attack simulator** — 10 attack types: PHISHING, DDOS, PORT_SCAN, DATA_EXFIL, RANSOMWARE, BRUTE_FORCE, LATERAL_MOVEMENT, SQL_INJECTION, PRIVILEGE_ESCALATION, ZERO_DAY_EXPLOIT
- **FastAPI backend** — 4 endpoints: POST /analyze, GET /simulate_attack, GET /simulate_normal, GET /system_status
- **Live dashboard** — dark cyberpunk HTML/CSS/JS with animated risk gauge and real-time event feed
- **Structured logging** — dual-sink (console + `logs/sentinel.log`)
- **Standalone model scripts** — `models/phishing_model.py`, `models/anomaly_model.py`
- **Pipeline simulation script** — `scripts/simulate_attacks.py` (runs without server)
- **Sample data** — `data/sample_events.json` (10 labeled test cases)
- `requirements.txt`, `.gitignore`, `LICENSE (MIT)`

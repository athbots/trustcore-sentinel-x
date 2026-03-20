# Contributing to TrustCore Sentinel X

Thank you for your interest in contributing! This document provides guidelines and workflows to make the process smooth for everyone.

---

## 🐛 Reporting Bugs

Before filing a bug report, please check if an issue already exists. When creating one, use the **Bug Report** template and include:

- OS and Python version
- Steps to reproduce
- Expected vs. actual behavior
- Relevant log output (from `logs/sentinel.log`)

---

## 💡 Suggesting Features

Use the **Feature Request** template. Good requests include:

- A clear problem description
- The proposed solution
- Why it benefits the project at scale

---

## 🔧 Development Workflow

### 1. Fork and clone

```bash
git clone https://github.com/YOUR_USERNAME/trustcore-sentinel-x.git
cd trustcore-sentinel-x
```

### 2. Set up the environment

```bash
python -m venv venv
source venv/bin/activate          # macOS/Linux
venv\Scripts\activate             # Windows

pip install -r requirements.txt
pip install ruff pytest pytest-asyncio
```

### 3. Create a feature branch

```bash
git checkout -b feature/my-feature-name
# or
git checkout -b fix/issue-number-description
```

### 4. Make your changes

Conventions:
- Follow existing module boundaries (`services/`, `controllers/`, `routes/`)
- Add docstrings to all new functions and classes
- Keep services stateless where possible
- Use type hints on all function signatures

### 5. Run linting

```bash
ruff check backend/ models/ scripts/
```

### 6. Verify the pipeline

```bash
python -X utf8 scripts/simulate_attacks.py
python models/phishing_model.py
python models/anomaly_model.py
```

### 7. Commit with conventional commits

```
feat:     New feature
fix:      Bug fix
docs:     Documentation changes
refactor: Code restructuring
test:     Adding tests
chore:    Build/config changes
```

Example:
```bash
git commit -m "feat(anomaly): add session_count as 6th feature to IF model"
```

### 8. Open a Pull Request

- Target the `develop` branch (not `main` directly)
- Summarize **what** changed and **why**
- Reference any related issues: `Fixes #42`

---

## 🏗️ Architecture Overview

```
backend/
  core/          → Pydantic schemas + custom exceptions (no logic)
  controllers/   → Business logic (orchestrates services)
  routes/        → HTTP boundary only (delegates to controllers)
  services/      → AI models + engines (stateless computation)
  utils/         → Shared utilities (logger, etc.)
```

**Rule:** Routes never call services directly. All logic flows through controllers.

---

## 📄 License

By contributing, you agree your code will be licensed under the [MIT License](LICENSE).

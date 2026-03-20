"""
TrustCore Sentinel X — Centralized Configuration

All tunable parameters in one place 
adjustable by the user via settings UI (persisted in SQLite).
"""
import os
import sys
from pathlib import Path

# ── Paths ─────────────────────────────────────────────────────────────────────
if sys.platform == "win32":
    APP_DATA_DIR = Path(os.environ.get("LOCALAPPDATA", "~")) / "TrustCoreSentinel"
else:
    APP_DATA_DIR = Path.home() / ".sentinel"

DB_PATH = APP_DATA_DIR / "data" / "events.db"
LOG_DIR = APP_DATA_DIR / "logs"
MODEL_DIR = Path(__file__).parent.parent / "models"

# Ensure directories exist
APP_DATA_DIR.mkdir(parents=True, exist_ok=True)
(APP_DATA_DIR / "data").mkdir(parents=True, exist_ok=True)
LOG_DIR.mkdir(parents=True, exist_ok=True)

# ── System ─────────────────────────────────────────────────────────────────────
SYSTEM_NAME = "TrustCore Sentinel X"
SYSTEM_VERSION = "2.0.0"
API_HOST = "127.0.0.1"
API_PORT = 8321

# ── Collector Intervals (seconds) ────────────────────────────────────────────
NETWORK_POLL_INTERVAL = 5.0       # aggregate flows every N seconds
PROCESS_POLL_INTERVAL = 3.0       # scan new processes every N seconds
LOGIN_POLL_INTERVAL = 10.0        # check login events every N seconds
EVENT_QUEUE_MAX_SIZE = 1000       # max events buffered before back-pressure

# ── Risk Scoring Weights (must sum to 1.0) ───────────────────────────────────
WEIGHT_PHISHING = 0.30
WEIGHT_NETWORK  = 0.30
WEIGHT_PROCESS  = 0.20
WEIGHT_CONTEXT  = 0.20

# ── Risk Thresholds (0–100) ──────────────────────────────────────────────────
RISK_LOW_THRESHOLD      = 25
RISK_MEDIUM_THRESHOLD   = 50
RISK_HIGH_THRESHOLD     = 70
RISK_CRITICAL_THRESHOLD = 85

# ── Anomaly Detection ────────────────────────────────────────────────────────
ANOMALY_CONTAMINATION = 0.05
ANOMALY_TRAINING_SAMPLES = 1000

# ── Response Rules ────────────────────────────────────────────────────────────
RESPONSE_RULES = {
    "SAFE":     {"action": "LOG",     "description": "Event logged — no action needed"},
    "LOW":      {"action": "LOG",     "description": "Event logged for review"},
    "MEDIUM":   {"action": "ALERT",   "description": "Security alert dispatched"},
    "HIGH":     {"action": "BLOCK",   "description": "Source IP blocked, session terminated"},
    "CRITICAL": {"action": "ISOLATE", "description": "Host isolated, incident ticket created"},
}

# ── Process Anomaly Rules ────────────────────────────────────────────────────
# Known Living-off-the-Land Binaries (LOLBins) that attackers abuse
LOLBINS = {
    "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe",
    "bitsadmin.exe", "msiexec.exe", "wmic.exe", "bash", "curl",
    "wget", "nc", "ncat", "netcat", "python", "python3", "perl",
}

# Suspicious command-line patterns (regex)
SUSPICIOUS_CMD_PATTERNS = [
    r"-enc\s",                          # encoded powershell
    r"bypass\s*-?exec",                 # execution policy bypass
    r"IEX\s*\(",                        # Invoke-Expression
    r"downloadstring",                  # web download
    r"Net\.WebClient",                  # .NET downloader
    r"reverse.*shell",                  # reverse shell
    r"/dev/tcp/",                       # bash reverse shell
    r"mkfifo.*nc\s",                    # named pipe netcat
    r"-e\s+(cmd|bash|sh|powershell)",   # netcat shell
    r"mimikatz",                        # credential dump
    r"lazagne",                         # password recovery
    r"base64\s+--?d",                   # base64 decode piping
]

# CPU/Memory thresholds for crypto-miner detection
CRYPTO_MINER_CPU_THRESHOLD = 80.0   # % sustained CPU
CRYPTO_MINER_DURATION = 60          # seconds before flagging

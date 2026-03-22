"""
TrustCore Sentinel X — Centralized Configuration
"""
import os
from dotenv import load_dotenv

load_dotenv()

# Secure API Key configuration
API_KEY = os.getenv("TRUSTCORE_API_KEY", "default-dev-key")

# Risk thresholds (0–100 scale)
RISK_LOW_THRESHOLD = 35
RISK_MEDIUM_THRESHOLD = 65
RISK_CRITICAL_THRESHOLD = 85

# Phishing detection weights
PHISHING_KEYWORD_WEIGHT = 0.6
PHISHING_PATTERN_WEIGHT = 0.4

# Anomaly detection
ANOMALY_CONTAMINATION = 0.1       # Expected fraction of anomalies in training data
ANOMALY_TRAINING_SAMPLES = 500    # Samples used to fit Isolation Forest on startup

# Risk scoring weights (must sum to 1.0)
WEIGHT_PHISHING = 0.40
WEIGHT_ANOMALY = 0.40
WEIGHT_CONTEXT = 0.20

# Autonomous response rules
RESPONSE_RULES = {
    "LOW": {"action": "LOG", "description": "Event logged for review"},
    "MEDIUM": {"action": "ALERT", "description": "Security team notified"},
    "HIGH": {"action": "BLOCK", "description": "Source IP blocked, session terminated"},
    "CRITICAL": {"action": "ISOLATE", "description": "Host isolated from network, incident created"},
}

# System metadata
SYSTEM_VERSION = "1.0.0"
SYSTEM_NAME = "TrustCore Sentinel X"

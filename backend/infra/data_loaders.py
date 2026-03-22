import json
import os
from typing import List, Dict

# Resolve absolute paths relative to project root
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PHISHING_PATH = os.path.join(PROJECT_ROOT, "data", "phishing_dataset.json")
NETWORK_PATH = os.path.join(PROJECT_ROOT, "data", "network_dataset.json")

def load_phishing_data() -> List[Dict]:
    """
    Loads realistic email/message dataset for phishing classification.
    Returns a list of dicts: {"text": str, "label": int (0=safe, 1=phishing)}
    """
    try:
        with open(PHISHING_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Dataset not found at {PHISHING_PATH}. Returning empty.")
        return []

def load_network_data() -> List[Dict]:
    """
    Loads UNSW-NB15 style network dataset for anomaly detection.
    Returns a list of dicts with fields: 
      bytes_sent, bytes_received, duration, failed_logins, packet_count, port, label (0=normal, 1=anomaly)
    """
    try:
        with open(NETWORK_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Dataset not found at {NETWORK_PATH}. Returning empty.")
        return []

def get_normal_network_traffic() -> List[Dict]:
    """
    Filters and returns only normal traffic (label=0) for fitting baseline models (like IsolationForest).
    """
    all_data = load_network_data()
    return [d for d in all_data if d.get("label", 0) == 0]

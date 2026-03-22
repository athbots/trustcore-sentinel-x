"""
TrustCore Sentinel X — Evaluation Pipeline
===========================================

Trains model algorithms on 80% of the datasets and evaluates strictly on the
20% holdout test set to provide undeniable, measurable performance metrics.
Generates `evaluation/results.json` and prints a clean report.
"""

import sys
import os
import json
import numpy as np

# Add project root to path so we can import internal modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from backend.infra.data_loaders import load_phishing_data, load_network_data
from evaluation.metrics import calculate_phishing_metrics, calculate_anomaly_metrics

RESULTS_PATH = os.path.join(os.path.dirname(__file__), "results.json")

def evaluate_phishing_model():
    """Train and evaluate the NLP Phishing pipeline on an 80/20 data split."""
    data = load_phishing_data()
    if not data:
        return {"error": "Phishing dataset missing."}

    texts = [d["text"] for d in data]
    labels = [d["label"] for d in data]

    # Split: 80% train, 20% test
    # Ensure stratify so we have both classes in test set. Given the tiny size, we might need a small adjustment
    # if it throws an error, but let's try standard stratify first.
    try:
        X_train, X_test, y_train, y_test = train_test_split(
            texts, labels, test_size=0.2, random_state=42, stratify=labels
        )
    except ValueError:
        # Fallback if too small for stratify
        X_train, X_test, y_train, y_test = train_test_split(
            texts, labels, test_size=0.2, random_state=42
        )

    # Train NLP Pipeline strictly on Training Set
    vectorizer = TfidfVectorizer(ngram_range=(1, 2), max_features=2000, sublinear_tf=True)
    clf = LogisticRegression()

    X_train_vec = vectorizer.fit_transform(X_train)
    clf.fit(X_train_vec, y_train)

    # Predict cleanly on Test Set
    X_test_vec = vectorizer.transform(X_test)
    y_pred = clf.predict(X_test_vec)

    # Calculate and return metrics
    return calculate_phishing_metrics(y_test, y_pred)


def evaluate_anomaly_model():
    """Train Isolation Forest on 80% of normal traffic, evaluate on 20% normal + ALL attack traffic."""
    data = load_network_data()
    if not data:
        return {"error": "Network dataset missing."}

    # Extract features matching the actual models
    # [bytes_per_second, request_rate, payload_entropy, session_duration, port_risk_score]
    # We will derive these loosely from the network_dataset.json fields.
    features = []
    labels = []
    
    for d in data:
        # Avoid div by zero
        duration = max(d["duration"], 0.01)
        bytes_sec = (d["bytes_sent"] + d["bytes_received"]) / duration
        req_rate = d["packet_count"] / duration
        # Simplified port risk: 1 if port in high risk, else 0
        port_risk = 1 if d["port"] in (21, 22, 3389, 4444) else 0
        entropy = 0.5  # placeholder
        
        row = [bytes_sec, req_rate, entropy, duration, port_risk]
        features.append(row)
        labels.append(d["label"])

    features = np.array(features)
    labels = np.array(labels)

    # Isolate normal vs anomalies
    normal_idx = (labels == 0)
    anomaly_idx = (labels == 1)

    X_normal = features[normal_idx]
    
    # Check if we have enough normal data to split
    if len(X_normal) < 2:
        return {"error": "Not enough normal network data to train."}

    # Split Normal Data: 80% train, 20% test holdout
    X_train_norm, X_test_norm = train_test_split(X_normal, test_size=0.2, random_state=42)

    # Train Isolation Forest on Normal Data Only
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train_norm)
    
    model = IsolationForest(contamination=0.1, random_state=42)
    model.fit(X_train_scaled)

    # Create Test Set: 20% Holdout Normal + ALL Anomalies
    X_test = np.vstack([X_test_norm, features[anomaly_idx]])
    y_test = np.concatenate([np.zeros(len(X_test_norm)), np.ones(np.sum(anomaly_idx))])

    # Predict
    X_test_scaled = scaler.transform(X_test)
    # IsolationForest outputs 1 for normal, -1 for anomaly
    raw_preds = model.predict(X_test_scaled)
    # Convert to 0=normal, 1=anomaly to align with our labels
    y_pred = np.where(raw_preds == -1, 1, 0)

    # Calculate and return metrics
    return calculate_anomaly_metrics(y_test, y_pred)

def generate_report(results: dict):
    print("\n" + "="*30)
    print("=== MODEL EVALUATION ===")
    print("="*30)
    
    p = results.get("phishing_model", {})
    if "error" in p:
        print("Phishing Model: ERROR -", p["error"])
    else:
        print(f"Phishing Accuracy: {p.get('accuracy', 0)*100:.1f}%")
        print(f"Precision: {p.get('precision', 0):.2f}")
        print(f"Recall: {p.get('recall', 0):.2f}")
        print(f"F1: {p.get('f1', 0):.2f}")

    print("-" * 30)

    a = results.get("anomaly_model", {})
    if "error" in a:
        print("Anomaly Model: ERROR -", a["error"])
    else:
        print(f"Anomaly Detection Rate: {a.get('detection_rate', 0)*100:.1f}%")
        print(f"False Positive Rate: {a.get('false_positive_rate', 0)*100:.1f}%")
    
    print("="*30 + "\n")


def run():
    print("Initializing evaluation pipeline...")
    
    phishing_metrics = evaluate_phishing_model()
    anomaly_metrics = evaluate_anomaly_model()

    results = {
        "phishing_model": phishing_metrics,
        "anomaly_model": anomaly_metrics,
    }

    # Save Results
    with open(RESULTS_PATH, "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"Results cleanly saved to {RESULTS_PATH}")
    generate_report(results)

if __name__ == "__main__":
    run()

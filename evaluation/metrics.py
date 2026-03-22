"""
TrustCore Sentinel X — Evaluation Metrics

Provides standardized calculation functions for model evaluation.
"""

from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

def calculate_phishing_metrics(y_true, y_pred) -> dict:
    """
    Calculate core classification metrics for the phishing model.
    """
    return {
        "accuracy": float(round(accuracy_score(y_true, y_pred), 4)),
        "precision": float(round(precision_score(y_true, y_pred, zero_division=0), 4)),
        "recall": float(round(recall_score(y_true, y_pred, zero_division=0), 4)),
        "f1": float(round(f1_score(y_true, y_pred, zero_division=0), 4))
    }

def calculate_anomaly_metrics(y_true, y_pred) -> dict:
    """
    Calculate detection metrics for the anomaly model.
    y_true: 0 = normal, 1 = anomaly
    y_pred: 0 = normal, 1 = anomaly
    """
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    
    # Structure:
    # cm[0][0] = True Negatives (Normal predicted as Normal)
    # cm[0][1] = False Positives (Normal predicted as Anomaly)
    # cm[1][0] = False Negatives (Anomaly predicted as Normal)
    # cm[1][1] = True Positives (Anomaly predicted as Anomaly)
    
    if cm.shape == (2, 2):
        tn, fp, fn, tp = cm.ravel()
    else:
        tn, fp, fn, tp = 0, 0, 0, 0

    detection_rate = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    false_positive_rate = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    return {
        "detection_rate": float(round(detection_rate, 4)),
        "false_positive_rate": float(round(false_positive_rate, 4))
    }

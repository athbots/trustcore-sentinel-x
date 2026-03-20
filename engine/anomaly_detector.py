"""
TrustCore Sentinel X — Anomaly Detector
Uses Isolation Forest (pre-fitted on synthetic normal traffic baseline).
Detects: port scans, DDoS, data exfiltration, brute force, lateral movement.
"""

import numpy as np
from sklearn.ensemble import IsolationForest
from typing import Dict, List, Tuple


# ── Synthetic Baseline: Normal Network Traffic ────────────────────────────────
# Shape: [bytes_sent, bytes_received, duration_seconds, failed_logins, packet_count, port_risk]

np.random.seed(42)

NORMAL_TRAFFIC = np.column_stack([
    np.random.normal(5000, 2000, 500),     # bytes_sent
    np.random.normal(8000, 3000, 500),     # bytes_received
    np.random.uniform(0.5, 30, 500),       # duration_seconds
    np.zeros(500),                          # failed_logins (0 for normal)
    np.random.randint(10, 200, 500),       # packet_count
    np.random.choice([0, 1], 500, p=[0.9, 0.1]),  # port_risk (low risk ports mostly)
])

# Clamp negatives
NORMAL_TRAFFIC = np.abs(NORMAL_TRAFFIC)

# Fit the model once at module load (fast, ~0.1s)
_iso_forest = IsolationForest(
    n_estimators=200,
    contamination=0.05,
    max_samples="auto",
    random_state=42,
)
_iso_forest.fit(NORMAL_TRAFFIC)


# ── Port Risk Classification ──────────────────────────────────────────────────

HIGH_RISK_PORTS = {
    22: "SSH",
    23: "Telnet",
    3389: "RDP",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    9200: "Elasticsearch",
    27017: "MongoDB",
    4444: "Metasploit",
    5555: "ADB / Android Debug",
    8080: "Alt-HTTP",
    9090: "Cockpit/Admin",
}

MEDIUM_RISK_PORTS = {80, 8000, 8888, 25, 110, 143, 21, 20}


def _get_port_risk(port: int) -> Tuple[float, str]:
    if port in HIGH_RISK_PORTS:
        return 1.0, f"High-risk port {port} ({HIGH_RISK_PORTS[port]})"
    elif port in MEDIUM_RISK_PORTS:
        return 0.5, f"Medium-risk port {port}"
    elif port < 1024:
        return 0.3, f"Well-known port {port}"
    else:
        return 0.0, ""


def _detect_attack_patterns(event: Dict) -> List[Tuple[float, str]]:
    """Rule-based attack pattern recognition on top of Isolation Forest."""
    findings = []

    bytes_sent = event.get("bytes_sent", 0)
    bytes_received = event.get("bytes_received", 0)
    duration = event.get("duration_seconds", 1)
    failed_logins = event.get("failed_logins", 0)
    packet_count = event.get("packet_count", 1)

    # Brute force detection
    if failed_logins >= 5:
        findings.append((min(failed_logins * 4, 40), f"Brute force: {failed_logins} failed login attempts"))

    # Data exfiltration (large outbound, small inbound)
    if bytes_sent > 50_000 and bytes_sent > bytes_received * 5:
        findings.append((35, f"Possible exfiltration: {bytes_sent:,.0f} bytes sent vs {bytes_received:,.0f} received"))

    # DDoS-style: high packet count, very short duration
    if packet_count > 500 and duration < 2:
        findings.append((30, f"DDoS-like traffic: {packet_count} packets in {duration:.2f}s"))

    # Port scan: lots of packets, tiny data
    if packet_count > 100 and bytes_sent < 500 and duration < 1:
        findings.append((25, "Possible port scan: high packet count with minimal data"))

    # C2 beacon: regular, tiny packets (low entropy)
    if 5 < packet_count < 20 and bytes_sent < 200 and 0.1 < duration < 0.5:
        findings.append((20, "Possible C2 beacon: small regular traffic pattern"))

    return findings


def analyze_network_event(
    source_ip: str,
    destination_ip: str,
    port: int,
    bytes_sent: float,
    bytes_received: float,
    duration_seconds: float,
    protocol: str,
    failed_logins: int = 0,
    packet_count: int = 1,
) -> Dict:
    """
    Runs Isolation Forest + rule-based analysis on a network event.
    Returns a dict with score, indicators, confidence.
    """
    port_risk, port_indicator = _get_port_risk(port)

    # Feature vector for Isolation Forest
    feature_vector = np.array([[
        bytes_sent,
        bytes_received,
        duration_seconds,
        float(failed_logins),
        float(packet_count),
        port_risk,
    ]])

    # Isolation Forest anomaly score (-1 = anomaly, 1 = normal)
    iso_prediction = _iso_forest.predict(feature_vector)[0]
    iso_score_raw = _iso_forest.score_samples(feature_vector)[0]  # Negative: more anomalous

    # Convert to 0–100: iso_score_raw typically in [-0.7, 0.15]
    # Map -0.7 → ~80 pts, 0.15 → ~0 pts
    iso_score_normalized = max(0, min(100, (-iso_score_raw - 0.05) * 160))

    # Rule-based detections
    event_dict = {
        "bytes_sent": bytes_sent, "bytes_received": bytes_received,
        "duration_seconds": duration_seconds, "failed_logins": failed_logins,
        "packet_count": packet_count,
    }
    pattern_findings = _detect_attack_patterns(event_dict)
    pattern_score = sum(f[0] for f in pattern_findings)
    indicators = [f[1] for f in pattern_findings]

    if port_indicator:
        indicators.append(port_indicator)

    if iso_prediction == -1:
        indicators.append("Isolation Forest: traffic deviates significantly from baseline")

    # Combined score
    total_score = min((iso_score_normalized * 0.5 + pattern_score * 0.5), 100.0)
    confidence = min(0.95, max(0.1, total_score / 100))

    return {
        "score": round(total_score, 2),
        "confidence": round(confidence, 3),
        "indicators": indicators if indicators else ["Traffic within normal parameters"],
        "category": "Network Anomaly / Intrusion Detection",
        "iso_flagged": bool(iso_prediction == -1),
    }

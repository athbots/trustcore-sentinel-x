"""
TrustCore Sentinel X — Threat Intelligence (Static)

Static blacklists for known-malicious indicators:
  - IP addresses (C2 servers, tor exit nodes, known attackers)
  - Ports (common malware C2 ports)
  - Domains (phishing/malware domains)

Returns a threat_intel score (0.0 – 1.0) and matched indicators.
"""
from sentinel.utils.logger import get_logger

logger = get_logger("intelligence.threat_intel")

# ── Blacklists ───────────────────────────────────────────────────────────────

MALICIOUS_IPS = {
    # Simulated C2 / known bad IPs (test ranges)
    "203.0.113.66", "203.0.113.99", "203.0.113.100",
    "198.51.100.23", "198.51.100.50", "198.51.100.77",
    "192.0.2.1", "192.0.2.100",
    # Tor exit nodes (examples)
    "185.220.101.1", "185.220.101.45",
    "45.33.32.156",  # scanme.nmap.org
}

SUSPICIOUS_PORTS = {
    4444,   # Metasploit default
    5555,   # ADB/Android debug
    1337,   # Common backdoor
    6666, 6667,  # IRC (botnet C2)
    8888,   # Common alt-HTTP
    31337,  # Elite backdoor
    12345,  # NetBus
    65534,  # High ephemeral (suspicious)
    4443,   # Alt HTTPS (C2)
    9001, 9050, 9150,  # Tor
}

MALICIOUS_DOMAINS = {
    "evil-phishing.com", "malware-download.net", "c2-server.xyz",
    "credential-harvest.com", "ransomware-payment.onion",
    "fake-bank-login.com", "update-flash-player.com",
}

# Suspicious IP ranges (first octets)
_SUSPICIOUS_PREFIXES = ("203.0.113.", "198.51.100.", "192.0.2.")


def analyze(event: dict) -> dict:
    """
    Check event against threat intelligence indicators.

    Returns:
        {
            "score": 0.0–1.0,
            "indicators": list of matched indicators,
            "severity": "NONE" | "LOW" | "MEDIUM" | "HIGH",
        }
    """
    indicators = []
    score = 0.0

    source_ip = event.get("source_ip", "")
    text = (event.get("text", "") or "").lower()
    features = event.get("features", [])

    # IP check
    if source_ip in MALICIOUS_IPS:
        indicators.append(f"Blacklisted IP: {source_ip}")
        score += 0.6
    elif any(source_ip.startswith(p) for p in _SUSPICIOUS_PREFIXES):
        indicators.append(f"Suspicious IP range: {source_ip}")
        score += 0.2

    # Port check (from features if available — features[3] is often dst_port)
    if features and len(features) >= 4:
        try:
            port = int(features[3])
            if port in SUSPICIOUS_PORTS:
                indicators.append(f"Suspicious port: {port}")
                score += 0.3
        except (ValueError, TypeError, IndexError):
            pass

    # Domain check (in text)
    for domain in MALICIOUS_DOMAINS:
        if domain in text:
            indicators.append(f"Malicious domain: {domain}")
            score += 0.5
            break

    score = min(score, 1.0)

    if score >= 0.5:
        severity = "HIGH"
    elif score >= 0.2:
        severity = "MEDIUM"
    elif score > 0:
        severity = "LOW"
    else:
        severity = "NONE"

    return {
        "score": round(score, 2),
        "indicators": indicators,
        "severity": severity,
    }

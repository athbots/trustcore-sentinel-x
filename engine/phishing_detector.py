"""
TrustCore Sentinel X — Phishing Detector
Uses rule-based NLP + optional zero-shot classification (HF transformers).
No training required — works immediately out of the box.
"""

import re
import math
from typing import List, Tuple, Dict


# ── Phishing Signal Patterns ─────────────────────────────────────────────────

URGENCY_PATTERNS = [
    r'\burgent\b', r'\bimmediately\b', r'\baction required\b',
    r'\baccount.*suspend', r'\bverify.*now\b', r'\blimited time\b',
    r'\bwithin 24 hours\b', r'\byour account.*expire',
    r'\bconfirm.*identity\b', r'\bunusual.*activity\b',
]

CREDENTIAL_HARVEST_PATTERNS = [
    r'\bclick here\b', r'\blog.*in.*below\b', r'\benter.*password\b',
    r'\bsecure.*login\b', r'\bupdate.*billing\b', r'\bpayment.*fail',
    r'\bacccount.*locked\b', r'\bverif.*email\b', r'\bclick.*link\b',
]

SUSPICIOUS_SENDER_PATTERNS = [
    r'[0-9]{2,}@',              # Numbers in username
    r'@.*\.(xyz|top|tk|ml|ga|cf|gq|pw)$',  # Suspicious TLDs
    r'paypa[l1]', r'amazon[s]?-', r'micro[s0]oft',  # Brand spoofing
    r'secure.*\d+\.', r'support.*-[a-z]+-',
    r'noreply@(?!.*(google|microsoft|amazon|apple))',  # Generic noreply
]

OBFUSCATION_PATTERNS = [
    r'[a-zA-Z][0-9][a-zA-Z]',  # Letter-number substitution
    r'\b(0|1|3|4|5)[a-z]',     # Digit-letter combos
    r'[^\x00-\x7F]',            # Non-ASCII characters (unicode lookalikes)
]


def _count_pattern_matches(text: str, patterns: List[str]) -> Tuple[int, List[str]]:
    """Returns count of pattern hits and matched indicator strings."""
    matched = []
    text_lower = text.lower()
    for p in patterns:
        if re.search(p, text_lower):
            matched.append(p.replace(r'\b', '').replace('.*', '…').strip())
    return len(matched), matched


def check_url_reputation(text: str) -> Tuple[float, List[str]]:
    """Simple heuristic URL analysis — no external API needed."""
    urls = re.findall(r'https?://[^\s\'"<>]+', text, re.IGNORECASE)
    indicators = []
    score = 0.0

    for url in urls:
        url_lower = url.lower()
        # IP address instead of domain
        if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url_lower):
            indicators.append(f"Raw IP URL: {url[:40]}")
            score += 30
        # URL shorteners
        if re.search(r'bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|short', url_lower):
            indicators.append(f"URL shortener detected: {url[:40]}")
            score += 20
        # Excessive subdomains (domain spoofing)
        domain_parts = re.findall(r'://([^/]+)', url_lower)
        if domain_parts and domain_parts[0].count('.') > 3:
            indicators.append(f"Suspicious subdomain depth: {domain_parts[0]}")
            score += 15
        # Brand names embedded in URL paths (not as root domain)
        for brand in ['paypal', 'amazon', 'microsoft', 'apple', 'google', 'netflix']:
            if brand in url_lower and not url_lower.split('://')[1].startswith(brand):
                indicators.append(f"Brand name '{brand}' embedded in URL path")
                score += 25

    return min(score, 60.0), indicators  # Cap URL score contribution


def analyze_email(subject: str, body: str, sender: str) -> Dict:
    """
    Analyzes an email for phishing indicators.
    Returns a dict with score contribution (0-100), indicators, and confidence.
    """
    combined_text = f"{subject} {body}"
    indicators = []
    raw_score = 0.0

    # 1. Urgency language
    urgency_count, urgency_hits = _count_pattern_matches(combined_text, URGENCY_PATTERNS)
    raw_score += urgency_count * 8
    indicators += [f"Urgency signal: '{h}'" for h in urgency_hits[:3]]

    # 2. Credential harvesting language
    cred_count, cred_hits = _count_pattern_matches(combined_text, CREDENTIAL_HARVEST_PATTERNS)
    raw_score += cred_count * 10
    indicators += [f"Credential harvest signal: '{h}'" for h in cred_hits[:3]]

    # 3. Sender analysis
    sender_count, sender_hits = _count_pattern_matches(sender, SUSPICIOUS_SENDER_PATTERNS)
    raw_score += sender_count * 15
    indicators += [f"Suspicious sender pattern: '{h}'" for h in sender_hits[:2]]

    # 4. URL analysis
    url_score, url_indicators = check_url_reputation(combined_text)
    raw_score += url_score
    indicators += url_indicators

    # 5. Obfuscation in sender
    obf_count, obf_hits = _count_pattern_matches(sender, OBFUSCATION_PATTERNS)
    raw_score += obf_count * 10
    indicators += [f"Sender obfuscation: '{h}'" for h in obf_hits[:2]]

    # 6. Subject/body length heuristics (very short body = suspicious)
    if len(body.split()) < 15:
        raw_score += 5
        indicators.append("Unusually short email body")

    # Normalize to 0–100
    phishing_score = min(raw_score, 100.0)

    # Sigmoid-style confidence: high score = high confidence
    confidence = 1 / (1 + math.exp(-0.1 * (phishing_score - 40)))

    return {
        "score": round(phishing_score, 2),
        "confidence": round(confidence, 3),
        "indicators": indicators if indicators else ["No phishing indicators found"],
        "category": "Phishing / Social Engineering",
    }

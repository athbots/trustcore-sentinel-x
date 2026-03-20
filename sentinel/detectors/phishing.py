"""
TrustCore Sentinel X — Phishing Detection Service (Production)

Re-uses the proven TF-IDF + MultinomialNB pipeline from the prototype,
with an expanded training corpus and improved heuristic boosting.

Phishing score: 0.0 (definitely legit) → 1.0 (definitely phishing)
"""
import re
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline

from sentinel.utils.logger import get_logger

logger = get_logger("detector.phishing")

# ── Training Data (expanded corpus) ──────────────────────────────────────────
_PHISHING_SAMPLES = [
    "Verify your PayPal account immediately or it will be suspended",
    "Click here to confirm your bank account details",
    "Your Amazon account has been compromised. Reset password now",
    "Urgent: Your credit card has been charged $499. Dispute now",
    "Dear customer, your account login was detected from unusual location. Verify now",
    "You have won a $1000 gift card. Claim your prize today",
    "Update your billing information to avoid service interruption",
    "ALERT: Unauthorized access detected. Secure your account immediately",
    "Your Netflix subscription will expire. Renew now to continue",
    "Confirm your identity to release your pending bank transfer",
    "Your Apple ID has been locked. Click to unlock now",
    "IRS notice: You owe back taxes. Pay immediately to avoid arrest",
    "Congratulations! You've been selected for a free iPhone. Click to claim",
    "Security breach detected in your Microsoft account. Verify now",
    "Your password expires today. Click to reset or lose access permanently",
    "Wire transfer request: Please approve $25,000 to vendor account",
    "Your DHL package is on hold due to unpaid customs fee",
    "Login from new device detected. Confirm it was you or click to secure",
    "Your social security number has been flagged. Call immediately",
    "Please provide your username and password to verify your account",
    "Phishing test: Enter credentials to validate your mailbox",
    "Your account access will be revoked in 24 hours. Confirm identity now",
    "You have a pending refund of $300. Enter bank details to receive it",
    "Suspicious activity detected. Verify your card number and CVV now",
    # Extended samples
    "Your blockchain wallet has been locked. Verify seed phrase now",
    "HR Department: Click to view your updated salary structure",
    "IT Support: Your mailbox quota exceeded. Click here to upgrade",
    "Invoice attached for payment of $12,500. Open immediately",
    "Board of Directors: Confidential acquisition document. Review now",
    "Tax refund: $1,523.00 pending. Verify your bank account to process",
]

_LEGIT_SAMPLES = [
    "Team meeting scheduled for Monday at 3pm in conference room B",
    "Please review and approve the Q4 budget report attached",
    "Hi John, following up on our call yesterday about the project timeline",
    "Your order has shipped and will arrive by Thursday",
    "Monthly newsletter: Here are our latest product updates",
    "Reminder: Performance reviews are due at end of quarter",
    "Welcome to TrustCore Sentinel X — your account has been created",
    "Here is the agenda for tomorrow's board meeting",
    "Thank you for your purchase. Your receipt is attached",
    "Please submit your timesheet by Friday end of day",
    "The development sprint review is scheduled for Wednesday",
    "Attached is the contract draft for your review",
    "Your flight booking confirmation for March 25th is confirmed",
    "Lunch is being catered in the main office today",
    "Please find the report you requested in the attachment",
    "The server maintenance window is this Saturday 2am-4am",
    "Congratulations on completing the security training module",
    "Your subscription has been renewed successfully",
    "Here are the notes from yesterday's sync meeting",
    "The project deadline has been extended to next Friday",
    "Please update your profile information in the HR portal",
    "The weekly digest from the engineering team is ready",
    "Your document has been shared with you on Google Drive",
    "Reminder to clock out before leaving the office today",
    # Extended samples
    "The CI/CD pipeline completed successfully — all tests passed",
    "Let's reschedule our 1-on-1 to Thursday at 2pm",
    "The new version of the design spec is ready for review",
    "Happy birthday from the whole team!",
    "The office will be closed on Monday for the holiday",
    "Security training reminder: complete your annual certification this week",
]

_TEXTS = _PHISHING_SAMPLES + _LEGIT_SAMPLES
_LABELS = [1] * len(_PHISHING_SAMPLES) + [0] * len(_LEGIT_SAMPLES)

# ── Model Pipeline ───────────────────────────────────────────────────────────
_pipeline = Pipeline([
    ("tfidf", TfidfVectorizer(ngram_range=(1, 2), max_features=3000, sublinear_tf=True)),
    ("clf", MultinomialNB(alpha=0.3)),
])
_pipeline.fit(_TEXTS, _LABELS)
logger.info(f"Phishing model trained on {len(_TEXTS)} samples")

# ── Heuristic Patterns ──────────────────────────────────────────────────────
_PHISHING_PATTERNS = [
    r"\bverify\b.*\baccount\b",
    r"\bclick here\b",
    r"\burgent\b",
    r"\bsuspend(ed)?\b",
    r"\bcompromised\b",
    r"\bconfirm.*identity\b",
    r"\bwire transfer\b",
    r"\bunauthorized access\b",
    r"\bexpire[sd]?\b.*\b(today|now|immediately)\b",
    r"\bpassword.*reset\b",
    r"\bfree (iphone|gift|prize)\b",
    r"\byou('ve| have) won\b",
    r"\benter.*\b(credentials|password|card|cvv|ssn)\b",
    r"\bpay.*immediately\b",
    r"\bseed phrase\b",
    r"\bwallet.*locked\b",
]


def _heuristic_boost(text: str) -> float:
    text_lower = text.lower()
    matches = sum(1 for p in _PHISHING_PATTERNS if re.search(p, text_lower))
    return min(matches * 0.04, 0.25)


def analyze_phishing(text: str) -> dict:
    """
    Analyze text for phishing signals.

    Returns:
        score (float): 0.0–1.0 phishing probability
        verdict (str): PHISHING | SUSPICIOUS | LEGITIMATE
        confidence (str): LOW | MEDIUM | HIGH
        signals (list): triggered heuristic patterns
    """
    if not text or not text.strip():
        return {"score": 0.0, "verdict": "LEGITIMATE", "confidence": "HIGH", "signals": []}

    # ML probability
    proba = _pipeline.predict_proba([text])[0][1]

    # Heuristic boost
    boost = _heuristic_boost(text)
    final_score = float(np.clip(proba + boost, 0.0, 1.0))

    # Triggered signals
    text_lower = text.lower()
    signals = [p for p in _PHISHING_PATTERNS if re.search(p, text_lower)]

    # Verdict
    if final_score >= 0.70:
        verdict = "PHISHING"
    elif final_score >= 0.45:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LEGITIMATE"

    # Confidence
    if abs(final_score - 0.5) > 0.35:
        confidence = "HIGH"
    elif abs(final_score - 0.5) > 0.15:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    return {
        "score": round(final_score, 4),
        "verdict": verdict,
        "confidence": confidence,
        "signals": signals[:5],
    }

"""
TrustCore Sentinel X — Phishing Detection Model
================================================
Standalone module. Can be imported or run directly.

Architecture:
  TF-IDF Vectorizer (ngrams 1-2, 2000 features)
  + Multinomial Naive Bayes (alpha=0.5)
  + Regex heuristic signal layer

Training: ~48 curated labeled samples, fits in <200ms on any machine.
No internet download, no GPU required.

Usage (standalone):
  python phishing_model.py

Usage (import):
  from models.phishing_model import PhishingModel
  model = PhishingModel()
  result = model.predict("Verify your PayPal account now!")
"""

import re
import sys
import os
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
from sklearn.model_selection import cross_val_score
import numpy as np

# ── Training Corpus ──────────────────────────────────────────────────────────

PHISHING_SAMPLES = [
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
    "Your account access will be revoked in 24 hours. Confirm identity now",
    "You have a pending refund of $300. Enter bank details to receive it",
    "Suspicious activity detected. Verify your card number and CVV now",
    "IT Alert: Your VPN password expires today. Reset immediately to maintain access",
]

LEGITIMATE_SAMPLES = [
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
]

PHISHING_PATTERNS = [
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
]


class PhishingModel:
    """
    Phishing text classifier.

    Attributes:
        pipeline: sklearn Pipeline (TF-IDF → Naive Bayes)
        accuracy:  Cross-validated accuracy on training data
    """

    def __init__(self):
        texts  = PHISHING_SAMPLES + LEGITIMATE_SAMPLES
        labels = [1] * len(PHISHING_SAMPLES) + [0] * len(LEGITIMATE_SAMPLES)

        self.pipeline = Pipeline([
            ("tfidf", TfidfVectorizer(
                ngram_range=(1, 2),
                max_features=2000,
                sublinear_tf=True,
                min_df=1,
            )),
            ("clf", MultinomialNB(alpha=0.5)),
        ])
        self.pipeline.fit(texts, labels)

        # 5-fold cross-validation accuracy
        cv_scores     = cross_val_score(self.pipeline, texts, labels, cv=5, scoring="accuracy")
        self.accuracy = float(cv_scores.mean())
        self.cv_std   = float(cv_scores.std())

    def _heuristic_boost(self, text: str) -> float:
        """Regex-based pattern matching boost (0.0–0.25)."""
        t = text.lower()
        hits = sum(1 for p in PHISHING_PATTERNS if re.search(p, t))
        return min(hits * 0.04, 0.25)

    def predict(self, text: str) -> dict:
        """
        Classify a single text string.

        Args:
            text: Raw email body or subject line.

        Returns:
            score (float):    0.0 (legit) → 1.0 (phishing)
            verdict (str):    PHISHING | SUSPICIOUS | LEGITIMATE
            confidence (str): LOW | MEDIUM | HIGH
            signals (list):   Matched heuristic patterns
        """
        if not text or not text.strip():
            return {"score": 0.0, "verdict": "LEGITIMATE", "confidence": "HIGH", "signals": []}

        ml_prob   = float(self.pipeline.predict_proba([text])[0][1])
        boost     = self._heuristic_boost(text)
        score     = float(np.clip(ml_prob + boost, 0.0, 1.0))
        signals   = [p for p in PHISHING_PATTERNS if re.search(p, text.lower())]

        if score >= 0.70:
            verdict = "PHISHING"
        elif score >= 0.45:
            verdict = "SUSPICIOUS"
        else:
            verdict = "LEGITIMATE"

        margin = abs(score - 0.5)
        confidence = "HIGH" if margin > 0.35 else ("MEDIUM" if margin > 0.15 else "LOW")

        return {
            "score":      round(score, 4),
            "verdict":    verdict,
            "confidence": confidence,
            "signals":    signals[:5],
            "ml_prob":    round(ml_prob, 4),
            "heuristic_boost": round(boost, 4),
        }

    def batch_predict(self, texts: list[str]) -> list[dict]:
        """Classify a list of texts."""
        return [self.predict(t) for t in texts]

    def model_info(self) -> dict:
        return {
            "model_type":        "TF-IDF + Multinomial Naive Bayes",
            "ngram_range":       "(1, 2)",
            "max_features":      2000,
            "training_samples":  len(PHISHING_SAMPLES) + len(LEGITIMATE_SAMPLES),
            "phishing_samples":  len(PHISHING_SAMPLES),
            "legit_samples":     len(LEGITIMATE_SAMPLES),
            "cv5_accuracy":      f"{self.accuracy:.1%}",
            "cv5_std":           f"±{self.cv_std:.1%}",
            "heuristic_patterns": len(PHISHING_PATTERNS),
        }


# ── Standalone Demo ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    model = PhishingModel()
    info  = model.model_info()

    print("\n" + "=" * 60)
    print("  TrustCore Sentinel X — Phishing Detection Model")
    print("=" * 60)
    print(f"  Training samples : {info['training_samples']}")
    print(f"  CV-5 Accuracy    : {info['cv5_accuracy']} {info['cv5_std']}")
    print(f"  Heuristic rules  : {info['heuristic_patterns']}")
    print("=" * 60)

    test_inputs = [
        ("PayPal Phishing",     "Verify your PayPal account immediately or it will be suspended"),
        ("CEO Fraud",           "Wire transfer request: Please approve $25,000 to vendor account urgently"),
        ("Microsoft Phishing",  "Your Microsoft account has been compromised. Secure it now."),
        ("Routine Email",       "Team standup is at 10am tomorrow. Please review the attached agenda."),
        ("Order Confirm",       "Your order has shipped and will arrive by Thursday. Thank you!"),
        ("Phishing Gift Card",  "You have won a $1000 Amazon gift card. Claim your prize today!"),
    ]

    print()
    for name, text in test_inputs:
        r = model.predict(text)
        verdict_icon = "🚨" if r["verdict"] == "PHISHING" else ("⚠️ " if r["verdict"] == "SUSPICIOUS" else "✅")
        print(f"  {verdict_icon} [{r['verdict']:10s}] Score={r['score']:.2f} | Conf={r['confidence']:6s} | {name}")
        print(f"     \"{text[:65]}{'…' if len(text)>65 else ''}\"")
        if r["signals"]:
            print(f"     Signals: {r['signals'][0]}")
        print()

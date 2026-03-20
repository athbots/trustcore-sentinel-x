"""
TrustCore Sentinel X — Phishing Model Training Script
======================================================

Trains a TF-IDF + MultinomialNB phishing classifier.
Can use either the built-in corpus or an external dataset.

Usage:
    python scripts/train/train_phishing.py                     # built-in corpus
    python scripts/train/train_phishing.py --data-file phishing_emails.csv --text-col text --label-col label

The trained pipeline is saved to models/ directory.
"""
import argparse
import sys
import os
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
from sklearn.model_selection import cross_val_score, StratifiedKFold
from sklearn.metrics import classification_report, confusion_matrix
import joblib

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

OUTPUT_DIR = PROJECT_ROOT / "models"
OUTPUT_DIR.mkdir(exist_ok=True)


def train_builtin() -> None:
    """Train on the built-in expanded phishing corpus."""
    from sentinel.detectors.phishing import _PHISHING_SAMPLES, _LEGIT_SAMPLES

    texts = _PHISHING_SAMPLES + _LEGIT_SAMPLES
    labels = [1] * len(_PHISHING_SAMPLES) + [0] * len(_LEGIT_SAMPLES)

    print(f"\n📊 Built-in corpus: {len(_PHISHING_SAMPLES)} phishing + {len(_LEGIT_SAMPLES)} legit = {len(texts)} total")

    _train_and_evaluate(texts, labels)


def train_from_file(data_file: str, text_col: str, label_col: str) -> None:
    """Train on an external CSV dataset."""
    print(f"\n📁 Loading dataset: {data_file}")

    df = pd.read_csv(data_file, low_memory=False)
    df = df.dropna(subset=[text_col, label_col])

    print(f"📊 Loaded {len(df):,} samples")
    print(f"📊 Label distribution:")
    print(df[label_col].value_counts().to_string())

    texts = df[text_col].tolist()

    # Normalize labels to 0/1
    unique_labels = df[label_col].unique()
    if set(unique_labels) <= {0, 1}:
        labels = df[label_col].tolist()
    elif set(unique_labels) <= {"phishing", "legit", "legitimate", "ham", "spam"}:
        phishing_labels = {"phishing", "spam"}
        labels = [1 if str(l).lower() in phishing_labels else 0 for l in df[label_col]]
    else:
        print(f"⚠ Unknown label values: {unique_labels}")
        print("  Assuming first unique value is legitimate (0), rest is phishing (1)")
        legit_label = unique_labels[0]
        labels = [0 if l == legit_label else 1 for l in df[label_col]]

    print(f"   Phishing: {sum(labels)}, Legitimate: {len(labels) - sum(labels)}")

    _train_and_evaluate(texts, labels)


def _train_and_evaluate(texts: list[str], labels: list[int]) -> None:
    """Train pipeline and evaluate with cross-validation."""

    # ── Build pipeline ───────────────────────────────────────────────────────
    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(
            ngram_range=(1, 2),
            max_features=5000,
            sublinear_tf=True,
            min_df=1,
        )),
        ("clf", MultinomialNB(alpha=0.3)),
    ])

    # ── Cross-validation ─────────────────────────────────────────────────────
    print("\n🔬 Running 5-fold stratified cross-validation...")
    cv = StratifiedKFold(n_splits=min(5, min(sum(labels), len(labels) - sum(labels))),
                          shuffle=True, random_state=42)

    scores = cross_val_score(pipeline, texts, labels, cv=cv, scoring="f1")
    print(f"   F1 scores: {[f'{s:.4f}' for s in scores]}")
    print(f"   Mean F1:   {scores.mean():.4f} ± {scores.std():.4f}")

    # ── Final training on full data ──────────────────────────────────────────
    print("\n🏋️ Training final model on full dataset...")
    pipeline.fit(texts, labels)

    # Evaluate on training data (to verify fit)
    y_pred = pipeline.predict(texts)
    print("\n📋 Training set results (sanity check):")
    print(classification_report(labels, y_pred, target_names=["Legitimate", "Phishing"]))

    cm = confusion_matrix(labels, y_pred)
    print(f"Confusion Matrix:")
    print(f"  TN={cm[0][0]:,}  FP={cm[0][1]:,}")
    print(f"  FN={cm[1][0]:,}  TP={cm[1][1]:,}")

    # ── Save model ───────────────────────────────────────────────────────────
    model_path = OUTPUT_DIR / "phishing_pipeline.joblib"
    joblib.dump(pipeline, model_path)

    print(f"\n💾 Model saved to: {model_path}")
    print(f"   Pipeline stages: {list(pipeline.named_steps.keys())}")
    print(f"   Vocabulary size: {len(pipeline.named_steps['tfidf'].vocabulary_)}")
    print(f"\n✅ Phishing model training complete! Mean F1={scores.mean():.4f}")


def main():
    parser = argparse.ArgumentParser(
        description="Train the TrustCore Sentinel X phishing detection model"
    )
    parser.add_argument("--data-file", type=str, default=None, help="Path to CSV dataset")
    parser.add_argument("--text-col", type=str, default="text", help="Column name for email text")
    parser.add_argument("--label-col", type=str, default="label", help="Column name for labels")

    args = parser.parse_args()

    print("=" * 60)
    print("  TrustCore Sentinel X — Phishing Model Trainer")
    print("=" * 60)

    if args.data_file:
        train_from_file(args.data_file, args.text_col, args.label_col)
    else:
        train_builtin()


if __name__ == "__main__":
    main()

"""
TrustCore Sentinel X — Network Anomaly Model Training Script
=============================================================

Trains an Isolation Forest model on real network intrusion data.

Supported datasets:
    - CICIDS 2017 (CSV format)
    - UNSW-NB15 (CSV format)

Usage:
    python scripts/train/train_anomaly.py --dataset cicids2017 --data-dir ./data/cicids/
    python scripts/train/train_anomaly.py --dataset unsw --data-dir ./data/unsw/

The trained model and scaler are saved to models/ directory.
"""
import argparse
import sys
import os
import time
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, f1_score, confusion_matrix
import joblib

# Ensure project root is in path
PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

OUTPUT_DIR = PROJECT_ROOT / "models"
OUTPUT_DIR.mkdir(exist_ok=True)


# ── Feature Mapping ─────────────────────────────────────────────────────────
# Maps dataset columns to our 5-feature schema:
#   [bytes_per_second, request_rate, payload_entropy, session_duration, port_risk_score]

# High-risk ports
HIGH_RISK_PORTS = {20, 21, 22, 23, 25, 53, 110, 135, 139, 445, 1433, 3306, 3389, 4444, 5900, 8080}

def _cicids_features(df: pd.DataFrame) -> pd.DataFrame:
    """Map CICIDS 2017 columns to our schema."""
    # CICIDS columns vary by file; normalize names
    df.columns = df.columns.str.strip()

    features = pd.DataFrame()
    features["bytes_per_second"] = df.get("Flow Bytes/s", df.get("flow_bytes_s", 0)).astype(float)
    features["request_rate"] = df.get("Flow Packets/s", df.get("flow_pkts_s", 0)).astype(float)
    features["payload_entropy"] = np.random.uniform(0.3, 0.7, len(df))  # CICIDS doesn't have raw entropy
    features["session_duration"] = df.get("Flow Duration", df.get("flow_duration", 0)).astype(float) / 1e6  # microseconds → seconds
    
    dst_port = df.get("Destination Port", df.get("dst_port", 0)).astype(int)
    features["port_risk_score"] = dst_port.apply(lambda p: 1.0 if p in HIGH_RISK_PORTS else 0.0)

    # Label
    label_col = "Label" if "Label" in df.columns else "label"
    features["label"] = df[label_col].str.strip().str.upper()
    features["is_attack"] = (features["label"] != "BENIGN").astype(int)

    return features


def _unsw_features(df: pd.DataFrame) -> pd.DataFrame:
    """Map UNSW-NB15 columns to our schema."""
    df.columns = df.columns.str.strip()

    features = pd.DataFrame()
    features["bytes_per_second"] = (df.get("sbytes", 0).astype(float) + df.get("dbytes", 0).astype(float)) / (df.get("dur", 1).astype(float) + 0.001)
    features["request_rate"] = (df.get("spkts", 0).astype(float) + df.get("dpkts", 0).astype(float)) / (df.get("dur", 1).astype(float) + 0.001)
    features["payload_entropy"] = df.get("ct_flw_http_mthd", np.random.uniform(0.3, 0.7, len(df))).astype(float)
    features["session_duration"] = df.get("dur", 0).astype(float)
    
    dst_port = df.get("dsport", df.get("Dsport", 0)).astype(int)
    features["port_risk_score"] = dst_port.apply(lambda p: 1.0 if p in HIGH_RISK_PORTS else 0.0)

    features["label"] = df.get("attack_cat", df.get("Label", "Normal")).fillna("Normal").str.strip()
    features["is_attack"] = df.get("label", df.get("Label", 0)).astype(int)

    return features


def load_dataset(dataset: str, data_dir: str) -> pd.DataFrame:
    """Load and preprocess a dataset."""
    data_path = Path(data_dir)
    
    print(f"\n📁 Loading {dataset} data from: {data_path}")
    
    csv_files = list(data_path.glob("*.csv"))
    if not csv_files:
        print(f"❌ No CSV files found in {data_path}")
        sys.exit(1)
    
    print(f"   Found {len(csv_files)} CSV file(s)")
    
    dfs = []
    for f in csv_files:
        print(f"   Loading: {f.name}...", end=" ")
        try:
            df = pd.read_csv(f, low_memory=False)
            dfs.append(df)
            print(f"✓ ({len(df)} rows)")
        except Exception as e:
            print(f"⚠ Skipped ({e})")
    
    if not dfs:
        print("❌ No data loaded")
        sys.exit(1)
    
    raw = pd.concat(dfs, ignore_index=True)
    print(f"\n📊 Total rows: {len(raw):,}")
    
    # Map features
    if dataset == "cicids2017":
        features = _cicids_features(raw)
    elif dataset == "unsw":
        features = _unsw_features(raw)
    else:
        print(f"❌ Unknown dataset: {dataset}")
        sys.exit(1)
    
    # Clean: drop inf/nan
    feature_cols = ["bytes_per_second", "request_rate", "payload_entropy", "session_duration", "port_risk_score"]
    features = features.replace([np.inf, -np.inf], np.nan).dropna(subset=feature_cols)
    
    print(f"📊 Clean rows: {len(features):,}")
    print(f"📊 Attack distribution:")
    print(features["label"].value_counts().head(10).to_string())
    
    return features


def train_model(features: pd.DataFrame) -> None:
    """Train Isolation Forest on benign-only data and evaluate."""
    feature_cols = ["bytes_per_second", "request_rate", "payload_entropy", "session_duration", "port_risk_score"]
    
    # Split: train on BENIGN only, test on mixed
    benign = features[features["is_attack"] == 0]
    attack = features[features["is_attack"] == 1]
    
    print(f"\n🔬 Training data: {len(benign):,} benign samples")
    print(f"🔬 Attack data:   {len(attack):,} attack samples")
    
    # Sample if dataset is too large
    MAX_TRAIN = 50000
    if len(benign) > MAX_TRAIN:
        benign_train = benign.sample(MAX_TRAIN, random_state=42)
        print(f"   Sampled {MAX_TRAIN:,} for training (dataset too large)")
    else:
        benign_train = benign
    
    X_train = benign_train[feature_cols].values
    
    # Scale
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    
    # Train
    print("\n🏋️ Training Isolation Forest...")
    t0 = time.time()
    model = IsolationForest(
        n_estimators=150,
        contamination=0.05,
        max_samples=min(len(X_train_scaled), 10000),
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train_scaled)
    train_time = time.time() - t0
    print(f"   Done in {train_time:.1f}s")
    
    # ── Evaluate ─────────────────────────────────────────────────────────────
    MAX_EVAL = 20000
    eval_benign = benign.sample(min(MAX_EVAL // 2, len(benign)), random_state=42)
    eval_attack = attack.sample(min(MAX_EVAL // 2, len(attack)), random_state=42)
    eval_data = pd.concat([eval_benign, eval_attack], ignore_index=True)
    
    X_eval = eval_data[feature_cols].values
    y_true = eval_data["is_attack"].values
    
    X_eval_scaled = scaler.transform(X_eval)
    y_pred = model.predict(X_eval_scaled)
    # IF returns: 1 = normal, -1 = anomaly → convert to 0/1
    y_pred_binary = (y_pred == -1).astype(int)
    
    print("\n📋 Evaluation Results:")
    print("-" * 50)
    print(classification_report(y_true, y_pred_binary, target_names=["Benign", "Attack"]))
    
    f1 = f1_score(y_true, y_pred_binary)
    print(f"F1 Score (Attack class): {f1:.4f}")
    print(f"\nConfusion Matrix:")
    cm = confusion_matrix(y_true, y_pred_binary)
    print(f"  TN={cm[0][0]:,}  FP={cm[0][1]:,}")
    print(f"  FN={cm[1][0]:,}  TP={cm[1][1]:,}")
    
    # ── Save ─────────────────────────────────────────────────────────────────
    model_path = OUTPUT_DIR / "anomaly_if.joblib"
    scaler_path = OUTPUT_DIR / "anomaly_scaler.joblib"
    
    joblib.dump(model, model_path)
    joblib.dump(scaler, scaler_path)
    
    print(f"\n💾 Model saved to: {model_path}")
    print(f"💾 Scaler saved to: {scaler_path}")
    print(f"\n✅ Training complete! F1={f1:.4f}")


def train_synthetic() -> None:
    """Train on synthetic data (no external dataset needed)."""
    from sentinel.detectors.network_anomaly import _generate_normal_traffic
    
    print("\n🔬 Training on synthetic normal traffic data...")
    print("   (Use --dataset and --data-dir for real dataset training)")
    
    X = _generate_normal_traffic(2000)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    model = IsolationForest(
        n_estimators=150,
        contamination=0.05,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_scaled)
    
    model_path = OUTPUT_DIR / "anomaly_if.joblib"
    scaler_path = OUTPUT_DIR / "anomaly_scaler.joblib"
    
    joblib.dump(model, model_path)
    joblib.dump(scaler, scaler_path)
    
    print(f"💾 Model saved to: {model_path}")
    print(f"💾 Scaler saved to: {scaler_path}")
    print("✅ Synthetic training complete!")


def main():
    parser = argparse.ArgumentParser(
        description="Train the TrustCore Sentinel X network anomaly detection model"
    )
    parser.add_argument(
        "--dataset",
        choices=["cicids2017", "unsw", "synthetic"],
        default="synthetic",
        help="Dataset to train on (default: synthetic)",
    )
    parser.add_argument(
        "--data-dir",
        type=str,
        default="./data",
        help="Directory containing the dataset CSV files",
    )
    args = parser.parse_args()
    
    print("=" * 60)
    print("  TrustCore Sentinel X — Anomaly Model Trainer")
    print("=" * 60)
    
    if args.dataset == "synthetic":
        train_synthetic()
    else:
        try:
            features = load_dataset(args.dataset, args.data_dir)
            train_model(features)
        except Exception as e:
            print(f"\n❌ Training failed: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)


if __name__ == "__main__":
    main()

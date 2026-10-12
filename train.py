"""
ML Model Training — Phase 13

Trains a Random Forest classifier on labeled code samples.
Uses features extracted by ml/src/features.py.

IMPORTANT: The demo dataset bundled in ml/dataset/ is SYNTHETIC and
clearly labeled as such. It exists only to validate the training pipeline.
Do NOT treat demo accuracy metrics as representative of real-world performance.
Replace with a real labeled dataset before any production or research use.

Usage:
    python3 -m ml.src.train
"""
import os
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

from ml.src.features import extract_features, CodeFeatures
from ml.src.evaluate import evaluate_model

DATASET_PATH = os.path.join(os.path.dirname(__file__), "..", "dataset", "demo_dataset.json")
MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "models")
MODEL_PATH = os.path.join(MODEL_DIR, "classifier.joblib")
ENCODER_PATH = os.path.join(MODEL_DIR, "label_encoder.joblib")


def load_dataset(path: str):
    """Load JSON dataset. Each entry: {code: str, label: str}"""
    with open(path) as f:
        data = json.load(f)
    print(f"[train] Loaded {len(data)} samples from {path}")
    return data


def build_feature_matrix(data: list[dict]):
    """Extract features from all samples, return X (numpy) and y (list)."""
    X, y = [], []
    for item in data:
        features = extract_features(item["code"])
        X.append(features.to_list())
        y.append(item["label"])
    return np.array(X), y


def train():
    print("═" * 50)
    print(" SecureCloud IDE — ML Training Pipeline")
    print("═" * 50)

    os.makedirs(MODEL_DIR, exist_ok=True)

    # Load dataset
    data = load_dataset(DATASET_PATH)

    # Feature extraction
    print("[train] Extracting features...")
    X, y_raw = build_feature_matrix(data)

    # Label encoding (BENIGN=0, SUSPICIOUS=1, MALICIOUS=2)
    encoder = LabelEncoder()
    y = encoder.fit_transform(y_raw)
    print(f"[train] Classes: {list(encoder.classes_)}")

    # Train/test split (80/20)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"[train] Train: {len(X_train)} | Test: {len(X_test)}")

    # Train Random Forest
    print("[train] Training Random Forest classifier...")
    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=42,
        class_weight="balanced",
    )
    clf.fit(X_train, y_train)

    # Evaluate
    print("[train] Evaluating...")
    evaluate_model(clf, X_test, y_test, encoder)

    # Save model + encoder
    joblib.dump(clf, MODEL_PATH)
    joblib.dump(encoder, ENCODER_PATH)
    print(f"[train] Model saved → {MODEL_PATH}")
    print(f"[train] Encoder saved → {ENCODER_PATH}")

    # Feature importance
    feature_names = CodeFeatures.feature_names()
    importances = clf.feature_importances_
    fi = sorted(zip(feature_names, importances), key=lambda x: x[1], reverse=True)
    print("\n[train] Top 10 feature importances:")
    for name, imp in fi[:10]:
        print(f"  {name:30s}: {imp:.4f}")

    print("\n[train] ✓ Training complete.")


if __name__ == "__main__":
    train()

"""
Multi-Model Research Benchmarking Pipeline:
Trains and compares 4 standard machine learning models for AST security analysis:
1. Logistic Regression
2. Random Forest
3. Support Vector Machine (SVM)
4. Gradient Boosting Classifier

Evaluates Accuracy, Precision, Recall, F1, ROC-AUC, and Confusion Matrix.
Exports comparison benchmark metrics as JSON and CSV for thesis/research paper publication.
"""
from __future__ import annotations
import os
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import SVC
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix

from ml.src.features import extract_features, CodeFeatures

DATASET_PATH = os.path.join(os.path.dirname(__file__), "..", "dataset", "demo_dataset.json")
RESULTS_DIR = os.path.join(os.path.dirname(__file__), "..", "benchmarks")

def run_benchmark():
    os.makedirs(RESULTS_DIR, exist_ok=True)
    with open(DATASET_PATH) as f:
        data = json.load(f)

    X_raw, y_raw = [], []
    for item in data:
        feats = extract_features(item["code"])
        X_raw.append(feats.to_list())
        y_raw.append(item["label"])

    X = np.array(X_raw)
    encoder = LabelEncoder()
    y = encoder.fit_transform(y_raw)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.25, random_state=42, stratify=y
    )

    models = {
        "Logistic Regression": LogisticRegression(max_iter=1000, random_state=42),
        "Random Forest": RandomForestClassifier(n_estimators=100, random_state=42),
        "Support Vector Machine": SVC(probability=True, random_state=42),
        "Gradient Boosting": GradientBoostingClassifier(random_state=42)
    }

    results = []

    for name, model in models.items():
        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)
        y_prob = model.predict_proba(X_test) if hasattr(model, "predict_proba") else None

        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, average="weighted", zero_division=0)
        rec = recall_score(y_test, y_pred, average="weighted", zero_division=0)
        f1 = f1_score(y_test, y_pred, average="weighted", zero_division=0)

        try:
            auc = roc_auc_score(y_test, y_prob, multi_class="ovr", average="weighted")
        except Exception:
            auc = None

        cm = confusion_matrix(y_test, y_pred).tolist()

        results.append({
            "model": name,
            "accuracy": round(float(acc), 4),
            "precision": round(float(prec), 4),
            "recall": round(float(rec), 4),
            "f1_score": round(float(f1), 4),
            "roc_auc": round(float(auc), 4) if auc else "N/A",
            "confusion_matrix": cm
        })

    # Save benchmark table
    benchmark_file = os.path.join(RESULTS_DIR, "model_comparison.json")
    with open(benchmark_file, "w") as f:
        json.dump(results, f, indent=2)

    df = pd.DataFrame(results)[["model", "accuracy", "precision", "recall", "f1_score", "roc_auc"]]
    csv_file = os.path.join(RESULTS_DIR, "model_comparison.csv")
    df.to_csv(csv_file, index=False)

    print("\n══════════════════════════════════════════════════════════════════")
    print(" Multi-Model Security Classifier Benchmark Results")
    print("══════════════════════════════════════════════════════════════════")
    print(df.to_string(index=False))
    print("══════════════════════════════════════════════════════════════════\n")

    return results

if __name__ == "__main__":
    run_benchmark()

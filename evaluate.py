"""
ML Model Evaluation — Phase 13

Computes accuracy, precision, recall, F1, and confusion matrix.
"""
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    roc_auc_score,
)
from sklearn.preprocessing import LabelEncoder


def evaluate_model(clf, X_test, y_test, encoder: LabelEncoder) -> dict:
    y_pred = clf.predict(X_test)
    y_prob = clf.predict_proba(X_test)

    acc = accuracy_score(y_test, y_pred)
    report = classification_report(
        y_test, y_pred, target_names=encoder.classes_, output_dict=True
    )
    cm = confusion_matrix(y_test, y_pred)

    print("\n[evaluate] ─── Evaluation Results ─────────────────────")
    print(f"  Accuracy : {acc:.4f}")
    print(f"\n  Classification Report:")
    print(
        classification_report(y_test, y_pred, target_names=encoder.classes_)
    )
    print(f"  Confusion Matrix:\n{cm}")

    # ROC-AUC (one-vs-rest for multi-class)
    try:
        auc = roc_auc_score(y_test, y_prob, multi_class="ovr", average="weighted")
        print(f"  ROC-AUC (weighted OvR): {auc:.4f}")
    except Exception as e:
        print(f"  ROC-AUC: N/A ({e})")
        auc = None

    print("[evaluate] ───────────────────────────────────────────────")

    return {
        "accuracy": acc,
        "classification_report": report,
        "confusion_matrix": cm.tolist(),
        "roc_auc": auc,
    }

"""
Explainable AI (XAI) feature attribution for AST security classifications.
Calculates feature-level contributions to explain why a snippet was flagged.
"""
from __future__ import annotations
import joblib
import os
import numpy as np
from ml.src.features import extract_features, CodeFeatures

MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "models")
MODEL_PATH = os.path.join(MODEL_DIR, "classifier.joblib")

def explain_prediction(code: str) -> dict:
    """
    Extracts features and calculates weighted feature contributions
    based on the trained Random Forest model's feature importances.
    """
    features = extract_features(code)
    feat_values = features.to_list()
    feat_names = CodeFeatures.feature_names()

    model = None
    if os.path.exists(MODEL_PATH):
        try:
            model = joblib.load(MODEL_PATH)
        except Exception:
            pass

    # Calculate contributions: feature_value * model_importance
    contributions = []
    if model and hasattr(model, "feature_importances_"):
        importances = model.feature_importances_
        for name, val, imp in zip(feat_names, feat_values, importances):
            impact_score = float(val) * float(imp)
            if impact_score > 0:
                contributions.append({
                    "feature": name,
                    "count": int(val),
                    "importance_weight": round(float(imp), 4),
                    "risk_contribution_score": round(impact_score, 4)
                })
    else:
        # Fallback to direct count weights
        for name, val in zip(feat_names, feat_values):
            if val > 0 and ("count" in name or "total" in name):
                contributions.append({
                    "feature": name,
                    "count": int(val),
                    "importance_weight": 0.1,
                    "risk_contribution_score": round(float(val) * 0.1, 4)
                })

    # Sort descending by contribution
    contributions.sort(key=lambda x: x["risk_contribution_score"], reverse=True)

    return {
        "top_contributing_features": contributions[:5],
        "explanation": (
            "These security and AST features contributed most strongly to the model's risk score."
            if contributions else "No suspicious AST or system API features detected."
        )
    }

"""
ML Prediction — Phase 13

Loads the trained classifier and predicts risk label for submitted code.
Integrated into the security pipeline in Phase 15.
"""
import os
import joblib
import numpy as np
from dataclasses import dataclass
from typing import Optional

from ml.src.features import extract_features

MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "classifier.joblib")
ENCODER_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "label_encoder.joblib")

_clf = None
_encoder = None


def _load_model():
    global _clf, _encoder
    if _clf is None:
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(
                f"ML model not found at {MODEL_PATH}. Run `python3 -m ml.src.train` first."
            )
        _clf = joblib.load(MODEL_PATH)
        _encoder = joblib.load(ENCODER_PATH)


@dataclass
class PredictionResult:
    label: str          # BENIGN | SUSPICIOUS | MALICIOUS
    confidence: float   # 0.0 – 1.0
    probabilities: dict # {label: probability}


def predict(code: str) -> Optional[PredictionResult]:
    """
    Predict whether code is BENIGN, SUSPICIOUS, or MALICIOUS.
    Returns None if model is not yet trained.
    """
    try:
        _load_model()
    except FileNotFoundError:
        return None  # Model not trained yet — Phase 15 will handle this gracefully

    features = extract_features(code)
    X = np.array([features.to_list()])

    pred_encoded = _clf.predict(X)[0]
    proba = _clf.predict_proba(X)[0]
    label = _encoder.inverse_transform([pred_encoded])[0]
    confidence = float(proba[pred_encoded])

    prob_dict = {
        _encoder.inverse_transform([i])[0]: float(p)
        for i, p in enumerate(proba)
    }

    return PredictionResult(
        label=label,
        confidence=round(confidence, 4),
        probabilities=prob_dict,
    )

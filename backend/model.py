"""
model.py — ML inference for CloudGuard.

Tries to load trained model artefacts from the model/ directory.
If any artefact is missing, falls back to weighted-random mock predictions
so the rest of the system keeps working while the ML pipeline is being built.
"""

import logging
import pickle
import random
from pathlib import Path

logger = logging.getLogger(__name__)

MODEL_DIR = Path(__file__).parent / "model"

# Module-level artefact cache
_model         = None
_scaler        = None
_label_encoder = None
_feature_cols  = None
_model_loaded  = False


def load_model() -> bool:
    """
    Attempt to load all model artefacts.
    Returns True if successful, False if falling back to mock mode.
    """
    global _model, _scaler, _label_encoder, _feature_cols, _model_loaded

    required = ["model.pkl", "scaler.pkl", "label_encoder.pkl", "feature_cols.pkl"]
    missing  = [f for f in required if not (MODEL_DIR / f).exists()]

    if missing:
        logger.warning(
            f"Model artefacts not found: {missing}. "
            "Running in simulation mode — drop model files into backend/model/ to enable real inference."
        )
        return False

    try:
        with open(MODEL_DIR / "model.pkl",         "rb") as f: _model         = pickle.load(f)
        with open(MODEL_DIR / "scaler.pkl",        "rb") as f: _scaler        = pickle.load(f)
        with open(MODEL_DIR / "label_encoder.pkl", "rb") as f: _label_encoder = pickle.load(f)
        with open(MODEL_DIR / "feature_cols.pkl",  "rb") as f: _feature_cols  = pickle.load(f)
        _model_loaded = True
        logger.info("ML model loaded successfully — real inference active.")
        return True
    except Exception as e:
        logger.error(f"Failed to load model artefacts: {e}. Falling back to simulation.")
        return False


def predict(flow: dict) -> dict:
    """Classify a network flow. Returns a prediction dict."""
    if _model_loaded:
        return _predict_real(flow)
    return _predict_mock(flow)


def is_model_loaded() -> bool:
    return _model_loaded


# ── Internal helpers ───────────────────────────────────────────────────────────

def _predict_real(flow: dict) -> dict:
    try:
        features = [[flow.get(col, 0) for col in _feature_cols]]
        scaled   = _scaler.transform(features)
        pred_idx = _model.predict(scaled)[0]
        proba    = _model.predict_proba(scaled)[0]

        attack_type = _label_encoder.inverse_transform([pred_idx])[0]
        confidence  = round(float(max(proba)), 4)
        is_attack   = attack_type != "BENIGN"

        return {
            "attack_type": attack_type,
            "confidence":  confidence,
            "is_attack":   is_attack,
            "severity":    _severity(attack_type, confidence),
        }
    except Exception as e:
        logger.error(f"Inference error: {e}. Falling back to mock for this flow.")
        return _predict_mock(flow)


_ATTACK_TYPES   = ["BENIGN", "DDoS", "PortScan", "BruteForce", "Infiltration"]
_ATTACK_WEIGHTS = [60, 15, 12, 8, 5]


def _predict_mock(flow: dict) -> dict:
    attack_type = random.choices(_ATTACK_TYPES, weights=_ATTACK_WEIGHTS)[0]
    is_attack   = attack_type != "BENIGN"
    confidence  = round(random.uniform(0.85, 0.99), 2)
    return {
        "attack_type": attack_type,
        "confidence":  confidence,
        "is_attack":   is_attack,
        "severity":    _severity(attack_type, confidence),
    }


def _severity(attack_type: str, confidence: float) -> str:
    if attack_type == "BENIGN":
        return "NONE"
    if confidence >= 0.95 or attack_type in ("DDoS", "Infiltration"):
        return "HIGH"
    return "MEDIUM"

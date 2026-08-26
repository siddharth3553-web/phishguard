"""Load trained artifacts and run URL/email phishing inference.

URL path: ONNX Runtime (scaler + RandomForest).
Email path: skops (custom sklearn pipeline).
"""

from __future__ import annotations

import os
from typing import Any

import numpy as np
import onnxruntime as ort
from skops.io import get_untrusted_types
from skops.io import load as skops_load

from phishguard.paths import models_dir
from phishguard.services.email_features import clean_email_text, find_phishing_keywords
from phishguard.services.url_features import (
    FEATURE_NAMES,
    extract_features,
    extract_features_array,
)
from phishguard.settings import (
    LOW_CONFIDENCE_PROB_THRESHOLD,
    MIN_EMAIL_CHARS,
    MIN_URL_CHARS,
    verdict_from_phishing_probability,
)


def _load_skops(path: str):
    """Load a local skops artifact after reviewing untrusted types."""
    trusted = get_untrusted_types(file=path)
    return skops_load(path, trusted=trusted)


class ModelArtifactsMissingError(FileNotFoundError):
    """Raised when required model files are not present under artifacts/models/."""


class PhishGuardPredictor:
    """Loads trained models and provides prediction methods."""

    _REQUIRED_FILES = (
        "url_model.onnx",
        "email_pipeline.skops",
    )

    def __init__(self, models_path: str | os.PathLike | None = None) -> None:
        base = os.fspath(models_path) if models_path else models_dir()
        missing = [f for f in self._REQUIRED_FILES if not os.path.isfile(os.path.join(base, f))]
        if missing:
            raise ModelArtifactsMissingError(
                f"Missing model files in {base}: {missing}. "
                "Run: uv run python scripts/train_models.py"
            )
        self._base = base
        self._url_session = ort.InferenceSession(
            os.path.join(base, "url_model.onnx"),
            providers=["CPUExecutionProvider"],
        )
        self._url_input = self._url_session.get_inputs()[0].name
        self.email_pipeline = _load_skops(os.path.join(base, "email_pipeline.skops"))

    def predict_url(self, url: str) -> dict[str, Any]:
        url = (url or "").strip()
        if not url:
            raise ValueError("URL must not be empty")
        if len(url) < MIN_URL_CHARS:
            return {
                "label": 0,
                "verdict": "Uncertain",
                "confidence": 0.0,
                "phishing_score": 50.0,
                "features": {},
                "feature_names": FEATURE_NAMES,
                "insufficient_input": True,
                "note": f"URL too short — provide at least {MIN_URL_CHARS} characters.",
                "low_confidence": True,
            }

        features = extract_features(url)
        feature_array = np.array([extract_features_array(url)], dtype=np.float32)
        outputs = self._url_session.run(None, {self._url_input: feature_array})
        # ONNX RF: label + probabilities (zipmap or array)
        prediction = int(outputs[0][0])
        proba_raw = outputs[1][0]
        if isinstance(proba_raw, dict):
            p0 = float(proba_raw.get(0, proba_raw.get("0", 0.0)))
            p1 = float(proba_raw.get(1, proba_raw.get("1", 0.0)))
            probabilities = np.array([p0, p1])
        else:
            probabilities = np.asarray(proba_raw, dtype=float).ravel()
        confidence = float(probabilities[prediction])
        phishing_score = float(probabilities[1]) if len(probabilities) > 1 else float(prediction)

        verdict = verdict_from_phishing_probability(phishing_score)
        low_confidence = confidence < LOW_CONFIDENCE_PROB_THRESHOLD

        return {
            "label": prediction,
            "verdict": verdict,
            "confidence": round(confidence * 100, 2),
            "phishing_score": round(phishing_score * 100, 2),
            "features": features,
            "feature_names": FEATURE_NAMES,
            "low_confidence": low_confidence,
            "insufficient_input": False,
            "note": (
                "Model confidence is low — treat this score as advisory."
                if low_confidence
                else None
            ),
        }

    def predict_email(self, text: str) -> dict[str, Any]:
        raw = text or ""
        t = raw.strip()
        if not t:
            raise ValueError("Email text must not be empty")
        if len(t) < MIN_EMAIL_CHARS:
            return {
                "label": 0,
                "verdict": "Uncertain",
                "confidence": 0.0,
                "phishing_score": 50.0,
                "flagged_keywords": find_phishing_keywords(t),
                "insufficient_input": True,
                "note": f"Provide at least {MIN_EMAIL_CHARS} characters for a reliable scan.",
                "low_confidence": True,
            }

        cleaned = clean_email_text(t)
        _ = cleaned
        proba = self.email_pipeline.predict_proba([t])[0]
        prediction = int(self.email_pipeline.predict([t])[0])
        confidence = float(proba[prediction])
        phishing_score = float(proba[1])

        flagged_keywords = find_phishing_keywords(t)
        verdict = verdict_from_phishing_probability(phishing_score)
        low_confidence = confidence < LOW_CONFIDENCE_PROB_THRESHOLD

        return {
            "label": prediction,
            "verdict": verdict,
            "confidence": round(confidence * 100, 2),
            "phishing_score": round(phishing_score * 100, 2),
            "flagged_keywords": flagged_keywords,
            "insufficient_input": False,
            "low_confidence": low_confidence,
            "note": (
                "Model confidence is low — treat this score as advisory."
                if low_confidence
                else None
            ),
        }

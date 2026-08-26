"""Predictor tests using committed fixture models."""

from __future__ import annotations

from pathlib import Path

import pytest

from phishguard.services.predictor import ModelArtifactsMissingError, PhishGuardPredictor

FIXTURE_MODELS = Path(__file__).parent / "fixtures" / "models"


def test_predict_url_safe() -> None:
    p = PhishGuardPredictor(FIXTURE_MODELS)
    r = p.predict_url("https://www.wikipedia.org/wiki/Python")
    assert r["verdict"] in ("Safe", "Suspicious", "Phishing", "Uncertain")
    assert "features" in r


def test_predict_email_safe() -> None:
    p = PhishGuardPredictor(FIXTURE_MODELS)
    r = p.predict_email("Meeting notes attached. Thanks.")
    assert r["verdict"] in ("Safe", "Suspicious", "Phishing", "Uncertain")


def test_predictor_missing_artifacts() -> None:
    with pytest.raises(ModelArtifactsMissingError):
        PhishGuardPredictor(models_path="/nonexistent/path/models")

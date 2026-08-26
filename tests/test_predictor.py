"""Predictor tests (requires trained artifacts)."""

from __future__ import annotations

import os

import pytest

from phishguard.paths import models_dir
from phishguard.services.predictor import ModelArtifactsMissingError, PhishGuardPredictor


def _artifacts_ready() -> bool:
    base = models_dir()
    needed = ["url_model.pkl", "url_scaler.pkl", "email_pipeline.pkl"]
    return all(os.path.isfile(os.path.join(base, f)) for f in needed)


@pytest.mark.skipif(not _artifacts_ready(), reason="Run scripts/train_models.py first")
def test_predict_url_safe():
    p = PhishGuardPredictor()
    r = p.predict_url("https://www.wikipedia.org/wiki/Python")
    assert r["verdict"] in ("Safe", "Suspicious", "Phishing")
    assert "features" in r


@pytest.mark.skipif(not _artifacts_ready(), reason="Run scripts/train_models.py first")
def test_predict_email_safe():
    p = PhishGuardPredictor()
    r = p.predict_email("Meeting notes attached. Thanks.")
    assert r["verdict"] in ("Safe", "Suspicious", "Phishing")


def test_predictor_missing_artifacts():
    with pytest.raises(ModelArtifactsMissingError):
        PhishGuardPredictor(models_path="/nonexistent/path/models")

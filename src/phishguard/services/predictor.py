"""Load trained artifacts and run fused URL/email phishing inference.

URL path: ONNX Runtime (scaler + RandomForest) + URL intel rules.
Email path: skops pipeline + email/URL intel fusion.
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
from phishguard.services.email_intel import enrich_email
from phishguard.services.url_features import (
    FEATURE_NAMES,
    extract_features,
    extract_features_array,
)
from phishguard.services.url_intel import DEFAULT_BRANDS, enrich_url
from phishguard.settings import (
    LOW_CONFIDENCE_PROB_THRESHOLD,
    MIN_EMAIL_CHARS,
    MIN_URL_CHARS,
    verdict_from_phishing_probability,
)

# Rule hits that force phishing / uncertain regardless of soft model score
HARD_PHISH_PREFIXES = (
    "lookalike_of:",
    "redirect_lookalike_of:",
    "display_name_brand_spoof:",
    "ip_literal_host",
)
HARD_UNCERTAIN = (
    "url_shortener",
    "risky_tld:",
    "punycode_host",
    "from_return_path_mismatch",
    "urgency_language:",
    "redirect_host_changed:",
    "dns_unresolved",
)


def _load_skops(path: str):
    trusted = get_untrusted_types(file=path)
    return skops_load(path, trusted=trusted)


def _fuse_verdict(
    model_verdict: str,
    phishing_score_pct: float,
    reasons: list[str],
    *,
    low_confidence: bool,
) -> tuple[str, list[str]]:
    _ = phishing_score_pct
    reasons = list(dict.fromkeys(reasons))
    if "allowlisted" in reasons:
        return "Safe", ["allowlisted"]

    hard_phish = False
    for r in reasons:
        for p in HARD_PHISH_PREFIXES:
            if p.endswith(":"):
                if r.startswith(p):
                    hard_phish = True
            elif r == p:
                hard_phish = True

    if hard_phish:
        if "rule_hard_phish" not in reasons:
            reasons.append("rule_hard_phish")
        return "Phishing", reasons

    uncertain_hit = False
    for r in reasons:
        for p in HARD_UNCERTAIN:
            if p.endswith(":"):
                if r.startswith(p) or r == p.rstrip(":"):
                    uncertain_hit = True
            elif r == p or r.startswith(p):
                uncertain_hit = True

    if low_confidence and "low_model_confidence" not in reasons:
        reasons.append("low_model_confidence")

    if model_verdict == "Phishing":
        return "Phishing", reasons
    if model_verdict == "Safe" and not uncertain_hit and not low_confidence:
        return "Safe", reasons
    if uncertain_hit or low_confidence or model_verdict == "Uncertain":
        if model_verdict == "Safe" and uncertain_hit:
            reasons.append("elevated_by_rules")
        return "Uncertain", reasons
    return model_verdict, reasons


class ModelArtifactsMissingError(FileNotFoundError):
    """Raised when required model files are not present under artifacts/models/."""


class PhishGuardPredictor:
    """Loads trained models and provides fused prediction methods."""

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
        self.brand_domains = list(DEFAULT_BRANDS)

    def predict_url(
        self,
        url: str,
        *,
        brands: list[str] | None = None,
        allowlisted: set[str] | None = None,
        follow_redirects: bool = True,
        extra_reasons: list[str] | None = None,
    ) -> dict[str, Any]:
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
                "reasons": ["insufficient_input"],
                "url_intel": None,
                "extracted_urls": [url] if url else [],
            }

        intel = enrich_url(
            url,
            brands=brands or self.brand_domains,
            allowlisted=allowlisted,
            follow=follow_redirects,
        )
        if intel.get("suppress"):
            return {
                "label": 0,
                "verdict": "Safe",
                "confidence": 100.0,
                "phishing_score": 0.0,
                "features": {},
                "feature_names": FEATURE_NAMES,
                "low_confidence": False,
                "insufficient_input": False,
                "note": "Matched org allowlist.",
                "reasons": ["allowlisted"],
                "url_intel": intel,
                "extracted_urls": [url],
            }

        features = extract_features(url)
        feature_array = np.array([extract_features_array(url)], dtype=np.float32)
        outputs = self._url_session.run(None, {self._url_input: feature_array})
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

        model_verdict = verdict_from_phishing_probability(phishing_score)
        low_confidence = confidence < LOW_CONFIDENCE_PROB_THRESHOLD
        reasons = list(intel.get("reasons") or [])
        if extra_reasons:
            reasons.extend(extra_reasons)
        verdict, reasons = _fuse_verdict(
            model_verdict, phishing_score * 100, reasons, low_confidence=low_confidence
        )
        # bump score slightly when rules elevate
        score_pct = round(phishing_score * 100, 2)
        if verdict == "Phishing" and score_pct < 70 and any(
            r.startswith("lookalike_of:") or r.startswith("rule_hard") for r in reasons
        ):
            score_pct = max(score_pct, 82.0)

        return {
            "label": 1 if verdict == "Phishing" else prediction,
            "verdict": verdict,
            "confidence": round(confidence * 100, 2),
            "phishing_score": score_pct,
            "features": features,
            "feature_names": FEATURE_NAMES,
            "low_confidence": low_confidence or verdict == "Uncertain",
            "insufficient_input": False,
            "note": (
                "Model confidence is low — treat this score as advisory."
                if low_confidence
                else None
            ),
            "reasons": reasons,
            "url_intel": intel,
            "extracted_urls": [url],
        }

    def predict_email(
        self,
        text: str,
        *,
        brands: list[str] | None = None,
        allowlisted: set[str] | None = None,
    ) -> dict[str, Any]:
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
                "reasons": ["insufficient_input"],
                "extracted_urls": [],
                "email_intel": None,
            }

        ein = enrich_email(t, brands=brands or self.brand_domains, allowlisted=allowlisted)
        if ein.get("suppress"):
            return {
                "label": 0,
                "verdict": "Safe",
                "confidence": 100.0,
                "phishing_score": 0.0,
                "flagged_keywords": [],
                "insufficient_input": False,
                "low_confidence": False,
                "note": "Sender matched org allowlist.",
                "reasons": ["allowlisted"],
                "extracted_urls": ein.get("extracted_urls") or [],
                "email_intel": ein,
            }

        cleaned = clean_email_text(t)
        _ = cleaned
        proba = self.email_pipeline.predict_proba([t])[0]
        prediction = int(self.email_pipeline.predict([t])[0])
        confidence = float(proba[prediction])
        phishing_score = float(proba[1])

        flagged_keywords = find_phishing_keywords(t)
        model_verdict = verdict_from_phishing_probability(phishing_score)
        low_confidence = confidence < LOW_CONFIDENCE_PROB_THRESHOLD
        reasons = list(ein.get("reasons") or [])
        verdict, reasons = _fuse_verdict(
            model_verdict, phishing_score * 100, reasons, low_confidence=low_confidence
        )
        score_pct = round(phishing_score * 100, 2)
        if verdict == "Phishing" and score_pct < 70:
            score_pct = max(score_pct, 78.0)

        return {
            "label": 1 if verdict == "Phishing" else prediction,
            "verdict": verdict,
            "confidence": round(confidence * 100, 2),
            "phishing_score": score_pct,
            "flagged_keywords": flagged_keywords,
            "insufficient_input": False,
            "low_confidence": low_confidence or verdict == "Uncertain",
            "note": (
                "Model confidence is low — treat this score as advisory."
                if low_confidence
                else None
            ),
            "reasons": reasons,
            "extracted_urls": ein.get("extracted_urls") or [],
            "email_intel": ein,
        }

"""Central defaults for data generation, training, and inference (single source of truth)."""

from __future__ import annotations

from dataclasses import dataclass

# Synthetic dataset sizes (scripts/prepare_data.py)
DATASET_URL_COUNT = 14_000
DATASET_EMAIL_COUNT = 10_000

# Training split (scripts/train_models.py)
TRAIN_TEST_SIZE = 0.2
RANDOM_STATE = 42

# Minimum text length for stable email scoring (characters)
MIN_EMAIL_CHARS = 16
MIN_URL_CHARS = 10

# If max class probability falls below this, mark as low-confidence (advisory)
LOW_CONFIDENCE_PROB_THRESHOLD = 0.52


@dataclass(frozen=True)
class PhishingVerdictThresholds:
    """Probability thresholds on P(phishing) in [0, 1]."""

    safe_below: float = 0.32
    suspicious_below: float = 0.72


VERDICT_THRESHOLDS = PhishingVerdictThresholds()


def verdict_from_phishing_probability(p_phish: float) -> str:
    """Map model phishing probability to Safe / Uncertain / Phishing."""
    t = VERDICT_THRESHOLDS
    if p_phish < t.safe_below:
        return "Safe"
    if p_phish < t.suspicious_below:
        return "Uncertain"
    return "Phishing"

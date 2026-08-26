"""Dense numeric / heuristic features for email phishing (stacked with TF-IDF)."""

from __future__ import annotations

import re
import unicodedata
from typing import Sequence

import numpy as np

from phishguard.services.email_features import PHISHING_KEYWORDS, clean_email_text

# Benign office / transactional cues (reduce false positives on real mail)
BENIGN_CUES = [
    "thanks",
    "thank you",
    "regards",
    "best regards",
    "meeting",
    "standup",
    "attached",
    "minutes",
    "invoice",
    "shipped",
    "calendar",
    "looking forward",
    "please let me know",
    "no action needed",
]

NUMERIC_EMAIL_FEATURE_NAMES: tuple[str, ...] = (
    "log_len_raw",
    "log_len_clean",
    "word_count",
    "unique_word_ratio",
    "exclaim_ratio",
    "digit_ratio",
    "upper_ratio",
    "url_like_count",
    "phish_kw_density",
    "benign_kw_density",
    "urgent_token",
    "non_ascii_ratio",
)


def extract_email_numeric_features(raw: str) -> np.ndarray:
    """Fixed-length vector aligned with NUMERIC_EMAIL_FEATURE_NAMES."""
    raw = raw or ""
    cleaned = clean_email_text(raw)
    words = cleaned.split()
    n_words = max(len(words), 1)
    unique = len(set(words))
    raw_len = max(len(raw), 1)
    exclaims = raw.count("!")
    digits = sum(c.isdigit() for c in raw)
    letters = sum(c.isalpha() for c in raw) or 1
    uppers = sum(c.isupper() for c in raw)
    url_like = len(re.findall(r"https?://\S+|www\.\S+", raw, re.I))
    low = raw.lower()
    phish_hits = sum(1 for kw in PHISHING_KEYWORDS if kw in low)
    benign_hits = sum(1 for kw in BENIGN_CUES if kw in low)
    urgent = 1.0 if re.search(r"\burgent\b|\bimmediate\b|\balert\b", low) else 0.0
    non_ascii = 0
    for ch in raw:
        if ord(ch) > 127:
            try:
                if unicodedata.category(ch) not in ("Cc", "Cf"):
                    non_ascii += 1
            except Exception:
                non_ascii += 1
    non_ascii_r = non_ascii / raw_len

    vec = np.array(
        [
            np.log1p(len(raw)),
            np.log1p(len(cleaned)),
            float(len(words)),
            unique / n_words,
            exclaims / raw_len,
            digits / raw_len,
            uppers / letters,
            float(url_like),
            phish_hits / max(len(PHISHING_KEYWORDS), 1),
            benign_hits / max(len(BENIGN_CUES), 1),
            urgent,
            non_ascii_r,
        ],
        dtype=np.float64,
    )
    assert vec.shape[0] == len(NUMERIC_EMAIL_FEATURE_NAMES)
    return vec


def stack_numeric_batch(texts: Sequence[str]) -> np.ndarray:
    return np.vstack([extract_email_numeric_features(t) for t in texts])

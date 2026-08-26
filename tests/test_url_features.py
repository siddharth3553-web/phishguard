"""Tests for URL feature extraction."""

from __future__ import annotations

import pytest

from phishguard.services.url_features import (
    FEATURE_NAMES,
    extract_features,
    extract_features_array,
)


def test_extract_features_google():
    feats = extract_features("https://www.google.com/search?q=test")
    assert feats["has_https"] == 1
    assert feats["url_length"] > 0
    assert len(FEATURE_NAMES) == len(extract_features_array("https://www.google.com/"))


def test_extract_features_empty_raises():
    with pytest.raises(ValueError):
        extract_features("")


def test_extract_features_without_scheme():
    feats = extract_features("example.com/path")
    assert "url_length" in feats

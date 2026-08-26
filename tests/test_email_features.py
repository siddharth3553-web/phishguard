"""Email preprocessing tests."""

from __future__ import annotations

from phishguard.services.email_features import clean_email_text, find_phishing_keywords


def test_clean_email_strips_html():
    t = clean_email_text("<p>Hello <b>World</b></p>")
    assert "hello" in t
    assert "<" not in t


def test_find_keywords():
    k = find_phishing_keywords("URGENT: verify your account now")
    assert any("urgent" in x or "verify" in x for x in k)

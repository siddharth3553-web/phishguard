"""Settings and verdict mapping."""

from phishguard.settings import verdict_from_phishing_probability


def test_verdict_mapping():
    assert verdict_from_phishing_probability(0.0) == "Safe"
    assert verdict_from_phishing_probability(0.29) == "Safe"
    assert verdict_from_phishing_probability(0.5) == "Suspicious"
    assert verdict_from_phishing_probability(0.95) == "Phishing"

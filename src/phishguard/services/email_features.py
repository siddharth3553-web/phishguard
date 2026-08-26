import re

PHISHING_KEYWORDS = [
    "urgent",
    "verify your account",
    "click here",
    "suspended",
    "confirm your identity",
    "update your information",
    "act now",
    "limited time",
    "congratulations",
    "you have won",
    "prize",
    "lottery",
    "free gift",
    "credit card",
    "social security",
    "password expired",
    "unauthorized access",
    "unusual activity",
    "wire transfer",
    "bank account",
    "paypal",
    "apple id",
    "immediate action",
    "security alert",
    "your account will be",
]


def clean_email_text(text: str) -> str:
    """Preprocess raw email text for ML ingestion."""
    text = re.sub(r"<[^>]+>", " ", text or "")
    text = text.lower()
    text = re.sub(r"http\S+|www\.\S+", " urltoken ", text)
    text = re.sub(r"\S+@\S+", " emailtoken ", text)
    text = re.sub(r"[^a-z\s]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def find_phishing_keywords(text: str) -> list[str]:
    """Return list of phishing keywords found in the email text."""
    text_lower = (text or "").lower()
    return [kw for kw in PHISHING_KEYWORDS if kw in text_lower]

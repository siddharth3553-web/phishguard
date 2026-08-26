#!/usr/bin/env python3
"""Train tiny models for CI (committed under tests/fixtures/models/)."""

from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import SGDClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from phishguard.ml.email_hybrid import EmailFeatureMixer
from phishguard.services.url_features import extract_features_array

OUT = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "models"


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    urls = [
        "https://www.google.com/search",
        "https://github.com/siddharth3553-web/phishguard",
        "https://www.wikipedia.org/wiki/Python",
        "https://www.microsoft.com/en-us",
        "https://www.apple.com/store",
        "http://verify-paypal.tk/login",
        "http://192.168.1.9/webscr?id=abc",
        "http://bit.ly/x9k2ab",
        "http://secure-apple.xyz/confirm?id=99",
        "http://login-microsoft.ml/account-update",
    ]
    y_url = np.array([0, 0, 0, 0, 0, 1, 1, 1, 1, 1])
    X = np.vstack([extract_features_array(u) for u in urls])
    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)
    clf = RandomForestClassifier(n_estimators=20, max_depth=6, random_state=42)
    clf.fit(Xs, y_url)
    joblib.dump(clf, OUT / "url_model.pkl")
    joblib.dump(scaler, OUT / "url_scaler.pkl")

    emails = [
        "Your order has shipped. Track it at https://amazon.com/orders/1",
        "Meeting reminder: project sync tomorrow at 10:00 AM.",
        "GitHub: a pull request is waiting for review.",
        "Weekly digest from wikipedia.org: top articles for you.",
        "Calendar invite accepted for design review on Friday.",
        "URGENT: verify your PayPal account now http://verify-paypal.tk/login",
        "Your package could not be delivered. Update shipping: http://bit.ly/x9k2ab",
        "We suspended your wallet. Verify ownership within 24 hours.",
        "Payroll deposit failed. Confirm bank details immediately.",
        "Security alert: password expires today. Reset here http://secure-apple.xyz/confirm",
    ]
    y_email = np.array([0, 0, 0, 0, 0, 1, 1, 1, 1, 1])
    pipe = Pipeline(
        [
            (
                "feats",
                EmailFeatureMixer(word_max_features=400, char_max_features=200),
            ),
            (
                "clf",
                SGDClassifier(
                    loss="log_loss",
                    max_iter=500,
                    random_state=42,
                    class_weight="balanced",
                ),
            ),
        ]
    )
    pipe.fit(emails, y_email)
    joblib.dump(pipe, OUT / "email_pipeline.pkl")
    print(f"[OK] wrote fixture models -> {OUT}")


if __name__ == "__main__":
    main()

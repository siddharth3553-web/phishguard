#!/usr/bin/env python3
"""Train tiny ONNX + skops models for CI (committed under tests/fixtures/models/)."""

from __future__ import annotations

from pathlib import Path

import numpy as np
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import SGDClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from skops.io import dump as skops_dump

from phishguard.ml.email_hybrid import EmailFeatureMixer
from phishguard.services.url_features import FEATURE_NAMES, extract_features_array

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
    pipe = Pipeline(
        [
            ("scaler", StandardScaler()),
            ("clf", RandomForestClassifier(n_estimators=20, max_depth=6, random_state=42)),
        ]
    )
    pipe.fit(X, y_url)
    onnx_model = convert_sklearn(
        pipe,
        initial_types=[("input", FloatTensorType([None, len(FEATURE_NAMES)]))],
        target_opset=12,
    )
    (OUT / "url_model.onnx").write_bytes(onnx_model.SerializeToString())

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
    email_pipe = Pipeline(
        [
            ("feats", EmailFeatureMixer(word_max_features=400, char_max_features=200)),
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
    email_pipe.fit(emails, y_email)
    skops_dump(email_pipe, OUT / "email_pipeline.skops")
    print(f"[OK] wrote fixture models -> {OUT}")


if __name__ == "__main__":
    main()

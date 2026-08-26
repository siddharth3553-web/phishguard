#!/usr/bin/env python3
"""
Train URL and email phishing classifiers.

Reads:  data/raw/url_data.csv, data/raw/email_data.csv
Writes: artifacts/models/url_model.onnx, email_pipeline.skops, artifacts/metrics/*.json

Run: uv run python scripts/train_models.py
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

import numpy as np
import pandas as pd
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    roc_auc_score,
)
from sklearn.model_selection import RandomizedSearchCV, StratifiedKFold, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from skops.io import dump as skops_dump

from phishguard.ml.email_hybrid import EmailFeatureMixer
from phishguard.paths import data_raw_dir, metrics_dir, models_dir
from phishguard.services.url_features import FEATURE_NAMES, extract_features_array
from phishguard.settings import RANDOM_STATE, TRAIN_TEST_SIZE

DATA_DIR = str(data_raw_dir())
MODEL_DIR = str(models_dir())
METRICS_DIR = str(metrics_dir())
LABELS = ["Legitimate", "Phishing"]


def _write_manifest(extra: dict) -> None:
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "random_state": RANDOM_STATE,
        "train_test_size": TRAIN_TEST_SIZE,
        **extra,
    }
    path = os.path.join(METRICS_DIR, "training_manifest.json")
    existing: dict = {}
    if os.path.isfile(path):
        with open(path, encoding="utf-8") as f:
            existing = json.load(f)
    existing.update(payload)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(existing, f, indent=2, default=str)


def _dump_metrics(name: str, payload: dict) -> None:
    os.makedirs(METRICS_DIR, exist_ok=True)
    with open(os.path.join(METRICS_DIR, name), "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def train_url(df: pd.DataFrame) -> None:
    X = np.vstack([extract_features_array(u) for u in df["url"].astype(str)])
    y = df["label"].astype(int).to_numpy()

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=TRAIN_TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=y,
    )

    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s = scaler.transform(X_test)

    base = RandomForestClassifier(random_state=RANDOM_STATE, n_jobs=-1)
    search = RandomizedSearchCV(
        base,
        param_distributions={
            "n_estimators": [200, 300, 350, 400],
            "max_depth": [10, 12, 14, 16, None],
            "min_samples_leaf": [1, 2],
            "max_features": ["sqrt", "log2"],
            "class_weight": ["balanced", "balanced_subsample"],
        },
        n_iter=12,
        cv=StratifiedKFold(5, shuffle=True, random_state=RANDOM_STATE),
        scoring="roc_auc",
        random_state=RANDOM_STATE,
        n_jobs=-1,
        refit=True,
    )
    search.fit(X_train_s, y_train)
    model = search.best_estimator_

    y_pred = model.predict(X_test_s)
    y_proba = model.predict_proba(X_test_s)[:, 1]
    auc = roc_auc_score(y_test, y_proba)
    f1 = f1_score(y_test, y_pred)

    os.makedirs(MODEL_DIR, exist_ok=True)
    url_pipe = Pipeline([("scaler", scaler), ("clf", model)])
    onnx_model = convert_sklearn(
        url_pipe,
        initial_types=[("input", FloatTensorType([None, len(FEATURE_NAMES)]))],
        target_opset=12,
    )
    with open(os.path.join(MODEL_DIR, "url_model.onnx"), "wb") as f:
        f.write(onnx_model.SerializeToString())

    metrics = {
        "task": "url",
        "artifact": "url_model.onnx",
        "best_params": search.best_params_,
        "cv_best_roc_auc": round(float(search.best_score_), 4),
        "holdout_roc_auc": round(float(auc), 4),
        "f1": round(float(f1), 4),
        "report": classification_report(
            y_test, y_pred, target_names=LABELS, output_dict=True, zero_division=0
        ),
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
        "labels": LABELS,
    }
    _dump_metrics("url_metrics.json", metrics)
    _write_manifest({"url_best_params": search.best_params_, "url_cv_auc": float(search.best_score_)})
    print(f"[OK] URL ONNX saved. Hold-out ROC-AUC: {auc:.4f} (CV: {search.best_score_:.4f})")


def train_email(df: pd.DataFrame) -> None:
    X = df["text"].astype(str)
    y = df["label"].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=TRAIN_TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=y,
    )

    pipe = Pipeline(
        [
            ("feats", EmailFeatureMixer()),
            (
                "clf",
                SGDClassifier(
                    loss="log_loss",
                    max_iter=2000,
                    random_state=RANDOM_STATE,
                    class_weight="balanced",
                ),
            ),
        ]
    )
    search = RandomizedSearchCV(
        pipe,
        param_distributions={
            "feats__word_max_features": [6000, 8000, 12_000],
            "feats__char_max_features": [4000, 6000],
            "clf__alpha": np.logspace(-5, -2, 8),
        },
        n_iter=12,
        cv=StratifiedKFold(5, shuffle=True, random_state=RANDOM_STATE),
        scoring="roc_auc",
        random_state=RANDOM_STATE,
        n_jobs=-1,
        refit=True,
    )
    search.fit(X_train.tolist(), y_train)
    best: Pipeline = search.best_estimator_

    y_pred = best.predict(X_test.tolist())
    y_proba = best.predict_proba(X_test.tolist())[:, 1]
    auc = roc_auc_score(y_test, y_proba)
    f1 = f1_score(y_test, y_pred)

    os.makedirs(MODEL_DIR, exist_ok=True)
    skops_dump(best, os.path.join(MODEL_DIR, "email_pipeline.skops"))

    metrics = {
        "task": "email",
        "artifact": "email_pipeline.skops",
        "best_params": {
            k: (str(v) if not isinstance(v, (int, float, bool)) else v)
            for k, v in search.best_params_.items()
        },
        "cv_best_roc_auc": round(float(search.best_score_), 4),
        "holdout_roc_auc": round(float(auc), 4),
        "f1": round(float(f1), 4),
        "report": classification_report(
            y_test, y_pred, target_names=LABELS, output_dict=True, zero_division=0
        ),
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
        "labels": LABELS,
    }
    _dump_metrics("email_metrics.json", metrics)
    _write_manifest(
        {"email_best_params": search.best_params_, "email_cv_auc": float(search.best_score_)}
    )
    print(f"[OK] Email model saved. Hold-out ROC-AUC: {auc:.4f} (CV: {search.best_score_:.4f})")


def main() -> None:
    url_csv = os.path.join(DATA_DIR, "url_data.csv")
    email_csv = os.path.join(DATA_DIR, "email_data.csv")
    if not os.path.isfile(url_csv) or not os.path.isfile(email_csv):
        raise SystemExit("Missing data/raw/*.csv. Run: python scripts/prepare_data.py")

    url_df = pd.read_csv(url_csv)
    email_df = pd.read_csv(email_csv)
    print(f"Loaded {len(url_df)} URLs, {len(email_df)} emails")
    train_url(url_df)
    train_email(email_df)
    print("Done.")


if __name__ == "__main__":
    main()

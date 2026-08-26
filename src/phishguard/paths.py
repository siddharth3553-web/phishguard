"""Project-root resolution for portable paths (no cwd assumptions)."""

from __future__ import annotations

from pathlib import Path


def project_root() -> Path:
    """Return PhishGuard app root (parent of ``src/``); monorepo: ``apps/phishguard``."""
    return Path(__file__).resolve().parent.parent.parent


def artifacts_dir() -> Path:
    p = project_root() / "artifacts"
    return p


def models_dir() -> Path:
    p = artifacts_dir() / "models"
    p.mkdir(parents=True, exist_ok=True)
    return p


def metrics_dir() -> Path:
    p = artifacts_dir() / "metrics"
    p.mkdir(parents=True, exist_ok=True)
    return p


def data_raw_dir() -> Path:
    p = project_root() / "data" / "raw"
    p.mkdir(parents=True, exist_ok=True)
    return p

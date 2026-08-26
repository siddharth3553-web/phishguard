from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from phishguard.core.config import Settings, get_settings

FIXTURE_MODELS = Path(__file__).parent / "fixtures" / "models"


@pytest.fixture()
def settings(tmp_path: Path) -> Settings:
    get_settings.cache_clear()
    s = Settings(
        environment="test",
        models_dir=str(FIXTURE_MODELS),
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        api_key=None,
        rate_limit_per_minute=1000,
        cors_origins="http://testserver",
        git_sha="test",
        model_version="fixture",
    )
    return s


@pytest.fixture()
def client(settings: Settings) -> TestClient:
    from phishguard.api.app import create_app

    app = create_app(settings)
    with TestClient(app) as tc:
        yield tc

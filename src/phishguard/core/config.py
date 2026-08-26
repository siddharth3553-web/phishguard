"""Environment-driven settings (12-factor). Never hardcode secrets."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from phishguard.paths import models_dir as default_models_dir


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    app_name: str = "PhishGuard"
    environment: str = "dev"
    log_level: str = "INFO"
    models_dir: str | None = None
    database_url: str = "sqlite:///./data/phishguard.db"
    api_key: str | None = None
    cors_origins: str = "http://localhost:8501,http://localhost:8000,http://127.0.0.1:8501"
    rate_limit_per_minute: int = Field(default=60, ge=1, le=10_000)
    max_body_bytes: int = Field(default=65_536, ge=1024, le=2_000_000)
    git_sha: str = "dev"
    model_version: str = "2026.1"
    batch_max_items: int = Field(default=50, ge=1, le=200)

    @field_validator("environment")
    @classmethod
    def _env(cls, v: str) -> str:
        v = (v or "dev").lower()
        if v not in {"dev", "production", "test"}:
            return "dev"
        return v

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    def resolved_models_dir(self) -> Path:
        if self.models_dir:
            return Path(self.models_dir)
        return default_models_dir()


@lru_cache
def get_settings() -> Settings:
    return Settings()

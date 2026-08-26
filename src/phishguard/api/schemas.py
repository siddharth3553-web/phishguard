"""Pydantic v2 request/response contracts."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


class UrlScanRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048)

    @field_validator("url")
    @classmethod
    def strip_url(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("url must not be empty")
        return v


class EmailScanRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=20_000)

    @field_validator("text")
    @classmethod
    def strip_text(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("text must not be empty")
        return v


class BatchItem(BaseModel):
    kind: Literal["url", "email"]
    value: str = Field(..., min_length=1, max_length=20_000)


class BatchScanRequest(BaseModel):
    items: list[BatchItem] = Field(..., min_length=1)


class ScanResponse(BaseModel):
    id: str
    kind: Literal["url", "email"]
    model_version: str
    created_at: datetime
    verdict: str
    confidence: float
    phishing_score: float
    label: int
    low_confidence: bool
    insufficient_input: bool
    note: str | None = None
    features: dict[str, Any] | None = None
    flagged_keywords: list[str] | None = None
    request_id: str | None = None


class BatchScanResponse(BaseModel):
    scans: list[ScanResponse]


class HealthResponse(BaseModel):
    status: Literal["ok"]
    app: str


class ReadyResponse(BaseModel):
    status: Literal["ready", "not_ready"]
    models_loaded: bool
    model_version: str
    detail: str | None = None


class VersionResponse(BaseModel):
    app: str
    version: str
    git_sha: str
    model_version: str
    environment: str

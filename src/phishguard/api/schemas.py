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
    kind: Literal["url", "email", "qr"]
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
    reasons: list[str] | None = None
    extracted_urls: list[str] | None = None
    status: str = "open"
    reported: bool = False
    reporter_id: str | None = None
    qr_payload: str | None = None
    url_intel: dict[str, Any] | None = None
    email_intel: dict[str, Any] | None = None
    disposition_note: str | None = None


class BatchScanResponse(BaseModel):
    scans: list[ScanResponse]


class ScanListResponse(BaseModel):
    scans: list[ScanResponse]


class DispositionRequest(BaseModel):
    status: Literal["confirmed_phish", "false_positive", "allowlisted", "in_review", "open"]
    note: str | None = Field(default=None, max_length=2000)
    allowlist_value: str | None = Field(default=None, max_length=512)


class AllowlistCreate(BaseModel):
    value: str = Field(..., min_length=1, max_length=512)
    kind: Literal["domain", "email"] = "domain"
    note: str | None = Field(default=None, max_length=500)


class AllowlistEntryOut(BaseModel):
    id: str
    value: str
    kind: str
    note: str | None
    created_at: datetime


class AllowlistListResponse(BaseModel):
    entries: list[AllowlistEntryOut]


class LoginRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=255)
    password: str = Field(..., min_length=1, max_length=128)


class UserOut(BaseModel):
    id: str
    email: str
    display_name: str
    role: str


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


class AuditEventOut(BaseModel):
    id: str
    actor_id: str | None
    action: str
    resource_type: str
    resource_id: str | None
    created_at: datetime
    detail: dict[str, Any] | None = None


class AuditListResponse(BaseModel):
    events: list[AuditEventOut]

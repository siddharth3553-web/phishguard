"""ORM models for PhishGuard — users, scans-as-cases, allowlist, audit, campaigns, click tokens."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(128))
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(32), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class Campaign(Base):
    __tablename__ = "campaigns"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    fingerprint: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    brand: Mapped[str | None] = mapped_column(String(128), nullable=True)
    member_count: Mapped[int] = mapped_column(Integer, default=1)
    status: Mapped[str] = mapped_column(String(32), default="open", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    kind: Mapped[str] = mapped_column(String(16), index=True)
    input_preview: Mapped[str] = mapped_column(Text)
    verdict: Mapped[str] = mapped_column(String(32), index=True)
    phishing_score: Mapped[float] = mapped_column(Float)
    model_version: Mapped[str] = mapped_column(String(32))
    payload_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    reporter_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(32), default="open", index=True)
    reported: Mapped[bool] = mapped_column(Boolean, default=False)
    reasons_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    org_id: Mapped[str] = mapped_column(String(64), default="demo")
    disposition_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    disposed_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    disposed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    campaign_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    bec_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    decision_log_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    coaching_json: Mapped[str | None] = mapped_column(Text, nullable=True)


class ClickToken(Base):
    __tablename__ = "click_tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    scan_id: Mapped[str] = mapped_column(String(36), index=True)
    target_url: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_verdict: Mapped[str | None] = mapped_column(String(32), nullable=True)
    last_reasons_json: Mapped[str | None] = mapped_column(Text, nullable=True)


class AllowlistEntry(Base):
    __tablename__ = "allowlist"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    value: Mapped[str] = mapped_column(String(512), index=True)
    kind: Mapped[str] = mapped_column(String(16))  # domain | email | campaign
    scope: Mapped[str] = mapped_column(String(32), default="domain")
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    org_id: Mapped[str] = mapped_column(String(64), default="demo")


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    actor_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(64), index=True)
    resource_type: Mapped[str] = mapped_column(String(32))
    resource_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    detail_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class OrgSetting(Base):
    __tablename__ = "org_settings"

    org_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    brand_domains_json: Mapped[str] = mapped_column(
        Text, default='["paypal.com","microsoft.com","google.com","apple.com","amazon.com"]'
    )
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

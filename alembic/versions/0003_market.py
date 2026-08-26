"""Campaigns, click tokens, expiring allowlist, BEC columns."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0003_market"
down_revision = "0002_cases"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "campaigns",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("fingerprint", sa.String(32), nullable=False),
        sa.Column("brand", sa.String(128), nullable=True),
        sa.Column("member_count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("status", sa.String(32), nullable=False, server_default="open"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_campaigns_fingerprint", "campaigns", ["fingerprint"], unique=True)
    op.create_index("ix_campaigns_status", "campaigns", ["status"])

    op.create_table(
        "click_tokens",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("scan_id", sa.String(36), nullable=False),
        sa.Column("target_url", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_verdict", sa.String(32), nullable=True),
        sa.Column("last_reasons_json", sa.Text(), nullable=True),
    )
    op.create_index("ix_click_tokens_scan_id", "click_tokens", ["scan_id"])

    op.add_column("scans", sa.Column("campaign_id", sa.String(36), nullable=True))
    op.add_column("scans", sa.Column("bec_score", sa.Float(), nullable=True))
    op.add_column("scans", sa.Column("decision_log_json", sa.Text(), nullable=True))
    op.add_column("scans", sa.Column("coaching_json", sa.Text(), nullable=True))
    op.create_index("ix_scans_campaign_id", "scans", ["campaign_id"])

    op.add_column("allowlist", sa.Column("scope", sa.String(32), nullable=False, server_default="domain"))
    op.add_column("allowlist", sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("allowlist", "expires_at")
    op.drop_column("allowlist", "scope")
    op.drop_index("ix_scans_campaign_id", table_name="scans")
    for col in ("coaching_json", "decision_log_json", "bec_score", "campaign_id"):
        op.drop_column("scans", col)
    op.drop_table("click_tokens")
    op.drop_table("campaigns")

"""Extend scans for case workflow; add users, allowlist, audit, org_settings."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0002_cases"
down_revision = "0001_scans"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("display_name", sa.String(128), nullable=False),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("role", sa.String(32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)
    op.create_index("ix_users_role", "users", ["role"])

    op.create_table(
        "allowlist",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("value", sa.String(512), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("created_by", sa.String(36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("org_id", sa.String(64), nullable=False),
    )
    op.create_index("ix_allowlist_value", "allowlist", ["value"])

    op.create_table(
        "audit_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("actor_id", sa.String(36), nullable=True),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("resource_type", sa.String(32), nullable=False),
        sa.Column("resource_id", sa.String(36), nullable=True),
        sa.Column("detail_json", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_audit_events_actor_id", "audit_events", ["actor_id"])
    op.create_index("ix_audit_events_action", "audit_events", ["action"])

    op.create_table(
        "org_settings",
        sa.Column("org_id", sa.String(64), primary_key=True),
        sa.Column("brand_domains_json", sa.Text(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.add_column("scans", sa.Column("reporter_id", sa.String(36), nullable=True))
    op.add_column("scans", sa.Column("status", sa.String(32), nullable=False, server_default="open"))
    op.add_column("scans", sa.Column("reported", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("scans", sa.Column("reasons_json", sa.Text(), nullable=True))
    op.add_column("scans", sa.Column("org_id", sa.String(64), nullable=False, server_default="demo"))
    op.add_column("scans", sa.Column("disposition_note", sa.Text(), nullable=True))
    op.add_column("scans", sa.Column("disposed_by", sa.String(36), nullable=True))
    op.add_column("scans", sa.Column("disposed_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_scans_reporter_id", "scans", ["reporter_id"])
    op.create_index("ix_scans_status", "scans", ["status"])


def downgrade() -> None:
    op.drop_index("ix_scans_status", table_name="scans")
    op.drop_index("ix_scans_reporter_id", table_name="scans")
    for col in (
        "disposed_at",
        "disposed_by",
        "disposition_note",
        "org_id",
        "reasons_json",
        "reported",
        "status",
        "reporter_id",
    ):
        op.drop_column("scans", col)
    op.drop_table("org_settings")
    op.drop_index("ix_audit_events_action", table_name="audit_events")
    op.drop_index("ix_audit_events_actor_id", table_name="audit_events")
    op.drop_table("audit_events")
    op.drop_index("ix_allowlist_value", table_name="allowlist")
    op.drop_table("allowlist")
    op.drop_index("ix_users_role", table_name="users")
    op.drop_index("ix_users_email", table_name="users")
    op.drop_table("users")

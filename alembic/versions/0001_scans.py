"""Initial scans table."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0001_scans"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scans",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("input_preview", sa.Text(), nullable=False),
        sa.Column("verdict", sa.String(length=32), nullable=False),
        sa.Column("phishing_score", sa.Float(), nullable=False),
        sa.Column("model_version", sa.String(length=32), nullable=False),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_scans_kind", "scans", ["kind"])
    op.create_index("ix_scans_verdict", "scans", ["verdict"])


def downgrade() -> None:
    op.drop_index("ix_scans_verdict", table_name="scans")
    op.drop_index("ix_scans_kind", table_name="scans")
    op.drop_table("scans")

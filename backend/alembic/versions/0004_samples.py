"""samples table

Malware samples: one row per distinct file (SHA-256), with the static
analysis result. The bytes live in the sample store on disk.

Revision ID: 0004_samples
Revises: 0003_browser_profiles
Create Date: 2026-11-09
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0004_samples"
down_revision = "0003_browser_profiles"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if "samples" in sa.inspect(op.get_bind()).get_table_names():
        return
    op.create_table(
        "samples",
        sa.Column("sha256", sa.String(length=64), primary_key=True),
        sa.Column("sha1", sa.String(length=40), nullable=False),
        sa.Column("md5", sa.String(length=32), nullable=False),
        sa.Column("size", sa.Integer(), nullable=False),
        sa.Column("type_id", sa.String(), nullable=False, server_default="unknown"),
        sa.Column("type_label", sa.String(), nullable=False, server_default=""),
        sa.Column("entropy", sa.Float(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("created_by", sa.String(), nullable=False, server_default=""),
        sa.Column("analysis", sa.JSON(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("samples")

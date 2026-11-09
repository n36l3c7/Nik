"""sample_code table

Disassembly results from the analyzer worker (rizin): function list, calls
and per-function control-flow graphs, one row per sample.

Revision ID: 0006_sample_code
Revises: 0005_yara_rules
Create Date: 2026-11-09
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0006_sample_code"
down_revision = "0005_yara_rules"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if "sample_code" in sa.inspect(op.get_bind()).get_table_names():
        return
    op.create_table(
        "sample_code",
        sa.Column("sha256", sa.String(length=64), primary_key=True),
        sa.Column("status", sa.String(), nullable=False, server_default="queued"),
        sa.Column("error", sa.String(), nullable=True),
        sa.Column("requested_at", sa.String(), nullable=False),
        sa.Column("requested_by", sa.String(), nullable=False, server_default=""),
        sa.Column("finished_at", sa.String(), nullable=True),
        sa.Column("summary", sa.JSON(), nullable=False),
        sa.Column("cfgs", sa.JSON(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("sample_code")

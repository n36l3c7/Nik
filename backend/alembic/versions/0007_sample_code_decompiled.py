"""sample_code.decompiled column

Pseudo-C of the sample's functions from rz-ghidra, keyed by address: filled
by the analysis within its time budget, then on demand per function.

Revision ID: 0007_sample_code_decompiled
Revises: 0006_sample_code
Create Date: 2026-11-09
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0007_sample_code_decompiled"
down_revision = "0006_sample_code"
branch_labels = None
depends_on = None


def upgrade() -> None:
    columns = {c["name"] for c in sa.inspect(op.get_bind()).get_columns("sample_code")}
    if "decompiled" not in columns:
        op.add_column("sample_code", sa.Column("decompiled", sa.JSON(), nullable=False, server_default="{}"))


def downgrade() -> None:
    op.drop_column("sample_code", "decompiled")

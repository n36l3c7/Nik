"""yara_rules table

Admin-managed YARA rules, compiled together with the built-in set when
scanning malware samples.

Revision ID: 0005_yara_rules
Revises: 0004_samples
Create Date: 2026-11-09
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0005_yara_rules"
down_revision = "0004_samples"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if "yara_rules" in sa.inspect(op.get_bind()).get_table_names():
        return
    op.create_table(
        "yara_rules",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("created_by", sa.String(), nullable=False, server_default=""),
        sa.Column("updated_at", sa.String(), nullable=False, server_default=""),
    )


def downgrade() -> None:
    op.drop_table("yara_rules")

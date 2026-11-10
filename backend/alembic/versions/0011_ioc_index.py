"""ioc_index table

One row per indicator of compromise seen in an incident (type, value, where
in the incident, how many times, first and last time), rebuilt from the
incident document when its data changes. The api fills it for existing
incidents on its first start (see ``main.on_startup``).

Revision ID: 0011_ioc_index
Revises: 0010_function_rows_capa_rules
Create Date: 2026-11-10
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0011_ioc_index"
down_revision = "0010_function_rows_capa_rules"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if "ioc_index" in sa.inspect(op.get_bind()).get_table_names():
        return
    op.create_table(
        "ioc_index",
        sa.Column("incident_id", sa.String(), sa.ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("type", sa.String(16), primary_key=True),
        sa.Column("value", sa.String(1024), primary_key=True),
        sa.Column("sources", sa.JSON(), nullable=False),
        sa.Column("count", sa.Integer(), nullable=False),
        sa.Column("first_seen", sa.BigInteger(), nullable=True),
        sa.Column("last_seen", sa.BigInteger(), nullable=True),
    )
    op.create_index("ix_ioc_index_type_value", "ioc_index", ["type", "value"])


def downgrade() -> None:
    op.drop_index("ix_ioc_index_type_value", table_name="ioc_index")
    op.drop_table("ioc_index")

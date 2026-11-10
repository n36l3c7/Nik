"""sample_capa table

capa's capabilities of each malware sample, filled by the capa worker.

Revision ID: 0009_sample_capa
Revises: 0008_annotations_flirt
Create Date: 2026-11-10
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0009_sample_capa"
down_revision = "0008_annotations_flirt"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if "sample_capa" in sa.inspect(op.get_bind()).get_table_names():
        return
    op.create_table(
        "sample_capa",
        sa.Column("sha256", sa.String(64), primary_key=True),
        sa.Column("status", sa.String(), nullable=False, server_default="queued"),
        sa.Column("error", sa.String(), nullable=True),
        sa.Column("requested_at", sa.String(), nullable=False),
        sa.Column("requested_by", sa.String(), nullable=False, server_default=""),
        sa.Column("started_at", sa.String(), nullable=True),
        sa.Column("finished_at", sa.String(), nullable=True),
        sa.Column("result", sa.JSON(), nullable=False, server_default="{}"),
    )


def downgrade() -> None:
    op.drop_table("sample_capa")

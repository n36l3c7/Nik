"""function_annotations and flirt_signatures tables

Analysts' names and comments for a sample's functions, and the FLIRT
signature files admins upload for the analyzer worker.

Revision ID: 0008_annotations_flirt
Revises: 0007_sample_code_decompiled
Create Date: 2026-11-10
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0008_annotations_flirt"
down_revision = "0007_sample_code_decompiled"
branch_labels = None
depends_on = None


def upgrade() -> None:
    tables = set(sa.inspect(op.get_bind()).get_table_names())
    if "function_annotations" not in tables:
        op.create_table(
            "function_annotations",
            sa.Column("sha256", sa.String(64), primary_key=True),
            sa.Column("addr", sa.BigInteger(), primary_key=True, autoincrement=False),
            sa.Column("name", sa.String(), nullable=True),
            sa.Column("comment", sa.Text(), nullable=True),
            sa.Column("updated_at", sa.String(), nullable=False),
            sa.Column("updated_by", sa.String(), nullable=False, server_default=""),
        )
    if "flirt_signatures" not in tables:
        op.create_table(
            "flirt_signatures",
            sa.Column("id", sa.String(32), primary_key=True),
            sa.Column("name", sa.String(), nullable=False),
            sa.Column("file_name", sa.String(), nullable=False),
            sa.Column("kind", sa.String(), nullable=False),
            sa.Column("size", sa.Integer(), nullable=False),
            sa.Column("sha256", sa.String(64), nullable=False),
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("created_at", sa.String(), nullable=False),
            sa.Column("created_by", sa.String(), nullable=False, server_default=""),
            sa.Column("updated_at", sa.String(), nullable=False, server_default=""),
        )


def downgrade() -> None:
    op.drop_table("flirt_signatures")
    op.drop_table("function_annotations")

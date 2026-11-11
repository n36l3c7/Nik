"""url_scans: URLs visited by the isolated browser

One row per distinct address, with the verdict and what the visit found.
The screenshot lives in the sample store (``_urls/<id>.jpg``).

Revision ID: 0018_url_scans
Revises: 0017_artifacts
Create Date: 2026-11-11
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0018_url_scans"
down_revision = "0017_artifacts"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if "url_scans" in sa.inspect(op.get_bind()).get_table_names():
        return
    op.create_table(
        "url_scans",
        sa.Column("id", sa.String(length=32), primary_key=True),
        sa.Column("url", sa.String(), nullable=False),
        sa.Column("host", sa.String(), nullable=False, server_default=""),
        sa.Column("status", sa.String(), nullable=False, server_default="queued"),
        sa.Column("error", sa.String(), nullable=True),
        sa.Column("verdict", sa.String(), nullable=False, server_default=""),
        sa.Column("score", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("created_by", sa.String(), nullable=False, server_default=""),
        sa.Column("scanned_at", sa.String(), nullable=True),
        sa.Column("capture_id", sa.String(length=32), nullable=True),
        sa.Column("result", sa.JSON(), nullable=False),
    )


def downgrade() -> None:
    op.execute("DELETE FROM artifacts WHERE kind = 'url'")
    op.drop_table("url_scans")

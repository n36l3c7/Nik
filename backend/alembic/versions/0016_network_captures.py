"""network_captures: packet captures and isolated browser sessions

One row per capture of an incident: an uploaded pcap / pcapng, or the
network log of an isolated browser session rebuilt as pcapng. The files
live in the sample store (``_captures/<id>/``).

Revision ID: 0016_network_captures
Revises: 0015_ioc_enrichment
Create Date: 2026-11-10
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0016_network_captures"
down_revision = "0015_ioc_enrichment"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if "network_captures" in sa.inspect(op.get_bind()).get_table_names():
        return
    op.create_table(
        "network_captures",
        sa.Column("id", sa.String(length=32), primary_key=True),
        sa.Column("incident_id", sa.String(), nullable=False),
        sa.Column("kind", sa.String(), nullable=False, server_default="pcap"),
        sa.Column("file_name", sa.String(), nullable=False, server_default=""),
        sa.Column("size", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("sha256", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("status", sa.String(), nullable=False, server_default="indexing"),
        sa.Column("error", sa.String(), nullable=True),
        sa.Column("packets", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("first_ms", sa.BigInteger(), nullable=True),
        sa.Column("last_ms", sa.BigInteger(), nullable=True),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("created_by", sa.String(), nullable=False, server_default=""),
        sa.Column("meta", sa.JSON(), nullable=False),
        sa.Column("summary", sa.JSON(), nullable=False),
        sa.Column("keylog", sa.Text(), nullable=True),
    )
    op.create_index("ix_network_captures_incident_id", "network_captures", ["incident_id"])


def downgrade() -> None:
    op.drop_index("ix_network_captures_incident_id", table_name="network_captures")
    op.drop_table("network_captures")

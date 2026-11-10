"""threat-intelligence enrichment: ioc_enrichment, integration_keys, leases

``ioc_enrichment`` caches each provider's answer about an indicator;
``integration_keys`` holds the providers' API keys, encrypted;
``leases`` lets one API process at a time run the background lookups.

Revision ID: 0015_ioc_enrichment
Revises: 0014_mails
Create Date: 2026-11-10
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0015_ioc_enrichment"
down_revision = "0014_mails"
branch_labels = None
depends_on = None


def upgrade() -> None:
    tables = set(sa.inspect(op.get_bind()).get_table_names())
    if "ioc_enrichment" not in tables:
        op.create_table(
            "ioc_enrichment",
            sa.Column("type", sa.String(), primary_key=True),
            sa.Column("value", sa.String(), primary_key=True),
            sa.Column("provider", sa.String(), primary_key=True),
            sa.Column("status", sa.String(), nullable=False, server_default="running"),
            sa.Column("verdict", sa.String(), nullable=False, server_default="unknown"),
            sa.Column("summary", sa.String(), nullable=False, server_default=""),
            sa.Column("link", sa.String(), nullable=False, server_default=""),
            sa.Column("data", sa.JSON(), nullable=False),
            sa.Column("error", sa.String(), nullable=True),
            sa.Column("checked_at", sa.String(), nullable=False),
        )
        op.create_index("ix_ioc_enrichment_value", "ioc_enrichment", ["value"])
    if "integration_keys" not in tables:
        op.create_table(
            "integration_keys",
            sa.Column("provider", sa.String(), primary_key=True),
            sa.Column("secret", sa.Text(), nullable=False),
            sa.Column("hint", sa.String(), nullable=False, server_default=""),
            sa.Column("updated_at", sa.String(), nullable=False),
            sa.Column("updated_by", sa.String(), nullable=False, server_default=""),
        )
    if "leases" not in tables:
        op.create_table(
            "leases",
            sa.Column("name", sa.String(), primary_key=True),
            sa.Column("holder", sa.String(), nullable=False),
            sa.Column("expires_at", sa.Float(), nullable=False),
        )


def downgrade() -> None:
    op.drop_table("leases")
    op.drop_table("integration_keys")
    op.drop_index("ix_ioc_enrichment_value", table_name="ioc_enrichment")
    op.drop_table("ioc_enrichment")

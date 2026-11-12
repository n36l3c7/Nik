"""the IoC library: indicators kept on their own, lists, bulk checks, alerts

- ``iocs``: indicators added by hand or from a file, and what an analyst
  wrote about any indicator (tags, note, TLP, expiry).
- ``ioc_lists`` / ``ioc_list_items``: named groups of indicators.
- ``ioc_checks``: bulk reputation checks worked through in the background.
- ``ioc_alerts``: an incident came to hold an indicator of a watched list.

Revision ID: 0023_ioc_library
Revises: 0022_intel_keys_history
Create Date: 2026-11-12
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0023_ioc_library"
down_revision = "0022_intel_keys_history"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # The baseline creates the schema from the models, so on a new database
    # these tables exist already: each is created only where it is missing.
    tables = set(sa.inspect(op.get_bind()).get_table_names())
    if "iocs" not in tables:
        _iocs()
    if "ioc_lists" not in tables:
        _lists()
    if "ioc_list_items" not in tables:
        _list_items()
    if "ioc_checks" not in tables:
        _checks()
    if "ioc_alerts" not in tables:
        _alerts()


def _iocs() -> None:
    op.create_table(
        "iocs",
        sa.Column("type", sa.String(16), primary_key=True),
        sa.Column("value", sa.String(1024), primary_key=True),
        sa.Column("origin", sa.String(16), nullable=False, server_default="manual"),
        sa.Column("tags", sa.JSON(), nullable=False),
        sa.Column("note", sa.String(), nullable=False, server_default=""),
        sa.Column("tlp", sa.String(8), nullable=False, server_default="amber"),
        sa.Column("expires_at", sa.String(), nullable=True),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("created_by", sa.String(), nullable=False, server_default=""),
        sa.Column("updated_at", sa.String(), nullable=False),
    )


def _lists() -> None:
    op.create_table(
        "ioc_lists",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("description", sa.String(), nullable=False, server_default=""),
        sa.Column("tlp", sa.String(8), nullable=False, server_default="amber"),
        sa.Column("watch", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("created_by", sa.String(), nullable=False, server_default=""),
        sa.Column("updated_at", sa.String(), nullable=False),
    )


def _list_items() -> None:
    op.create_table(
        "ioc_list_items",
        sa.Column("list_id", sa.String(), sa.ForeignKey("ioc_lists.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("type", sa.String(16), primary_key=True),
        sa.Column("value", sa.String(1024), primary_key=True),
        sa.Column("added_at", sa.String(), nullable=False),
        sa.Column("added_by", sa.String(), nullable=False, server_default=""),
    )
    op.create_index("ix_ioc_list_items_type_value", "ioc_list_items", ["type", "value"])


def _checks() -> None:
    op.create_table(
        "ioc_checks",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("label", sa.String(), nullable=False, server_default=""),
        sa.Column("status", sa.String(16), nullable=False, server_default="running"),
        sa.Column("total", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("done", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("message", sa.String(), nullable=False, server_default=""),
        sa.Column("pending", sa.JSON(), nullable=False),
        sa.Column("items", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("created_by", sa.String(), nullable=False, server_default=""),
        sa.Column("updated_at", sa.String(), nullable=False),
    )
    op.create_index("ix_ioc_checks_status", "ioc_checks", ["status"])


def _alerts() -> None:
    op.create_table(
        "ioc_alerts",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("at", sa.String(), nullable=False),
        sa.Column("list_id", sa.String(), sa.ForeignKey("ioc_lists.id", ondelete="CASCADE"), nullable=False),
        sa.Column("incident_id", sa.String(), sa.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("type", sa.String(16), nullable=False),
        sa.Column("value", sa.String(1024), nullable=False),
        sa.Column("seen", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.create_index("ix_ioc_alerts_at", "ioc_alerts", ["at"])


def downgrade() -> None:
    op.drop_index("ix_ioc_alerts_at", table_name="ioc_alerts")
    op.drop_table("ioc_alerts")
    op.drop_index("ix_ioc_checks_status", table_name="ioc_checks")
    op.drop_table("ioc_checks")
    op.drop_index("ix_ioc_list_items_type_value", table_name="ioc_list_items")
    op.drop_table("ioc_list_items")
    op.drop_table("ioc_lists")
    op.drop_table("iocs")

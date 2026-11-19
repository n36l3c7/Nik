"""dashboards, content packs, debug runs

The tables of release 4.6 (``dashboards``, ``packs``, ``pack_items``,
``pack_uploads``) and the column ``runs.debug``, each added only where it is
missing: the baseline creates the schema from the models, so on a new
database they exist already. No run that exists is a debug run.

Revision ID: 0033_dashboards_packs
Revises: 0032_fetch_mappers
Create Date: 2026-11-18
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0033_dashboards_packs"
down_revision = "0032_fetch_mappers"
branch_labels = None
depends_on = None


def upgrade() -> None:
    from app.core.db import Base
    from app.core.models import DASHBOARD_PACK_COLUMNS, DASHBOARD_PACK_TABLES

    bind = op.get_bind()
    existing = set(sa.inspect(bind).get_table_names())
    for name in DASHBOARD_PACK_TABLES:
        if name not in existing:
            Base.metadata.tables[name].create(bind)
    for table, columns in DASHBOARD_PACK_COLUMNS.items():
        if table not in existing:
            continue
        held = {column["name"] for column in sa.inspect(bind).get_columns(table)}
        for name in columns:
            if name in held:
                continue
            column = Base.metadata.tables[table].columns[name]
            op.add_column(
                table,
                sa.Column(name, column.type, nullable=column.nullable, server_default=column.server_default),
            )


def downgrade() -> None:
    from app.core.models import DASHBOARD_PACK_COLUMNS, DASHBOARD_PACK_TABLES

    bind = op.get_bind()
    existing = set(sa.inspect(bind).get_table_names())
    for table, columns in DASHBOARD_PACK_COLUMNS.items():
        if table not in existing:
            continue
        held = {column["name"] for column in sa.inspect(bind).get_columns(table)}
        with op.batch_alter_table(table) as batch:
            for name in columns:
                if name in held:
                    batch.drop_column(name)
    for name in reversed(DASHBOARD_PACK_TABLES):
        if name in existing:
            op.drop_table(name)

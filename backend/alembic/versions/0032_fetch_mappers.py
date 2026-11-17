"""fetching: classifiers, mappers, what was fetched, pre-processing rules, the mirror queue

Tables ``classifiers``, ``mappers``, ``fetched_items``, ``preprocess_rules``
and ``mirror_queue``, and on ``connections`` the columns ``fetch_enabled``,
``fetch_state`` and ``fetch_status``. Each table and each column is added
only where it is missing: the baseline creates the schema from the models,
so on a new database they exist already. No connection fetches until it is
told to.

Revision ID: 0032_fetch_mappers
Revises: 0031_lists
Create Date: 2026-11-17
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0032_fetch_mappers"
down_revision = "0031_lists"
branch_labels = None
depends_on = None


def upgrade() -> None:
    from app.core.db import Base
    from app.core.models import FETCH_COLUMNS, FETCH_TABLES

    bind = op.get_bind()
    existing = set(sa.inspect(bind).get_table_names())
    for name in FETCH_TABLES:
        if name not in existing:
            Base.metadata.tables[name].create(bind)
    for table, columns in FETCH_COLUMNS.items():
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
    from app.core.models import FETCH_COLUMNS, FETCH_TABLES

    bind = op.get_bind()
    existing = set(sa.inspect(bind).get_table_names())
    for table, columns in FETCH_COLUMNS.items():
        if table not in existing:
            continue
        held = {column["name"] for column in sa.inspect(bind).get_columns(table)}
        with op.batch_alter_table(table) as batch:
            for name in columns:
                if name in held:
                    batch.drop_column(name)
    for name in reversed(FETCH_TABLES):
        if name in existing:
            op.drop_table(name)

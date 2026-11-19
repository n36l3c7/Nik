"""script signatures, the history of watch lists, the expiry of artifacts

The tables and columns of release 4.7, each added only where it is missing:
the baseline creates the schema from the models, so on a new database they
exist already. No artifact gets a date and no signature changes: what was
there behaves as it did.

Revision ID: 0034_misc
Revises: 0033_dashboards_packs
Create Date: 2026-11-19
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0034_misc"
down_revision = "0033_dashboards_packs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    from app.core.db import Base
    from app.core.models import MISC_COLUMNS, MISC_TABLES

    bind = op.get_bind()
    existing = set(sa.inspect(bind).get_table_names())
    for name in MISC_TABLES:
        if name not in existing:
            Base.metadata.tables[name].create(bind)
    for table, columns in MISC_COLUMNS.items():
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
    from app.core.models import MISC_COLUMNS, MISC_TABLES

    bind = op.get_bind()
    existing = set(sa.inspect(bind).get_table_names())
    for table, columns in MISC_COLUMNS.items():
        if table not in existing:
            continue
        held = {column["name"] for column in sa.inspect(bind).get_columns(table)}
        with op.batch_alter_table(table) as batch:
            for name in columns:
                if name in held:
                    batch.drop_column(name)
    for name in reversed(MISC_TABLES):
        if name in existing:
            op.drop_table(name)

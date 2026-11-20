"""how an instance fetches

Release 6.4. How often an instance fetches, how far back its first cycle
reads and its look-back are kept on the instance, where they differ from
what its connector says. The column is added only where missing; an instance
that has none fetches as its connector says, as before.

Revision ID: 0043_instance_fetch
Revises: 0041_saved_filters
Create Date: 2026-11-19
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0043_instance_fetch"
down_revision = "0041_saved_filters"
branch_labels = None
depends_on = None


def upgrade() -> None:
    from app.core.models import INSTANCE_FETCH_COLUMNS

    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())
    for table, columns in INSTANCE_FETCH_COLUMNS.items():
        if table not in tables:
            continue
        existing = {column["name"] for column in inspector.get_columns(table)}
        for name in columns:
            if name not in existing:
                op.add_column(table, sa.Column(name, sa.JSON(), nullable=True))


def downgrade() -> None:
    from app.core.models import INSTANCE_FETCH_COLUMNS

    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())
    for table, columns in INSTANCE_FETCH_COLUMNS.items():
        if table not in tables:
            continue
        existing = {column["name"] for column in inspector.get_columns(table)}
        wanted = [name for name in columns if name in existing]
        if wanted:
            with op.batch_alter_table(table) as batch:
                for name in wanted:
                    batch.drop_column(name)

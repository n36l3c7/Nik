"""instances of a connector can be turned off; a connector has a logo and a README

Release 5.1. A connection is an instance of its connector; ``enabled`` says
whether it is on. Every connection there is stays on: nothing changes until
someone turns one off. A connector gains what a package brings beside its
file: a logo and a README, both empty for the connectors there are. Each
column is added only where it is missing: the baseline creates the schema
from the models.

Revision ID: 0036_instances
Revises: 0035_incident_numbers
Create Date: 2026-11-19
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0036_instances"
down_revision = "0035_incident_numbers"
branch_labels = None
depends_on = None


def upgrade() -> None:
    from app.core.db import Base
    from app.core.models import INSTANCE_COLUMNS

    bind = op.get_bind()
    existing = set(sa.inspect(bind).get_table_names())
    for table, columns in INSTANCE_COLUMNS.items():
        if table not in existing:
            continue
        held = {column["name"] for column in sa.inspect(bind).get_columns(table)}
        for name in columns:
            if name in held:
                continue
            column = Base.metadata.tables[table].columns[name]
            op.add_column(
                table, sa.Column(name, column.type, nullable=column.nullable, server_default=column.server_default)
            )


def downgrade() -> None:
    from app.core.models import INSTANCE_COLUMNS

    bind = op.get_bind()
    existing = set(sa.inspect(bind).get_table_names())
    for table, columns in INSTANCE_COLUMNS.items():
        if table not in existing:
            continue
        held = {column["name"] for column in sa.inspect(bind).get_columns(table)}
        with op.batch_alter_table(table) as batch:
            for name in columns:
                if name in held:
                    batch.drop_column(name)

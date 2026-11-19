"""instances of a connector can be turned off

Release 5.1. A connection is an instance of its connector; ``enabled`` says
whether it is on. Every connection there is stays on: nothing changes until
someone turns one off. Added only where it is missing: the baseline creates
the schema from the models.

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
    from app.core.models import INSTANCE_COLUMNS

    bind = op.get_bind()
    existing = set(sa.inspect(bind).get_table_names())
    for table, columns in INSTANCE_COLUMNS.items():
        if table not in existing:
            continue
        held = {column["name"] for column in sa.inspect(bind).get_columns(table)}
        for name in columns:
            if name not in held:
                op.add_column(table, sa.Column(name, sa.Boolean(), nullable=False, server_default=sa.true()))


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

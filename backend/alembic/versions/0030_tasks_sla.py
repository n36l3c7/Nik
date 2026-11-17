"""tasks and notifications: what people do for an incident, and what they are told

Tables ``tasks`` and ``notifications``. Each is created only where it is
missing: the baseline creates the schema from the models, so on a new database
they exist already. SLA timers need no table: a timer is a field of an
incident, kept with its other fields.

``run_steps.port`` grows from 12 to 40 characters where it is still short: a
question leaves by a port named after the choice made. SQLite does not hold a
length for a text column, so there is nothing to change there.

Revision ID: 0030_tasks_sla
Revises: 0029_context_war_room
Create Date: 2026-11-17
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0030_tasks_sla"
down_revision = "0029_context_war_room"
branch_labels = None
depends_on = None


PORT_LENGTH = 40


def upgrade() -> None:
    from app.core.db import Base
    from app.core.models import TASK_TABLES

    bind = op.get_bind()
    existing = set(sa.inspect(bind).get_table_names())
    for name in TASK_TABLES:
        if name not in existing:
            Base.metadata.tables[name].create(bind)
    if bind.dialect.name == "postgresql" and "run_steps" in existing:
        port = next((c for c in sa.inspect(bind).get_columns("run_steps") if c["name"] == "port"), None)
        if port is not None and (getattr(port["type"], "length", None) or PORT_LENGTH) < PORT_LENGTH:
            op.alter_column("run_steps", "port", type_=sa.String(PORT_LENGTH), existing_nullable=True)


def downgrade() -> None:
    from app.core.models import TASK_TABLES

    existing = set(sa.inspect(op.get_bind()).get_table_names())
    for name in reversed(TASK_TABLES):
        if name in existing:
            op.drop_table(name)

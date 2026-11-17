"""automation: playbooks, scripts, the events outbox, runs, steps, approvals, schedules

The tables of Nik's own automation engine (``app/automation``). Each is
created only where it is missing: the baseline creates the schema from the
models, so on a new database they exist already.

Revision ID: 0026_automation
Revises: 0025_roles
Create Date: 2026-11-17
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0026_automation"
down_revision = "0025_roles"
branch_labels = None
depends_on = None


def upgrade() -> None:
    from app.core.db import Base
    from app.core.models import AUTOMATION_TABLES

    bind = op.get_bind()
    existing = set(sa.inspect(bind).get_table_names())
    # In the order of their foreign keys (playbooks before their versions and runs).
    for name in AUTOMATION_TABLES:
        if name not in existing:
            Base.metadata.tables[name].create(bind)


def downgrade() -> None:
    from app.core.models import AUTOMATION_TABLES

    existing = set(sa.inspect(op.get_bind()).get_table_names())
    for name in reversed(AUTOMATION_TABLES):
        if name in existing:
            op.drop_table(name)

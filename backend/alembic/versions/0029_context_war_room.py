"""context and War Room: what is known of an incident as data, and its log

Tables ``incident_context`` (one document per incident), ``incident_context_meta``
(who last set each item) and ``war_room_entries``. Each is created only where
it is missing: the baseline creates the schema from the models, so on a new
database they exist already. Nothing that exists is changed: the notes of an
incident stay in its document.

Revision ID: 0029_context_war_room
Revises: 0028_fields_types
Create Date: 2026-11-17
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0029_context_war_room"
down_revision = "0028_fields_types"
branch_labels = None
depends_on = None


def upgrade() -> None:
    from app.core.db import Base
    from app.core.models import CONTEXT_TABLES

    bind = op.get_bind()
    existing = set(sa.inspect(bind).get_table_names())
    for name in CONTEXT_TABLES:
        if name not in existing:
            Base.metadata.tables[name].create(bind)


def downgrade() -> None:
    from app.core.models import CONTEXT_TABLES

    existing = set(sa.inspect(op.get_bind()).get_table_names())
    for name in reversed(CONTEXT_TABLES):
        if name in existing:
            op.drop_table(name)

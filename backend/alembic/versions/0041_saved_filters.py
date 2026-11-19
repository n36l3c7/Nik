"""saved filters of the incident list

Release 6.2. A person keeps the queries they use on the list of incidents
under a name, an administrator shares one with everyone, and each person
chooses the one the list opens with. Tables are created only where missing.

Revision ID: 0041_saved_filters
Revises: 0040_instance_keys
Create Date: 2026-11-19
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0041_saved_filters"
down_revision = "0040_instance_keys"
branch_labels = None
depends_on = None


def upgrade() -> None:
    from app.core.db import Base
    from app.core.models import SAVED_FILTER_TABLES

    bind = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names())
    for name in SAVED_FILTER_TABLES:
        if name not in tables:
            Base.metadata.tables[name].create(bind)


def downgrade() -> None:
    from app.core.models import SAVED_FILTER_TABLES

    bind = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names())
    for name in reversed(SAVED_FILTER_TABLES):
        if name in tables:
            op.drop_table(name)

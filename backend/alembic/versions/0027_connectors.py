"""connectors: the files that say how to talk to a product, and connections to them

Each table is created only where it is missing: the baseline creates the
schema from the models, so on a new database they exist already.

Revision ID: 0027_connectors
Revises: 0026_automation
Create Date: 2026-11-17
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0027_connectors"
down_revision = "0026_automation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    from app.core.db import Base
    from app.core.models import CONNECTOR_TABLES

    bind = op.get_bind()
    existing = set(sa.inspect(bind).get_table_names())
    # In the order of their foreign keys (connectors before their connections).
    for name in CONNECTOR_TABLES:
        if name not in existing:
            Base.metadata.tables[name].create(bind)


def downgrade() -> None:
    from app.core.models import CONNECTOR_TABLES

    existing = set(sa.inspect(op.get_bind()).get_table_names())
    for name in reversed(CONNECTOR_TABLES):
        if name in existing:
            op.drop_table(name)

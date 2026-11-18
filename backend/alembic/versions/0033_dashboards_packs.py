"""dashboards and content packs

The tables of release 4.6, each created only where it is missing: the baseline
creates the schema from the models, so on a new database they exist already.

Revision ID: 0033_dashboards_packs
Revises: 0032_fetch_mappers
Create Date: 2026-11-18
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0033_dashboards_packs"
down_revision = "0032_fetch_mappers"
branch_labels = None
depends_on = None


def upgrade() -> None:
    from app.core.db import Base
    from app.core.models import DASHBOARD_PACK_TABLES

    bind = op.get_bind()
    existing = set(sa.inspect(bind).get_table_names())
    for name in DASHBOARD_PACK_TABLES:
        if name not in existing:
            Base.metadata.tables[name].create(bind)


def downgrade() -> None:
    from app.core.models import DASHBOARD_PACK_TABLES

    bind = op.get_bind()
    existing = set(sa.inspect(bind).get_table_names())
    for name in reversed(DASHBOARD_PACK_TABLES):
        if name in existing:
            op.drop_table(name)

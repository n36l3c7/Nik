"""bulk actions on incidents, artifacts and indicators

Release 6.10. An action asked of many items at once is a job
(``app/bulk.py``):

- ``bulk_jobs``: who asked for what, of how many, and how it went;
- ``bulk_items``: each item of a job and what was done to it, written in the
  commit of its own change, so that a job a restart cut goes on from where it
  was and does nothing twice.

Nothing is filled in. Idempotent: each table is created only where it is
missing.

Revision ID: 0055_bulk
Revises: 0054_indicators_found
Create Date: 2026-11-22
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0055_bulk"
down_revision = "0054_indicators_found"
branch_labels = None
depends_on = None


def upgrade() -> None:
    from app.core.db import Base
    from app.core.models import BULK_TABLES

    bind = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names())
    for name in BULK_TABLES:
        if name not in tables:
            Base.metadata.tables[name].create(bind)


def downgrade() -> None:
    from app.core.models import BULK_TABLES

    tables = set(sa.inspect(op.get_bind()).get_table_names())
    for name in reversed(BULK_TABLES):
        if name in tables:
            op.drop_table(name)

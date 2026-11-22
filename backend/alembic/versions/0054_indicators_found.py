"""indicators found by themselves when an incident comes in

Release 6.10. When an incident is made (a fetch, a mail, the API, a person, a
playbook) its fields and its context are read for indicators
(``app/indicators_found.py``):

- ``found_indicators``: one row per incident and indicator found that way,
  with the path it was read at; a row a person removed stays, marked, so the
  value is not found again at the next update;
- ``found_scans``: the last time each incident was read, and what came of it.

Nothing is filled in: the incidents there are were never read, and are not
read by this migration. An incident is read when it comes in, or when
someone asks for it from its Indicators panel.

Idempotent: each table is created only where it is missing.

Revision ID: 0054_indicators_found
Revises: 0053_jobs
Create Date: 2026-11-21
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0054_indicators_found"
down_revision = "0053_jobs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    from app.core.db import Base
    from app.core.models import FOUND_TABLES

    bind = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names())
    for name in FOUND_TABLES:
        if name not in tables:
            Base.metadata.tables[name].create(bind)


def downgrade() -> None:
    from app.core.models import FOUND_TABLES

    tables = set(sa.inspect(op.get_bind()).get_table_names())
    for name in reversed(FOUND_TABLES):
        if name in tables:
            op.drop_table(name)

"""the Playground

Release 5.3. The Playground keeps what each person typed outside any
incident and what it gave. The table is created only where it is missing:
the baseline creates the schema from the models.

Revision ID: 0038_incident_page
Revises: 0037_branches
Create Date: 2026-11-19
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0038_incident_page"
down_revision = "0037_branches"
branch_labels = None
depends_on = None


def upgrade() -> None:
    from app.core.db import Base
    from app.core.models import INCIDENT_PAGE_TABLES

    bind = op.get_bind()
    existing = set(sa.inspect(bind).get_table_names())
    for name in INCIDENT_PAGE_TABLES:
        if name not in existing:
            Base.metadata.tables[name].create(bind)


def downgrade() -> None:
    from app.core.models import INCIDENT_PAGE_TABLES

    bind = op.get_bind()
    existing = set(sa.inspect(bind).get_table_names())
    for name in reversed(INCIDENT_PAGE_TABLES):
        if name in existing:
            op.drop_table(name)

"""branches of a playbook

Release 5.2. A branch is a copy of a playbook that is worked on beside the
version in use, then pushed over it. The table is created only where it is
missing: the baseline creates the schema from the models. No playbook gets
a branch by itself.

Revision ID: 0037_branches
Revises: 0036_instances
Create Date: 2026-11-19
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0037_branches"
down_revision = "0036_instances"
branch_labels = None
depends_on = None


def upgrade() -> None:
    from app.core.db import Base
    from app.core.models import BRANCH_TABLES

    bind = op.get_bind()
    existing = set(sa.inspect(bind).get_table_names())
    for name in BRANCH_TABLES:
        if name not in existing:
            Base.metadata.tables[name].create(bind)


def downgrade() -> None:
    from app.core.models import BRANCH_TABLES

    bind = op.get_bind()
    existing = set(sa.inspect(bind).get_table_names())
    for name in reversed(BRANCH_TABLES):
        if name in existing:
            op.drop_table(name)

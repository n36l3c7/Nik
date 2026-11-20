"""what a playbook asks the API process to do with a file

Release 6.6. A playbook can keep a file and start the analysis of an
artifact. The worker that runs playbooks cannot write to the store of files
nor reach the analysis workers, so its nodes write what they want in a table
and the API process does it. The table is added only where it is missing.

Revision ID: 0047_playbook_files
Revises: 0045_lookups_through_connectors
Create Date: 2026-11-20
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0047_playbook_files"
down_revision = "0045_lookups_through_connectors"
branch_labels = None
depends_on = None


def upgrade() -> None:
    from app.core.db import Base
    from app.core.models import PLAYBOOK_FILE_TABLES

    bind = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names())
    for name in PLAYBOOK_FILE_TABLES:
        if name not in tables:
            Base.metadata.tables[name].create(bind)


def downgrade() -> None:
    from app.core.models import PLAYBOOK_FILE_TABLES

    bind = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names())
    for name in reversed(PLAYBOOK_FILE_TABLES):
        if name in tables:
            op.drop_table(name)

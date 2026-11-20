"""the backups Nik takes

Release 6.7. Nik takes its backups by itself, tests each one by restoring
it, and sends a copy off the server. The table holds what it knows of every
backup; the backups themselves are files. It is added only where it is
missing.

Revision ID: 0048_backups
Revises: 0047_playbook_files
Create Date: 2026-11-20
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0048_backups"
down_revision = "0047_playbook_files"
branch_labels = None
depends_on = None


def upgrade() -> None:
    from app.core.db import Base
    from app.core.models import BACKUP_TABLES

    bind = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names())
    for name in BACKUP_TABLES:
        if name not in tables:
            Base.metadata.tables[name].create(bind)


def downgrade() -> None:
    from app.core.models import BACKUP_TABLES

    bind = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names())
    for name in reversed(BACKUP_TABLES):
        if name in tables:
            op.drop_table(name)

"""recovery to a moment, and the copy of the store on the second host

Release 6.9. The log of PostgreSQL is archived and base backups are taken, so
that the database can be brought back to any moment and a standby kept up to
date (``app/recovery``). One table holds what the server knows of each base
backup; another, for each file of the store, where its copy on the second
host stands. The archive itself and the files are on the disk. Both tables
are added only where they are missing.

Revision ID: 0052_recovery
Revises: 0051_audit_chain
Create Date: 2026-11-21
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0052_recovery"
down_revision = "0051_audit_chain"
branch_labels = None
depends_on = None


def upgrade() -> None:
    from app.core.db import Base
    from app.core.models import RECOVERY_TABLES

    bind = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names())
    for name in RECOVERY_TABLES:
        if name not in tables:
            Base.metadata.tables[name].create(bind)


def downgrade() -> None:
    from app.core.models import RECOVERY_TABLES

    bind = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names())
    for name in reversed(RECOVERY_TABLES):
        if name in tables:
            op.drop_table(name)

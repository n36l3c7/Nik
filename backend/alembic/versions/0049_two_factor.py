"""a second factor at sign-in, and sessions that can be seen and ended

Release 6.7. An account can have a second factor (a code from an
authenticator app) with its recovery codes; the right password of such an
account gives a ticket for the second step; failed sign-ins are counted per
account and per address. A session gets a name the lists can show, the time
of its last use, and where it was opened from. Tables and columns are added
only where missing; the sessions that are open stay open (their last use is
the moment of the upgrade).

Revision ID: 0049_two_factor
Revises: 0048_backups
Create Date: 2026-11-20
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import sqlalchemy as sa

from alembic import op

revision = "0049_two_factor"
down_revision = "0048_backups"
branch_labels = None
depends_on = None

_COLUMNS = {
    "users": {
        "signin_addresses": lambda: sa.Column("signin_addresses", sa.JSON(), nullable=True),
        "signin_notice": lambda: sa.Column("signin_notice", sa.String(40), nullable=True),
    },
    "sessions": {
        "public_id": lambda: sa.Column("public_id", sa.String(32), nullable=True),
        "last_used_at": lambda: sa.Column("last_used_at", sa.String(), nullable=True),
        "address": lambda: sa.Column("address", sa.String(64), nullable=True),
        "user_agent": lambda: sa.Column("user_agent", sa.String(400), nullable=True),
    },
}
_INDEX = "ix_sessions_public_id"


def upgrade() -> None:
    from app.core.db import Base
    from app.core.models import TWO_FACTOR_TABLES

    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())
    for table, columns in _COLUMNS.items():
        if table not in tables:
            continue
        existing = {column["name"] for column in inspector.get_columns(table)}
        for name, column in columns.items():
            if name not in existing:
                op.add_column(table, column())
    if "sessions" in tables:
        if _INDEX not in {index["name"] for index in sa.inspect(bind).get_indexes("sessions")}:
            op.create_index(_INDEX, "sessions", ["public_id"])
        # The sessions that are open: a name each, and "used now", so that none ends because of the upgrade.
        now = datetime.now(timezone.utc).isoformat()
        sessions = sa.table("sessions", sa.column("token"), sa.column("public_id"), sa.column("last_used_at"))
        for (token,) in bind.execute(sa.select(sessions.c.token).where(sessions.c.public_id.is_(None))).all():
            bind.execute(
                sa.update(sessions)
                .where(sessions.c.token == token)
                .values(public_id=uuid.uuid4().hex, last_used_at=now)
            )
    for name in TWO_FACTOR_TABLES:
        if name not in tables:
            Base.metadata.tables[name].create(bind)


def downgrade() -> None:
    from app.core.models import TWO_FACTOR_TABLES

    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())
    for name in reversed(TWO_FACTOR_TABLES):
        if name in tables:
            op.drop_table(name)
    if "sessions" in tables and _INDEX in {index["name"] for index in inspector.get_indexes("sessions")}:
        op.drop_index(_INDEX, table_name="sessions")
    for table, columns in _COLUMNS.items():
        if table not in tables:
            continue
        existing = {column["name"] for column in inspector.get_columns(table)}
        wanted = [name for name in columns if name in existing]
        if wanted:
            with op.batch_alter_table(table) as batch:
                for name in wanted:
                    batch.drop_column(name)

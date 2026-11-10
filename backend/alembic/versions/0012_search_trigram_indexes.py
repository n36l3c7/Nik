"""Trigram indexes for the global search (PostgreSQL only)

``pg_trgm`` GIN indexes let ``ILIKE '%text%'`` on incident names, hosts and
users and on indicator values use an index instead of a full scan. The
extension is trusted since PostgreSQL 13, so the database owner can create
it; when it cannot be created the search still works, without the indexes.
SQLite needs nothing.

Revision ID: 0012_search_trigram_indexes
Revises: 0011_ioc_index
Create Date: 2026-11-10
"""

from __future__ import annotations

import logging

from alembic import op

revision = "0012_search_trigram_indexes"
down_revision = "0011_ioc_index"
branch_labels = None
depends_on = None

log = logging.getLogger("alembic.runtime.migration")

INDEXES = {
    "ix_incidents_name_trgm": ("incidents", "name"),
    "ix_incidents_host_trgm": ("incidents", "host"),
    "ix_incidents_username_trgm": ("incidents", "username"),
    "ix_ioc_index_value_trgm": ("ioc_index", "value"),
}


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    savepoint = bind.begin_nested()
    try:
        bind.exec_driver_sql("CREATE EXTENSION IF NOT EXISTS pg_trgm")
        savepoint.commit()
    except Exception as exc:  # noqa: BLE001 - not allowed: search works without the indexes
        savepoint.rollback()
        log.warning("pg_trgm unavailable (%s): the search runs without trigram indexes", exc)
        return
    for name, (table, column) in INDEXES.items():
        bind.exec_driver_sql(f"CREATE INDEX IF NOT EXISTS {name} ON {table} USING gin ({column} gin_trgm_ops)")


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    for name in INDEXES:
        bind.exec_driver_sql(f"DROP INDEX IF EXISTS {name}")

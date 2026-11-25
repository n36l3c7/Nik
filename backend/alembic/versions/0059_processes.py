"""processes and logons of host evidence: linking, the screens, the search

Release 7.0, stage 7. The tables of processes and logons (migration 0056) get what linking and the screens
need:

- ``evidence_processes``: ``parent_id`` (the process that started it, when the evidence holds it), ``parent_image``
  and ``parent_command_line`` (what the log said of a parent that is not in the evidence), ``hashes``, and the
  indexes of one host in start order, of a pid, of the parent and of the record;
- ``evidence_logons``: ``status`` (what a failure said), ``target_host`` (the server an explicit logon went to),
  and the indexes of one host in time and of the record (a record that goes takes its rows with it without a scan
  of the table);
- on PostgreSQL, the trigram index of the summary of a record (migration 0056 makes it only where ``pg_trgm`` was
  there; it is tried again) and the ones of the image and the command line of a process, for the same reason.

Idempotent: each column and index is created only where missing. On SQLite ``parent_id`` is added without its
foreign key (the database cannot add one to a table); the code clears the references itself.

Downgrade removes the columns and the indexes this migration made.

Revision ID: 0059_processes
Revises: 0058_collections
Create Date: 2026-11-25
"""

from __future__ import annotations

import logging

import sqlalchemy as sa

from alembic import op

revision = "0059_processes"
down_revision = "0058_collections"
branch_labels = None
depends_on = None

log = logging.getLogger("alembic.runtime.migration")

_COLUMNS = {
    "evidence_processes": {
        "parent_id": lambda: sa.Column("parent_id", sa.BigInteger, nullable=True),
        "parent_image": lambda: sa.Column("parent_image", sa.String(1000), nullable=False, server_default=""),
        "parent_command_line": lambda: sa.Column("parent_command_line", sa.Text, nullable=False, server_default=""),
        "hashes": lambda: sa.Column("hashes", sa.JSON, nullable=False, server_default="{}"),
    },
    "evidence_logons": {
        "status": lambda: sa.Column("status", sa.String(120), nullable=False, server_default=""),
        "target_host": lambda: sa.Column("target_host", sa.String(255), nullable=False, server_default=""),
    },
}
_INDEXES = {
    "evidence_processes": {
        "ix_evidence_processes_host_time": ["incident_id", "host", "start_ts", "id"],
        "ix_evidence_processes_pid": ["incident_id", "host", "pid", "start_ts"],
        "ix_evidence_processes_parent_id": ["parent_id"],
        "ix_evidence_processes_record": ["record_id"],
    },
    "evidence_logons": {
        "ix_evidence_logons_host": ["incident_id", "host", "ts"],
        "ix_evidence_logons_record": ["record_id"],
    },
}
_PARENT_KEY = "fk_evidence_processes_parent_id"
_TRIGRAMS = {
    "ix_evidence_records_summary_trgm": ("evidence_records", "summary"),
    "ix_evidence_processes_image_trgm": ("evidence_processes", "image"),
    "ix_evidence_processes_command_trgm": ("evidence_processes", "command_line"),
}


def _trigrams(bind) -> None:
    if bind.dialect.name != "postgresql":
        return
    if not bind.exec_driver_sql("SELECT 1 FROM pg_extension WHERE extname = 'pg_trgm'").first():
        log.warning("pg_trgm unavailable: the search of evidence runs without its trigram indexes")
        return
    for name, (table, column) in _TRIGRAMS.items():
        bind.exec_driver_sql(f"CREATE INDEX IF NOT EXISTS {name} ON {table} USING gin ({column} gin_trgm_ops)")


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())
    for table, columns in _COLUMNS.items():
        if table not in tables:
            continue
        existing = {column["name"] for column in inspector.get_columns(table)}
        for name, make in columns.items():
            if name not in existing:
                op.add_column(table, make())
    if "evidence_processes" in tables and bind.dialect.name == "postgresql":
        keys = {key["name"] for key in inspector.get_foreign_keys("evidence_processes")}
        if _PARENT_KEY not in keys:
            op.create_foreign_key(
                _PARENT_KEY, "evidence_processes", "evidence_processes", ["parent_id"], ["id"], ondelete="SET NULL"
            )
    for table, indexes in _INDEXES.items():
        if table not in tables:
            continue
        existing = {index["name"] for index in sa.inspect(bind).get_indexes(table)}
        for name, columns in indexes.items():
            if name not in existing:
                op.create_index(name, table, columns)
    _trigrams(bind)


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        for name in ("ix_evidence_processes_image_trgm", "ix_evidence_processes_command_trgm"):
            bind.exec_driver_sql(f"DROP INDEX IF EXISTS {name}")
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())
    for table, indexes in _INDEXES.items():
        if table not in tables:
            continue
        existing = {index["name"] for index in sa.inspect(bind).get_indexes(table)}
        for name in indexes:
            if name in existing:
                op.drop_index(name, table_name=table)
    for table, columns in _COLUMNS.items():
        if table not in tables:
            continue
        existing = {column["name"] for column in sa.inspect(bind).get_columns(table)}
        wanted = [name for name in columns if name in existing]
        if not wanted:
            continue
        if table == "evidence_processes" and bind.dialect.name == "postgresql":
            if _PARENT_KEY in {key["name"] for key in inspector.get_foreign_keys(table)}:
                op.drop_constraint(_PARENT_KEY, table, type_="foreignkey")
        with op.batch_alter_table(table) as batch:
            for name in wanted:
                batch.drop_column(name)

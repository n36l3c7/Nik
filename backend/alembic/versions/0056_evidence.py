"""host evidence leaves the incident document

Release 7.0. What was read out of the files of host evidence (event logs,
endpoint artifacts, browsers, command histories, and from 7.0 disks and the
logs of Linux and macOS) is kept in tables of its own instead of the incident
document, with the original file and the report of its reading:

- ``evidence_sources``: one row per file an incident holds, with its parse
  report (what was in it, read, kept, skipped and why);
- ``evidence_records``: what was read out of it, one row per record, with
  where it is in the original;
- ``evidence_marks``: the flags and notes on records, by the record's natural
  key, so they outlive a new reading of the file;
- ``evidence_detections``, ``evidence_processes``, ``evidence_logons``: the
  rules that matched, the process tree, the logons of the lateral graph;
- ``upload_sessions``: files sent in parts;
- ``sigma_rules``: the rules host evidence is matched against;
- ``incidents.tz``: the time zone an incident is read in, when it is not Nik's;
- ``incidents.archived_at``, ``archived_by``: an incident put in the archive;
- ``backup_blobs``, ``backup_blob_refs``: the pool of the backups, where a file
  of the store named by its SHA-256 is written once instead of in every backup
  (``app/backups/pool.py``). The backups taken before 7.0 name nothing there
  and are restored as they always were.

On PostgreSQL the one-line summary of a record gets a trigram index, for the
search of all Nik (when ``pg_trgm`` is there, as migration 0012 found it).

Nothing is moved here: what incident documents hold is moved by the server
after the upgrade, in the background (``app/evidence/legacy.py``).

Idempotent: each table, column and index is created only where missing.

Revision ID: 0056_evidence
Revises: 0055_bulk
Create Date: 2026-11-24
"""

from __future__ import annotations

import logging

import sqlalchemy as sa

from alembic import op

revision = "0056_evidence"
down_revision = "0055_bulk"
branch_labels = None
depends_on = None

log = logging.getLogger("alembic.runtime.migration")

_COLUMNS = {
    "incidents": {
        "tz": lambda: sa.Column("tz", sa.String(64), nullable=True),
        "archived_at": lambda: sa.Column("archived_at", sa.String(40), nullable=True),
        "archived_by": lambda: sa.Column("archived_by", sa.String(200), nullable=True),
    }
}
_ARCHIVED = "ix_incidents_archived_at"
_TRIGRAM = "ix_evidence_records_summary_trgm"


def _trigram(bind) -> None:
    if bind.dialect.name != "postgresql":
        return
    found = bind.exec_driver_sql("SELECT 1 FROM pg_extension WHERE extname = 'pg_trgm'").first()
    if not found:
        log.warning("pg_trgm unavailable: the search of evidence runs without its trigram index")
        return
    bind.exec_driver_sql(f"CREATE INDEX IF NOT EXISTS {_TRIGRAM} ON evidence_records USING gin (summary gin_trgm_ops)")


def upgrade() -> None:
    from app.core.db import Base
    from app.core.models import EVIDENCE_TABLES, POOL_TABLES

    bind = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names())
    for name in (*EVIDENCE_TABLES, *POOL_TABLES):
        if name not in tables:
            Base.metadata.tables[name].create(bind)
    for table, columns in _COLUMNS.items():
        if table not in tables:
            continue
        existing = {column["name"] for column in sa.inspect(bind).get_columns(table)}
        for name, make in columns.items():
            if name not in existing:
                op.add_column(table, make())
    if "incidents" in tables and _ARCHIVED not in {
        index["name"] for index in sa.inspect(bind).get_indexes("incidents")
    }:
        op.create_index(_ARCHIVED, "incidents", ["archived_at"])
    _trigram(bind)


def downgrade() -> None:
    from app.core.models import EVIDENCE_TABLES, POOL_TABLES

    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        bind.exec_driver_sql(f"DROP INDEX IF EXISTS {_TRIGRAM}")
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())
    if "incidents" in tables and _ARCHIVED in {index["name"] for index in inspector.get_indexes("incidents")}:
        op.drop_index(_ARCHIVED, table_name="incidents")
    for table, columns in _COLUMNS.items():
        if table not in tables:
            continue
        existing = {column["name"] for column in inspector.get_columns(table)}
        wanted = [name for name in columns if name in existing]
        if wanted:
            with op.batch_alter_table(table) as batch:
                for name in wanted:
                    batch.drop_column(name)
    for name in reversed((*EVIDENCE_TABLES, *POOL_TABLES)):
        if name in tables:
            op.drop_table(name)

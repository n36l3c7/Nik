"""collections of host evidence

Release 7.0. A triage collection (a KAPE or Velociraptor zip) is a source of an incident whose files are listed
before anything is imported, and an export of Plaso holds records of every section:

- ``evidence_members``: the files the worker found in a collection, with what a parser reads each as, the
  user and the host its place says, and the source it became once it was imported;
- ``evidence_records.source``: the source a record is of when it is not its file's (None: its file's);
- ``evidence_sources.file_time``: the file's own last-modified time (ms), which gives the year of syslog lines.

Idempotent: the table and the columns are created only where missing.

Downgrade removes all three.

Revision ID: 0058_collections
Revises: 0057_sigma
Create Date: 2026-11-25
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0058_collections"
down_revision = "0057_sigma"
branch_labels = None
depends_on = None


def upgrade() -> None:
    from app.core.db import Base
    from app.core.models import COLLECTION_TABLES

    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())
    if "evidence_records" in tables:
        existing = {column["name"] for column in inspector.get_columns("evidence_records")}
        if "source" not in existing:
            op.add_column("evidence_records", sa.Column("source", sa.String(60), nullable=True))
    if "evidence_sources" in tables:
        existing = {column["name"] for column in inspector.get_columns("evidence_sources")}
        if "file_time" not in existing:
            op.add_column("evidence_sources", sa.Column("file_time", sa.BigInteger, nullable=True))
    for name in COLLECTION_TABLES:
        if name not in tables:
            Base.metadata.tables[name].create(bind)


def downgrade() -> None:
    from app.core.models import COLLECTION_TABLES

    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())
    for name in reversed(COLLECTION_TABLES):
        if name in tables:
            op.drop_table(name)
    if "evidence_sources" in tables:
        if "file_time" in {column["name"] for column in inspector.get_columns("evidence_sources")}:
            with op.batch_alter_table("evidence_sources") as batch:
                batch.drop_column("file_time")
    if "evidence_records" in tables:
        if "source" in {column["name"] for column in inspector.get_columns("evidence_records")}:
            with op.batch_alter_table("evidence_records") as batch:
                batch.drop_column("source")

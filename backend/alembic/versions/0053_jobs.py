"""work in progress survives a restart

Release 6.9. What the server does outside a request is written down well
enough for another process, on this host or on another, to go on with it
after a stop:

- ``work_claims``: who holds each piece of work the API process does (an
  analysis, a scan, an upload being parsed), and since when it last said it
  was alive (``app/work.py``);
- ``run_steps.calling_at``: the mark a step of a playbook writes before a
  call that changes something outside Nik; ``run_steps.restarts``: what
  restarts did to the step; ``run_steps.status`` grows to hold
  ``interrupted``;
- ``runs.event_key``, unique: the same event never starts the same playbook
  twice;
- ``mirror_queue.holder``: who is sending a change to a mirrored system.

Steps that are ``running`` at this moment were claimed by the version before,
which wrote no mark: an action among them is marked as calling, so that the
worker of this version asks a person about the ones that change something
outside instead of repeating them.

The analyses, scans, mailboxes and uploads that were in progress when the
server was stopped for this upgrade were threads of the version before, and
are gone with it. Each gets a row of ``work_claims`` that says it is wanted:
the server of this version starts it again a few seconds after it is up (an
upload that was being parsed fails with a sentence instead, its bytes are
gone). Until 6.9 they stayed "running" until someone asked again.

Idempotent: the table, the columns and the index are added only where missing.

Revision ID: 0053_jobs
Revises: 0052_recovery
Create Date: 2026-11-21
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0053_jobs"
down_revision = "0052_recovery"
branch_labels = None
depends_on = None

_COLUMNS = {
    "runs": {"event_key": lambda: sa.Column("event_key", sa.String(80), nullable=True)},
    "run_steps": {
        "calling_at": lambda: sa.Column("calling_at", sa.Float(), nullable=True),
        "restarts": lambda: sa.Column("restarts", sa.JSON(), nullable=True),
    },
    "mirror_queue": {"holder": lambda: sa.Column("holder", sa.String(40), nullable=True)},
}
_INDEX = "ux_runs_event_key"
_STATUS_LENGTH = 12
# kind of work → (table, the column that is its id, the states in which it was in progress).
_IN_PROGRESS = {
    "code": ("sample_code", "sha256", ("queued", "running")),
    "capa": ("sample_capa", "sha256", ("queued", "running")),
    "capture": ("network_captures", "id", ("indexing",)),
    "mailbox": ("mailboxes", "id", ("indexing",)),
    "import": ("mailboxes", "id", ("importing",)),
    "scan": ("url_scans", "id", ("queued", "running")),
    "upload": ("jobs", "id", ("queued", "running")),
    "artifact-job": ("artifact_jobs", "id", ("running",)),
}
_NOTE = "In progress when the server was upgraded to 6.9"


def _adopt_what_was_in_progress(bind, tables: set[str]) -> None:
    claims = sa.table(
        "work_claims",
        *(sa.column(name) for name in ("kind", "ref", "state", "holder", "beat_at", "wanted_at", "attempts")),
        sa.column("progress"),
        sa.column("note"),
        sa.column("params", sa.JSON()),
    )
    rows = []
    for kind, (table, key, states) in _IN_PROGRESS.items():
        if table not in tables:
            continue
        found = sa.table(table, sa.column(key), sa.column("status"))
        for (ref,) in bind.execute(sa.select(found.c[key]).where(found.c.status.in_(states))).all():
            rows.append(
                {
                    "kind": kind,
                    "ref": str(ref),
                    "state": "wanted",
                    "holder": "",
                    "beat_at": 0.0,
                    "wanted_at": 0.0,
                    "attempts": 0,
                    "progress": "",
                    "note": _NOTE,
                    "params": {},
                }
            )
    if rows:
        op.bulk_insert(claims, rows)


def upgrade() -> None:
    from app.core.db import Base
    from app.core.models import JOB_TABLES

    bind = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names())
    for name in JOB_TABLES:
        if name not in tables:
            Base.metadata.tables[name].create(bind)
            if name == "work_claims":
                _adopt_what_was_in_progress(bind, tables)
    added: set[str] = set()
    for table, columns in _COLUMNS.items():
        if table not in tables:
            continue
        existing = {column["name"] for column in sa.inspect(bind).get_columns(table)}
        for name, make in columns.items():
            if name not in existing:
                op.add_column(table, make())
                added.add(f"{table}.{name}")
    if "runs" in tables and _INDEX not in {index["name"] for index in sa.inspect(bind).get_indexes("runs")}:
        op.create_index(_INDEX, "runs", ["event_key"], unique=True)
    if "run_steps" in tables:
        status = next(c for c in sa.inspect(bind).get_columns("run_steps") if c["name"] == "status")
        length = getattr(status["type"], "length", None)
        # SQLite does not hold a text to its length; PostgreSQL does, and widening is a change of the catalog only.
        if bind.dialect.name == "postgresql" and length is not None and length < _STATUS_LENGTH:
            op.alter_column("run_steps", "status", type_=sa.String(_STATUS_LENGTH), existing_nullable=False)
        if "run_steps.calling_at" in added:
            steps = sa.table(
                "run_steps",
                sa.column("status"),
                sa.column("kind"),
                sa.column("claimed_at"),
                sa.column("calling_at"),
            )
            bind.execute(
                sa.update(steps)
                .where(steps.c.status == "running", steps.c.kind == "action", steps.c.claimed_at.isnot(None))
                .values(calling_at=steps.c.claimed_at)
            )


def downgrade() -> None:
    from app.core.models import JOB_TABLES

    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())
    if "run_steps" in tables:
        # The version before knows no such state: the steps that wait for a person's word fail with it.
        steps = sa.table("run_steps", sa.column("status"), sa.column("error"))
        bind.execute(
            sa.update(steps)
            .where(steps.c.status == "interrupted")
            .values(status="failed", error="The worker stopped while this ran: outcome unknown")
        )
    if "runs" in tables and _INDEX in {index["name"] for index in inspector.get_indexes("runs")}:
        op.drop_index(_INDEX, table_name="runs")
    for table, columns in _COLUMNS.items():
        if table not in tables:
            continue
        existing = {column["name"] for column in inspector.get_columns(table)}
        wanted = [name for name in columns if name in existing]
        if wanted:
            with op.batch_alter_table(table) as batch:
                for name in wanted:
                    batch.drop_column(name)
    for name in reversed(JOB_TABLES):
        if name in tables:
            op.drop_table(name)

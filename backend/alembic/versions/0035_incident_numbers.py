"""incidents get a number; "is not" in stored queries is written as it is now

Release 5.0. What was the id of an incident stays its key (its uuid); a
number is added beside it, given in the order the incidents were created, and
a counter remembers the last one given so that none is used twice. Each step
is done only where it is missing: the baseline creates the schema from the
models.

The queries a dashboard holds are rewritten from ``status:!closed`` to
``!status:closed``. They mean the same, and the old writing is still read.

Revision ID: 0035_incident_numbers
Revises: 0034_misc
Create Date: 2026-11-19
"""

from __future__ import annotations

import json

import sqlalchemy as sa

from alembic import op

revision = "0035_incident_numbers"
down_revision = "0034_misc"
branch_labels = None
depends_on = None


def _rewrite_queries(bind) -> None:
    from app.query.parser import modern

    tables = set(sa.inspect(bind).get_table_names())
    if "dashboards" not in tables:
        return
    held = {column["name"] for column in sa.inspect(bind).get_columns("dashboards")}
    if not {"layout", "filter_query"} <= held:
        return
    for row in bind.execute(sa.text("SELECT id, layout, filter_query FROM dashboards")).all():
        layout = row.layout
        if isinstance(layout, str):
            try:
                layout = json.loads(layout)
            except ValueError:
                layout = None
        changed = False
        if isinstance(layout, list):
            for widget in layout:
                if isinstance(widget, dict) and isinstance(widget.get("query"), str):
                    now = modern(widget["query"])
                    if now != widget["query"]:
                        widget["query"], changed = now, True
        filter_query = modern(row.filter_query or "")
        if len(filter_query) > 400:
            filter_query = row.filter_query
        if changed or filter_query != (row.filter_query or ""):
            bind.execute(
                sa.text("UPDATE dashboards SET layout = :layout, filter_query = :filter WHERE id = :id"),
                {"layout": json.dumps(layout if changed else layout), "filter": filter_query, "id": row.id},
            )


def upgrade() -> None:
    from app.core.db import Base
    from app.core.models import NUMBER_COLUMNS, NUMBER_TABLES

    bind = op.get_bind()
    existing = set(sa.inspect(bind).get_table_names())
    for name in NUMBER_TABLES:
        if name not in existing:
            Base.metadata.tables[name].create(bind)
    if "incidents" in existing:
        held = {column["name"] for column in sa.inspect(bind).get_columns("incidents")}
        for name in NUMBER_COLUMNS["incidents"]:
            if name not in held:
                op.add_column("incidents", sa.Column(name, sa.Integer(), nullable=True))
        columns = {column["name"] for column in sa.inspect(bind).get_columns("incidents")}
        # The incidents that have no number yet, the oldest first, after the numbers already given.
        order = "created_at, id" if "created_at" in columns else "id"
        last = int(bind.execute(sa.text("SELECT MAX(number) FROM incidents")).scalar() or 0)
        counted = bind.execute(sa.text("SELECT value FROM sequences WHERE name = 'incidents'")).scalar()
        last = max(last, int(counted or 0))
        for (incident_id,) in bind.execute(
            sa.text(f"SELECT id FROM incidents WHERE number IS NULL ORDER BY {order}")  # noqa: S608 - fixed text
        ).all():
            last += 1
            bind.execute(sa.text("UPDATE incidents SET number = :n WHERE id = :id"), {"n": last, "id": incident_id})
        if counted is None:
            bind.execute(sa.text("INSERT INTO sequences (name, value) VALUES ('incidents', :v)"), {"v": last})
        elif last > int(counted):
            bind.execute(sa.text("UPDATE sequences SET value = :v WHERE name = 'incidents'"), {"v": last})
        indexes = {index["name"] for index in sa.inspect(bind).get_indexes("incidents")}
        if "uq_incidents_number" not in indexes:
            op.create_index("uq_incidents_number", "incidents", ["number"], unique=True)
    _rewrite_queries(bind)


def downgrade() -> None:
    from app.core.models import NUMBER_COLUMNS, NUMBER_TABLES

    bind = op.get_bind()
    existing = set(sa.inspect(bind).get_table_names())
    if "incidents" in existing:
        indexes = {index["name"] for index in sa.inspect(bind).get_indexes("incidents")}
        if "uq_incidents_number" in indexes:
            op.drop_index("uq_incidents_number", table_name="incidents")
        held = {column["name"] for column in sa.inspect(bind).get_columns("incidents")}
        with op.batch_alter_table("incidents") as batch:
            for name in NUMBER_COLUMNS["incidents"]:
                if name in held:
                    batch.drop_column(name)
    for name in NUMBER_TABLES:
        if name in existing:
            op.drop_table(name)

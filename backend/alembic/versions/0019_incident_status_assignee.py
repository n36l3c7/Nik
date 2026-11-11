"""incidents.status and incidents.assignee

Where the work on an incident stands (open, in progress, closed) and the
analyst who has it are mirrored from the incident document into columns, so
the light incident list (``view=summary``) can show and filter them without
reading documents. Existing incidents are open and unassigned unless their
document says otherwise.

Revision ID: 0019_incident_status_assignee
Revises: 0018_url_scans
Create Date: 2026-11-11
"""

from __future__ import annotations

import json

import sqlalchemy as sa

from alembic import op

revision = "0019_incident_status_assignee"
down_revision = "0018_url_scans"
branch_labels = None
depends_on = None

STATUSES = ("open", "in_progress", "closed")


def upgrade() -> None:
    bind = op.get_bind()
    columns = {c["name"] for c in sa.inspect(bind).get_columns("incidents")}
    with op.batch_alter_table("incidents") as batch:
        if "status" not in columns:
            batch.add_column(sa.Column("status", sa.String(), nullable=False, server_default="open"))
        if "assignee" not in columns:
            batch.add_column(sa.Column("assignee", sa.String(), nullable=False, server_default=""))
    incidents = sa.table(
        "incidents",
        sa.column("id", sa.String),
        sa.column("doc", sa.JSON),
        sa.column("status"),
        sa.column("assignee"),
    )
    for incident_id, doc in bind.execute(sa.select(incidents.c.id, incidents.c.doc)).all():
        doc = json.loads(doc) if isinstance(doc, (str, bytes)) else (doc or {})
        status = str(doc.get("status") or "")
        assignee = str(doc.get("assignee") or "")
        if assignee or status in STATUSES:
            bind.execute(
                incidents.update()
                .where(incidents.c.id == incident_id)
                .values(status=status if status in STATUSES else "open", assignee=assignee)
            )


def downgrade() -> None:
    with op.batch_alter_table("incidents") as batch:
        batch.drop_column("assignee")
        batch.drop_column("status")

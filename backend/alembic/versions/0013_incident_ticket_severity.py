"""incidents.ticket_id and incidents.severity

The ticket ID (first part of an incident's name) and the analysts' severity
tag are mirrored from the incident document into columns, so the light
incident list (``view=summary``) can show them without reading documents.
Existing rows are filled from their documents.

Revision ID: 0013_incident_ticket_severity
Revises: 0012_search_trigram_indexes
Create Date: 2026-11-10
"""

from __future__ import annotations

import json

import sqlalchemy as sa

from alembic import op

revision = "0013_incident_ticket_severity"
down_revision = "0012_search_trigram_indexes"
branch_labels = None
depends_on = None

SEVERITIES = ("low", "medium", "high", "critical")


def upgrade() -> None:
    bind = op.get_bind()
    columns = {c["name"] for c in sa.inspect(bind).get_columns("incidents")}
    with op.batch_alter_table("incidents") as batch:
        if "ticket_id" not in columns:
            batch.add_column(sa.Column("ticket_id", sa.String(), nullable=False, server_default=""))
        if "severity" not in columns:
            batch.add_column(sa.Column("severity", sa.String(), nullable=False, server_default=""))
    incidents = sa.table(
        "incidents",
        sa.column("id", sa.String),
        sa.column("doc", sa.JSON),
        sa.column("ticket_id"),
        sa.column("severity"),
    )
    for incident_id, doc in bind.execute(sa.select(incidents.c.id, incidents.c.doc)).all():
        doc = json.loads(doc) if isinstance(doc, (str, bytes)) else (doc or {})
        ticket = str(doc.get("ticketId") or "")
        severity = str(doc.get("severity") or "")
        if ticket or severity in SEVERITIES:
            bind.execute(
                incidents.update()
                .where(incidents.c.id == incident_id)
                .values(ticket_id=ticket, severity=severity if severity in SEVERITIES else "")
            )


def downgrade() -> None:
    with op.batch_alter_table("incidents") as batch:
        batch.drop_column("severity")
        batch.drop_column("ticket_id")

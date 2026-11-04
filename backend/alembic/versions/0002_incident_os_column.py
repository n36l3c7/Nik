"""incident os column

Mirror the incident host OS (``doc.os``) into its own column so the light
``view=summary`` listing can return it without reading the document body.
Existing rows are backfilled from their stored document.

Revision ID: 0002_incident_os_column
Revises: 0001_baseline
Create Date: 2026-11-04
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0002_incident_os_column"
down_revision = "0001_baseline"
branch_labels = None
depends_on = None

incidents = sa.table(
    "incidents",
    sa.column("id", sa.String),
    sa.column("os", sa.String),
    sa.column("doc", sa.JSON),
)


def upgrade() -> None:
    columns = {c["name"] for c in sa.inspect(op.get_bind()).get_columns("incidents")}
    if "os" not in columns:
        op.add_column("incidents", sa.Column("os", sa.String(), nullable=False, server_default=""))
    bind = op.get_bind()
    for row in bind.execute(sa.select(incidents.c.id, incidents.c.doc)).all():
        doc = row.doc or {}
        os_id = str(doc.get("os") or "") if isinstance(doc, dict) else ""
        if os_id:
            bind.execute(incidents.update().where(incidents.c.id == row.id).values(os=os_id))


def downgrade() -> None:
    with op.batch_alter_table("incidents") as batch:
        batch.drop_column("os")

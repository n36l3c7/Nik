"""incidents.rev

A revision counter for the incident document: one more at every write. It is
the incident's ETag (it replaces the client-supplied ``updatedAt``), so a
client that edits a stale copy is answered 412 and merges instead of
overwriting somebody else's change.

Revision ID: 0020_incident_rev
Revises: 0019_incident_status_assignee
Create Date: 2026-11-11
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0020_incident_rev"
down_revision = "0019_incident_status_assignee"
branch_labels = None
depends_on = None


def upgrade() -> None:
    columns = {c["name"] for c in sa.inspect(op.get_bind()).get_columns("incidents")}
    if "rev" not in columns:
        with op.batch_alter_table("incidents") as batch:
            batch.add_column(sa.Column("rev", sa.Integer(), nullable=False, server_default="0"))


def downgrade() -> None:
    with op.batch_alter_table("incidents") as batch:
        batch.drop_column("rev")

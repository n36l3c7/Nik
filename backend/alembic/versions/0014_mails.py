"""mails table and incidents.has_mail

Analysed e-mails (Mail Analysis tab): one row per distinct ``.eml``/``.msg``
file with its analysis; the file itself is in the sample store. Incidents
get a ``has_mail`` column (mirrored from ``data.mail.messages``) so the
sidebar can show a mail icon from the light incident list.

Revision ID: 0014_mails
Revises: 0013_incident_ticket_severity
Create Date: 2026-11-10
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0014_mails"
down_revision = "0013_incident_ticket_severity"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "mails" not in inspector.get_table_names():
        op.create_table(
            "mails",
            sa.Column("sha256", sa.String(length=64), primary_key=True),
            sa.Column("format", sa.String(), nullable=False, server_default="eml"),
            sa.Column("size", sa.Integer(), nullable=False),
            sa.Column("subject", sa.String(), nullable=False, server_default=""),
            sa.Column("sender", sa.String(), nullable=False, server_default=""),
            sa.Column("sent_at", sa.BigInteger(), nullable=True),
            sa.Column("verdict", sa.String(), nullable=False, server_default="clean"),
            sa.Column("score", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("created_at", sa.String(), nullable=False),
            sa.Column("created_by", sa.String(), nullable=False, server_default=""),
            sa.Column("analysis", sa.JSON(), nullable=False),
        )
    if "has_mail" not in {c["name"] for c in inspector.get_columns("incidents")}:
        with op.batch_alter_table("incidents") as batch:
            batch.add_column(sa.Column("has_mail", sa.Boolean(), nullable=False, server_default=sa.false()))


def downgrade() -> None:
    with op.batch_alter_table("incidents") as batch:
        batch.drop_column("has_mail")
    op.drop_table("mails")

"""mailboxes: files of many e-mails (mbox, Maildir, PST) and the index of their messages

Revision ID: 0024_mailboxes
Revises: 0023_ioc_library
Create Date: 2026-11-13
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0024_mailboxes"
down_revision = "0023_ioc_library"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # The baseline creates the schema from the models: on a new database the
    # tables exist already, and each is created only where it is missing.
    tables = set(sa.inspect(op.get_bind()).get_table_names())
    if "mailboxes" not in tables:
        op.create_table(
            "mailboxes",
            sa.Column("id", sa.String(32), primary_key=True),
            sa.Column("file_name", sa.String(), nullable=False, server_default=""),
            sa.Column("format", sa.String(16), nullable=False, server_default="mbox"),
            sa.Column("size", sa.BigInteger(), nullable=False, server_default="0"),
            sa.Column("status", sa.String(16), nullable=False, server_default="indexing"),
            sa.Column("error", sa.String(), nullable=True),
            sa.Column("total", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("created_at", sa.String(), nullable=False),
            sa.Column("created_by", sa.String(), nullable=False, server_default=""),
            sa.Column("meta", sa.JSON(), nullable=False),
        )
    if "mailbox_messages" not in tables:
        op.create_table(
            "mailbox_messages",
            sa.Column("mailbox_id", sa.String(32), sa.ForeignKey("mailboxes.id", ondelete="CASCADE"), primary_key=True),
            sa.Column("seq", sa.Integer(), primary_key=True),
            sa.Column("offset", sa.BigInteger(), nullable=False),
            sa.Column("length", sa.BigInteger(), nullable=False),
            sa.Column("sha256", sa.String(64), nullable=False),
            sa.Column("message_id", sa.String(400), nullable=False, server_default=""),
            sa.Column("parent", sa.Integer(), nullable=True),
            sa.Column("thread", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("duplicate_of", sa.Integer(), nullable=True),
            sa.Column("subject", sa.String(500), nullable=False, server_default=""),
            sa.Column("sender", sa.String(320), nullable=False, server_default=""),
            sa.Column("recipients", sa.String(500), nullable=False, server_default=""),
            sa.Column("date_ms", sa.BigInteger(), nullable=True),
            sa.Column("attachments", sa.Boolean(), nullable=False, server_default=sa.false()),
        )
        op.create_index("ix_mailbox_messages_sha256", "mailbox_messages", ["sha256"])


def downgrade() -> None:
    op.drop_index("ix_mailbox_messages_sha256", table_name="mailbox_messages")
    op.drop_table("mailbox_messages")
    op.drop_table("mailboxes")

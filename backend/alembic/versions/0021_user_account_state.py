"""users.disabled, users.failed_logins, users.locked_until

An account can be disabled by an admin (it keeps its history and cannot sign
in), and is locked for a few minutes after too many wrong passwords in a row.

Revision ID: 0021_user_account_state
Revises: 0020_incident_rev
Create Date: 2026-11-11
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0021_user_account_state"
down_revision = "0020_incident_rev"
branch_labels = None
depends_on = None


def upgrade() -> None:
    columns = {c["name"] for c in sa.inspect(op.get_bind()).get_columns("users")}
    with op.batch_alter_table("users") as batch:
        if "disabled" not in columns:
            batch.add_column(sa.Column("disabled", sa.Boolean(), nullable=False, server_default=sa.false()))
        if "failed_logins" not in columns:
            batch.add_column(sa.Column("failed_logins", sa.Integer(), nullable=False, server_default="0"))
        if "locked_until" not in columns:
            batch.add_column(sa.Column("locked_until", sa.String(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("users") as batch:
        batch.drop_column("locked_until")
        batch.drop_column("failed_logins")
        batch.drop_column("disabled")

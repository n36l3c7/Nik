"""connectors: the files that say how to talk to a product, and connections to them

Also the address a playbook can be started at from outside (``playbooks.hook_hash``,
``playbooks.hook_created_at``).

Each table and column is created only where it is missing: the baseline
creates the schema from the models, so on a new database they exist already.

Revision ID: 0027_connectors
Revises: 0026_automation
Create Date: 2026-11-17
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0027_connectors"
down_revision = "0026_automation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    from app.core.db import Base
    from app.core.models import CONNECTOR_TABLES

    bind = op.get_bind()
    existing = set(sa.inspect(bind).get_table_names())
    # In the order of their foreign keys (connectors before their connections).
    for name in CONNECTOR_TABLES:
        if name not in existing:
            Base.metadata.tables[name].create(bind)
    if "playbooks" in existing:
        columns = {column["name"] for column in sa.inspect(bind).get_columns("playbooks")}
        with op.batch_alter_table("playbooks") as batch:
            if "hook_hash" not in columns:
                batch.add_column(sa.Column("hook_hash", sa.String(64), nullable=True))
                batch.create_unique_constraint("uq_playbooks_hook_hash", ["hook_hash"])
            if "hook_created_at" not in columns:
                batch.add_column(sa.Column("hook_created_at", sa.String(), nullable=True))


def downgrade() -> None:
    from app.core.models import CONNECTOR_TABLES

    bind = op.get_bind()
    if "playbooks" in set(sa.inspect(bind).get_table_names()):
        columns = {column["name"] for column in sa.inspect(bind).get_columns("playbooks")}
        with op.batch_alter_table("playbooks") as batch:
            if "hook_hash" in columns:
                batch.drop_constraint("uq_playbooks_hook_hash", type_="unique")
                batch.drop_column("hook_hash")
            if "hook_created_at" in columns:
                batch.drop_column("hook_created_at")
    existing = set(sa.inspect(op.get_bind()).get_table_names())
    for name in reversed(CONNECTOR_TABLES):
        if name in existing:
            op.drop_table(name)

"""several keys for an instance

Release 6.1. An instance holds more keys than one and says how they take
turns; what each key was used for is counted, and the answers an instance
keeps are stored. Tables and columns are added only where missing.

Revision ID: 0040_instance_keys
Revises: 0039_pack_catalogue
Create Date: 2026-11-19
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0040_instance_keys"
down_revision = "0039_pack_catalogue"
branch_labels = None
depends_on = None


def upgrade() -> None:
    from app.core.db import Base
    from app.core.models import INSTANCE_KEY_TABLES

    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())
    if "connections" in tables:
        existing = {column["name"] for column in inspector.get_columns("connections")}
        if "extra_keys" not in existing:
            op.add_column("connections", sa.Column("extra_keys", sa.Text(), nullable=False, server_default=""))
        if "key_policy" not in existing:
            op.add_column("connections", sa.Column("key_policy", sa.JSON(), nullable=True))
    for name in INSTANCE_KEY_TABLES:
        if name not in tables:
            Base.metadata.tables[name].create(bind)


def downgrade() -> None:
    from app.core.models import INSTANCE_KEY_TABLES

    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())
    for name in reversed(INSTANCE_KEY_TABLES):
        if name in tables:
            op.drop_table(name)
    if "connections" in tables:
        existing = {column["name"] for column in inspector.get_columns("connections")}
        wanted = [name for name in ("extra_keys", "key_policy") if name in existing]
        if wanted:
            with op.batch_alter_table("connections") as batch:
                for name in wanted:
                    batch.drop_column(name)

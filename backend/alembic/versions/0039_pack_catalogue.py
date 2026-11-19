"""packs of vendors' products

Release 6.0. A pack says where it came from and may carry a logo, and each
thing a pack gave is kept with what it was then, so that a later change is
told when the pack is uninstalled. Columns are added only where missing.

Revision ID: 0039_pack_catalogue
Revises: 0038_incident_page
Create Date: 2026-11-19
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0039_pack_catalogue"
down_revision = "0038_incident_page"
branch_labels = None
depends_on = None

COLUMNS = {
    "packs": (
        ("source", lambda: sa.Column("source", sa.String(20), nullable=False, server_default="file")),
        ("logo", lambda: sa.Column("logo", sa.LargeBinary(), nullable=True)),
        ("logo_type", lambda: sa.Column("logo_type", sa.String(20), nullable=False, server_default="")),
    ),
    "pack_items": (("digest", lambda: sa.Column("digest", sa.String(64), nullable=False, server_default="")),),
}


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    tables = set(inspector.get_table_names())
    for table, columns in COLUMNS.items():
        if table not in tables:
            continue
        existing = {column["name"] for column in inspector.get_columns(table)}
        for name, make in columns:
            if name not in existing:
                op.add_column(table, make())


def downgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    tables = set(inspector.get_table_names())
    for table, columns in COLUMNS.items():
        if table not in tables:
            continue
        existing = {column["name"] for column in inspector.get_columns(table)}
        wanted = [name for name, _make in columns if name in existing]
        if wanted:
            with op.batch_alter_table(table) as batch:
                for name in wanted:
                    batch.drop_column(name)

"""fields and incident types: the registry, the types, what an incident holds of them

Tables ``fields`` and ``incident_types``; on ``incidents`` the type, the custom
fields (JSONB with a GIN index on PostgreSQL), how it was closed, when it
occurred, where it came from. Each table, column and index is created only
where it is missing: the baseline creates the schema from the models, so on a
new database most of it exists already.

Existing incidents keep everything they hold: they have no type (which reads
as "Unclassified") and no custom field.

Revision ID: 0028_fields_types
Revises: 0027_connectors
Create Date: 2026-11-17
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0028_fields_types"
down_revision = "0027_connectors"
branch_labels = None
depends_on = None

# name → what to add; in the order they are added.
COLUMNS = (
    ("type_id", lambda: sa.Column("type_id", sa.String(32), nullable=True)),
    ("fields", lambda: sa.Column("fields", sa.JSON(), nullable=False, server_default="{}")),
    ("fields_rev", lambda: sa.Column("fields_rev", sa.Integer(), nullable=False, server_default="0")),
    ("closed_at", lambda: sa.Column("closed_at", sa.String(), nullable=True)),
    ("close_reason", lambda: sa.Column("close_reason", sa.String(), nullable=False, server_default="")),
    ("close_notes", lambda: sa.Column("close_notes", sa.String(), nullable=False, server_default="")),
    ("occurred_at", lambda: sa.Column("occurred_at", sa.String(), nullable=True)),
    ("source_connection_id", lambda: sa.Column("source_connection_id", sa.String(32), nullable=True)),
    ("source_id", lambda: sa.Column("source_id", sa.String(500), nullable=True)),
    ("mirror", lambda: sa.Column("mirror", sa.JSON(), nullable=True)),
)
INDEXES = ("ix_incidents_type_id", "ix_incidents_status", "uq_incidents_source", "ix_incidents_fields_gin")


def upgrade() -> None:
    from app.core.db import Base
    from app.core.models import FIELD_TABLES

    bind = op.get_bind()
    postgres = bind.dialect.name == "postgresql"
    inspector = sa.inspect(bind)
    existing = set(inspector.get_table_names())
    for name in FIELD_TABLES:
        if name not in existing:
            Base.metadata.tables[name].create(bind)
    if "incidents" not in existing:
        return
    columns = {column["name"] for column in inspector.get_columns("incidents")}
    for name, make in COLUMNS:
        if name in columns:
            continue
        column = make()
        if name == "fields" and postgres:
            from sqlalchemy.dialects.postgresql import JSONB

            column = sa.Column("fields", JSONB(), nullable=False, server_default="{}")
        op.add_column("incidents", column)
    indexes = {index["name"] for index in sa.inspect(bind).get_indexes("incidents")}
    if "ix_incidents_type_id" not in indexes:
        op.create_index("ix_incidents_type_id", "incidents", ["type_id"])
    if "ix_incidents_status" not in indexes:
        op.create_index("ix_incidents_status", "incidents", ["status"])
    if "uq_incidents_source" not in indexes:
        op.create_index(
            "uq_incidents_source",
            "incidents",
            ["source_connection_id", "source_id"],
            unique=True,
            sqlite_where=sa.text("source_id IS NOT NULL"),
            postgresql_where=sa.text("source_id IS NOT NULL"),
        )
    if postgres and "ix_incidents_fields_gin" not in indexes:
        # A database made from an older model may hold the column as JSON: the index needs JSONB.
        kind = bind.execute(
            sa.text(
                "SELECT data_type FROM information_schema.columns WHERE table_name='incidents' AND column_name='fields'"
            )
        ).scalar()
        if kind == "json":
            op.execute("ALTER TABLE incidents ALTER COLUMN fields TYPE JSONB USING fields::jsonb")
        op.create_index("ix_incidents_fields_gin", "incidents", ["fields"], postgresql_using="gin")


def downgrade() -> None:
    from app.core.models import FIELD_TABLES

    bind = op.get_bind()
    existing = set(sa.inspect(bind).get_table_names())
    if "incidents" in existing:
        indexes = {index["name"] for index in sa.inspect(bind).get_indexes("incidents")}
        for name in INDEXES:
            if name in indexes:
                op.drop_index(name, table_name="incidents")
        columns = {column["name"] for column in sa.inspect(bind).get_columns("incidents")}
        with op.batch_alter_table("incidents") as batch:
            for name, _make in reversed(COLUMNS):
                if name in columns:
                    batch.drop_column(name)
    for name in reversed(FIELD_TABLES):
        if name in existing:
            op.drop_table(name)

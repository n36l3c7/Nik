"""the single role of an account and the role and scopes of a key go

Release 6.4. Since 4.0 an account and an API key hold a list of roles; the
columns of before (``users.role``, ``api_keys.role``, ``api_keys.scopes``)
were kept filled and never read. They are dropped here. Before that, an
account or a key that still has no roles is given the ones its old columns
stand for (0025 did it for every row; this is for a row written since by
something that did not go through the application), so nobody comes out of
the upgrade able to do nothing. Columns are dropped only where they exist.

A downgrade puts the columns back and fills them from the roles.

Revision ID: 0044_no_legacy_roles
Revises: 0041_saved_filters
Create Date: 2026-11-20
"""

from __future__ import annotations

import json

import sqlalchemy as sa

from alembic import op

revision = "0044_no_legacy_roles"
down_revision = "0041_saved_filters"
branch_labels = None
depends_on = None


def _columns(table: str) -> set[str]:
    inspector = sa.inspect(op.get_bind())
    if table not in inspector.get_table_names():
        return set()
    return {column["name"] for column in inspector.get_columns(table)}


def _listed(value) -> list:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return []
    return value if isinstance(value, list) else []


def _roles(role: str | None, scopes: str | None = None) -> list[str]:
    """What the old columns stand for, as 0025 read them."""
    if role == "admin":
        return ["admin"]
    if role == "viewer":
        return ["viewer"]
    if scopes is not None and "write" not in {scope.strip() for scope in scopes.split(",")}:
        return ["viewer"]
    return ["analyst"]


def _fill(table: str, columns: set[str]) -> None:
    """Give the rows without roles the ones their old columns stand for."""
    if "roles" not in columns or "role" not in columns:
        return
    bind = op.get_bind()
    with_scopes = "scopes" in columns
    old = [sa.column("role", sa.String)] + ([sa.column("scopes", sa.String)] if with_scopes else [])
    rows = sa.table(table, sa.column("id", sa.String), sa.column("roles", sa.JSON), *old)
    for row in bind.execute(sa.select(rows)).mappings().all():
        if not _listed(row["roles"]):
            roles = _roles(row["role"], (row["scopes"] or "") if with_scopes else None)
            bind.execute(rows.update().where(rows.c.id == row["id"]).values(roles=roles))


def upgrade() -> None:
    for table, old in (("users", ("role",)), ("api_keys", ("role", "scopes"))):
        columns = _columns(table)
        _fill(table, columns)
        wanted = [name for name in old if name in columns]
        if wanted:
            with op.batch_alter_table(table) as batch:
                for name in wanted:
                    batch.drop_column(name)


def downgrade() -> None:
    bind = op.get_bind()

    columns = _columns("users")
    if columns and "role" not in columns:
        with op.batch_alter_table("users") as batch:
            batch.add_column(sa.Column("role", sa.String(), nullable=False, server_default="analyst"))
        users = sa.table("users", sa.column("id", sa.String), sa.column("roles", sa.JSON), sa.column("role", sa.String))
        for user_id, roles in bind.execute(sa.select(users.c.id, users.c.roles)).all():
            if "admin" in _listed(roles):
                bind.execute(users.update().where(users.c.id == user_id).values(role="admin"))

    columns = _columns("api_keys")
    if not columns:
        return
    with op.batch_alter_table("api_keys") as batch:
        if "role" not in columns:
            batch.add_column(sa.Column("role", sa.String(), nullable=False, server_default="analyst"))
        if "scopes" not in columns:
            batch.add_column(sa.Column("scopes", sa.String(), nullable=False, server_default="read,write"))
    keys = sa.table(
        "api_keys",
        sa.column("id", sa.String),
        sa.column("roles", sa.JSON),
        sa.column("role", sa.String),
        sa.column("scopes", sa.String),
    )
    for key_id, roles in bind.execute(sa.select(keys.c.id, keys.c.roles)).all():
        held = _listed(roles)
        if "admin" in held:
            bind.execute(keys.update().where(keys.c.id == key_id).values(role="admin", scopes="read,write,admin"))
        elif "analyst" not in held:
            # A key that could not write was an analyst key with the read scope alone.
            bind.execute(keys.update().where(keys.c.id == key_id).values(scopes="read"))

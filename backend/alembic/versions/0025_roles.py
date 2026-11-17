"""users.roles, api_keys.roles: additive role tags instead of one role per account

An account had one role (``admin`` or ``analyst``) and an API key a role plus
scopes. Both now hold a list of roles (``app/core/permissions.py``), filled
here from what they had:

- ``admin`` becomes ``["admin"]``, ``analyst`` becomes ``["analyst"]``;
- an analyst key without the ``write`` scope becomes ``["viewer"]``.

The old ``role`` (and ``scopes``) columns stay, filled, so a downgrade finds
them; the code no longer reads them. ``users.session_epoch`` counts the
changes of an account's roles.

Revision ID: 0025_roles
Revises: 0024_mailboxes
Create Date: 2026-11-17
"""

from __future__ import annotations

import json

import sqlalchemy as sa

from alembic import op

revision = "0025_roles"
down_revision = "0024_mailboxes"
branch_labels = None
depends_on = None


def _columns(table: str) -> set[str]:
    return {c["name"] for c in sa.inspect(op.get_bind()).get_columns(table)}


def _roles(role: str | None, scopes: str | None = None) -> list[str]:
    """As ``permissions.roles_from_legacy``, kept here so the migration does
    not change when the application does."""
    if role == "admin":
        return ["admin"]
    if scopes is not None and "write" not in {s.strip() for s in scopes.split(",")}:
        return ["viewer"]
    return ["analyst"]


def _empty(value) -> bool:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return True
    return not value


def upgrade() -> None:
    # The baseline creates the schema from the models: on a new database the
    # columns exist already, and each is added only where it is missing.
    bind = op.get_bind()

    columns = _columns("users")
    with op.batch_alter_table("users") as batch:
        if "roles" not in columns:
            batch.add_column(sa.Column("roles", sa.JSON(), nullable=False, server_default=sa.text("'[]'")))
        if "session_epoch" not in columns:
            batch.add_column(sa.Column("session_epoch", sa.Integer(), nullable=False, server_default="0"))

    columns = _columns("api_keys")
    if "roles" not in columns:
        with op.batch_alter_table("api_keys") as batch:
            batch.add_column(sa.Column("roles", sa.JSON(), nullable=False, server_default=sa.text("'[]'")))

    # Fill the accounts and keys that have no roles yet (a second run finds none).
    users = sa.table("users", sa.column("id", sa.String), sa.column("role", sa.String), sa.column("roles", sa.JSON))
    for user_id, role, roles in bind.execute(sa.select(users.c.id, users.c.role, users.c.roles)).all():
        if _empty(roles):
            bind.execute(users.update().where(users.c.id == user_id).values(roles=_roles(role)))

    keys = sa.table(
        "api_keys",
        sa.column("id", sa.String),
        sa.column("role", sa.String),
        sa.column("scopes", sa.String),
        sa.column("roles", sa.JSON),
    )
    for key_id, role, scopes, roles in bind.execute(
        sa.select(keys.c.id, keys.c.role, keys.c.scopes, keys.c.roles)
    ).all():
        if _empty(roles):
            bind.execute(keys.update().where(keys.c.id == key_id).values(roles=_roles(role, scopes or "")))


def downgrade() -> None:
    with op.batch_alter_table("api_keys") as batch:
        batch.drop_column("roles")
    with op.batch_alter_table("users") as batch:
        batch.drop_column("session_epoch")
        batch.drop_column("roles")

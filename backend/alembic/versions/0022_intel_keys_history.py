"""threat intelligence: several keys per provider, raw answers, a short history

- ``integration_keys`` was keyed by provider (one key each). Each key now has
  its own id, an optional label, a status and a count of refusals, so a
  provider can have several keys that lookups rotate over. Existing keys are
  kept.
- ``ioc_enrichment.raw`` keeps the provider's own answer (JSON download).
- ``ioc_enrichment_history`` keeps the verdict of the last few checks.

Revision ID: 0022_intel_keys_history
Revises: 0021_user_account_state
Create Date: 2026-11-12
"""

from __future__ import annotations

import uuid

import sqlalchemy as sa

from alembic import op

revision = "0022_intel_keys_history"
down_revision = "0021_user_account_state"
branch_labels = None
depends_on = None


def _new_table(name: str) -> sa.Table:
    return op.create_table(
        name,
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("provider", sa.String(), nullable=False),
        sa.Column("secret", sa.Text(), nullable=False),
        sa.Column("hint", sa.String(), nullable=False, server_default=""),
        sa.Column("label", sa.String(), nullable=False, server_default=""),
        sa.Column("status", sa.String(), nullable=False, server_default="ok"),
        sa.Column("error", sa.String(), nullable=True),
        sa.Column("failures", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("updated_at", sa.String(), nullable=False),
        sa.Column("updated_by", sa.String(), nullable=False, server_default=""),
    )


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())
    if "ioc_enrichment" in tables and "raw" not in {c["name"] for c in inspector.get_columns("ioc_enrichment")}:
        with op.batch_alter_table("ioc_enrichment") as batch:
            batch.add_column(sa.Column("raw", sa.JSON(), nullable=True))
    if "ioc_enrichment_history" not in tables:
        op.create_table(
            "ioc_enrichment_history",
            sa.Column("id", sa.String(), primary_key=True),
            sa.Column("type", sa.String(), nullable=False),
            sa.Column("value", sa.String(), nullable=False),
            sa.Column("provider", sa.String(), nullable=False),
            sa.Column("verdict", sa.String(), nullable=False, server_default="unknown"),
            sa.Column("summary", sa.String(), nullable=False, server_default=""),
            sa.Column("checked_at", sa.String(), nullable=False),
        )
        op.create_index("ix_ioc_enrichment_history_value", "ioc_enrichment_history", ["value", "type"])
    _keys_upgrade(bind, inspector, tables)


def _keys_upgrade(bind, inspector, tables: set[str]) -> None:
    if "integration_keys" not in tables:
        _new_table("integration_keys")
        op.create_index("ix_integration_keys_provider", "integration_keys", ["provider"])
        return
    if "id" in {c["name"] for c in inspector.get_columns("integration_keys")}:
        return
    rows = bind.execute(sa.text("SELECT provider, secret, hint, updated_at, updated_by FROM integration_keys")).all()
    op.drop_table("integration_keys")
    table = _new_table("integration_keys")
    op.create_index("ix_integration_keys_provider", "integration_keys", ["provider"])
    if rows:
        op.bulk_insert(
            table,
            [
                {
                    "id": uuid.uuid4().hex,
                    "provider": provider,
                    "secret": secret,
                    "hint": hint or "",
                    "label": "",
                    "status": "ok",
                    "error": None,
                    "failures": 0,
                    "updated_at": updated_at,
                    "updated_by": updated_by or "",
                }
                for provider, secret, hint, updated_at, updated_by in rows
            ],
        )


def downgrade() -> None:
    """Back to one key per provider: the first working key of each is kept."""
    bind = op.get_bind()
    op.drop_index("ix_ioc_enrichment_history_value", table_name="ioc_enrichment_history")
    op.drop_table("ioc_enrichment_history")
    with op.batch_alter_table("ioc_enrichment") as batch:
        batch.drop_column("raw")
    rows = bind.execute(
        sa.text(
            "SELECT provider, secret, hint, updated_at, updated_by FROM integration_keys"
            " ORDER BY CASE status WHEN 'ok' THEN 0 ELSE 1 END, updated_at"
        )
    ).all()
    op.drop_index("ix_integration_keys_provider", table_name="integration_keys")
    op.drop_table("integration_keys")
    table = op.create_table(
        "integration_keys",
        sa.Column("provider", sa.String(), primary_key=True),
        sa.Column("secret", sa.Text(), nullable=False),
        sa.Column("hint", sa.String(), nullable=False, server_default=""),
        sa.Column("updated_at", sa.String(), nullable=False),
        sa.Column("updated_by", sa.String(), nullable=False, server_default=""),
    )
    first: dict[str, dict] = {}
    for provider, secret, hint, updated_at, updated_by in rows:
        first.setdefault(
            provider,
            {"provider": provider, "secret": secret, "hint": hint, "updated_at": updated_at, "updated_by": updated_by},
        )
    if first:
        op.bulk_insert(table, list(first.values()))

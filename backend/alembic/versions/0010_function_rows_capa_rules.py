"""sample_functions and capa_rules tables

- ``sample_functions``: one row per function of a disassembled sample, with
  its control-flow graph and pseudo-C, moved out of the ``cfgs`` and
  ``decompiled`` JSON columns of ``sample_code`` (tens of megabytes on large
  binaries, read in full to open one function). Existing data is copied.
- ``capa_rules``: capa rules added by admins.

Revision ID: 0010_function_rows_capa_rules
Revises: 0009_sample_capa
Create Date: 2026-11-10
"""

from __future__ import annotations

import json

import sqlalchemy as sa

from alembic import op

revision = "0010_function_rows_capa_rules"
down_revision = "0009_sample_capa"
branch_labels = None
depends_on = None

FUNCTIONS = sa.table(
    "sample_functions",
    sa.column("sha256", sa.String),
    sa.column("addr", sa.BigInteger),
    sa.column("cfg", sa.JSON(none_as_null=True)),
    sa.column("decompiled", sa.JSON(none_as_null=True)),
)


def _json(value):
    """A JSON column value as Python (SQLite hands back text)."""
    if isinstance(value, (str, bytes)):
        return json.loads(value or "{}")
    return value or {}


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())
    if "sample_functions" not in tables:
        op.create_table(
            "sample_functions",
            sa.Column("sha256", sa.String(64), primary_key=True),
            sa.Column("addr", sa.BigInteger(), primary_key=True, autoincrement=False),
            sa.Column("cfg", sa.JSON(), nullable=True),
            sa.Column("decompiled", sa.JSON(), nullable=True),
        )
    columns = {c["name"] for c in inspector.get_columns("sample_code")} if "sample_code" in tables else set()
    # Either may be missing: a fresh database gets the current schema from the
    # baseline, then 0007 adds `decompiled` back.
    legacy = [name for name in ("cfgs", "decompiled") if name in columns]
    if legacy:
        selected = ", ".join(legacy)
        digests = [r[0] for r in bind.execute(sa.text("SELECT sha256 FROM sample_code")).fetchall()]
        for sha256 in digests:  # one sample at a time: each can hold tens of megabytes
            values = bind.execute(
                sa.text(f"SELECT {selected} FROM sample_code WHERE sha256 = :sha256"),  # noqa: S608 - fixed names
                {"sha256": sha256},
            ).one()
            found = {name: _json(value) for name, value in zip(legacy, values, strict=True)}
            cfgs, decompiled = found.get("cfgs", {}), found.get("decompiled", {})
            addrs = {int(a) for a in cfgs} | {int(a) for a in decompiled}
            if addrs:
                op.bulk_insert(
                    FUNCTIONS,
                    [
                        {"sha256": sha256, "addr": a, "cfg": cfgs.get(str(a)), "decompiled": decompiled.get(str(a))}
                        for a in sorted(addrs)
                    ],
                )
        with op.batch_alter_table("sample_code") as batch:
            for name in legacy:
                batch.drop_column(name)
    if "capa_rules" not in tables:
        op.create_table(
            "capa_rules",
            sa.Column("id", sa.String(32), primary_key=True),
            sa.Column("name", sa.String(), nullable=False),
            sa.Column("namespace", sa.String(), nullable=False, server_default=""),
            sa.Column("scope", sa.String(), nullable=False, server_default=""),
            sa.Column("source", sa.Text(), nullable=False),
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("created_at", sa.String(), nullable=False),
            sa.Column("created_by", sa.String(), nullable=False, server_default=""),
            sa.Column("updated_at", sa.String(), nullable=False, server_default=""),
        )


def downgrade() -> None:
    op.drop_table("capa_rules")
    with op.batch_alter_table("sample_code") as batch:
        batch.add_column(sa.Column("cfgs", sa.JSON(), nullable=False, server_default="{}"))
        batch.add_column(sa.Column("decompiled", sa.JSON(), nullable=False, server_default="{}"))
    bind = op.get_bind()
    rows = bind.execute(sa.text("SELECT sha256, addr, cfg, decompiled FROM sample_functions")).fetchall()
    per_sample: dict[str, tuple[dict, dict]] = {}
    for sha256, addr, cfg, decompiled in rows:
        cfgs, pseudo = per_sample.setdefault(sha256, ({}, {}))
        if cfg is not None:
            cfgs[str(addr)] = _json(cfg)
        if decompiled is not None:
            pseudo[str(addr)] = _json(decompiled)
    for sha256, (cfgs, pseudo) in per_sample.items():
        bind.execute(
            sa.text("UPDATE sample_code SET cfgs = :cfgs, decompiled = :decompiled WHERE sha256 = :sha256"),
            {"cfgs": json.dumps(cfgs), "decompiled": json.dumps(pseudo), "sha256": sha256},
        )
    op.drop_table("sample_functions")

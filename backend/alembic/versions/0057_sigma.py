"""Sigma detection on host evidence

Release 7.0. Host evidence is read against Sigma rules (``app/sigma``):

- ``evidence_detections``: a rule matches a record once (unique on the record and the rule);
- ``sigma_rules``: ``name`` (what a correlation rule names the rules it counts by), ``engine`` (the version
  of the worker's evaluator that last checked the rule; empty: never checked) and ``original`` (the text of
  the pack, for a rule of a pack a person changed), and an index on ``pack``;
- the suspicious keywords stop being a setting. The entries a person wrote or changed (those that are not
  what Nik shipped) become Sigma rules written here, on the records of browsers, stored as not checked: the
  server checks them when the forensics worker answers. The list ``suspicious_keywords`` and the key
  ``keywords`` of the settings go.

Idempotent: each column and index is created only where missing, and the keywords are moved once (a second
run finds none).

Downgrade removes the columns and the index; the rules made out of keywords stay (they are rules, and
nothing reads the keywords any more).

Revision ID: 0057_sigma
Revises: 0056_evidence
Create Date: 2026-11-25
"""

from __future__ import annotations

import logging

import sqlalchemy as sa

from alembic import op

revision = "0057_sigma"
down_revision = "0056_evidence"
branch_labels = None
depends_on = None

log = logging.getLogger("alembic.runtime.migration")

_UNIQUE = "uq_evidence_detections_record_rule"
_PACK = "ix_sigma_rules_pack"
_COLUMNS = {
    "name": lambda: sa.Column("name", sa.String(200), nullable=False, server_default=""),
    "engine": lambda: sa.Column("engine", sa.String(20), nullable=False, server_default=""),
    "original": lambda: sa.Column("original", sa.Text(), nullable=True),
}
LIST = "suspicious_keywords"


def _indexes(bind, table: str) -> set[str]:
    return {index["name"] for index in sa.inspect(bind).get_indexes(table)}


def _move_keywords(bind, tables: set[str]) -> None:
    """The keywords a person wrote or changed become Sigma rules; the list and the setting go."""
    from app.core.db import Base
    from app.core.security import now_iso
    from app.defaults import DEFAULT_SUSPICIOUS_KEYWORDS
    from app.sigma import keywords

    if not {"settings", "sigma_rules"} <= tables:
        return
    settings = Base.metadata.tables["settings"]
    rules = Base.metadata.tables["sigma_rules"]
    row = bind.execute(sa.select(settings.c.doc).where(settings.c.id == 1)).first()
    doc = dict(row[0]) if row is not None and isinstance(row[0], dict) else {}
    held = doc.get("keywords")
    entries: list = []
    name = LIST
    if isinstance(held, list):
        entries = held
    elif isinstance(held, dict) and held.get("list"):
        name = str(held["list"])
    if not isinstance(held, list) and {"lists", "list_items"} <= tables:
        lists, items = Base.metadata.tables["lists"], Base.metadata.tables["list_items"]
        found = bind.execute(sa.select(lists.c.id).where(lists.c.name == name)).first()
        if found is not None:
            for key, value in bind.execute(
                sa.select(items.c.key, items.c.value).where(items.c.list_id == found[0]).order_by(items.c.position)
            ):
                entries.append({"id": key, **(value if isinstance(value, dict) else {})})
    now = now_iso()
    moved = [keywords.row_of(entry, now) for entry in keywords.changed(entries, DEFAULT_SUSPICIOUS_KEYWORDS)]
    if moved:
        bind.execute(sa.insert(rules), moved)
        log.info("%d suspicious keywords became Sigma rules (not checked yet)", len(moved))
    if {"lists", "list_items"} <= tables:
        lists, items = Base.metadata.tables["lists"], Base.metadata.tables["list_items"]
        found = bind.execute(sa.select(lists.c.id).where(lists.c.name == LIST)).first()
        if found is not None:
            bind.execute(sa.delete(items).where(items.c.list_id == found[0]))
            bind.execute(sa.delete(lists).where(lists.c.id == found[0]))
    if "keywords" in doc:
        doc.pop("keywords")
        bind.execute(sa.update(settings).where(settings.c.id == 1).values(doc=doc))


def upgrade() -> None:
    bind = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names())
    if "evidence_detections" in tables:
        # A rule and a record say it once: what a file read twice may have written twice goes.
        bind.exec_driver_sql(
            "DELETE FROM evidence_detections WHERE id NOT IN "
            "(SELECT MIN(id) FROM evidence_detections GROUP BY record_id, rule_id)"
        )
        if _UNIQUE not in _indexes(bind, "evidence_detections"):
            op.create_index(_UNIQUE, "evidence_detections", ["record_id", "rule_id"], unique=True)
    if "sigma_rules" in tables:
        existing = {column["name"] for column in sa.inspect(bind).get_columns("sigma_rules")}
        for name, make in _COLUMNS.items():
            if name not in existing:
                op.add_column("sigma_rules", make())
        if _PACK not in _indexes(bind, "sigma_rules"):
            op.create_index(_PACK, "sigma_rules", ["pack"])
    _move_keywords(bind, tables)


def downgrade() -> None:
    bind = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names())
    if "sigma_rules" in tables:
        if _PACK in _indexes(bind, "sigma_rules"):
            op.drop_index(_PACK, table_name="sigma_rules")
        existing = {column["name"] for column in sa.inspect(bind).get_columns("sigma_rules")}
        wanted = [name for name in _COLUMNS if name in existing]
        if wanted:
            with op.batch_alter_table("sigma_rules") as batch:
                for name in wanted:
                    batch.drop_column(name)
    if "evidence_detections" in tables and _UNIQUE in _indexes(bind, "evidence_detections"):
        op.drop_index(_UNIQUE, table_name="evidence_detections")

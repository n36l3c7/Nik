"""the audit log becomes a chain

Release 6.8. Every entry of the audit log gets a number, the hash of the
entry before it and its own (``app/auditlog``), and one row keeps the head of
the chain. The entries that are there are linked once, here, as they are
found: in the order of their time, without one of their fields being
touched. An entry is then added that says so (``audit.chain``), because the
chain can say nothing of what happened to them before this day.

Each entry is signed in the same pass (``mac``, ``key_id``) with the key of
the server (``app/auditlog/key.py``): the one derived from ``SECRET_KEY``
unless ``AUDIT_KEY`` is set. A fourth column, ``origin``, marks from now on the entries that come in a
file of content from another server; the ones that are there have none.

Idempotent: columns, index and table are added only where missing, and only
the entries that have no number yet are linked, after the ones that have.

Revision ID: 0051_audit_chain
Revises: 0049_two_factor
Create Date: 2026-11-20
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import sqlalchemy as sa

from alembic import op

revision = "0051_audit_chain"
down_revision = "0049_two_factor"
branch_labels = None
depends_on = None

_COLUMNS = {
    "seq": lambda: sa.Column("seq", sa.BigInteger(), nullable=True),
    "prev_hash": lambda: sa.Column("prev_hash", sa.String(64), nullable=True),
    "hash": lambda: sa.Column("hash", sa.String(64), nullable=True),
    "origin": lambda: sa.Column("origin", sa.String(20), nullable=True),
    "mac": lambda: sa.Column("mac", sa.String(64), nullable=True),
    "key_id": lambda: sa.Column("key_id", sa.String(40), nullable=True),
}
_INDEX = "ux_audit_log_seq"
_BATCH = 5000


def _link_what_is_there(bind) -> None:
    from app.auditlog import chain, key
    from app.auditlog.verifier import CHAINED, FIELDS, ZERO, entry_hash, sign

    key_id, secret = key.current()

    log = sa.table(
        "audit_log",
        *(sa.column(name) for name in (*FIELDS, "origin")),
        sa.column("seq"),
        sa.column("prev_hash"),
        sa.column("hash"),
        sa.column("mac"),
        sa.column("key_id"),
    )
    head = sa.table("audit_chain", sa.column("id"), sa.column("seq"), sa.column("hash"))
    last = bind.execute(
        sa.select(log.c.seq, log.c.hash).where(log.c.seq.isnot(None)).order_by(log.c.seq.desc()).limit(1)
    ).first()
    seq, held = (int(last[0]), str(last[1])) if last else (0, ZERO)
    fresh = last is None
    linked = 0
    change = (
        sa.update(log)
        .where(log.c.id == sa.bindparam("entry"))
        .values(
            seq=sa.bindparam("number"),
            prev_hash=sa.bindparam("before"),
            hash=sa.bindparam("hashed"),
            mac=sa.bindparam("signed"),
            key_id=key_id,
        )
    )
    while True:
        rows = (
            bind.execute(
                sa.select(*(log.c[name] for name in (*FIELDS, "origin")))
                .where(log.c.seq.is_(None))
                .order_by(log.c.at, log.c.id)
                .limit(_BATCH)
            )
            .mappings()
            .all()
        )
        if not rows:
            break
        values = []
        for row in rows:
            seq += 1
            hashed = entry_hash(seq, held, row)
            values.append(
                {"entry": row["id"], "number": seq, "before": held, "hashed": hashed, "signed": sign(secret, hashed)}
            )
            held = hashed
        bind.execute(change, values)
        linked += len(rows)
    if fresh and linked:
        # The first link the server itself answers for: what is before it is as found today.
        now = datetime.now(timezone.utc)
        entry = {
            "id": str(uuid.uuid4()),
            "at": now.isoformat(),
            "actor": chain.ACTOR,
            "action": CHAINED,
            "target": "audit log",
            "details": chain.chained_details(linked, seq, held, now.strftime("%Y-%m-%d")),
            "incident_id": None,
            "incident_name": None,
        }
        seq += 1
        hashed = entry_hash(seq, held, entry)
        bind.execute(
            sa.insert(log).values(
                **entry, seq=seq, prev_hash=held, hash=hashed, mac=sign(secret, hashed), key_id=key_id
            )
        )
        held = hashed
    if bind.execute(sa.select(head.c.id).where(head.c.id == 1)).first() is None:
        bind.execute(sa.insert(head).values(id=1, seq=seq, hash=held))
    else:
        bind.execute(sa.update(head).where(head.c.id == 1).values(seq=seq, hash=held))


def upgrade() -> None:
    from app.core.db import Base
    from app.core.models import AUDIT_CHAIN_TABLES

    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())
    for name in AUDIT_CHAIN_TABLES:
        if name not in tables:
            Base.metadata.tables[name].create(bind)
    if "audit_log" not in tables:
        return
    existing = {column["name"] for column in inspector.get_columns("audit_log")}
    for name, column in _COLUMNS.items():
        if name not in existing:
            op.add_column("audit_log", column())
    _link_what_is_there(bind)
    if _INDEX not in {index["name"] for index in sa.inspect(bind).get_indexes("audit_log")}:
        op.create_index(_INDEX, "audit_log", ["seq"], unique=True)


def downgrade() -> None:
    from app.core.models import AUDIT_CHAIN_TABLES

    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())
    if "audit_log" in tables:
        if _INDEX in {index["name"] for index in inspector.get_indexes("audit_log")}:
            op.drop_index(_INDEX, table_name="audit_log")
        existing = {column["name"] for column in inspector.get_columns("audit_log")}
        with op.batch_alter_table("audit_log") as batch:
            for name in _COLUMNS:
                if name in existing:
                    batch.drop_column(name)
    for name in AUDIT_CHAIN_TABLES:
        if name in tables:
            op.drop_table(name)

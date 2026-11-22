"""How the server chains its audit log, checks the chain, and removes old entries.

**Linking.** An entry is written as before, by whoever records it
(``audit.record`` or a row added to the session), without a number. It is
numbered and linked when its transaction commits: a listener on every
session flushes what is pending, takes the one row of ``audit_chain`` (the
head) with ``SELECT … FOR UPDATE``, gives the entries of the transaction the
next numbers in the order of their time, writes the hashes, moves the head,
and the commit follows at once. So:

- the order is strict. Two transactions cannot hold the head together; the
  second reads it only after the first committed, and a unique index on the
  number refuses a fork whatever else goes wrong;
- nothing waits on it for long, and nothing can deadlock on it: the head is
  the last lock a transaction takes, and it is held for the few statements
  before the commit, never while a handler works;
- a reader never sees a hole: an entry is visible with its number, or not at
  all, and number N is committed before anybody can take N + 1.

On SQLite (a development server, the tests) there is one writer at a time by
construction, and the same code runs without the lock.

An entry that reaches the table without going through a session of the
server (a restore writes one with plain SQL; a script might) has no number:
the next transaction that links entries links it too, and so does the
verification pass, which runs every few minutes: marked ``outside``.

**Signing.** In the same step each entry gets its signature: an HMAC of its
hash under a key that is not in the database (``key.py``), and the id of that
key. Somebody who can write to the database can compute the hashes of a
rewritten log again; they cannot make its signatures. So that this holds,
the server signs as its own only what its own transaction wrote: an entry it
finds without a number that this transaction did not write is linked and
signed with its ``origin`` set to ``outside`` (hashed, like the rest).
Otherwise taking the numbers away from a stretch of the log would be a way to
have the server sign whatever was put in it.

**Nothing edits or removes an entry**, with one exception that says so
itself: ``trim`` removes the oldest entries and writes an ``audit.trim``
entry that names how many, their numbers and the hash of the last one, so
that the chain still verifies from where it now starts. There is no database
trigger behind this: a trigger is an object the backups of 6.7 refuse to
carry, and the role the server connects with owns the table, so privileges
cannot hold it back either. What protects the log is the chain and the copy
outside it.

**Checking.** ``verify`` walks the chain and names the first thing that does
not hold (``verifier.py`` lists the names). It remembers how far it got, so
the pass of every few minutes only reads what is new; a full walk reads
everything and is always possible. The end of the log is held against every
head that is kept somewhere else: the head row, the file of heads in the
backup directory (``audit-heads.jsonl``, written at each good pass: outside
the database, on the server), the forwarding cursor, and a head given by
hand (the last checkpoint a syslog receiver got).

**What this cannot see.** Whoever can write to the database and to the
backup directory can remove the newest entries, or compute the whole chain
again from the point of a change, and leave everything here consistent. Only
a copy that left the server shows it: the syslog receiver, its checkpoints,
an export kept elsewhere.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import bindparam, delete, event, func, select, update
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.engine import Connection
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm.attributes import flag_modified, set_committed_value

from ..core import leases
from ..core.clock import iso_or_none as _iso
from ..core.clock import stamp as _stamp
from ..core.models import AuditChain, AuditEntry, Setting
from . import key as signing
from . import verifier
from .verifier import CHAINED, OUTSIDE, RESTORE, TRIM, ZERO

logger = logging.getLogger("nik.audit")

SETTINGS_ID = 42  # 40 the forwarding as set, 41 the forwarding as it stands (forward.py)
LEASE = "audit-verify"
VERIFY_EVERY = 300
FULL_EVERY = 86400
BATCH = 2000
HEADS_FILE = "audit-heads.jsonl"
HEADS_KEPT = 500
ACTOR = "nik"

_PENDING = "audit_entries_to_link"
_OWN = "audit_entries_written_here"
_T = AuditEntry.__table__
_H = AuditChain.__table__
_COLUMNS = (
    _T.c.id,
    _T.c.at,
    _T.c.actor,
    _T.c.action,
    _T.c.target,
    _T.c.details,
    _T.c.incident_id,
    _T.c.incident_name,
    _T.c.origin,
)
_started = False


# --------------------------------------------------------------------------- #
# Linking                                                                     #
# --------------------------------------------------------------------------- #
@event.listens_for(OrmSession, "before_flush")
def _note_entries(session: OrmSession, _context, _instances) -> None:
    mine = [row.id for row in session.new if isinstance(row, AuditEntry)]
    if mine:
        session.info[_PENDING] = True
        session.info.setdefault(_OWN, set()).update(mine)


@event.listens_for(OrmSession, "before_commit")
def _link_entries(session: OrmSession) -> None:
    if session.in_nested_transaction():
        return  # a savepoint: the entries are linked when the whole transaction commits
    session.flush()
    if session.info.pop(_PENDING, False):
        linked = link(session.connection(), session.info.pop(_OWN, set()))
        for entry_id, values in linked.items():
            row = session.identity_map.get(sa_inspect(AuditEntry).identity_key_from_primary_key((entry_id,)))
            if row is not None:
                for name, value in values.items():
                    set_committed_value(row, name, value)


@event.listens_for(OrmSession, "after_rollback")
def _forget_entries(session: OrmSession) -> None:
    # Only when the whole transaction went: what a savepoint rolls back leaves the rest to link.
    if not session.in_nested_transaction():
        session.info.pop(_PENDING, None)
        session.info.pop(_OWN, None)


def _head(conn: Connection) -> tuple[int, str]:
    """The head of the chain, locked until this transaction ends."""
    wanted = select(_H.c.seq, _H.c.hash).where(_H.c.id == 1).with_for_update()
    found = conn.execute(wanted).first()
    if found is None:
        if conn.dialect.name == "postgresql":
            from sqlalchemy.dialects.postgresql import insert
        else:
            from sqlalchemy.dialects.sqlite import insert
        conn.execute(insert(_H).values(id=1, seq=0, hash=ZERO).on_conflict_do_nothing())
        found = conn.execute(wanted).one()
        # A head that was lost: the chain goes on from its last entry.
        last = conn.execute(select(_T.c.seq, _T.c.hash).where(_T.c.seq.isnot(None)).order_by(_T.c.seq.desc())).first()
        if last is not None:
            return int(last[0]), str(last[1])
    return int(found[0]), str(found[1])


def link(conn: Connection, own: set[str] | frozenset[str] = frozenset()) -> dict[str, dict[str, Any]]:
    """Number, link and sign every entry this transaction can see that has no number yet, in
    the order of their time. ``own`` are the ids of the entries this transaction wrote itself:
    any other is marked as written outside the server. Returns what each got. The caller's
    transaction commits it."""
    seq, held = _head(conn)
    waiting = conn.execute(select(*_COLUMNS).where(_T.c.seq.is_(None)).order_by(_T.c.at, _T.c.id)).mappings().all()
    if not waiting:
        return {}
    key_id, key = signing.current()
    linked: dict[str, dict[str, Any]] = {}
    for found in waiting:
        entry = dict(found) if found["id"] in own else {**found, "origin": OUTSIDE}
        seq += 1
        hashed = verifier.entry_hash(seq, held, entry)
        linked[entry["id"]] = {
            "seq": seq,
            "prev_hash": held,
            "hash": hashed,
            "origin": entry["origin"],
            "mac": verifier.sign(key, hashed),
            "key_id": key_id,
        }
        held = hashed
    conn.execute(
        update(_T)
        .where(_T.c.id == bindparam("entry"), _T.c.seq.is_(None))
        .values(
            seq=bindparam("number"),
            prev_hash=bindparam("before"),
            hash=bindparam("hashed"),
            origin=bindparam("from_where"),
            mac=bindparam("signed"),
            key_id=bindparam("signed_by"),
        ),
        [
            {
                "entry": entry_id,
                "number": values["seq"],
                "before": values["prev_hash"],
                "hashed": values["hash"],
                "from_where": values["origin"],
                "signed": values["mac"],
                "signed_by": values["key_id"],
            }
            for entry_id, values in linked.items()
        ],
    )
    conn.execute(update(_H).where(_H.c.id == 1).values(seq=seq, hash=held))
    return linked


def link_strays() -> int:
    """Link the entries that reached the table from outside a session of the server."""
    from ..core.db import engine

    with engine.begin() as conn:
        if conn.execute(select(_T.c.id).where(_T.c.seq.is_(None)).limit(1)).first() is None:
            return 0
        return len(link(conn))


# --------------------------------------------------------------------------- #
# What is kept                                                                #
# --------------------------------------------------------------------------- #
def _held(db: OrmSession) -> dict[str, Any]:
    row = db.get(Setting, SETTINGS_ID)
    return dict((row.doc if row else None) or {})


def _keep(db: OrmSession, doc: dict[str, Any]) -> None:
    row = db.get(Setting, SETTINGS_ID)
    if row is None:
        db.add(Setting(id=SETTINGS_ID, doc=doc))
        return
    row.doc = doc
    flag_modified(row, "doc")


def head(db: OrmSession) -> tuple[int, str]:
    """The number and the hash of the last entry linked (0 and zeros for an empty chain)."""
    row = db.execute(select(_H.c.seq, _H.c.hash).where(_H.c.id == 1)).first()
    return (int(row[0]), str(row[1])) if row else (0, ZERO)


def _hash_of(db: OrmSession, seq: int) -> str | None:
    return db.execute(select(_T.c.hash).where(_T.c.seq == seq)).scalar()


def _number_of(db: OrmSession, hashed: str) -> int | None:
    return db.execute(select(_T.c.seq).where(_T.c.hash == hashed).order_by(_T.c.seq).limit(1)).scalar()


def _entry(row) -> dict[str, Any]:
    return {**{column.name: row[column.name] for column in _COLUMNS}, "seq": row["seq"], "prev": row["prev_hash"],
            "hash": row["hash"], "mac": row["mac"], "key_id": row["key_id"]}  # fmt: skip


# --------------------------------------------------------------------------- #
# The heads kept outside the database                                         #
# --------------------------------------------------------------------------- #
def heads_path() -> Path:
    from ..core.config import settings

    return Path(settings.BACKUP_DIR) / HEADS_FILE


def write_head(seq: int, hashed: str, count: int, now: float) -> bool:
    """Add the head to the file of heads (the backup directory: on the server, outside the
    database). Says whether it was written: the directory may not be there, or not writable."""
    path = heads_path()
    line = json.dumps({"seq": seq, "hash": hashed, "count": count, "at": now}, separators=(",", ":"))
    try:
        if not path.parent.is_dir():
            return False
        lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
        if lines and (json.loads(lines[-1]).get("seq"), json.loads(lines[-1]).get("hash")) == (seq, hashed):
            return True
        if len(lines) >= 2 * HEADS_KEPT:
            path.write_text("\n".join([*lines[-HEADS_KEPT:], line]) + "\n", encoding="utf-8")
        else:
            with open(path, "a", encoding="utf-8") as target:
                target.write(line + "\n")
        return True
    except (OSError, ValueError):
        return False


def file_head(since: float = 0.0) -> dict[str, Any] | None:
    """The highest head of the file that was written after ``since``, or None."""
    try:
        lines = heads_path().read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    best: dict[str, Any] | None = None
    for line in lines:
        try:
            found = json.loads(line)
        except ValueError:
            continue
        if not isinstance(found, dict) or not isinstance(found.get("seq"), int):
            continue
        if float(found.get("at") or 0) > since and (best is None or found["seq"] >= best["seq"]):
            best = found
    return best


# --------------------------------------------------------------------------- #
# Checking                                                                    #
# --------------------------------------------------------------------------- #
def _walk(db: OrmSession, upto: int, after: tuple[int, str] | None) -> verifier.Walk:
    walk = verifier.Walk(after=after, locate=lambda hashed: _number_of(db, hashed), keys=signing.known())
    last = after[0] if after else 0
    while walk.problem is None:
        rows = (
            db.execute(
                select(*_COLUMNS, _T.c.seq, _T.c.prev_hash, _T.c.hash, _T.c.mac, _T.c.key_id)
                .where(_T.c.seq > last, _T.c.seq <= upto)
                .order_by(_T.c.seq)
                .limit(BATCH)
            )
            .mappings()
            .all()
        )
        if not rows:
            break
        for row in rows:
            if walk.feed(_entry(row)) is not None:
                break
        last = int(rows[-1]["seq"])
    if after is None:
        walk.finish()
    return walk


def _examine(
    db: OrmSession, full: bool, outside: tuple[int, str] | None, state: dict[str, Any]
) -> tuple[verifier.Walk, verifier.Problem | None, bool]:
    # The head and the end of the table as one statement sees them: an entry linked while the
    # walk reads is past both, and is not taken for an entry past the head.
    ends = db.execute(
        select(
            select(_H.c.seq).where(_H.c.id == 1).scalar_subquery(),
            select(_H.c.hash).where(_H.c.id == 1).scalar_subquery(),
            select(func.max(_T.c.seq)).scalar_subquery(),
        )
    ).one()
    seq, held, last = int(ends[0] or 0), str(ends[1] or ZERO), int(ends[2] or 0)
    after = None
    remembered = state.get("verified") or {}
    if not full and isinstance(remembered.get("seq"), int) and 0 < remembered["seq"] <= seq:
        # The entry the last pass ended on must still be the one it was.
        if _hash_of(db, remembered["seq"]) == remembered.get("hash"):
            after = (remembered["seq"], str(remembered["hash"]))
    walk = _walk(db, seq, after)
    problem = walk.problem
    if problem is None:
        if walk.last_seq < seq:
            gone = seq - walk.last_seq
            problem = verifier.Problem(
                "cut",
                walk.last_seq + 1,
                f"The head of the chain is entry {seq} and the log ends at entry {walk.last_seq}: the newest "
                f"{gone} {'entry was' if gone == 1 else 'entries were'} removed",
            )
        elif last > seq:
            problem = verifier.Problem(
                "relinked", seq + 1, f"The log holds entries past the head of the chain (entry {seq})"
            )
        elif seq and walk.count and walk.last_hash != held:
            problem = verifier.Problem(
                "rewritten", seq, f"Entry {seq} has another hash than the head of the chain: the log was rewritten"
            )
    if problem is None:
        # What knows the head from outside the table. A restore puts the log back to an earlier
        # head on purpose, and says so with an entry: the heads noted before it are not held against it.
        restored = db.execute(select(func.max(_T.c.at)).where(_T.c.action == RESTORE)).scalar()
        witnesses: list[tuple[int, str, str]] = []
        noted = file_head(since=_stamp(restored))
        if noted is not None:
            witnesses.append((noted["seq"], str(noted.get("hash") or ""), "The file of heads in the backup directory"))
        from . import forward

        sent = forward.cursor(db)
        if sent is not None:
            witnesses.append((sent[0], sent[1], "The forwarding to syslog"))
        if outside is not None:
            witnesses.append((outside[0], outside[1], "The head given"))
        for number, hashed, where in witnesses:
            problem = verifier.against_head(walk, lambda wanted: _hash_of(db, wanted), number, hashed, where)
            if problem is not None:
                break
    return walk, problem, after is None


def verify(
    db: OrmSession, *, full: bool = False, outside: tuple[int, str] | None = None, now: float | None = None
) -> dict[str, Any]:
    """Walk the chain and write down what was found (the caller commits, and comes with nothing
    pending: a walk that finds something looks a second time from a new transaction).

    ``full`` reads every entry; otherwise the walk starts after the entry the
    last good pass ended on. ``outside`` is a head noted elsewhere, as
    ``(number, hash)``. Returns the state as ``out`` gives it.
    """
    now = time.time() if now is None else now
    clock = time.monotonic()
    state = _held(db)
    # An entry being removed or added while the walk reads can look like a break: looked at twice.
    for _attempt in range(2):
        walk, problem, whole = _examine(db, full, outside, state)
        if problem is None:
            break
        db.rollback()
    count = db.execute(select(func.count()).select_from(_T)).scalar() or 0
    state["checkedAt"] = now
    state["count"] = count
    if problem is None:
        state["verified"] = {"seq": walk.last_seq, "hash": walk.last_hash, "at": now, "first": walk.first_seq}
        state["problem"] = None
        state["outside"] = bool(write_head(walk.last_seq, walk.last_hash, count, now)) if walk.last_seq else False
        # The entries whose key this server can no longer make: counted, not a problem. A walk of
        # what is new adds to what the last full walk counted.
        before = {} if whole else dict(state.get("unchecked") or {})
        for name, number in walk.unchecked.items():
            before[name] = int(before.get(name) or 0) + number
        state["unchecked"] = before
        if whole:
            state["full"] = {"at": now, "entries": walk.count, "seconds": round(time.monotonic() - clock, 3)}
    else:
        before = state.get("problem") or {}
        same = before.get("kind") == problem.kind and before.get("seq") == problem.seq
        state["problem"] = {**problem.out(), "since": before.get("since") if same else now}
        logger.warning("The audit log does not verify: %s", problem.text)
    _keep(db, state)
    return state


def check(now: float | None = None, holder: str | None = None) -> dict[str, Any] | None:
    """One pass of the loop, when this process holds its lease: link what has no number, walk
    what is new (everything once a day), write down. Returns the state, or None without the lease."""
    from ..backups import runner
    from ..core.db import SessionLocal

    clock = time.time() if now is None else now
    with SessionLocal() as db:
        if not runner.acquire(db, holder or runner.HOLDER, now, LEASE):
            return None
    link_strays()
    with SessionLocal() as db:
        state = _held(db)
        whole = clock - float((state.get("full") or {}).get("at") or 0) >= FULL_EVERY
        found = verify(db, full=whole, now=clock)
        db.commit()
    return found


def _loop() -> None:
    leases.wait(25)  # let the server start
    while not leases.stopping():
        try:
            check()
        except Exception:  # noqa: BLE001 - the loop must survive a bad pass
            logger.exception("The check of the audit log failed")
        leases.wait(VERIFY_EVERY)


def start() -> None:
    """Start the loop in this process (the API process; one of them checks at a time)."""
    global _started
    if _started:
        return
    _started = True
    import threading

    threading.Thread(target=_loop, name="nik-audit-verify", daemon=True).start()


def out(db: OrmSession) -> dict[str, Any]:
    """Where the chain stands, for the screen and the health page."""
    state = _held(db)
    seq, held = head(db)
    verified = state.get("verified") or {}
    problem = state.get("problem") or None
    whole = state.get("full") or {}
    waiting = db.execute(select(func.count()).select_from(_T).where(_T.c.seq.is_(None))).scalar() or 0
    noted = file_head()
    return {
        "head": {"seq": seq, "hash": held},
        "entries": db.execute(select(func.count()).select_from(_T)).scalar() or 0,
        "unlinked": waiting,
        "verified": (
            {"seq": verified.get("seq"), "hash": verified.get("hash"), "at": _iso(verified.get("at"))}
            if verified
            else None
        ),
        "problem": ({**problem, "since": _iso(problem.get("since"))} if problem else None),
        "checkedAt": _iso(state.get("checkedAt")),
        "fullWalk": (
            {"at": _iso(whole.get("at")), "entries": whole.get("entries"), "seconds": whole.get("seconds")}
            if whole
            else None
        ),
        # Whether the last good pass could note the head outside the database, and the last one noted.
        "headFile": ({"seq": noted["seq"], "hash": noted.get("hash"), "at": _iso(noted.get("at"))} if noted else None),
        "everySeconds": VERIFY_EVERY,
        "guard": False,
        # The key that signs entries now (its id, never the key), and the entries of the last walks
        # whose key this server can no longer make, by key id: they cannot be checked.
        "keyId": signing.current()[0],
        # Entries the server linked without having written them itself (a restore leaves one).
        "outside": db.execute(select(func.count()).select_from(_T).where(_T.c.origin == OUTSIDE)).scalar() or 0,
        "unchecked": dict(state.get("unchecked") or {}),
    }


# --------------------------------------------------------------------------- #
# Removing old entries                                                        #
# --------------------------------------------------------------------------- #
def trim(db: OrmSession, actor: str, *, older_than_days: int | None = None, now: float | None = None) -> int:
    """Remove the oldest entries and say so in the chain (the caller commits).

    With ``older_than_days``, the entries from the start of the log up to the
    first one that is not that old; without, everything that is linked. What
    was not forwarded yet, when forwarding is on, stays: an entry never
    leaves the table before it left the server. Returns how many went.
    """
    from . import forward

    now = time.time() if now is None else now
    # What this transaction wrote so far is linked first: it comes before the entry of the trim.
    db.flush()
    link(db.connection(), db.info.get(_OWN) or frozenset())
    last, _held_hash = head(db)
    through = last
    if older_than_days is not None:
        cutoff = datetime.fromtimestamp(now - older_than_days * 86400, timezone.utc).isoformat()
        young = db.execute(select(func.min(_T.c.seq)).where(_T.c.seq.isnot(None), _T.c.at >= cutoff)).scalar()
        through = min(through, (young - 1) if young else through)
        rule = f"by the rule that removes entries older than {older_than_days} days"
    else:
        rule = "by clearing the log"
    waiting = forward.unsent_from(db)
    if waiting is not None:
        through = min(through, waiting - 1)
    first = db.execute(select(func.min(_T.c.seq)).where(_T.c.seq.isnot(None))).scalar()
    if not first or through < first:
        return 0
    upto = _hash_of(db, through)
    count = db.execute(select(func.count()).select_from(_T).where(_T.c.seq >= first, _T.c.seq <= through)).scalar()
    if not count or not upto:
        return 0
    db.execute(delete(_T).where(_T.c.seq >= first, _T.c.seq <= through))
    db.add(
        AuditEntry(
            id=str(uuid.uuid4()),
            at=datetime.fromtimestamp(now, timezone.utc).isoformat(),
            actor=actor,
            action=TRIM,
            target="audit log",
            details=verifier.trim_details(count, first, through, upto, rule),
        )
    )
    # The walk that remembered an entry which is gone starts again from the new start.
    state = _held(db)
    if ((state.get("verified") or {}).get("seq") or 0) <= through:
        state.pop("verified", None)
        _keep(db, state)
    return int(count)


# --------------------------------------------------------------------------- #
# The entries a migration or a restore leaves                                 #
# --------------------------------------------------------------------------- #
def chained_details(count: int, last: int, hashed: str, day: str) -> str:
    """The sentence of the entry that follows the ones written before the log was chained."""
    return (
        f"The {count} entries before this one were written before the audit log was chained (Nik before 6.8). "
        f"They were linked on {day} as they were found, sequence 1 to {last}, up to hash {hashed}: "
        "the chain says nothing of what happened to them before that day"
    )


__all__ = ["ACTOR", "CHAINED", "RESTORE", "TRIM", "check", "head", "link", "link_strays", "out", "trim", "verify"]

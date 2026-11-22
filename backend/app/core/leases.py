"""Leases: what lets one process at a time run a loop that must run once.

A lease is a row of ``leases``: a name, who holds it, until when. A process
takes it, renews it while it works, and gives it back when it stops. Every
loop of the server that must not run twice holds one (the automation worker,
the backups and their copies, the watches, the verification and the
forwarding of the audit log, the conversion of the store, the look-ups).

**Taking** is one statement, an insert that becomes an update when the row is
there and is either ours or run out. It never fails: a lease another process
holds changes nothing and says so by the number of rows. (Until 6.9 the row
was inserted after an update that found nothing, and the insert of the loser
was an error of the database, written to its log every few seconds for what
is the normal state of a server with more than one process.)

**After a hard stop** (a kill, the power, a promotion to the standby) nobody
gives the lease back: it runs out by itself, ``seconds`` after its last
renewal, and the next process takes it. Nothing about a lease lives outside
its row, so the process that takes over may be on another host.

**At a clean stop** every lease this process took is given back at once
(``release_all``, called by the loops that are told to stop): the process that
starts next does not wait for them to run out. When the process itself ends
(``close``: the automation worker at the end of its loop, any process as it
exits) it is given none from then on: a loop that is still in the middle of a
pass (a file half sent to the second host) cannot take back, for a process
that is about to end, what was just given back.

**On a server that does not serve** no lease is given at all: a standby,
whose database cannot be written, and a server that was replaced by its
standby (``recovery/role.py``). Every loop takes a lease before it does
anything, so this one place is what keeps all of them still there: nothing
runs, and nothing fills the log with the refusals of a read-only database.
The loops go on by themselves once the server may serve. The two loops every
process runs without a lease (what playbooks ask about files and addresses:
rows claimed one by one) ask the same question first (``may_work``).

**Between two passes** a loop waits on the flag of the process (``wait``),
not on the clock alone: asked to stop, it starts no new pass.
"""

from __future__ import annotations

import atexit
import logging
import threading
import time

from sqlalchemy import delete, insert, or_, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as OrmSession

from .models import Lease

logger = logging.getLogger("nik.leases")

# What this process took and did not give back: (name, holder).
_held: set[tuple[str, str]] = set()
_lock = threading.Lock()
_registered = False
# Set when this process has given its leases back because it ends: it takes none after that.
_closed = False


def _upsert(db: OrmSession, name: str, holder: str, now: float, seconds: float) -> int | None:
    """The single statement, where the database has one; None where it has not."""
    dialect = db.get_bind().dialect.name
    if dialect == "postgresql":
        from sqlalchemy.dialects.postgresql import insert as upsert
    elif dialect == "sqlite":
        from sqlalchemy.dialects.sqlite import insert as upsert
    else:
        return None
    table = Lease.__table__
    statement = upsert(table).values(name=name, holder=holder, expires_at=now + seconds)
    statement = statement.on_conflict_do_update(
        index_elements=[table.c.name],
        set_={"holder": statement.excluded.holder, "expires_at": statement.excluded.expires_at},
        where=or_(table.c.holder == holder, table.c.expires_at < now),
    ).returning(table.c.name)
    # The row comes back when it was written, and nothing does when another process holds the
    # lease (the count of rows of an insert is not something every driver reports).
    return 1 if db.execute(statement).first() is not None else 0


def stop_flag() -> threading.Event:
    """What says that this process was asked to stop: one flag for every loop of the process (the
    automation worker sets it on a signal, the API when it shuts down)."""
    from ..automation import worker

    return worker._stopping


def stopping() -> bool:
    """Whether this process was asked to stop: a loop starts no new pass."""
    return stop_flag().is_set()


def wait(seconds: float) -> bool:
    """The pause of a loop between two passes. It ends at once when the process is asked to stop,
    and says so."""
    return bool(stop_flag().wait(seconds))


def may_work(db: OrmSession) -> bool:
    """Whether a loop of this process may do anything now: not once the process ends, and not on a
    server that does not serve. ``take`` asks; a loop that takes no lease because every process
    runs it (rows are claimed one by one) asks here before it looks for work."""
    if _closed:
        return False
    from ..recovery import role

    return role.may_work(db)


def take(db: OrmSession, name: str, holder: str, seconds: float, now: float | None = None) -> bool:
    """Take or renew the lease ``name`` for ``seconds``, and commit; False while another holds it."""
    global _registered
    if not may_work(db):
        return False
    now = time.time() if now is None else now
    taken = _upsert(db, name, holder, now, seconds)
    if taken is None:
        # A database without the statement: the update, then the insert inside a savepoint, so
        # that losing to another process undoes nothing else and is no error of the session.
        taken = db.execute(
            update(Lease)
            .where(Lease.name == name, or_(Lease.holder == holder, Lease.expires_at < now))
            .values(holder=holder, expires_at=now + seconds)
        ).rowcount
        if not taken:
            try:
                with db.begin_nested():
                    db.execute(insert(Lease).values(name=name, holder=holder, expires_at=now + seconds))
                taken = 1
            except IntegrityError:
                taken = 0
    db.commit()
    if not taken:
        return False
    with _lock:
        _held.add((name, holder))
        if not _registered:
            _registered = True
            atexit.register(close)
    return True


class Renewing:
    """Keeps a lease while a long piece of work runs in the thread that entered it: the lease is
    taken again every quarter of its length, until the work is through."""

    def __init__(self, name: str, holder: str, seconds: float) -> None:
        self._name, self._holder, self._seconds, self._stop = name, holder, seconds, threading.Event()
        self._thread = threading.Thread(target=self._run, name=f"nik-lease-{name}", daemon=True)

    def _run(self) -> None:
        from .db import SessionLocal

        while not self._stop.wait(self._seconds / 4):
            try:
                with SessionLocal() as db:
                    take(db, self._name, self._holder, self._seconds)
            except Exception:  # noqa: BLE001 - the work goes on; the next renewal tries again
                logger.exception("The lease %s could not be renewed", self._name)

    def __enter__(self) -> Renewing:
        self._thread.start()
        return self

    def __exit__(self, *_exc) -> None:
        self._stop.set()


def release(db: OrmSession, name: str, holder: str) -> None:
    """Give the lease back when it is ours, and commit."""
    with _lock:
        mine = (name, holder) in _held
        _held.discard((name, holder))
    from ..recovery import role

    if not mine and role.in_recovery(db):
        return  # a standby holds none, and its database takes no change
    db.execute(delete(Lease).where(Lease.name == name, Lease.holder == holder))
    db.commit()


def holder_of(db: OrmSession, name: str, now: float | None = None) -> str:
    """Who holds the lease now ("" when nobody does, or when it ran out)."""
    now = time.time() if now is None else now
    row = db.get(Lease, name)
    return row.holder if row is not None and row.expires_at >= now else ""


def held() -> list[tuple[str, str]]:
    """The leases this process took and has not given back."""
    with _lock:
        return sorted(_held)


def starting() -> None:
    """The process starts (or starts again, in a test): it holds nothing and may take leases."""
    global _closed
    _closed = False
    with _lock:
        _held.clear()


def close() -> int:
    """The process ends: every lease it took is given back, and it is given none from here on."""
    global _closed
    _closed = True
    return release_all()


def release_all() -> int:
    """Give back every lease this process took: at a clean stop. Returns how many. Never raises:
    the process is stopping, and a lease that is not given back runs out by itself."""
    from .db import SessionLocal

    mine = held()
    if not mine:
        return 0
    try:
        with SessionLocal() as db:
            for name, holder in mine:
                db.execute(delete(Lease).where(Lease.name == name, Lease.holder == holder))
            db.commit()
    except Exception:  # noqa: BLE001 - stopping anyway
        logger.warning("The leases could not be given back: they run out by themselves")
        return 0
    with _lock:
        _held.difference_update(mine)
    return len(mine)

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
(``release_all``, called when the process exits and by the loops that are
told to stop): the process that starts next does not wait for them to run out.
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


def take(db: OrmSession, name: str, holder: str, seconds: float, now: float | None = None) -> bool:
    """Take or renew the lease ``name`` for ``seconds``, and commit; False while another holds it."""
    global _registered
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
            atexit.register(release_all)
    return True


def release(db: OrmSession, name: str, holder: str) -> None:
    """Give the lease back when it is ours, and commit."""
    db.execute(delete(Lease).where(Lease.name == name, Lease.holder == holder))
    db.commit()
    with _lock:
        _held.discard((name, holder))


def holder_of(db: OrmSession, name: str, now: float | None = None) -> str:
    """Who holds the lease now ("" when nobody does, or when it ran out)."""
    now = time.time() if now is None else now
    row = db.get(Lease, name)
    return row.holder if row is not None and row.expires_at >= now else ""


def held() -> list[tuple[str, str]]:
    """The leases this process took and has not given back."""
    with _lock:
        return sorted(_held)


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

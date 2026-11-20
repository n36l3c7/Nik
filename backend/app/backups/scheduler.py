"""The two loops that make backups happen without anybody asking.

**In the API process** (``start``): every few seconds, under the ``backup``
lease, one pass (``tick``): the rows are made to say what the directory
holds, a backup somebody asked for with *Back up now* is taken, a restore
test somebody asked for is run, and when the schedule says a backup is due
it is taken. Then the watch looks (``watch.check``).

**In the process that has a way out** (``start_shipper``): the automation
worker, or the API process when playbooks run inside it. Every few seconds
it sends the copies off the server (``offsite.ship``), and it looks too
(``watch.check``): it is the one that notices when the first loop has
stopped.

Both are threads that survive a bad pass and start once per process.
"""

from __future__ import annotations

import atexit
import logging
import threading
import time

from sqlalchemy import select

from ..core.models import Backup
from . import config, offsite, policy, runner, watch

logger = logging.getLogger("nik.backups")

TICK_EVERY = 5
SHIP_EVERY = 5
_started = _shipping = False
_last_watch = 0.0


def tick(now: float | None = None, holder: str = runner.HOLDER) -> list[str]:
    """One pass of the API process. Returns what it did, for the tests and the log."""
    from ..core.db import SessionLocal

    did: list[str] = []
    with SessionLocal() as db:
        if not runner.acquire(db, holder, now):
            return did
        runner.sync(db, now, holder)
        db.commit()
        queued = list(
            db.scalars(
                select(Backup.id).where(Backup.kind == "full", Backup.state == "queued").order_by(Backup.created_at)
            )
        )
        tests = list(
            db.scalars(
                select(Backup.id)
                .where(Backup.state == "done", Backup.local.is_(True), Backup.verify_state == "queued")
                .order_by(Backup.created_at)
            )
        )
        doc = config.read(db)
        clock = time.time() if now is None else now
        since = max(float(doc.get("scheduleSetAt") or 0), float(doc.get("passphraseSetAt") or 0))
        owed = bool(doc.get("passphrase")) and policy.due(doc["schedule"], runner.taken(db), clock, since)
    with runner.Renewing(holder):
        for name in queued:
            runner.take(name, now=now)
            did.append(f"backup:{name}")
        for name in tests:
            if name not in queued:
                runner.verify(name, now=now)
                did.append(f"verify:{name}")
        if owed and not queued:
            did.append(f"backup:{runner.take(by='schedule', now=now)}")
    if did:
        with SessionLocal() as db:
            runner.apply_retention(db, now)
            db.commit()
    return did


def _watch() -> None:
    global _last_watch
    if time.time() - _last_watch >= watch.WATCH_EVERY:
        _last_watch = time.time()
        watch.check()


def _loop() -> None:
    time.sleep(10)  # let the server start
    while True:
        try:
            if tick():
                watch.check()
            _watch()
        except Exception:  # noqa: BLE001 - the loop must survive a bad pass
            logger.exception("A pass of the backups failed")
        time.sleep(TICK_EVERY)


def _ship_loop() -> None:
    time.sleep(15)
    while True:
        try:
            if offsite.ship():
                watch.check()
            _watch()
        except Exception:  # noqa: BLE001 - the loop must survive a bad pass
            logger.exception("A pass of the copies off the server failed")
        time.sleep(SHIP_EVERY)


def _let_go() -> None:
    """At a clean stop, give the leases back: the process that takes over does not wait for them to run out."""
    from ..core.db import SessionLocal

    try:
        with SessionLocal() as db:
            for name in (runner.LEASE, watch.LEASE, offsite.LEASE):
                runner.release(db, name=name)
    except Exception:  # noqa: BLE001 - stopping anyway; the leases run out by themselves
        pass


def start() -> None:
    """Start the loop of the API process."""
    global _started
    if _started:
        return
    _started = True
    atexit.register(_let_go)
    threading.Thread(target=_loop, name="nik-backups", daemon=True).start()


def start_shipper() -> None:
    """Start the loop of the process that has a way out."""
    global _shipping
    if _shipping:
        return
    _shipping = True
    atexit.register(_let_go)
    threading.Thread(target=_ship_loop, name="nik-backups-offsite", daemon=True).start()

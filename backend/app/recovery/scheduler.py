"""The loops of the recovery, each a thread that survives a bad pass and starts once per process.

**In the API process** (``start``): every few seconds the pass of
``archive.py`` under its lease; once a minute the rows of the copies are made
to say what the store holds (``files.scan``), when copies are sent; and the
watch. This loop is also the one that notices that the server was replaced
while it was running, and stops it: the container starts again and its
entrypoint then answers with why it does not serve (``gate.py``).

**In the process that has a way out** (``start_shipper``): every few seconds
``ship.ship``, and the watch. ``ask_at_start`` is what that process does
before anything else when it starts: ask the second host whether this server
was replaced, and hold everything if it was.

**Stopping.** Both loops end when their process is asked to stop (the flag
the automation worker sets at SIGTERM, and the API process when it shuts
down): the pass that runs is finished, the shipper finishes the file it is
sending and starts no other, and the leases are given back with all the
others of the process (``core/leases.py``). A file cut half-way by a kill is
a ``.partial`` on the other host, resumed or sent again at the next pass. A
base backup or a recovery test the recovery service was doing is its own
(``deploy/db/recovery-agent.sh``): it is done again when that service
starts, and the row that waits for it says "failed" when no answer comes.
"""

from __future__ import annotations

import logging
import os
import signal
import sys
import threading
import time

from ..backups import config as backup_config
from ..backups import runner
from ..backups.offsite import OffsiteError
from . import archive, config, files, layout, role, ship, watch
from .remote import open_remote

logger = logging.getLogger("nik.recovery")

TICK_EVERY = 5
SHIP_EVERY = 5
SCAN_EVERY = 60
_started = _shipping = False
_last_watch = _last_scan = 0.0


def _watch() -> None:
    global _last_watch
    if time.time() - _last_watch >= watch.WATCH_EVERY:
        _last_watch = time.time()
        watch.check()


def scan(now: float | None = None, holder: str = runner.HOLDER) -> dict[str, int] | None:
    """Make the rows of the copies say what the store holds, when copies are sent and this
    process is the one that runs the pass of the archive."""
    from ..core.db import SessionLocal

    with SessionLocal() as db:
        doc = backup_config.read(db)
        if not (doc.get("passphrase") and backup_config.ready(doc.get("destination") or {})):
            return None
        if not config.acquire(db, holder, now, archive.LEASE):
            return None
        did = files.scan(db, now)
        db.commit()
    return did


def stop_if_superseded() -> bool:
    """A server that learns it was replaced stops serving at once: the process that serves is told
    to end, the container starts again, and its entrypoint answers with why (``gate.py``)."""
    from ..core.db import SessionLocal

    with SessionLocal() as db:
        if not archive.postgres(db) or role.in_recovery(db) or not role.superseded(db):
            return False
    logger.warning("This server was replaced by its standby: it stops serving")
    # Under gunicorn the parent is the process whose end ends the container.
    if "gunicorn" in os.path.basename(sys.argv[0] or ""):
        os.kill(os.getppid(), signal.SIGTERM)
    return True


def _stop_flag() -> threading.Event:
    """What says that this process was asked to stop: one flag for every loop of the process."""
    from ..core import leases

    return leases.stop_flag()


def _loop() -> None:
    global _last_scan
    stopping = _stop_flag()
    stopping.wait(12)  # let the server start
    while not stopping.is_set():
        try:
            if stop_if_superseded():
                stopping.wait(30)
                continue
            if archive.tick():
                watch.check()
            if time.time() - _last_scan >= SCAN_EVERY:
                _last_scan = time.time()
                scan()
            _watch()
        except Exception:  # noqa: BLE001 - the loop must survive a bad pass
            logger.exception("A pass of the recovery failed")
        stopping.wait(TICK_EVERY)


def _ship_loop() -> None:
    stopping = _stop_flag()
    stopping.wait(20)
    while not stopping.is_set():
        try:
            did = ship.ship(stopping=stopping.is_set)
            if "superseded" in did:
                # Nothing more must run here: the worker ends as on a stop, starts again, and
                # then waits for a backend that says it serves.
                logger.warning("This server was replaced by its standby: the worker stops")
                os.kill(os.getpid(), signal.SIGTERM)
                return
            if did:
                watch.check()
            _watch()
        except Exception:  # noqa: BLE001 - the loop must survive a bad pass
            logger.exception("A pass of the copies of the archive failed")
        stopping.wait(SHIP_EVERY)


def start() -> None:
    """Start the loop of the API process (nothing on a server without an archive volume)."""
    global _started
    if _started or not layout.root():
        return
    _started = True
    threading.Thread(target=_loop, name="nik-recovery", daemon=True).start()


def start_shipper() -> None:
    """Start the loop of the process that has a way out."""
    global _shipping
    if _shipping or not layout.root():
        return
    _shipping = True
    # A connection is opened every minute at least: the three lines the SSH library says of each
    # one at INFO would be most of the log of this container.
    logging.getLogger("paramiko").setLevel(logging.WARNING)
    threading.Thread(target=_ship_loop, name="nik-recovery-ship", daemon=True).start()


def ask(now: float | None = None) -> str:
    """Ask the second host whether this server was replaced, and write the answer down. Returns
    ``none``, ``own``, ``superseded``, ``unreachable``, or ``off`` when no copies are sent."""
    from ..core.db import SessionLocal

    if not layout.available():
        return "off"
    with SessionLocal() as db:
        if not archive.postgres(db) or role.in_recovery(db):
            return "off"
        doc = backup_config.read(db)
        if not (doc.get("passphrase") and backup_config.ready(doc.get("destination") or {})):
            return "off"
        try:
            remote = open_remote(db)
        except OffsiteError as error:
            role.note_unreachable(db, str(error), now)
            db.commit()
            return "unreachable"
    if remote is None:
        return "off"
    try:
        with remote.session() as session:
            raw = session.read_bytes(role.MARKER)
    except Exception as error:  # noqa: BLE001 - whatever the connection raises, the answer is "not reached"
        with SessionLocal() as db:
            role.note_unreachable(db, str(error) or type(error).__name__, now)
            db.commit()
        return "unreachable"
    with SessionLocal() as db:
        verdict = role.note_marker(db, role.read_marker(raw), now)
        db.commit()
    return verdict


def ask_at_start(stopping: threading.Event | None = None) -> None:
    """What the process that has a way out does first: ask, and run nothing on a server that was
    replaced (it waits here until it is stopped: the database of a replaced server is put aside
    by ``deploy/standby.sh rejoin``, which stops the stack first)."""
    from ..core.db import SessionLocal

    stopping = stopping or threading.Event()
    try:
        verdict = ask()
        if verdict == "unreachable":
            logger.warning("The second host could not be asked whether this server was replaced")
        said = False
        while not stopping.is_set():
            with SessionLocal() as db:
                if not archive.postgres(db) or role.in_recovery(db) or not role.superseded(db):
                    return
            if not said:
                logger.warning("This server was replaced by its standby: this worker runs nothing")
                said = True
            stopping.wait(10)
    except Exception:  # noqa: BLE001 - a start must not fail on this: the pass of the copies asks again
        logger.exception("The second host could not be asked whether this server was replaced")

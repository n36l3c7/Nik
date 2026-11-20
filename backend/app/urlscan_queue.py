"""The scans of addresses a playbook asked for, run by the API process.

A scan started from the interface runs as a background task of the request
that asked for it. A playbook cannot do the same: its steps are taken by the
automation worker, which is on no network with the isolated browser (only the
backend is) and reads the file store read-only. So the node ``nik.scan-url``
writes the scan down as asked for (``ask``): the row is ``queued`` and its
result carries a mark with the run that wants it. Every API process looks for
such rows every few seconds, takes one at a time with an update that only one
of them wins, and runs ``urlscan.run_scan`` exactly as the interface does.
The node meanwhile gives its step back and asks again later: nothing waits
holding a worker.

A scan the interface queued has no mark and is never taken here.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm.attributes import flag_modified

from . import artifacts, urlscan
from .core.models import UrlScan
from .core.security import now_iso

logger = logging.getLogger("nik.urlscan")

MARK = "askedBy"
LOOK_EVERY = 3
_started = False


def ask(db: OrmSession, row: UrlScan, actor: str, run_id: str, depth: int) -> None:
    """Write the scan down as asked for by a run (the caller commits). What the
    row held of an earlier visit goes, as when an analyst scans again."""
    row.status, row.error = "queued", None
    row.verdict, row.score = "", 0
    row.result = {"startedAt": now_iso(), MARK: {"actor": actor, "run": run_id, "depth": depth}}
    flag_modified(row, "result")
    artifacts.register_url(db, row)


def asked(row: UrlScan) -> dict[str, Any] | None:
    """The mark of a scan that waits to be taken here, or None."""
    mark = (row.result or {}).get(MARK) if row.status == "queued" else None
    return mark if isinstance(mark, dict) else None


def take(db: OrmSession) -> tuple[str, dict[str, Any]] | None:
    """Take one scan that was asked for: its id and its mark. None when there is none."""
    waiting = db.scalars(select(UrlScan).where(UrlScan.status == "queued").order_by(UrlScan.created_at)).all()
    for scan, mark in [(row.id, asked(row)) for row in waiting]:
        if mark is None:
            continue
        # Several API processes look at once: the one whose update changes the row has it.
        won = db.execute(
            update(UrlScan).where(UrlScan.id == scan, UrlScan.status == "queued").values(status="running")
        ).rowcount
        db.commit()
        if won:
            return scan, mark
    return None


def run_due(limit: int = 20) -> int:
    """Run the scans that were asked for, one after the other. Returns how many."""
    from .automation import triggers
    from .core.db import SessionLocal

    done = 0
    while done < limit:
        with SessionLocal() as db:
            taken = take(db)
        if taken is None:
            break
        scan, mark = taken
        # What the scan sets off (``url.analysed``) is caused by the run that asked: no loop starts from it.
        cause = (str(mark.get("run") or ""), int(mark.get("depth") or 0)) if mark.get("run") else None
        token = triggers.current_run.set(cause)
        try:
            urlscan.run_scan(scan, str(mark.get("actor") or "nik-automation"))
        except Exception:  # noqa: BLE001 - one bad scan must not stop the others
            logger.exception("The scan %s a playbook asked for failed", scan)
            urlscan._fail(scan, "The scan failed for a reason Nik did not expect: see the server's log.")
        finally:
            triggers.current_run.reset(token)
        done += 1
    return done


def _loop() -> None:
    time.sleep(15)  # let the API start
    while True:
        try:
            run_due()
        except Exception:  # noqa: BLE001 - the loop must survive a bad pass
            logger.exception("Looking for the scans playbooks asked for failed")
        time.sleep(LOOK_EVERY)


def start() -> None:
    global _started
    if _started:
        return
    _started = True
    threading.Thread(target=_loop, name="nik-url-scans", daemon=True).start()

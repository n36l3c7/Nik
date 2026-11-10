"""The background worker of the automatic threat-intelligence lookups.

Every API process starts one thread; a lease row (``leases``) lets only one
of them work at a time, so several gunicorn workers do not multiply the
requests (and the providers' quotas). The thread sleeps between passes; a
pass checks the indicators not in the cache (``service.run_cycle``).
"""

from __future__ import annotations

import logging
import threading
import time
import uuid

from sqlalchemy import insert, or_, update
from sqlalchemy.exc import IntegrityError

from ..db import SessionLocal
from ..models import Lease
from . import service

logger = logging.getLogger("nik.enrichment")
LEASE = "enrichment-worker"
LEASE_SECONDS = 300
PAUSE_SECONDS = 30
BUDGET_SECONDS = 120
HOLDER = f"{uuid.uuid4()}"
_started = False


def acquire(db, holder: str = HOLDER, now: float | None = None, seconds: float = LEASE_SECONDS) -> bool:
    """Take or renew the lease; False while another process holds it."""
    now = time.time() if now is None else now
    taken = db.execute(
        update(Lease)
        .where(Lease.name == LEASE, or_(Lease.holder == holder, Lease.expires_at < now))
        .values(holder=holder, expires_at=now + seconds)
    ).rowcount
    if taken:
        db.commit()
        return True
    try:
        db.execute(insert(Lease).values(name=LEASE, holder=holder, expires_at=now + seconds))
        db.commit()
        return True
    except IntegrityError:
        db.rollback()
        return False


def _loop() -> None:
    from ..routers.settings import read_settings

    time.sleep(15)  # let the API start
    while True:
        try:
            with SessionLocal() as db:
                if acquire(db):
                    done = service.run_cycle(db, read_settings(db), budget_seconds=BUDGET_SECONDS)
                    if done:
                        logger.info("Threat-intelligence lookups: %d request(s)", done)
        except Exception:  # noqa: BLE001 - the worker must survive a bad pass
            logger.exception("Threat-intelligence pass failed")
        time.sleep(PAUSE_SECONDS)


def start() -> None:
    global _started
    if _started:
        return
    _started = True
    threading.Thread(target=_loop, name="nik-enrichment", daemon=True).start()

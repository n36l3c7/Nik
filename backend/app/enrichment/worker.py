"""The background worker of the automatic threat-intelligence lookups.

Every API process starts one thread; a lease row (``leases``) lets only one
of them work at a time, so several gunicorn workers do not multiply the
requests (and what they take from the keys of the instances). The thread
sleeps between passes; a pass checks the indicators that have no answer
that stands (``service.run_cycle``).
"""

from __future__ import annotations

import logging
import threading
import time
import uuid

from ..core import leases
from ..core.db import SessionLocal
from ..core.models import Lease  # noqa: F401 - the tests reach the table through this module
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
    return leases.take(db, LEASE, holder, seconds, now)


def _loop() -> None:
    from ..routers.settings import read_settings

    time.sleep(15)  # let the API start
    while True:
        try:
            with SessionLocal() as db:
                if acquire(db):
                    shared = read_settings(db)
                    # What an analyst asked for comes before the automatic lookups.
                    done = service.run_checks(db, shared, budget_seconds=BUDGET_SECONDS / 2)
                    acquire(db)
                    done += service.run_cycle(db, shared, budget_seconds=BUDGET_SECONDS / 2)
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

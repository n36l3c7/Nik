"""Telling the administrators when a worker stops answering, and when it is back.

Nik leans on processes of its own that live elsewhere: the automation worker
(it takes the steps of every playbook, fetches and expires) and the analysis
workers reached over HTTP (analyzer, capa, document viewer, isolated browser,
packet capture, script sandbox). When one of them is down, what it does
simply waits, and nobody is told. This module tells every account that holds
the ``admin`` role, once when a worker is found down and once when it answers
again; nothing in between.

How it decides:

- only a worker that is **configured** is watched: an analysis worker with its
  ``*_URL`` set, the automation worker when it is a container of its own
  (``AUTOMATION_WORKER=container``: inline it is a thread of this very
  process, and off there is none);
- a worker **answers** when its ``GET /health`` returns 200 within
  ``HEALTH_TIMEOUT`` seconds; the automation worker, when its heartbeat is
  fresh (``automation/state.py``);
- a worker is **down** once it has not answered for ``DOWN_AFTER`` seconds
  without a break. A container that restarts answers again well within that,
  so an update or a blip tells nobody.

Where it runs: in the API process, because the automation worker is one of
the things watched. Every API process starts the thread; a lease row lets one
of them check at a time, and what was found is kept in one row of
``settings``, written in the same transaction as the notifications. So
several processes, or a restart of the server, do not tell anybody twice.
"""

from __future__ import annotations

import logging
import threading
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import insert, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm.attributes import flag_modified

from .core.config import settings
from .core.models import Lease, Setting, User
from .core.permissions import stored_roles

logger = logging.getLogger("nik.workers")

SETTINGS_ID = 4  # 1 the analysts' settings, 2 automation, 3 the catalogue of packs
LEASE = "worker-watch"
LEASE_SECONDS = 120
WATCH_EVERY = 30
DOWN_AFTER = 120
HEALTH_TIMEOUT = 5
HOLDER = f"{uuid.uuid4()}"
LINK = "/settings/system/workers"
AUTOMATION = "automation"
_started = False


@dataclass(frozen=True)
class Worker:
    id: str
    label: str  # as it reads in a sentence, after "The"
    waits: str  # what does not happen while it is down
    url: str = ""  # the name of its address in the configuration; none for the automation worker


WORKERS: tuple[Worker, ...] = (
    Worker(AUTOMATION, "automation worker", "playbooks, fetching, timers and expiries wait"),
    Worker("analyzer", "analyzer worker", "the Code view of a sample cannot be built", "ANALYZER_URL"),
    Worker("capa", "capa worker", "the capabilities of a sample cannot be read", "CAPA_URL"),
    Worker("docview", "document worker", "documents and PST files cannot be opened", "DOCVIEW_URL"),
    Worker("browser", "isolated browser", "addresses cannot be scanned and pages cannot be opened", "BROWSER_URL"),
    Worker("pcap", "packet capture worker", "captures cannot be analysed", "PCAP_URL"),
    Worker("sandbox", "script sandbox", "scripts cannot run", "SANDBOX_URL"),
)
BY_ID = {worker.id: worker for worker in WORKERS}


def configured(worker: Worker) -> bool:
    if worker.id == AUTOMATION:
        return settings.AUTOMATION_WORKER == "container"
    return bool(getattr(settings, worker.url, ""))


def watched() -> list[Worker]:
    return [worker for worker in WORKERS if configured(worker)]


# --------------------------------------------------------------------------- #
# Asking                                                                      #
# --------------------------------------------------------------------------- #
def healthy(base: str) -> bool:
    """Whether the worker at this address answers its health check."""
    try:
        with urllib.request.urlopen(f"{base}/health", timeout=HEALTH_TIMEOUT) as response:  # noqa: S310 - operator-configured URL
            return response.status == 200
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return False


def probe() -> dict[str, bool]:
    """Ask every analysis worker that is configured: its id → whether it answered."""
    return {worker.id: healthy(getattr(settings, worker.url)) for worker in watched() if worker.url}


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


def _stamp(at: float) -> str:
    return datetime.fromtimestamp(at, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def lasted(seconds: float) -> str:
    """How long it was down, in words: "1 minute", "12 minutes", "2 hours 5 minutes"."""
    minutes = max(1, round(seconds / 60))
    hours, rest = divmod(minutes, 60)
    parts = []
    if hours:
        parts.append(f"{hours} hour" + ("" if hours == 1 else "s"))
    if rest or not hours:
        parts.append(f"{rest} minute" + ("" if rest == 1 else "s"))
    return " ".join(parts)


def _tell_admins(db: OrmSession, kind: str, text: str) -> None:
    from . import tasks

    for user in db.scalars(select(User).where(User.disabled.is_(False))):
        if "admin" in stored_roles(user.roles):
            tasks.notify(db, user.username, kind, text, LINK)


# --------------------------------------------------------------------------- #
# One pass                                                                    #
# --------------------------------------------------------------------------- #
def record(db: OrmSession, answers: dict[str, bool], now: float | None = None) -> list[str]:
    """Write down what a pass found and tell the administrators what changed
    (the caller commits). ``answers`` holds, for each worker that was asked,
    whether it answered. Returns the kinds of the notices sent, for the log.

    A worker goes through three states: ``up``; ``failing`` from its first
    check without an answer; ``down`` once that has lasted ``DOWN_AFTER``.
    The administrators hear of the passage to ``down`` and of the way back
    from it, and of nothing else.
    """
    now = time.time() if now is None else now
    before = _held(db).get("workers") or {}
    after: dict[str, Any] = {}
    told: list[str] = []
    for worker in watched():
        was = before.get(worker.id) if isinstance(before.get(worker.id), dict) else {}
        if worker.id not in answers:
            # Not asked in this pass: what was known stays.
            if was:
                after[worker.id] = was
            continue
        state, since = was.get("state", ""), float(was.get("since") or now)
        if answers[worker.id]:
            if state == "down":
                _tell_admins(
                    db, "worker.back", f"The {worker.label} is answering again: it was down for {lasted(now - since)}."
                )
                told.append("worker.back")
            after[worker.id] = {"state": "up", "since": since if state == "up" else now, "checked": now}
            continue
        if state not in ("failing", "down"):
            state, since = "failing", now
        if state == "failing" and now - since >= DOWN_AFTER:
            state = "down"
            _tell_admins(
                db,
                "worker.down",
                f"The {worker.label} has not answered since {_stamp(since)}: {worker.waits}. "
                "Its state is in Settings → System → Workers; look at its container.",
            )
            told.append("worker.down")
            logger.warning("The %s has not answered since %s", worker.label, _stamp(since))
        after[worker.id] = {"state": state, "since": since, "checked": now}
    # A worker that is no longer configured is forgotten: nothing is said of it.
    _keep(db, {"workers": after, "checked": now})
    return told


def acquire(db: OrmSession, holder: str = HOLDER, now: float | None = None) -> bool:
    """Take or renew the lease of the watch; False while another process holds it."""
    now = time.time() if now is None else now
    taken = db.execute(
        update(Lease)
        .where(Lease.name == LEASE, or_(Lease.holder == holder, Lease.expires_at < now))
        .values(holder=holder, expires_at=now + LEASE_SECONDS)
    ).rowcount
    if taken:
        db.commit()
        return True
    try:
        db.execute(insert(Lease).values(name=LEASE, holder=holder, expires_at=now + LEASE_SECONDS))
        db.commit()
        return True
    except IntegrityError:
        db.rollback()
        return False


def check(now: float | None = None, holder: str = HOLDER) -> list[str]:
    """One pass, when this process holds the lease: ask, write down, tell."""
    from .automation import state
    from .core.db import SessionLocal

    with SessionLocal() as db:
        if not acquire(db, holder, now):
            return []
    # Asked with no session open: a worker that hangs holds no connection of the pool.
    answers = probe()
    with SessionLocal() as db:
        if configured(BY_ID[AUTOMATION]):
            answers[AUTOMATION] = state.worker_alive(db, now)
        told = record(db, answers, now)
        db.commit()
    return told


def _loop() -> None:
    time.sleep(20)  # let the API and the other containers start
    while True:
        try:
            check()
        except Exception:  # noqa: BLE001 - the watch must survive a bad pass
            logger.exception("The check of the workers failed")
        time.sleep(WATCH_EVERY)


def start() -> None:
    """Start the watch in this process, when there is a worker to watch."""
    global _started
    if _started or not watched():
        return
    _started = True
    threading.Thread(target=_loop, name="nik-worker-watch", daemon=True).start()


# --------------------------------------------------------------------------- #
# Showing                                                                     #
# --------------------------------------------------------------------------- #
def _iso(at: Any) -> str | None:
    return datetime.fromtimestamp(float(at), timezone.utc).isoformat() if at else None


def out(db: OrmSession) -> dict[str, Any]:
    """Every worker Nik knows, with what the last pass found of those that are configured."""
    doc = _held(db)
    held = doc.get("workers") or {}
    rows = []
    for worker in WORKERS:
        found = held.get(worker.id) if isinstance(held.get(worker.id), dict) else {}
        on = configured(worker)
        rows.append(
            {
                "id": worker.id,
                "label": worker.label,
                "waits": worker.waits,
                "configured": on,
                # up | failing | down, or "" before its first check and when it is not configured
                "state": found.get("state", "") if on else "",
                "since": _iso(found.get("since")) if on else None,
                "checkedAt": _iso(found.get("checked")) if on else None,
            }
        )
    return {"workers": rows, "checkedAt": _iso(doc.get("checked")), "downAfterSeconds": DOWN_AFTER}

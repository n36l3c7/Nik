"""The pass that remembers, and tells the administrators before things break.

Modelled on ``worker_watch.py`` and ``backups/watch.py``, with the same
notices (``tasks.notify`` to every account that holds the ``admin`` role)
and the same rule: one notice when a problem appears, one when it is solved,
nothing in between, however long it lasts and however many processes look.

Once a minute, under the ``health-watch`` lease, in the API process and in
the automation worker both (whichever is alive looks):

- every row of the page is computed (``checks.gather``);
- a sample of how full each disk is, and of the size of the database, is
  kept once an hour for two weeks: the growth and the day a disk will be
  full are read from them;
- for each row, since when it is in its state;
- for the rows that warn (``notify``): a notice when the row has become
  worse than what was last told (fine → attention → problem) and one when it
  is fine again. A state has to be found by two passes in a row before
  anybody is told, so a value that crosses its limit for a moment tells
  nobody. A row that could not be measured changes nothing.

What is kept is one row of ``settings``, written in the same transaction as
the notices. Each notice links to the health page.
"""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm.attributes import flag_modified

from ..core.models import Setting, User
from ..core.permissions import stored_roles
from . import checks, thresholds
from .checks import ATTENTION, FINE, PROBLEM, UNKNOWN, WORSE

logger = logging.getLogger("nik.health")

SETTINGS_ID = 45
LEASE = "health-watch"
WATCH_EVERY = 60
SAMPLE_EVERY = 3600
SAMPLES_KEPT = 24 * 14
_started = False


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


def _tell_admins(db: OrmSession, kind: str, text: str) -> None:
    from .. import tasks

    for user in db.scalars(select(User).where(User.disabled.is_(False))):
        if "admin" in stored_roles(user.roles):
            tasks.notify(db, user.username, kind, text, checks.LINK)


def sample(kept: dict[str, Any], rows: list[dict[str, Any]], now: float) -> dict[str, list]:
    """The samples of the disks with this hour's added: ``{"store": [[time, bytes used], …], …}``."""
    disks = {name: list(points) for name, points in (kept.get("disks") or {}).items()}
    found: dict[str, float] = {}
    for row in rows:
        for name, labels, value in row["metrics"]:
            if name == "nik_disk_used_bytes":
                found[labels["disk"]] = value
            elif name == "nik_database_size_bytes":
                found["database"] = value
    for name, used in found.items():
        points = disks.setdefault(name, [])
        if not points or now - float(points[-1][0]) >= SAMPLE_EVERY:
            points.append([now, used])
            del points[:-SAMPLES_KEPT]
    return disks


def record(db: OrmSession, rows: list[dict[str, Any]], kept: dict[str, Any], now: float) -> list[str]:
    """Write down what a pass found and tell the administrators what changed (the caller
    commits). Returns the notices sent, as ``problem:<row>`` and ``solved:<row>``."""
    before = kept.get("states") or {}
    after: dict[str, Any] = {}
    told: list[str] = []
    for row in rows:
        was = before.get(row["id"]) if isinstance(before.get(row["id"]), dict) else {}
        state = row["state"]
        said = was.get("told", FINE)
        if state == UNKNOWN:
            # Not measured: what was known stays, and nobody is told anything.
            after[row["id"]] = {"state": UNKNOWN, "since": now, "told": FINE} | was | {"unknown": True}
            continue
        steady = was.get("state") == state and not was.get("unknown")
        entry = {"state": state, "since": was.get("since", now) if was.get("state") == state else now, "told": said}
        if row["notify"] and steady:
            if WORSE[state] > WORSE[said]:
                words = f"{row['label']}: {row['value']}. {row['detail']}".strip()
                _tell_admins(db, "health.problem", words)
                told.append(f"problem:{row['id']}")
                logger.warning("Health: %s", words)
                entry["told"] = state
            elif state == FINE and said != FINE:
                _tell_admins(db, "health.solved", f"{row['label']} is fine again: {row['value']}.")
                told.append(f"solved:{row['id']}")
                entry["told"] = FINE
        after[row["id"]] = entry
    doc = {
        "states": after,
        "disks": sample(kept, rows, now),
        "tls": checks.certificate(kept, now),
        "checked": now,
    }
    _keep(db, doc)
    return told


def check(now: float | None = None, holder: str | None = None) -> list[str]:
    """One pass, when this process holds the lease of the watch."""
    from ..backups import runner
    from ..core.db import SessionLocal

    clock = time.time() if now is None else now
    with SessionLocal() as db:
        if not runner.acquire(db, holder or runner.HOLDER, now, LEASE):
            return []
        kept = _held(db)
        # The certificate is read here, not when somebody opens the page.
        kept["tls"] = checks.certificate(kept, clock)
        rows = checks.gather(db, thresholds.read(db), kept, clock)
        told = record(db, rows, kept, clock)
        db.commit()
    return told


def _loop() -> None:
    time.sleep(30)  # let the server start
    while True:
        try:
            check()
        except Exception:  # noqa: BLE001 - the watch must survive a bad pass
            logger.exception("The check of the health of the server failed")
        time.sleep(WATCH_EVERY)


def start() -> None:
    global _started
    if _started:
        return
    _started = True
    threading.Thread(target=_loop, name="nik-health-watch", daemon=True).start()


def _iso(at: Any) -> str | None:
    return datetime.fromtimestamp(float(at), timezone.utc).isoformat() if at else None


def page(db: OrmSession, now: float | None = None) -> dict[str, Any]:
    """The health page: every row as it is now, with since when it is in its state."""
    now = time.time() if now is None else now
    kept = _held(db)
    rows = checks.gather(db, thresholds.read(db), kept, now)
    states = kept.get("states") or {}
    shown = []
    for row in rows:
        was = states.get(row["id"]) if isinstance(states.get(row["id"]), dict) else {}
        since = was.get("since") if was.get("state") == row["state"] else None
        shown.append(
            {key: row[key] for key in ("id", "group", "label", "value", "state", "detail", "link")}
            | {"since": _iso(since)}
        )
    counts = {state: sum(1 for row in rows if row["state"] == state) for state in (FINE, ATTENTION, PROBLEM, UNKNOWN)}
    return {
        "rows": shown,
        "counts": counts,
        "state": PROBLEM if counts[PROBLEM] else ATTENTION if counts[ATTENTION] else FINE,
        "watchedAt": _iso(kept.get("checked")),
        "thresholds": thresholds.out(db),
    }

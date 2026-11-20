"""Telling the administrators when the backups are not what they should be.

Modelled on ``worker_watch.py``: every account that holds the ``admin`` role
gets one notice when a problem appears and one when it is solved, nothing in
between, however long it lasts and however many processes look.

The problems, each on its own:

- ``unset``    no passphrase is set (or it cannot be read any more), so no backup is taken;
- ``failed``   the latest backup did not get written;
- ``verify``   the latest backup was written and failed its restore test;
- ``missed``   the schedule passed and no backup started;
- ``stale``    the last good backup is older than the age the administrator set;
- ``disk``     the backup directory is nearly full;
- ``offsite``  the copy off the server failed, or waits for too long, while the local one is there.

**Where it runs.** In the API process and in the automation worker both:
whichever holds the ``backup-watch`` lease looks, once a minute. The backups
themselves are taken by the API process, so a watch that lived only there
would say nothing on the day that process is the thing that is stuck; and
the worker alone would say nothing on an installation that runs without it.
What was found is kept in one row of ``settings``, written in the same
transaction as the notices.
"""

from __future__ import annotations

import logging
import shutil
import time
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm.attributes import flag_modified

from ..core.models import Backup, Setting, User
from ..core.permissions import stored_roles
from . import config, policy, runner

logger = logging.getLogger("nik.backups")

SETTINGS_ID = 21
LEASE = "backup-watch"
WATCH_EVERY = 60
LINK = "/settings/system/backup"
# A new server is given a day to be set up before it is told it has no backups.
UNSET_AFTER = 86400
DISK_PERCENT = 10
COPY_WAITS = 6 * 3600

SOLVED = {
    "unset": "A backup passphrase is set: Nik takes its backups again.",
    "failed": "A backup was written again.",
    "verify": "The latest backup passed its restore test.",
    "missed": "A backup was taken again.",
    "stale": "There is a recent good backup again.",
    "disk": "The backup directory has room again.",
    "offsite": "The copy off the server works again.",
}


def _when(at: float) -> str:
    return datetime.fromtimestamp(at, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


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
            tasks.notify(db, user.username, kind, text, LINK)


def problems(db: OrmSession, now: float | None = None, usage=shutil.disk_usage) -> dict[str, str]:
    """What is wrong with the backups at this moment: the name of each problem and its sentence."""
    now = time.time() if now is None else now
    doc = config.read(db)
    found: dict[str, str] = {}
    rows = list(db.scalars(select(Backup).where(Backup.kind == "full").order_by(Backup.created_at.desc())))
    phrase_kept = bool(doc.get("passphrase"))
    phrase = config.passphrase(db) if phrase_kept else None

    if phrase is None:
        first = db.scalars(select(User.created_at).order_by(User.created_at).limit(1)).first()
        if phrase_kept:
            found["unset"] = (
                "The backup passphrase cannot be read any more (SECRET_KEY changed): no backup is taken until "
                "it is entered again in Settings → Backup."
            )
        elif first and now - runner.stamp(first) >= UNSET_AFTER:
            found["unset"] = "No backup passphrase is set, so Nik takes no backup. Set one in Settings → Backup."
        # The room of a directory nothing is written to yet is nobody's problem.
        return found

    finished = [row for row in rows if row.state in ("done", "failed")]
    latest = finished[0] if finished else None
    if latest is not None and latest.state == "failed":
        found["failed"] = f"The backup of {_when(runner.stamp(latest.created_at))} failed: {latest.error}"[:480]
    elif latest is not None and latest.verify_state == "failed":
        why = (latest.verify or {}).get("error") or "no reason was kept"
        found["verify"] = f"The backup {latest.id} failed its restore test: {why}"[:480]

    taken = [policy.Taken(row.id, runner.stamp(row.created_at), row.state, row.verify_state) for row in rows]
    since = float(doc.get("scheduleSetAt") or 0)
    slot = policy.missed(doc["schedule"], taken, now, max(since, float(doc.get("passphraseSetAt") or 0)))
    if slot is not None:
        found["missed"] = (
            f"No backup was taken at {_when(slot)}: the schedule passed and none started. "
            "Look at the server (docker compose logs api)."
        )

    good = next((row for row in rows if row.state == "done" and row.verify_state == "passed"), None)
    limit = int(doc["warnAfterHours"]) * 3600
    if doc["schedule"].get("enabled"):
        reference = runner.stamp(good.created_at) if good else float(doc.get("passphraseSetAt") or now)
        if now - reference > limit:
            found["stale"] = (
                f"The last good backup is from {_when(reference)}, more than {doc['warnAfterHours']} hours ago."
                if good
                else f"There is no good backup yet, {doc['warnAfterHours']} hours after the passphrase was set."
            )

    if config.ready(doc.get("destination") or {}):
        for row in rows:
            if row.state != "done" or not row.local:
                continue
            if row.offsite_state == "failed":
                why = (row.offsite or {}).get("error") or "no reason was kept"
                found["offsite"] = f"The copy of the backup {row.id} off the server failed: {why}"[:480]
            elif row.offsite_state == "pending" and now - runner.stamp(row.finished_at or row.created_at) > COPY_WAITS:
                found["offsite"] = (
                    f"The backup {row.id} has waited more than {COPY_WAITS // 3600} hours for its copy off the "
                    "server: the automation worker sends it. Its state is in Settings → System → Workers."
                )
            break  # the latest backup that is here is the one that matters
    return found | _disk(rows, usage)


def _disk(rows: list[Backup], usage) -> dict[str, str]:
    try:
        disk = usage(runner.directory())
    except OSError:
        return {}
    good = next((row for row in rows if row.state == "done" and row.verify_state == "passed"), None)
    wanted = 2 * (good.size if good else 0)
    if disk.total and (disk.free * 100 < disk.total * DISK_PERCENT or disk.free < wanted):
        return {
            "disk": f"The backup directory is nearly full: {disk.free // 2**20} MB free of {disk.total // 2**20} MB. "
            "Keep fewer backups, or give it more room."
        }
    return {}


def record(db: OrmSession, found: dict[str, str], now: float | None = None) -> list[str]:
    """Write down the problems of this pass and tell the administrators what changed (the caller
    commits). Returns the notices sent, as ``problem:<name>`` and ``solved:<name>``."""
    now = time.time() if now is None else now
    before = _held(db).get("problems") or {}
    after: dict[str, Any] = {}
    told = []
    for name, text in found.items():
        if name in before:
            after[name] = {**before[name], "text": text}
            continue
        after[name] = {"since": now, "text": text}
        _tell_admins(db, "backup.problem", text)
        told.append(f"problem:{name}")
        logger.warning("Backups: %s", text)
    for name in before:
        if name not in found:
            _tell_admins(db, "backup.solved", SOLVED.get(name, "A problem with the backups is solved."))
            told.append(f"solved:{name}")
    _keep(db, {"problems": after, "checked": now})
    return told


def check(now: float | None = None, holder: str = runner.HOLDER, usage=shutil.disk_usage) -> list[str]:
    """One pass, when this process holds the lease of the watch."""
    from ..core.db import SessionLocal

    with SessionLocal() as db:
        if not runner.acquire(db, holder, now, LEASE):
            return []
        told = record(db, problems(db, now, usage), now)
        db.commit()
    return told


def out(db: OrmSession) -> list[dict[str, Any]]:
    """The problems the last pass found, for the top of the screen."""
    held = _held(db).get("problems") or {}
    return [
        {"id": name, "text": entry.get("text", ""), "since": runner.iso(float(entry.get("since") or 0))}
        for name, entry in held.items()
        if isinstance(entry, dict)
    ]

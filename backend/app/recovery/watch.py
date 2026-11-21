"""The administrators are told when the recovery to a moment would not work, or the standby falls behind.

The same way as for the backups (``app/backups/watch.py``): each problem has
a name, a notice is sent once when it appears and once when it is solved,
and what is wrong now is kept in a row of ``settings`` for the screen and
the health page. Both loops look (the API process and the one that sends the
copies), under one lease.

The problems:

- ``archive``    PostgreSQL cannot hand its segments to the archive: it keeps
                 them, and the disk of the database fills. Told after a few
                 minutes, with how much log waits, long before the disk is full;
- ``archive-off`` the archive volume is there but PostgreSQL does not archive;
- ``service``    the recovery service does not answer: no base backup, no proof;
- ``base``       the last base backup failed, or there is none after a day;
- ``room``       no room for the next base backup;
- ``test``       the last recovery test failed;
- ``link``       the second host has not been reached for a while;
- ``behind``     what is on the second host is older than the threshold;
- ``copies``     this server was promoted and still sends its copies to itself;
- ``asked``      this server started without being able to ask the second
                 host whether it was replaced.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from ..backups import runner
from ..core.models import RecoveryBase, User
from ..core.security import stored_roles
from . import agent, archive, config, layout, role, ship

logger = logging.getLogger("nik.recovery")

LEASE = "recovery-watch"
WATCH_EVERY = 60
LINK = "/settings/system/backup"
# A failed segment is told once it has been failing for this long: one failure between two tries is nothing.
ARCHIVE_STUCK_AFTER = 300
SERVICE_AFTER = 600
LINK_AFTER = 600
NO_BASE_AFTER = 86400

SOLVED = {
    "archive": "PostgreSQL hands its log to the archive again.",
    "archive-off": "The log of PostgreSQL is archived again.",
    "service": "The recovery service answers again.",
    "base": "A base backup was taken again.",
    "room": "The archive volume has room for the next base backup again.",
    "test": "The recovery to a moment is proven again.",
    "link": "The second host is reached again.",
    "behind": "The second host has caught up.",
    "copies": "The copies go to another host again.",
    "asked": "The second host was asked: this server was not replaced.",
}


def _when(at: float) -> str:
    from datetime import datetime, timezone

    return datetime.fromtimestamp(at, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _tell_admins(db: OrmSession, kind: str, text: str) -> None:
    from .. import tasks

    for user in db.scalars(select(User).where(User.disabled.is_(False))):
        if "admin" in stored_roles(user.roles):
            tasks.notify(db, user.username, kind, text, LINK)


def problems(db: OrmSession, now: float | None = None) -> dict[str, str]:
    """What is wrong at this moment: the name of each problem and its sentence."""
    now = time.time() if now is None else now
    found: dict[str, str] = {}
    if not layout.available() or not archive.postgres(db) or role.in_recovery(db):
        return found
    state = config.held(db, config.ARCHIVE_SETTINGS_ID)
    doc = config.read(db)
    seen = state.get("archiver") or {}
    if seen and seen.get("mode") not in ("on", "always"):
        found["archive-off"] = (
            "PostgreSQL does not archive its log, so the server cannot be brought back to a moment: the database "
            "container was started without the archive (NIK_WAL_ARCHIVE=off, or an entrypoint from before 6.9). "
            "Start the stack again with docker compose up -d."
        )
        return found
    if seen and archive.stuck(seen) and now - float(seen.get("stuckSince") or now) >= ARCHIVE_STUCK_AFTER:
        found["archive"] = (
            f"PostgreSQL has not been able to archive its log since {_when(float(seen['stuckSince']))} (segment "
            f"{seen.get('failedWal')}). Nothing is lost, but it keeps every segment until the archive works: "
            f"{int(seen.get('waiting') or 0)} segments wait ({int(seen.get('waiting') or 0) * 16} MB) and its log "
            f"takes {int(seen.get('walBytes') or 0) // 2**20} MB on the disk of the database, which fills. "
            "The reason is in the log of the database container (docker compose logs db)."
        )[:480]
    alive = agent.alive(now)
    if state.get("at") and (alive is None or alive > SERVICE_AFTER):
        found["service"] = (
            "The recovery service does not answer, so no base backup is taken and the archive is not proven: "
            "start it (docker compose up -d recovery)."
        )
    rows = list(db.scalars(select(RecoveryBase).order_by(RecoveryBase.created_at.desc())))
    latest = rows[0] if rows else None
    good = next((row for row in rows if row.state == "done" and row.local), None)
    if latest is not None and latest.state == "failed":
        found["base"] = f"The base backup of {_when(runner.stamp(latest.created_at))} failed: {latest.error}"[:480]
    elif good is None and state.get("since") and now - float(state["since"]) > NO_BASE_AFTER:
        found["base"] = "There is no base backup yet, a day after the archive started: no moment can be gone back to."
    if state.get("noRoom"):
        found["room"] = str(state["noRoom"])[:480]
    tested = state.get("tested") or {}
    if tested.get("state") == "failed":
        found["test"] = (
            f"The recovery test of {_when(float(tested.get('at') or now))} failed: {tested.get('error')} "
            "Until one passes, a recovery to a moment is not proven to work."
        )[:480]
    asked = role.state(db).get("asked") or {}
    sent = ship.status(db, now)
    if sent["on"]:
        link = sent.get("link") or {}
        if link.get("ok") is False and now - float(link.get("since") or now) >= LINK_AFTER:
            found["link"] = (
                f"The second host has not been reached since {_when(float(link['since']))}: {link.get('error')}. "
                "Nothing new is safe there until it is."
            )[:480]
        if sent.get("hold") == "own":
            found["copies"] = (
                "This server was the standby and was promoted: its copies are still set to go to this host itself, "
                "so nothing is sent. Set the other host as the destination in Settings → Backup once it is ready "
                "to be the standby (deploy/standby.sh rejoin there)."
            )
        behind = (sent.get("behind") or {}).get("seconds")
        limit = int(doc["lagMinutes"]) * 60
        if behind is not None and behind > limit and "copies" not in found:
            found["behind"] = (
                f"What the second host holds is {int(behind // 60)} minutes old (the limit set is "
                f"{doc['lagMinutes']} minutes): if this host died now, that much would be lost."
            )
        if asked.get("reachable") is False and "link" not in found and now - float(asked.get("at") or now) < 3600:
            found["asked"] = (
                "The second host could not be asked whether this server was replaced: if its standby was promoted "
                "while this server was away, stop this one (deploy/standby.sh rejoin makes it the standby)."
            )
    return found


def record(db: OrmSession, found: dict[str, str], now: float | None = None) -> list[str]:
    """Write down the problems of this pass and tell the administrators what changed (the caller commits)."""
    now = time.time() if now is None else now
    before = config.held(db, config.WATCH_SETTINGS_ID).get("problems") or {}
    after: dict[str, Any] = {}
    told = []
    for name, text in found.items():
        if name in before:
            after[name] = {**before[name], "text": text}
            continue
        after[name] = {"since": now, "text": text}
        _tell_admins(db, "recovery.problem", text)
        told.append(f"problem:{name}")
        logger.warning("Recovery: %s", text)
    for name in before:
        if name not in found:
            _tell_admins(db, "recovery.solved", SOLVED.get(name, "A problem with the recovery is solved."))
            told.append(f"solved:{name}")
    config.keep(db, config.WATCH_SETTINGS_ID, {"problems": after, "checked": now})
    return told


def check(now: float | None = None, holder: str = runner.HOLDER) -> list[str]:
    """One pass, when this process holds the lease of the watch."""
    from ..core.db import SessionLocal

    with SessionLocal() as db:
        if not layout.available() or not archive.postgres(db) or role.in_recovery(db):
            return []
        if not config.acquire(db, holder, now, LEASE):
            return []
        told = record(db, problems(db, now), now)
        db.commit()
    return told


def out(db: OrmSession) -> list[dict[str, Any]]:
    held = config.held(db, config.WATCH_SETTINGS_ID).get("problems") or {}
    return [
        {"id": name, "text": entry.get("text", ""), "since": runner.iso(float(entry.get("since") or 0))}
        for name, entry in held.items()
        if isinstance(entry, dict)
    ]

"""Everything the recovery knows, put together: for the screen, the health page and the command line.

``overview`` is what *Settings → Backup* shows under "Recovery to a moment"
and what ``deploy/standby.sh status`` prints. ``rows`` are the rows of the
health page (group "Recovery"), each with its metrics. None of them has
``notify`` on: every trouble they show is one the watch of the recovery
(``watch.py``) tells the administrators about itself, once. ``loss`` is the
sentence that matters before a promotion: what this standby does not hold.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from ..backups import runner
from ..core.clock import iso_or_none as _iso
from ..core.config import settings
from ..core.models import RecoveryBase
from . import agent, archive, config, kept, layout, role, ship, standby, watch


def command(moment: float | None = None) -> str:
    """What an operator types on the server to go back to a moment. With --replace: the server it
    is typed on holds a database, which the command keeps aside."""
    if moment is None:
        return 'deploy/restore.sh --replace --to "YYYY-MM-DD HH:MM:SS+00"'
    written = datetime.fromtimestamp(moment, timezone.utc).strftime("%Y-%m-%d %H:%M:%S+00")
    return f'deploy/restore.sh --replace --to "{written}"'


def base_out(row: RecoveryBase) -> dict[str, Any]:
    copy = row.offsite or {}
    return {
        "id": row.id,
        "state": row.state,
        "createdAt": row.created_at,
        "finishedAt": row.finished_at,
        "size": row.size,
        "timeline": row.timeline,
        "startWal": row.start_wal,
        "verified": bool((row.facts or {}).get("verified")),
        "seconds": (row.facts or {}).get("seconds"),
        "error": row.error,
        "requestedBy": row.requested_by,
        "local": row.local,
        "offsiteState": row.offsite_state,
        "offsite": {key: copy.get(key) for key in ("where", "at", "error", "bytes") if copy.get(key)},
    }


def estimate(disk: dict[str, int], bases: list[RecoveryBase], keep_days: int, now: float) -> dict[str, Any]:
    """What the archive will take once it has run for the days it keeps: as many base backups as
    are kept at their latest size, and the log of those days at the rate seen so far."""
    done = [row for row in bases if row.state == "done" and row.local]
    if not done:
        return {"perDay": None, "steady": None}
    oldest = min(runner.stamp(row.finished_at or row.created_at) for row in done)
    span = max(3600.0, now - oldest)
    per_day = int(disk.get("wal", 0) * 86400 / span)
    latest = max(done, key=lambda row: row.created_at)
    return {"perDay": per_day, "steady": int((keep_days + 1) * (latest.size + per_day))}


def overview(db: OrmSession, now: float | None = None) -> dict[str, Any]:
    now = time.time() if now is None else now
    found: dict[str, Any] = {"available": layout.available() and archive.postgres(db), "name": role.name(db)}
    if not found["available"]:
        found["role"] = role.PRIMARY
        return found
    found["role"] = role.of(db)
    pair = role.state(db)
    found["pair"] = {
        "generation": int(pair.get("generation") or 1),
        "promotedAt": _iso(pair.get("promotedAt")),
        "promotedBy": pair.get("promotedBy") or "",
        "superseded": pair.get("superseded") or None,
        "asked": pair.get("asked") or None,
    }
    if found["role"] == role.STANDBY:
        found["standby"] = standby.status(db, now)
        found["loss"] = loss(found["standby"], now)
        return found
    state = config.held(db, config.ARCHIVE_SETTINGS_ID)
    doc = config.read(db)
    seen = state.get("archiver") or {}
    rows = list(db.scalars(select(RecoveryBase).order_by(RecoveryBase.created_at.desc())))
    disk = dict(state.get("disk") or {})
    held = kept.usage()
    disk["kept"], disk["keptFiles"] = held["bytes"], held["files"]
    oldest = state.get("oldest") or None
    alive = agent.alive(now)
    found |= {
        "archive": {
            "mode": seen.get("mode") or "",
            "on": seen.get("mode") in ("on", "always"),
            "stuck": bool(seen) and archive.stuck(seen),
            "lastWal": seen.get("lastWal") or "",
            "lastAt": _iso(seen.get("lastAt")),
            "failedWal": seen.get("failedWal") or "",
            "failedAt": _iso(seen.get("failedAt")),
            "waiting": int(seen.get("waiting") or 0),
            "waitingBytes": int(seen.get("waiting") or 0) * layout.SEGMENT_BYTES,
            "logBytes": int(seen.get("walBytes") or 0),
            "timeline": int(seen.get("timeline") or 0),
            "timeout": settings.ARCHIVE_TIMEOUT,
        },
        "window": {
            "oldest": _iso(oldest["at"]) if oldest else None,
            "newest": _iso(seen.get("lastAt")) if oldest else None,
        },
        "bases": [base_out(row) for row in rows if row.offsite_state != "delete"],
        "test": {
            "running": (state.get("test") or {}).get("state") == "running",
            "last": _test_out(state.get("tested")),
            "proven": _test_out(state.get("proven")),
        },
        "disk": disk | estimate(disk, rows, int(doc["keepDays"]), now),
        "service": {"alive": alive, "running": agent.running(now)},
        "copies": ship.status(db, now),
        "settings": config.out(db),
        "problems": watch.out(db),
        "command": command(float(seen["lastAt"]) - 60 if oldest and seen.get("lastAt") else None),
        "checked": _iso(state.get("at")),
    }
    return found


def _test_out(found: dict[str, Any] | None) -> dict[str, Any] | None:
    if not found:
        return None
    return {
        "state": found.get("state"),
        "at": _iso(found.get("at")),
        "target": _iso(found.get("target")),
        "base": found.get("base"),
        "seconds": found.get("seconds"),
        "auditSeq": found.get("auditSeq"),
        "error": found.get("error") or "",
    }


def loss(found: dict[str, Any], now: float | None = None) -> dict[str, Any]:
    """What a promotion of this standby would lose, as far as it can know. The first host said, in
    its last heartbeat, when it spoke and up to when its log had left it; this standby knows the
    last change it replayed. Everything written on the first host after the end of the last
    segment that arrived is not here."""
    now = time.time() if now is None else now
    beat = found.get("heartbeat") or {}
    replayed = (found.get("replay") or {}).get("lastChange")
    spoke = float(beat.get("at") or 0)
    waiting = int(found.get("waiting") or 0)
    lines = []
    if replayed:
        lines.append(f"The last change this standby holds was made at {_text(replayed)}.")
    else:
        lines.append("This standby has replayed no change yet.")
    if waiting:
        lines.append(
            f"{waiting} segment(s) of log that arrived are still to be replayed: a promotion replays them first."
        )
    if spoke:
        lines.append(f"The first host last spoke at {_text(spoke)} ({_ago(now - spoke)} ago).")
        gap = max(0.0, spoke - float(replayed or 0)) if replayed else None
        timeout = int(beat.get("archiveTimeout") or settings.ARCHIVE_TIMEOUT)
        if gap is not None:
            lines.append(
                f"A promotion now loses what the first host wrote after {_text(replayed)}: at least the "
                f"{_ago(gap)} before it last spoke, and whatever it wrote after that. With the first host "
                f"sending normally this is at most about {_ago(timeout + 30)}."
            )
    elif found.get("heartbeatRefused"):
        lines.append(
            "A heartbeat is here, but it is not signed with a key this host holds, so it is not believed: what the "
            "first host wrote after the last change above is lost by a promotion, and this standby cannot say how "
            "much that is. If SECRET_KEY was changed on the first host, carry its keys here again "
            "(deploy/standby.sh secrets export, then import)."
        )
    else:
        lines.append(
            "The first host has left no heartbeat here: what it wrote after the last change above is lost by a "
            "promotion, and this standby cannot say how much that is."
        )
    return {"lastChange": _iso(replayed), "heardAt": _iso(spoke) if spoke else None, "waiting": waiting, "lines": lines}


def _text(at: float) -> str:
    return datetime.fromtimestamp(float(at), timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _ago(seconds: float) -> str:
    from ..health.checks import lasted

    return lasted(seconds)


# --------------------------------------------------------------------------- #
# The health page                                                             #
# --------------------------------------------------------------------------- #
METRICS: dict[str, tuple[str, str]] = {
    "nik_recovery_archive_ok": (
        "gauge",
        "1 when PostgreSQL archives its log and the last attempt worked, 0 otherwise.",
    ),
    "nik_recovery_archive_last_timestamp_seconds": ("gauge", "When the last segment of the log was archived."),
    "nik_recovery_wal_waiting_bytes": ("gauge", "Bytes of log PostgreSQL has finished and not archived yet."),
    "nik_recovery_wal_bytes": ("gauge", "Bytes the log of PostgreSQL takes in its own directory."),
    "nik_recovery_archive_bytes": ("gauge", "Bytes the archive takes on its volume, by what they are."),
    "nik_recovery_oldest_timestamp_seconds": ("gauge", "The oldest moment the server can be brought back to."),
    "nik_recovery_base_last_timestamp_seconds": ("gauge", "When the last base backup was finished."),
    "nik_recovery_base_last_size_bytes": ("gauge", "Size of the last base backup."),
    "nik_recovery_test_ok": ("gauge", "1 when the last recovery test passed, 0 when it failed."),
    "nik_recovery_test_timestamp_seconds": ("gauge", "When the recovery to a moment was last proven."),
    "nik_recovery_service_up": ("gauge", "1 when the recovery service answered in the last two minutes."),
    "nik_recovery_problems": ("gauge", "Problems the watch of the recovery holds."),
    "nik_recovery_copy_behind_seconds": ("gauge", "How old what the second host holds is."),
    "nik_recovery_copy_behind_bytes": (
        "gauge",
        "Distance in the log between what is written and what is on the second host (an upper bound in bytes).",
    ),
    "nik_recovery_copy_link_ok": ("gauge", "1 when the second host was reached at the last pass, 0 when not."),
    "nik_recovery_store_files_waiting": ("gauge", "Files of the store that wait to be copied to the second host."),
    "nik_server_generation": ("gauge", "How many times a standby was promoted to become this server, plus one."),
    "nik_server_promoted_timestamp_seconds": ("gauge", "When this server was promoted from standby."),
    "nik_server_role": ("gauge", "The role of this server, as a label: primary, standby or superseded."),
}


def rows(db: OrmSession, now: float) -> list[dict[str, Any]]:
    """The rows of the health page. Nothing on a server without an archive volume."""
    from ..health.checks import ATTENTION, FINE, PROBLEM, UNKNOWN, lasted, row, size

    if not layout.available() or not archive.postgres(db):
        return []
    group, link = "Recovery", watch.LINK
    seen = overview(db, now)
    problems = {problem["id"]: problem["text"] for problem in seen.get("problems") or []}
    pair = seen["pair"]
    found = [
        row(
            "recovery.role",
            group,
            "Role of this server",
            {"primary": "The server", "standby": "Standby", "superseded": "Replaced"}[seen["role"]]
            + (
                f", promoted from standby on {pair['promotedAt'][:16].replace('T', ' ')} UTC"
                if pair["promotedAt"]
                else ""
            ),
            PROBLEM
            if seen["role"] == role.SUPERSEDED or "marker" in problems
            else ATTENTION
            if "asked" in problems
            else FINE,
            problems.get("marker") or problems.get("asked", ""),
            link=link,
            metrics=[
                ("nik_server_role", {"role": seen["role"]}, 1),
                ("nik_server_generation", {}, pair["generation"]),
                *(
                    [("nik_server_promoted_timestamp_seconds", {}, runner.stamp(pair["promotedAt"]))]
                    if pair["promotedAt"]
                    else []
                ),
            ],
        )
    ]
    if seen["role"] == role.STANDBY:
        return found
    log = seen["archive"]
    last = runner.stamp(log["lastAt"]) if log["lastAt"] else 0.0
    wrong = problems.get("archive") or problems.get("archive-off") or ""
    found.append(
        row(
            "recovery.archive",
            group,
            "Archive of the log",
            (
                "Off"
                if not log["on"]
                else "Stuck"
                if log["stuck"]
                else f"Last segment {lasted(now - last)} ago"
                if last
                else "On, no segment yet"
            )
            + (f"; {log['waiting']} segments wait to be archived" if log["waiting"] > 1 else ""),
            PROBLEM if wrong else ATTENTION if log["stuck"] else FINE if log["on"] else PROBLEM,
            wrong,
            link=link,
            metrics=[
                ("nik_recovery_archive_ok", {}, int(log["on"] and not log["stuck"])),
                ("nik_recovery_wal_waiting_bytes", {}, log["waitingBytes"]),
                ("nik_recovery_wal_bytes", {}, log["logBytes"]),
                *([("nik_recovery_archive_last_timestamp_seconds", {}, last)] if last else []),
                ("nik_recovery_problems", {}, len(problems)),
            ],
        )
    )
    done = [entry for entry in seen["bases"] if entry["state"] == "done" and entry["local"]]
    newest = done[0] if done else None
    oldest = runner.stamp(seen["window"]["oldest"]) if seen["window"]["oldest"] else 0.0
    wrong = problems.get("base") or problems.get("room") or ""
    found.append(
        row(
            "recovery.base",
            group,
            "Base backups",
            (
                f"{len(done)} kept, the last {lasted(now - runner.stamp(newest['finishedAt']))} ago "
                f"({size(newest['size'])}); "
                f"one can go back to {seen['window']['oldest'][:16].replace('T', ' ')} UTC"
                if newest and oldest
                else "None yet"
            ),
            PROBLEM if wrong else FINE if newest else UNKNOWN,
            wrong,
            link=link,
            metrics=[
                *(
                    [
                        ("nik_recovery_base_last_timestamp_seconds", {}, runner.stamp(newest["finishedAt"])),
                        ("nik_recovery_base_last_size_bytes", {}, newest["size"]),
                    ]
                    if newest
                    else []
                ),
                *([("nik_recovery_oldest_timestamp_seconds", {}, oldest)] if oldest else []),
                ("nik_recovery_archive_bytes", {"what": "log"}, int(seen["disk"].get("wal") or 0)),
                ("nik_recovery_archive_bytes", {"what": "base"}, int(seen["disk"].get("base") or 0)),
                ("nik_recovery_archive_bytes", {"what": "kept"}, int(seen["disk"].get("kept") or 0)),
            ],
        )
    )
    proven, tried = seen["test"]["proven"], seen["test"]["last"]
    found.append(
        row(
            "recovery.test",
            group,
            "Recovery proven",
            (
                f"To {proven['target'][:16].replace('T', ' ')} UTC, {lasted(now - runner.stamp(proven['at']))} ago"
                if proven
                else "Not yet"
            ),
            PROBLEM if "test" in problems else FINE if proven else UNKNOWN,
            problems.get("test", ""),
            link=link,
            metrics=[
                *([("nik_recovery_test_ok", {}, int(tried["state"] == "passed"))] if tried else []),
                *([("nik_recovery_test_timestamp_seconds", {}, runner.stamp(proven["at"]))] if proven else []),
            ],
        )
    )
    found.append(
        row(
            "recovery.service",
            group,
            "Recovery service",
            "Answers" if seen["service"]["running"] else "Does not answer",
            PROBLEM if "service" in problems else FINE if seen["service"]["running"] else ATTENTION,
            problems.get("service", ""),
            link="/settings/system/workers",
            metrics=[("nik_recovery_service_up", {}, int(seen["service"]["running"]))],
        )
    )
    copies = seen["copies"]
    if copies["on"]:
        behind = copies["behind"]
        link_state = copies.get("link") or {}
        wrong = problems.get("link") or problems.get("copies") or problems.get("behind") or ""
        found.append(
            row(
                "recovery.copies",
                group,
                "Second host",
                (
                    "Nothing is sent: the copies point at this host"
                    if copies.get("hold") == "own"
                    else "Not reached"
                    if link_state.get("ok") is False
                    else f"{lasted(behind['seconds'])} behind"
                    + (f" (at most {size(behind['bytes'])} of log)" if behind.get("bytes") else "")
                    + f"; {copies['store']['files']} files of the store wait"
                    if behind.get("seconds") is not None
                    else "Nothing sent yet"
                ),
                PROBLEM if wrong else FINE,
                wrong,
                link=link,
                metrics=[
                    ("nik_recovery_copy_link_ok", {}, int(link_state.get("ok") is not False)),
                    *(
                        [("nik_recovery_copy_behind_seconds", {}, behind["seconds"])]
                        if behind.get("seconds") is not None
                        else []
                    ),
                    *(
                        [("nik_recovery_copy_behind_bytes", {}, behind["bytes"])]
                        if behind.get("bytes") is not None
                        else []
                    ),
                    ("nik_recovery_store_files_waiting", {}, copies["store"]["files"]),
                ],
            )
        )
    return found

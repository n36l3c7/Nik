"""Every row of the health page.

A row is one thing an operator would otherwise have to go and look at::

    {"id": "disk.store", "group": "Disk", "label": "Store of files",
     "value": "62% used, 118.0 GB free of 320.0 GB",
     "state": "fine",              fine | attention | problem | unknown
     "detail": "…",                what the value means, and what to do when it is not fine
     "link": "/settings/system/storage",   the screen that has the whole story, when there is one
     "notify": True,               whether the administrators are told when its state changes
     "metrics": [("nik_disk_used_bytes", {"disk": "store"}, 1.2e11), …]}

``unknown`` is for what could not be measured (a directory that is not
there, a certificate nobody could read): it is said, never guessed.

The pages of Workers, Storage, Backup and the audit log are not repeated
here: a row sums one up and links to it. Rows whose trouble another watch
already tells the administrators about (a worker down, a backup that failed,
an archive that is stuck, a step a restart interrupted) have ``notify`` off:
nobody is told twice.

``gather`` computes every row from the database and the disks at the moment
it is called. What needs a memory (how fast a disk fills, since when a row is
in its state, the certificate read an hour ago) comes from what the watch
keeps (``watch.py``) and is passed in as ``kept``.
"""

from __future__ import annotations

import os
import shutil
import socket
import ssl
import time
from pathlib import Path
from typing import Any

from sqlalchemy import func, or_, select, text
from sqlalchemy.orm import Session as OrmSession

from ..core.clock import stamp
from ..core.clock import when as _when
from ..core.config import settings

LINK = "/settings/system/health"
FINE, ATTENTION, PROBLEM, UNKNOWN = "fine", "attention", "problem", "unknown"
WORSE = {UNKNOWN: 0, FINE: 0, ATTENTION: 1, PROBLEM: 2}
# The growth of a disk is read over this long, and needs this much of it to say anything.
GROWTH_WINDOW = 7 * 86400
GROWTH_NEEDS = 6 * 3600
TLS_TIMEOUT = 3
TLS_KEPT = 3600

# name: (type, help). Everything /api/metrics can say, besides the requests counted in observability.py.
METRICS: dict[str, tuple[str, str]] = {
    "nik_health_state": ("gauge", "State of a row of the health page: 0 fine, 1 attention, 2 problem, -1 unknown."),
    "nik_disk_total_bytes": ("gauge", "Size of the disk that holds a directory of the server."),
    "nik_disk_used_bytes": ("gauge", "Bytes used on the disk that holds a directory of the server."),
    "nik_disk_free_bytes": ("gauge", "Bytes free on the disk that holds a directory of the server."),
    "nik_disk_growth_bytes_per_day": ("gauge", "How fast the disk fills, measured over the last days."),
    "nik_disk_full_in_seconds": ("gauge", "Time left before the disk is full at this rate (absent when not filling)."),
    "nik_database_size_bytes": ("gauge", "Size of the database."),
    "nik_database_growth_bytes_per_day": ("gauge", "How fast the database grows, measured over the last days."),
    "nik_database_connections": ("gauge", "Connections open on the database of Nik."),
    "nik_database_connections_max": ("gauge", "Connections the database server accepts."),
    "nik_database_pool_in_use": ("gauge", "Connections of the pool of this API process that are in use."),
    "nik_database_pool_size": ("gauge", "Connections the pool of this API process may open."),
    "nik_database_longest_transaction_seconds": ("gauge", "Age of the oldest open transaction."),
    "nik_database_revision_current": ("gauge", "1 when the database is at the revision this version expects."),
    "nik_clock_skew_seconds": ("gauge", "Clock of the server minus clock of the database."),
    "nik_queue_waiting": ("gauge", "Items of a queue that wait."),
    "nik_queue_running": ("gauge", "Items of a queue that are being done."),
    "nik_queue_oldest_seconds": ("gauge", "How long the oldest waiting item of a queue has waited."),
    "nik_playbook_runs": ("gauge", "Playbook runs the server keeps, by state."),
    "nik_schedules": ("gauge", "Schedules of playbooks."),
    "nik_schedules_late": ("gauge", "Schedules whose time has passed without a run."),
    "nik_fetch_instances": ("gauge", "Instances that fetch, by state."),
    "nik_work_held": ("gauge", "Pieces of work an API process holds now (analyses, scans, mailboxes)."),
    "nik_work_interrupted": ("gauge", "Steps of playbooks a restart interrupted that wait for a person to say."),
    "nik_work_interrupted_oldest_seconds": ("gauge", "How long the oldest of them has waited."),
    "nik_work_set_aside": ("gauge", "Pieces of work set aside after they were interrupted, not tried again."),
    "nik_work_silent_seconds": ("gauge", "Age of the oldest sign of life among the work that is held."),
    "nik_worker_up": ("gauge", "1 when a worker answered its last check, 0 when it did not."),
    "nik_automation_heartbeat_age_seconds": ("gauge", "Time since the automation worker last said it was alive."),
    "nik_backup_last_good_age_seconds": ("gauge", "Age of the last backup that passed its restore test."),
    "nik_backup_last_good_size_bytes": ("gauge", "Size of the last backup that passed its restore test."),
    "nik_backup_problems": ("gauge", "Problems the watch of the backups holds."),
    "nik_backup_next_run_timestamp_seconds": ("gauge", "When the next backup is due."),
    "nik_upgrade_snapshots": ("gauge", "Snapshots taken before upgrades that are on the server."),
    "nik_certificate_expiry_timestamp_seconds": ("gauge", "When the certificate of the web container expires."),
    "nik_audit_entries_total": ("counter", "Entries ever linked into the chain of the audit log."),
    "nik_audit_entries": ("gauge", "Entries the audit log holds."),
    "nik_audit_chain_ok": ("gauge", "1 when the last walk of the chain found nothing wrong, 0 when it found a break."),
    "nik_audit_chain_verified_timestamp_seconds": ("gauge", "When the chain was last walked without a problem."),
    "nik_audit_forward_enabled": ("gauge", "1 when the audit log is forwarded to syslog."),
    "nik_audit_forward_backlog": ("gauge", "Entries that wait to be sent to the syslog receiver."),
    "nik_audit_forward_oldest_seconds": ("gauge", "How long the oldest entry has waited to be sent."),
    "nik_audit_forward_sent_total": ("counter", "Entries sent to the current syslog receiver."),
    "nik_signin_failures_total": ("counter", "Failed sign-ins the audit log holds."),
    "nik_signin_waiting": ("gauge", "Accounts and addresses that must wait before the next sign-in attempt."),
    "nik_administrators_without_second_factor": ("gauge", "Administrators that have no second factor."),
    "nik_keys_in_environment": ("gauge", "Secrets of the server that are in the environment of its containers."),
    "nik_key_rotation_state": ("gauge", "Where a change of a key stands: 0 none, 1 half-way, 2 failed."),
    "nik_key_rotated_timestamp_seconds": ("gauge", "When a key of the server last changed."),
    "nik_audit_entries_unchecked": ("gauge", "Entries of the audit log whose key this server cannot make."),
    "nik_store_encrypted": ("gauge", "1 when every file of the store is sealed, 0 while some are in clear."),
    "nik_store_files_in_clear": ("gauge", "Files of the store that are still to be sealed."),
    "nik_store_bytes_in_clear": ("gauge", "Bytes of the store that are still to be sealed."),
    "nik_store_files_stuck": ("gauge", "Files of the store the server could not seal."),
    "nik_store_files_damaged": ("gauge", "Files of the store that failed their check."),
    "nik_info": ("gauge", "The version of Nik, as a label."),
}  # fmt: skip


def _recovery_metrics() -> None:
    """What the recovery to a moment and the standby can say (app/recovery/status.py lists them)."""
    from ..recovery import status

    METRICS.update(status.METRICS)


def size(count: float) -> str:
    """A number of bytes as a person reads it."""
    count = float(count)
    for unit in ("bytes", "KB", "MB", "GB", "TB"):
        if abs(count) < 1024 or unit == "TB":
            return f"{int(count)} bytes" if unit == "bytes" else f"{count:.1f} {unit}"
        count /= 1024
    return ""


def lasted(seconds: float) -> str:
    """A length of time in words: "40 seconds", "12 minutes", "3 hours", "5 days"."""
    seconds = max(0.0, float(seconds))
    for unit, length in (("day", 86400), ("hour", 3600), ("minute", 60)):
        if seconds >= length:
            count = round(seconds / length)
            return f"{count} {unit}" + ("" if count == 1 else "s")
    count = round(seconds)
    return f"{count} second" + ("" if count == 1 else "s")


def rising(value: float, attention: float, problem: float) -> str:
    """The state of a value that is worse when larger."""
    return PROBLEM if value >= problem else ATTENTION if value >= attention else FINE


def row(
    row_id: str,
    group: str,
    label: str,
    value: str,
    state: str = FINE,
    detail: str = "",
    *,
    link: str = "",
    notify: bool = False,
    metrics: list[tuple[str, dict[str, str], float]] | None = None,
) -> dict[str, Any]:
    return {
        "id": row_id,
        "group": group,
        "label": label,
        "value": value,
        "state": state,
        "detail": detail,
        "link": link,
        "notify": notify,
        "metrics": metrics or [],
    }


# --------------------------------------------------------------------------- #
# Disks                                                                       #
# --------------------------------------------------------------------------- #
def disk_usage(path: str):
    """The disk a directory is on (replaced in tests)."""
    return shutil.disk_usage(path)


def growth(samples: list, now: float) -> float | None:
    """Bytes a day, from the samples ``[[time, bytes], …]`` of the last days: the slope of the
    line through them. None while they do not cover enough time to say."""
    recent = [(float(at), float(used)) for at, used in samples if now - float(at) <= GROWTH_WINDOW]
    if len(recent) < 3 or recent[-1][0] - recent[0][0] < GROWTH_NEEDS:
        return None
    mean_at = sum(at for at, _ in recent) / len(recent)
    mean_used = sum(used for _, used in recent) / len(recent)
    spread = sum((at - mean_at) ** 2 for at, _ in recent)
    if not spread:
        return None
    return sum((at - mean_at) * (used - mean_used) for at, used in recent) / spread * 86400


def _disk(
    name: str,
    label: str,
    path: str,
    link: str,
    kept: dict[str, Any],
    limits: dict[str, int],
    now: float,
    measured: Any = None,
) -> dict[str, Any]:
    """``measured``: the disk as another process measured it, for a process that does not see it."""
    row_id = f"disk.{name}"
    try:
        disk = measured or disk_usage(path)
    except OSError as error:
        return row(row_id, "Disk", label, "Not readable", UNKNOWN, f"{path}: {error.strerror or error}", link=link)
    if not disk.total:
        return row(row_id, "Disk", label, "Not readable", UNKNOWN, f"{path} reports no size", link=link)
    used = disk.total - disk.free
    percent = used * 100 / disk.total
    rate = growth((kept.get("disks") or {}).get(name) or [], now)
    state = rising(percent, limits["diskAttentionPercent"], limits["diskProblemPercent"])
    metrics = [
        ("nik_disk_total_bytes", {"disk": name}, disk.total),
        ("nik_disk_used_bytes", {"disk": name}, used),
        ("nik_disk_free_bytes", {"disk": name}, disk.free),
    ]
    if rate is None:
        detail = "How fast it fills is not known yet: it is measured over the coming hours."
    else:
        metrics.append(("nik_disk_growth_bytes_per_day", {"disk": name}, rate))
        if rate * 30 < disk.total / 10000:
            detail = "It is not filling."
        else:
            days = disk.free / rate
            metrics.append(("nik_disk_full_in_seconds", {"disk": name}, days * 86400))
            detail = f"It fills by {size(rate)} a day: full in about {lasted(days * 86400)} at this rate."
            if days <= limits["diskFullProblemDays"]:
                state = PROBLEM
            elif days <= limits["diskFullAttentionDays"]:
                state = max(state, ATTENTION, key=WORSE.get)
    if state != FINE:
        detail += " Free some room or give it a larger disk before it is full: a full disk stops uploads and backups."
    value = f"{percent:.0f}% used, {size(disk.free)} free of {size(disk.total)}"
    return row(row_id, "Disk", label, value, state, detail, link=link, notify=True, metrics=metrics)


STORE_DISK_FRESH = 3600


def _store_disk(db: OrmSession, path: str, kept: dict[str, Any], limits: dict[str, int], now: float) -> dict[str, Any]:
    """The disk of the store of files. The automation worker looks at the health of the server too,
    and is given neither the store nor its key: at the path of the store it would measure its own
    container. It reads what the backend last measured instead (``store_seal.disk_seen``), and says
    so when that is old."""
    from collections import namedtuple

    from .. import store_seal
    from ..core import store as sealed_store

    name, label, link = "store", "Store of files", "/settings/system/storage"
    if sealed_store.local():
        return _disk(name, label, path, link, kept, limits, now)
    seen = store_seal.disk_seen(db)
    if not seen or now - float(seen.get("at") or 0) > STORE_DISK_FRESH or not seen.get("total"):
        return row(
            f"disk.{name}",
            "Disk",
            label,
            "Not known here",
            UNKNOWN,
            "This process is not given the store of files: the backend measures its disk, and has not for an hour.",
            link=link,
        )
    total, free = int(seen["total"]), int(seen.get("free") or 0)
    disk = namedtuple("Disk", "total used free")(total, total - free, free)
    return _disk(name, label, path, link, kept, limits, now, measured=disk)


# --------------------------------------------------------------------------- #
# The database                                                                #
# --------------------------------------------------------------------------- #
def database_facts(db: OrmSession) -> dict[str, Any]:
    """What the database says of itself (replaced in tests)."""
    from ..core.db import engine

    facts: dict[str, Any] = {"engine": engine.dialect.name}
    if engine.dialect.name == "postgresql":
        facts["version"] = db.execute(text("SHOW server_version")).scalar()
        facts["bytes"] = int(db.execute(text("SELECT pg_database_size(current_database())")).scalar() or 0)
        facts["connections"] = int(
            db.execute(text("SELECT count(*) FROM pg_stat_activity WHERE datname = current_database()")).scalar() or 0
        )
        facts["maxConnections"] = int(db.execute(text("SHOW max_connections")).scalar() or 0)
        # A backup reads the whole database in one transaction, for as long as that takes: it is
        # not what this row is for. Its connection is known by the advisory lock a dump holds
        # (backups/database.py; the upgrade holds the same one). The rehearsal of an upgrade and
        # the restore test run in scratch databases, which the first condition leaves out already.
        from ..backups.database import MIGRATION_LOCK

        facts["longest"] = float(
            db.execute(
                text(
                    "SELECT coalesce(max(extract(epoch FROM clock_timestamp() - xact_start)), 0) "
                    "FROM pg_stat_activity WHERE datname = current_database() AND xact_start IS NOT NULL "
                    "AND state <> 'idle' AND pid <> pg_backend_pid() AND pid NOT IN ("
                    "SELECT pid FROM pg_locks WHERE locktype = 'advisory' AND granted AND objsubid = 1 "
                    "AND classid = :high AND objid = :low)"
                ),
                {"high": MIGRATION_LOCK >> 32, "low": MIGRATION_LOCK & 0xFFFFFFFF},
            ).scalar()
            or 0
        )
        facts["clock"] = float(db.execute(text("SELECT extract(epoch FROM clock_timestamp())")).scalar())
        pool = engine.pool
        facts["poolInUse"] = pool.checkedout()
        facts["poolSize"] = settings.DB_POOL_SIZE + settings.DB_MAX_OVERFLOW
    else:
        facts["version"] = db.execute(text("SELECT sqlite_version()")).scalar()
        path = engine.url.database or ""
        facts["bytes"] = os.path.getsize(path) if path and os.path.exists(path) else 0
        facts["clock"] = float(db.execute(text("SELECT (julianday('now') - 2440587.5) * 86400.0")).scalar())
    try:
        facts["revision"] = db.execute(text("SELECT version_num FROM alembic_version")).scalar()
    except Exception:  # noqa: BLE001 - a development database made without the migrations has no such table
        db.rollback()
        facts["revision"] = None
    return facts


def head_revision() -> str:
    from ..backups import database

    return database.head_revision()


def _database(db: OrmSession, kept: dict[str, Any], limits: dict[str, int], now: float) -> list[dict[str, Any]]:
    group = "Database"
    before = time.time()
    try:
        facts = database_facts(db)
    except Exception as error:  # noqa: BLE001 - the page says what it could not read
        db.rollback()
        return [row("db.version", group, "Database", "Not readable", UNKNOWN, f"{type(error).__name__}: {error}"[:300])]
    took = time.time() - before
    name = "PostgreSQL" if facts["engine"] == "postgresql" else "SQLite"
    rows = [row("db.version", group, "Engine", f"{name} {facts.get('version')}")]
    rate = growth((kept.get("disks") or {}).get("database") or [], now)
    metrics = [("nik_database_size_bytes", {}, facts["bytes"])]
    if rate is not None:
        metrics.append(("nik_database_growth_bytes_per_day", {}, rate))
    rows.append(
        row(
            "db.size",
            group,
            "Size",
            size(facts["bytes"]),
            FINE,
            (f"It grows by {size(rate)} a day. " if rate is not None and rate > 0 else "")
            + "The disk it is on belongs to the database container and cannot be read from here: watch the "
            "volume of the database on the host.",
            metrics=metrics,
        )
    )
    if "connections" in facts:
        share = facts["connections"] * 100 / facts["maxConnections"] if facts["maxConnections"] else 0
        state = rising(share, limits["connectionsAttentionPercent"], limits["connectionsProblemPercent"])
        rows.append(
            row(
                "db.connections",
                group,
                "Connections",
                f"{facts['connections']} of {facts['maxConnections']} in use",
                state,
                ""
                if state == FINE
                else "The database is close to refusing connections: look for a process that opens them without "
                "closing them, or raise max_connections.",
                notify=True,
                metrics=[
                    ("nik_database_connections", {}, facts["connections"]),
                    ("nik_database_connections_max", {}, facts["maxConnections"]),
                ],
            )
        )
        full = facts["poolSize"] and facts["poolInUse"] >= facts["poolSize"]
        rows.append(
            row(
                "db.pool",
                group,
                "Pool of this process",
                f"{facts['poolInUse']} of {facts['poolSize']} in use",
                PROBLEM if full else FINE,
                "Every connection of the pool is taken: requests wait for one. Raise DB_POOL_SIZE or "
                "DB_MAX_OVERFLOW, or look for what holds them."
                if full
                else "Each API process has a pool of its own: this is the one that answered.",
                notify=True,
                metrics=[
                    ("nik_database_pool_in_use", {}, facts["poolInUse"]),
                    ("nik_database_pool_size", {}, facts["poolSize"]),
                ],
            )
        )
        long = facts["longest"] >= limits["transactionAttentionMinutes"] * 60
        rows.append(
            row(
                "db.transactions",
                group,
                "Longest transaction",
                lasted(facts["longest"]) if facts["longest"] >= 1 else "None open",
                ATTENTION if long else FINE,
                "A transaction that stays open keeps the database from cleaning up after itself: find it in "
                "pg_stat_activity."
                if long
                else "",
                notify=True,
                metrics=[("nik_database_longest_transaction_seconds", {}, facts["longest"])],
            )
        )
    try:
        head = head_revision()
    except Exception:  # noqa: BLE001 - no migrations beside the code (a test): nothing to compare
        head = None
    revision = facts.get("revision")
    if revision is None:
        rows.append(
            row(
                "db.revision",
                group,
                "Schema",
                "Not under migrations",
                UNKNOWN,
                "A development database: made without Alembic.",
            )
        )
    else:
        same = head is None or revision == head
        rows.append(
            row(
                "db.revision",
                group,
                "Schema",
                revision if same else f"{revision}, and this version expects {head}",
                FINE if same else PROBLEM,
                ""
                if same
                else "The database is not the one this version of Nik was written for: restart the "
                "server so that it migrates, and read its log if it stops.",
                metrics=[("nik_database_revision_current", {}, 1 if same else 0)],
            )
        )
    # Asked in the middle of the reading above: half of what that took is the most the answer is off by.
    skew = (before + took / 2) - facts["clock"]
    state = rising(abs(skew), limits["clockAttentionSeconds"], limits["clockProblemSeconds"])
    rows.append(
        row(
            "clock.skew",
            "Server",
            "Clock against the database",
            "The same" if abs(skew) < 1 else f"{lasted(abs(skew))} {'ahead' if skew > 0 else 'behind'}",
            state,
            ""
            if state == FINE
            else "The server and the database do not agree on the time: sessions, schedules and the times of "
            "the audit log go by it. Synchronise the clock of the host.",
            notify=True,
            metrics=[("nik_clock_skew_seconds", {}, skew)],
        )
    )
    return rows


# --------------------------------------------------------------------------- #
# Queues                                                                      #
# --------------------------------------------------------------------------- #
def _queue(
    name: str,
    label: str,
    waiting: int,
    running: int | None,
    oldest: float,
    limits: dict[str, int],
    *,
    detail: str = "",
    link: str = "",
    who: str = "",
    worst: str = FINE,
) -> dict[str, Any]:
    """A queue: how many wait, how many are being done, how long the oldest has waited."""
    oldest = max(0.0, oldest) if waiting else 0.0
    state = rising(oldest / 60, limits["queueAttentionMinutes"], limits["queueProblemMinutes"]) if waiting else FINE
    state = max(state, worst, key=WORSE.get)
    parts = [f"{waiting} waiting"]
    if running is not None:
        parts.append(f"{running} running")
    if waiting and oldest >= 1:
        parts.append(f"the oldest for {lasted(oldest)}")
    if state != FINE and who and not detail:
        detail = f"{who} Its state is in Settings → System → Workers."
    metrics = [("nik_queue_waiting", {"queue": name}, waiting), ("nik_queue_oldest_seconds", {"queue": name}, oldest)]
    if running is not None:
        metrics.append(("nik_queue_running", {"queue": name}, running))
    return row(
        f"queue.{name}", "Queues", label, ", ".join(parts), state, detail, link=link, notify=True, metrics=metrics
    )


def _queues(db: OrmSession, limits: dict[str, int], now: float) -> list[dict[str, Any]]:
    from .. import urlscan_queue
    from ..automation import state as automation_state
    from ..core.models import (
        ArtifactJob,
        AutomationEvent,
        AutomationSchedule,
        Backup,
        Connection,
        IocCheck,
        Job,
        MirrorJob,
        Run,
        RunStep,
        UrlScan,
    )

    rows = []
    api = "The API process takes these: look at its container (docker compose logs api)."
    worker = "The automation worker takes these."
    switched_on = automation_state.enabled(db)

    counts = dict(db.execute(select(ArtifactJob.status, func.count()).group_by(ArtifactJob.status)).all())
    oldest = db.execute(select(func.min(ArtifactJob.created_epoch)).where(ArtifactJob.status == "queued")).scalar()
    rows.append(
        _queue(
            "artifact_jobs",
            "What playbooks ask about files",
            counts.get("queued", 0),
            counts.get("running", 0),
            now - float(oldest or now),
            limits,
            who=api,
        )
    )

    scans = [
        scan for scan in db.scalars(select(UrlScan).where(UrlScan.status == "queued")) if urlscan_queue.asked(scan)
    ]
    asked_at = [stamp((scan.result or {}).get("startedAt")) or stamp(scan.created_at) for scan in scans]
    running = db.execute(select(func.count()).select_from(UrlScan).where(UrlScan.status == "running")).scalar() or 0
    rows.append(
        _queue(
            "url_scans",
            "Scans of addresses playbooks ask for",
            len(scans),
            running,
            now - min(asked_at) if asked_at else 0,
            limits,
            who=api,
        )
    )

    counts = dict(db.execute(select(Job.status, func.count()).group_by(Job.status)).all())
    oldest = db.execute(select(func.min(Job.created_at)).where(Job.status.in_(("queued", "running")))).scalar()
    rows.append(
        _queue(
            "uploads",
            "Uploads parsed in the background",
            counts.get("queued", 0) + counts.get("running", 0),
            None,
            now - (stamp(oldest) or now),
            limits,
            detail="An upload that was being parsed when the server restarted fails within a minute, and says to "
            "upload the file again.",
        )
    )

    by_state = dict(db.execute(select(Run.status, func.count()).group_by(Run.status)).all())
    due = or_(RunStep.status == "pending", (RunStep.status == "waiting") & RunStep.next_at.isnot(None))
    steps = db.execute(select(func.count(), func.min(RunStep.next_at)).where(due, RunStep.next_at <= now)).one()
    found = _queue(
        "playbook_steps",
        "Steps of playbooks that are due",
        int(steps[0] or 0) if switched_on else 0,
        by_state.get("running", 0),
        now - float(steps[1] or now),
        limits,
        who=worker,
        link="/automation/runs",
    )
    found["value"] += f"; {by_state.get('waiting', 0)} runs wait for a person"
    if not switched_on:
        found["value"] = "Automation is stopped (Settings → Automation → Stop all)"
    found["metrics"] += [("nik_playbook_runs", {"state": str(name)}, count) for name, count in sorted(by_state.items())]
    rows.append(found)

    events = db.execute(
        select(func.count(), func.min(AutomationEvent.created_at)).where(AutomationEvent.done.is_(False))
    ).one()
    rows.append(
        _queue(
            "events",
            "Events that start playbooks",
            int(events[0] or 0) if switched_on else 0,
            None,
            now - (stamp(events[1]) or now),
            limits,
            who=worker,
        )
    )

    total = db.execute(select(func.count()).select_from(AutomationSchedule)).scalar() or 0
    grace = limits["lateAttentionMinutes"] * 60
    late = db.execute(
        select(func.count(), func.min(AutomationSchedule.next_at)).where(AutomationSchedule.next_at < now - grace)
    ).one()
    behind = now - float(late[1] or now) if late[0] and switched_on else 0.0
    state = FINE if not behind else PROBLEM if behind >= limits["lateProblemMinutes"] * 60 else ATTENTION
    rows.append(
        row(
            "queue.schedules",
            "Queues",
            "Schedules of playbooks",
            f"{total} set"
            + ("" if switched_on else ", automation is stopped")
            + (f", {late[0]} late, the latest by {lasted(behind)}" if behind else ""),
            state,
            f"{worker} Its state is in Settings → System → Workers." if behind else "",
            notify=True,
            metrics=[("nik_schedules", {}, total), ("nik_schedules_late", {}, int(late[0] or 0) if behind else 0)],
        )
    )

    states = {"ok": 0, "failing": 0, "paused": 0}
    latest = 0.0
    for connection in db.scalars(
        select(Connection).where(Connection.fetch_enabled.is_(True), Connection.enabled.is_(True))
    ):
        status = connection.fetch_status or {}
        name = status.get("state") if status.get("state") in states else "ok"
        states[name] += 1
        if name != "paused" and switched_on:
            latest = max(latest, now - float(status.get("nextAt") or now))
    fetching = sum(states.values())
    state = FINE
    if latest >= grace:
        state = PROBLEM if latest >= limits["lateProblemMinutes"] * 60 else ATTENTION
    elif states["failing"] or states["paused"]:
        state = ATTENTION
    said = [f"{fetching} {'instance fetches' if fetching == 1 else 'instances fetch'}"]
    said += [f"{states[name]} {name}" for name in ("failing", "paused") if states[name]]
    if latest >= grace:
        said.append(f"the latest cycle is {lasted(latest)} late")
    rows.append(
        row(
            "queue.fetch",
            "Queues",
            "Fetching",
            ", ".join(said),
            state,
            "" if state == FINE else "Each instance says why on its Fetch tab (Settings → Automation → Connectors).",
            link="/settings/automation/connectors",
            notify=True,
            metrics=[("nik_fetch_instances", {"state": name}, count) for name, count in states.items()]
            + [("nik_queue_oldest_seconds", {"queue": "fetch"}, latest if latest >= grace else 0)],
        )
    )

    checks = list(db.scalars(select(IocCheck).where(IocCheck.status.in_(("running", "waiting")))))
    left = sum(len(check.pending or []) for check in checks)
    still = max((now - (stamp(check.updated_at) or now) for check in checks), default=0.0)
    rows.append(
        _queue(
            "lookups",
            "Look-ups of indicators asked in bulk",
            left,
            None,
            still,
            limits,
            detail="A check waits while every source is out of its quota: it goes on by itself."
            if any(check.status == "waiting" for check in checks)
            else "",
            link="/iocs",
        )
    )

    pending = db.execute(
        select(func.count(), func.min(MirrorJob.next_at)).where(MirrorJob.status == "pending", MirrorJob.next_at <= now)
    ).one()
    failed = db.execute(select(func.count()).select_from(MirrorJob).where(MirrorJob.status == "failed")).scalar() or 0
    found = _queue(
        "mirror",
        "Changes to send to mirrored systems",
        int(pending[0] or 0) if switched_on else 0,
        None,
        now - float(pending[1] or now),
        limits,
        who=worker,
        worst=ATTENTION if failed else FINE,
        detail=f"{failed} could not be sent after every attempt: the incident says which." if failed else "",
    )
    rows.append(found)

    copies = list(
        db.scalars(
            select(Backup).where(
                Backup.state == "done", Backup.local.is_(True), Backup.offsite_state.in_(("pending", "failed"))
            )
        )
    )
    waits = [
        now - (stamp(copy.finished_at or copy.created_at) or now) for copy in copies if copy.offsite_state == "pending"
    ]
    failed = sum(1 for copy in copies if copy.offsite_state == "failed")
    found = _queue(
        "backup_copies",
        "Copies of backups off the server",
        len(waits),
        None,
        max(waits, default=0.0),
        limits,
        link="/settings/system/backup",
        worst=ATTENTION if failed else FINE,
        detail=f"{failed} failed: Settings → System → Backup says why." if failed else "",
    )
    # A copy of gigabytes takes its time, and the watch of the backups tells when one fails or waits for hours.
    found["notify"] = False
    if not failed:
        found["state"] = FINE
    rows.append(found)
    return rows


# --------------------------------------------------------------------------- #
# Work in progress across restarts                                            #
# --------------------------------------------------------------------------- #
# A piece of work is taken back after work.STALE_AFTER seconds without a sign of life: twice that
# without anybody taking it back is the sweeper not doing its part, ten minutes is a problem.
SILENT_ATTENTION, SILENT_PROBLEM = 120, 600


def _work(db: OrmSession, now: float) -> list[dict[str, Any]]:
    """What restarts left behind: what waits for a person, what was given up, what nobody holds."""
    from .. import work
    from ..automation import worker as automation_worker
    from ..core.models import MirrorJob, RunStep

    rows = []
    group = "Work in progress"
    waiting = list(db.scalars(select(RunStep).where(RunStep.status == "interrupted")))
    since = []
    for step in waiting:
        asked = next((line for line in reversed(step.restarts or []) if line.get("what") == "waiting"), None)
        since.append(stamp(asked["at"]) if asked else now)
    oldest = now - min(since) if since else 0.0
    said = "None"
    if waiting:
        said = f"{len(waiting)} {'step waits' if len(waiting) == 1 else 'steps wait'}, the oldest for {lasted(oldest)}"
    rows.append(
        row(
            "work.interrupted",
            group,
            "Steps a restart interrupted that wait for a person",
            said,
            ATTENTION if waiting else FINE,
            "The worker stopped while each of them called another system, and Nik does not know whether the call "
            "was made: it does not repeat it. Open the run and say what happened: it happened, it did not, or stop."
            if waiting
            else "",
            link="/automation/runs?status=interrupted",
            # Each of these steps told the people who can answer it when it was interrupted
            # (tasks.notify_interrupted): the row shows them, and tells nobody a second time.
            metrics=[
                ("nik_work_interrupted", {}, len(waiting)),
                ("nik_work_interrupted_oldest_seconds", {}, oldest),
            ],
        )
    )

    facts = work.facts(db, now)
    kinds = work.kinds()
    by_kind: dict[str, int] = {}
    for kind, _ref in facts["aside"]:
        by_kind[kind] = by_kind.get(kind, 0) + 1
    unsent = (
        db.execute(
            select(func.count())
            .select_from(MirrorJob)
            .where(MirrorJob.status == "failed", MirrorJob.error.like("%restart%"))
        ).scalar()
        or 0
    )
    aside = sum(by_kind.values())
    parts = [f"{count} × {kinds[kind].label if kind in kinds else kind}" for kind, count in sorted(by_kind.items())] + (
        [f"{unsent} × a comment to a mirrored system that was not sent again"] if unsent else []
    )
    rows.append(
        row(
            "work.aside",
            group,
            "Work set aside after it was interrupted",
            "; ".join(parts) if parts else "None",
            ATTENTION if aside or unsent else FINE,
            f"Work that was interrupted {work.MAX_ATTEMPTS} times is not started again by itself: it may be what "
            "stops its worker (look at the log of that container). Each says so where it is shown, and can be "
            "asked for again there. A row is kept here for a week."
            if aside or unsent
            else "",
            notify=True,
            metrics=[("nik_work_set_aside", {}, aside + unsent)],
        )
    )

    # Steps that are running under a worker that is not the one alive, or past their time: nobody
    # took them back yet.
    silent = float(facts["silent"])
    for step in db.scalars(select(RunStep).where(RunStep.status == "running", RunStep.claimed_at.isnot(None))):
        late = now - float(step.claimed_at or now) - float(step.timeout_s or 60) - automation_worker.LEASE_SECONDS
        silent = max(silent, late)
    silent = max(0.0, silent)
    state = PROBLEM if silent >= SILENT_PROBLEM else ATTENTION if silent >= SILENT_ATTENTION else FINE
    rows.append(
        row(
            "work.silent",
            group,
            "Oldest work held without a sign of life",
            f"{facts['held']} held, "
            + ("all alive" if silent < work.STALE_AFTER else f"one silent for {lasted(silent)}"),
            state,
            "Work whose holder is gone is taken back within a minute, by an API process (the analyses) or by the "
            "automation worker (the steps of playbooks). This one was not: see whether both run "
            "(Settings → System → Workers)."
            if state != FINE
            else "",
            link="/settings/system/workers",
            notify=True,
            metrics=[("nik_work_held", {}, facts["held"]), ("nik_work_silent_seconds", {}, silent)],
        )
    )
    return rows


# --------------------------------------------------------------------------- #
# Workers                                                                     #
# --------------------------------------------------------------------------- #
def _workers(db: OrmSession, limits: dict[str, int], now: float) -> list[dict[str, Any]]:
    from .. import worker_watch
    from ..automation import state as automation_state

    link = "/settings/system/workers"
    rows = []
    for worker in worker_watch.out(db)["workers"]:
        if not worker["configured"]:
            continue
        state = {"up": FINE, "failing": ATTENTION, "down": PROBLEM}.get(worker["state"], UNKNOWN)
        value = {"up": "Answers", "failing": "Does not answer", "down": "Down"}.get(worker["state"], "Not checked yet")
        since = stamp(worker["since"])
        if state != FINE and since:
            value += f" for {lasted(now - since)}"
        metrics = [] if state == UNKNOWN else [("nik_worker_up", {"worker": worker["id"]}, 1 if state == FINE else 0)]
        label = worker["label"][:1].upper() + worker["label"][1:]
        detail = "" if state in (FINE, UNKNOWN) else f"While it is down, {worker['waits']}. Look at its container."
        rows.append(row(f"worker.{worker['id']}", "Workers", label, value, state, detail, link=link, metrics=metrics))
    if settings.AUTOMATION_WORKER != "off":
        beat = float(automation_state.read(db).get("heartbeat") or 0)
        age = now - beat if beat else None
        late = age is None or age >= limits["heartbeatAttentionSeconds"]
        rows.append(
            row(
                "worker.heartbeat",
                "Workers",
                "Last sign of life of the automation worker",
                "None yet" if age is None else f"{lasted(age)} ago",
                (UNKNOWN if age is None else ATTENTION) if late else FINE,
                "It says it is alive every ten seconds. Playbooks, fetching, the copies of the backups and the "
                "forwarding of the audit log wait for it."
                if late
                else "",
                link=link,
                metrics=[] if age is None else [("nik_automation_heartbeat_age_seconds", {}, age)],
            )
        )
    return rows


# --------------------------------------------------------------------------- #
# Backups                                                                     #
# --------------------------------------------------------------------------- #
def _backups(db: OrmSession, now: float) -> list[dict[str, Any]]:
    from ..backups import config, policy, runner, watch
    from ..core.models import Backup

    link = "/settings/system/backup"
    group = "Backups"
    doc = config.read(db)
    problems = {problem["id"]: problem["text"] for problem in watch.out(db)}
    good = runner.last_good(db)
    wrong = [problems[name] for name in ("unset", "failed", "missed", "stale") if name in problems]
    metrics = [("nik_backup_problems", {}, len(problems))]
    if good is not None:
        age = now - runner.stamp(good.created_at)
        metrics += [("nik_backup_last_good_age_seconds", {}, age), ("nik_backup_last_good_size_bytes", {}, good.size)]
        value = f"{lasted(age)} ago ({good.id}, {size(good.size)})"
    else:
        value = "None yet"
    rows = [
        row(
            "backup.last",
            group,
            "Last good backup",
            value,
            PROBLEM if wrong else FINE if good is not None or not doc.get("passphrase") else UNKNOWN,
            " ".join(wrong)
            if wrong
            else ""
            if good is not None
            else "A backup is good once it passed its restore test.",
            link=link,
            metrics=metrics,
        )
    ]
    tested = db.scalars(
        select(Backup).where(Backup.verified_at.isnot(None)).order_by(Backup.verified_at.desc()).limit(1)
    ).first()
    if tested is not None:
        passed = tested.verify_state == "passed"
        rows.append(
            row(
                "backup.test",
                group,
                "Last restore test",
                f"{'Passed' if passed else 'Failed'} {lasted(now - runner.stamp(tested.verified_at))} ago "
                f"({tested.id})",
                FINE if passed or "verify" not in problems else PROBLEM,
                problems.get("verify", ""),
                link=link,
            )
        )
    ready = bool(doc.get("passphrase")) and config.passphrase(db) is not None
    upcoming = policy.next_slot(doc["schedule"], now) if ready else None
    rows.append(
        row(
            "backup.next",
            group,
            "Next backup",
            f"In {lasted(upcoming - now)} ({_when(upcoming)})"
            if upcoming
            else "No passphrase is set: none is taken"
            if not ready
            else "The schedule is off",
            FINE if upcoming else ATTENTION,
            "" if upcoming else "Set it in Settings → System → Backup: a server without backups cannot be put back.",
            link=link,
            metrics=[("nik_backup_next_run_timestamp_seconds", {}, upcoming)] if upcoming else [],
        )
    )
    for name in ("disk", "offsite"):
        if name in problems:
            rows.append(row(f"backup.{name}", group, "Backups", "A problem", PROBLEM, problems[name], link=link))
    snapshots = list(
        db.scalars(
            select(Backup).where(Backup.kind == "upgrade", Backup.state == "done", Backup.local.is_(True))
            .order_by(Backup.created_at.desc())
        )
    )  # fmt: skip
    rows.append(
        row(
            "backup.snapshots",
            group,
            "Snapshots taken before upgrades",
            f"{len(snapshots)} kept"
            + (f", the latest {lasted(now - runner.stamp(snapshots[0].created_at))} ago" if snapshots else ""),
            FINE,
            (snapshots[0].label + ". " if snapshots and snapshots[0].label else "")
            + "An upgrade that cannot run stops the server before it changes the database, and the page then says "
            "at which step and how to go back (deploy/rollback.sh).",
            link=link,
            metrics=[("nik_upgrade_snapshots", {}, len(snapshots))],
        )
    )
    return rows


# --------------------------------------------------------------------------- #
# The certificate of the web container                                        #
# --------------------------------------------------------------------------- #
def _recovery(db: OrmSession, kept: dict[str, Any], limits: dict[str, int], now: float) -> list[dict[str, Any]]:
    """The recovery to a moment and the standby: the disk the archive is on, then the rows of
    app/recovery/status.py. Nothing on a server without an archive volume."""
    from ..recovery import layout, status

    found = status.rows(db, now)
    if found and layout.root() is not None:
        found.insert(
            0, _disk("archive", "Archive volume", str(layout.root()), "/settings/system/backup", kept, limits, now)
        )
    return found


def web_address() -> tuple[str, int] | None:
    """Where the web container listens for TLS, as the backend reaches it: ``NIK_WEB_TLS``
    (``web:443`` in the stack; empty for an installation that has none)."""
    value = os.environ.get("NIK_WEB_TLS", "web:443").strip()
    host, _, port = value.rpartition(":")
    return (host, int(port)) if host and port.isdigit() else None


def tls_dates(host: str, port: int) -> dict[str, Any]:
    """The certificate the web container serves, read as a browser gets it: the backend connects
    to it and looks at what is presented. Nothing is verified and nothing is sent: only the
    dates and the names are read. (Replaced in tests.)"""
    from cryptography import x509

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # The web container serves TLS 1.2 and 1.3 and nothing older (frontend/nginx/nginx.conf):
    # nothing older is spoken here either.
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), TLS_TIMEOUT) as plain:
        with context.wrap_socket(plain, server_hostname=host) as secured:
            certificate = x509.load_der_x509_certificate(secured.getpeercert(binary_form=True))
    return {
        "notAfter": certificate.not_valid_after_utc.timestamp(),
        "notBefore": certificate.not_valid_before_utc.timestamp(),
        "subject": certificate.subject.rfc4514_string(),
        "selfSigned": certificate.subject == certificate.issuer,
    }


def certificate(kept: dict[str, Any], now: float) -> dict[str, Any]:
    """The certificate as last read, read again when that is more than an hour old.
    ``{"at": …, "found": {…}}`` or ``{"at": …, "error": "…"}``; empty when there is no web container to ask."""
    held = kept.get("tls") if isinstance(kept.get("tls"), dict) else {}
    if held and now - float(held.get("at") or 0) < TLS_KEPT:
        return held
    address = web_address()
    if address is None:
        return {}
    try:
        return {"at": now, "found": tls_dates(*address)}
    except Exception as error:  # noqa: BLE001 - whatever kept it from being read is what the row says
        return {"at": now, "error": f"{address[0]}:{address[1]}: {getattr(error, 'strerror', None) or error}"[:300]}


def _certificate(kept: dict[str, Any], limits: dict[str, int], now: float) -> list[dict[str, Any]]:
    held = certificate(kept, now)
    label = "Certificate of the web container"
    if not held:
        return []
    if "found" not in held:
        return [
            row(
                "tls.certificate",
                "Certificate",
                label,
                "Could not be read",
                UNKNOWN,
                f"The backend asks the web container for it and got no answer ({held.get('error')}). NIK_WEB_TLS "
                "names where it listens.",
            )
        ]
    found = held["found"]
    left = (float(found["notAfter"]) - now) / 86400
    days = int(left)  # whole days: "expires in 30 days" is within thirty days
    if left <= 0:
        state, value = PROBLEM, f"Expired {lasted(-left * 86400)} ago"
    else:
        state = (
            PROBLEM
            if days <= limits["certificateProblemDays"]
            else ATTENTION
            if days <= limits["certificateAttentionDays"]
            else FINE
        )
        value = f"Expires in {days} days ({_when(float(found['notAfter']))[:10]})"
    detail = f"{found.get('subject') or 'No subject'}{', self-signed' if found.get('selfSigned') else ''}."
    if state != FINE:
        detail += (
            " Replace nik.crt and nik.key in the certificate volume of the web container and restart it; a "
            "self-signed one is made again when both files are removed."
        )
    return [
        row(
            "tls.certificate",
            "Certificate",
            label,
            value,
            state,
            detail,
            notify=True,
            metrics=[("nik_certificate_expiry_timestamp_seconds", {}, float(found["notAfter"]))],
        )
    ]


# --------------------------------------------------------------------------- #
# The audit log                                                               #
# --------------------------------------------------------------------------- #
def _audit(db: OrmSession, limits: dict[str, int], now: float) -> list[dict[str, Any]]:
    from ..auditlog import chain, forward
    from ..core.models import AuditEntry

    link = "/settings/system/audit-log"
    group = "Audit log"
    found = chain.out(db)
    problem = found["problem"]
    verified = found["verified"] or {}
    checked = stamp(found["checkedAt"])
    metrics = [
        ("nik_audit_entries_total", {}, found["head"]["seq"]),
        ("nik_audit_entries", {}, found["entries"]),
    ]
    if checked:
        metrics.append(("nik_audit_chain_ok", {}, 0 if problem else 1))
    if verified.get("at"):
        metrics.append(("nik_audit_chain_verified_timestamp_seconds", {}, stamp(verified["at"])))
    if problem:
        state, value = PROBLEM, f"Broken at entry {problem['seq']}"
        detail = (
            f"{problem['text']}. Somebody changed the log outside Nik, or the database was damaged: compare it "
            "with the copy of the syslog receiver (python -m app.auditlog export, then verifier.py)."
        )
    elif not checked:
        state, value, detail = UNKNOWN, "Not verified yet", "The chain is walked a few minutes after the server starts."
    else:
        stale = settings.API_BACKGROUND and now - checked > 4 * chain.VERIFY_EVERY
        state = ATTENTION if stale else FINE
        value = f"Holds up to entry {verified.get('seq') or 0}, verified {lasted(now - checked)} ago"
        detail = (
            "The walk that runs every few minutes has not run: look at the API container."
            if stale
            else ""
            if found["headFile"]
            else "The head could not be noted in the backup directory: it is not there or not writable."
        )
    failures = db.execute(
        select(func.count()).select_from(AuditEntry).where(AuditEntry.action.in_(("auth.failed", "auth.code.failed")))
    ).scalar()
    metrics.append(("nik_signin_failures_total", {}, failures or 0))
    rows = [row("audit.chain", group, "Chain", value, state, detail, link=link, notify=True, metrics=metrics)]

    sent = forward.out(db, now)
    held, wanted = sent["state"], sent["settings"]
    on = bool(held["destination"]) or bool(wanted["enabled"])
    metrics = [("nik_audit_forward_enabled", {}, 1 if on else 0)]
    if not on:
        rows.append(
            row(
                "audit.forwarding",
                group,
                "Forwarding to syslog",
                "Off",
                FINE,
                "The log exists on this server only: whoever can change the database can remove entries from "
                "its end unseen. A receiver elsewhere is what shows it.",
                link=link,
                metrics=metrics,
            )
        )
        return rows
    waiting, age = held["backlog"]["entries"], float(held["backlog"]["seconds"])
    failing = now - stamp(held["errorSince"]) if held["error"] and held["errorSince"] else 0.0
    worst = max(age if waiting else 0.0, failing)
    state = rising(worst / 60, limits["syslogAttentionMinutes"], limits["syslogProblemMinutes"])
    value = held["destination"] or f"{wanted['protocol']}://{wanted['host']}:{wanted['port']}, not taken up yet"
    value += f": {waiting} waiting" + (f", the oldest for {lasted(age)}" if waiting and age >= 1 else "")
    detail = ""
    if held["error"]:
        detail = f"{held['error']}. The entries wait in order and are sent when the receiver is back."
    elif state != FINE:
        detail = "The entries are not leaving: the automation worker sends them (Settings → System → Workers)."
    metrics += [
        ("nik_audit_forward_backlog", {}, waiting),
        ("nik_audit_forward_oldest_seconds", {}, age if waiting else 0),
        ("nik_audit_forward_sent_total", {}, held["sent"]),
    ]
    rows.append(
        row(
            "audit.forwarding",
            group,
            "Forwarding to syslog",
            value,
            state,
            detail,
            link=link,
            notify=True,
            metrics=metrics,
        )
    )
    return rows


# --------------------------------------------------------------------------- #
# Sign-in                                                                     #
# --------------------------------------------------------------------------- #
def _signin(db: OrmSession, now: float) -> list[dict[str, Any]]:
    from .. import signin
    from ..core import client_address, signin_policy
    from ..core.models import SigninAttempt, User
    from ..core.permissions import stored_roles

    link = "/settings/access/sign-in-and-sessions"
    group = "Sign-in"
    rows = []
    wide = client_address.overtrusting()
    rows.append(
        row(
            "signin.proxies",
            group,
            "Whose word is taken for the address of a client",
            "Everybody's (FORWARDED_ALLOW_IPS holds *)" if wide else "The trusted proxies only",
            ATTENTION if wide else FINE,
            "Any client can then claim any address: the waits after failed sign-ins and the networks of the "
            "administrators go by it. Leave FORWARDED_ALLOW_IPS empty and name the proxy in TRUSTED_PROXIES."
            if wide
            else "",
            link=link,
        )
    )
    policy = signin_policy.load(db)
    having = signin.with_factors(db)
    admins = [
        user
        for user in db.scalars(select(User).where(User.disabled.is_(False)))
        if signin_policy.is_admin(stored_roles(user.roles))
    ]
    without = [user for user in admins if user.id not in having]
    required = bool(policy["adminSecondFactor"])
    rows.append(
        row(
            "signin.second_factor",
            group,
            "Second factor of the administrators",
            f"{len(admins) - len(without)} of {len(admins)} have one"
            + (", required" if required else ", not required"),
            ATTENTION if without and required else FINE,
            (
                f"{', '.join(sorted(user.username for user in without)[:10])}: asked to set one up at the next "
                "sign-in, and able to do nothing else until then."
            )
            if without and required
            else "A password alone protects the accounts that can do everything: require it in Settings → "
            "Access → Sign-in and sessions."
            if without
            else "",
            link=link,
            metrics=[("nik_administrators_without_second_factor", {}, len(without))],
        )
    )
    waiting = db.execute(select(func.count()).select_from(SigninAttempt).where(SigninAttempt.wait_until > now)).scalar()
    rows[-1]["metrics"].append(("nik_signin_waiting", {}, waiting or 0))
    return rows


# --------------------------------------------------------------------------- #
# Keys and the encryption of the store                                        #
# --------------------------------------------------------------------------- #
ROTATION_NUMBER = {"idle": 0, "verified": 0, "running": 1, "failed": 2}


def keys_and_encryption(db: OrmSession, now: float) -> list[dict[str, Any]]:
    """The keys of the server and the encryption of the store, from the two functions
    ``key_rotation.py`` keeps for this page (``keys_state``, ``store_encryption``) and the count of
    the entries of the audit log whose key is gone (``audit_signed``).

    ``keys.state`` asks for attention while a key is in the environment of the containers, while a
    change of key is half-way or has failed, and when entries of the audit log cannot be checked for
    want of the key that signed them. ``store.encryption`` asks for attention while a store from
    before 6.8 is being sealed, and is a problem when a file failed its check or when files stay in
    clear that the server could not seal.
    """
    from .. import key_rotation

    group = "Keys and encryption"
    held = key_rotation.keys_state(db)
    in_environment = [entry["name"] for entry in held if entry["source"] == "environment"]
    changing = {entry["name"]: entry["rotation"] for entry in held if entry["rotation"] in ("running", "failed")}
    unchecked = key_rotation.audit_signed(db)["cannotBeChecked"]
    metrics: list[tuple[str, dict[str, str], float]] = [
        ("nik_keys_in_environment", {}, len(in_environment)),
        ("nik_audit_entries_unchecked", {}, unchecked),
    ]
    changed = []
    for entry in held:
        if entry["rotation"] is None:
            continue
        metrics.append(("nik_key_rotation_state", {"key": entry["name"]}, ROTATION_NUMBER.get(entry["rotation"], 0)))
        if entry["rotatedAt"]:
            metrics.append(("nik_key_rotated_timestamp_seconds", {"key": entry["name"]}, stamp(entry["rotatedAt"])))
            changed.append(f"{entry['name']} {lasted(now - stamp(entry['rotatedAt']))} ago")
    said = []
    if "failed" in changing.values():
        failed = sorted(name for name, state in changing.items() if state == "failed")
        said.append(
            f"The change of {', '.join(failed)} could not put everything under the new key: the earlier key stays "
            "where it is and nothing is lost. Settings → Keys names what failed; deploy/secrets.sh goes on once it "
            "is set right."
        )
    running = sorted(name for name, state in changing.items() if state == "running")
    if running:
        said.append(
            f"A change of {', '.join(running)} is half-way: the server holds both keys until everything reads "
            "under the new one. deploy/secrets.sh rotate, run again, ends it."
        )
    if in_environment:
        said.append(
            "The secrets of this server are in the environment of its containers (the .env file): whoever can "
            "inspect a container reads them. deploy/secrets.sh move puts them in files."
        )
    if unchecked:
        said.append(
            f"{unchecked} entries of the audit log cannot be checked: the key that signed them is not among the keys "
            "of this server. Put it back into AUDIT_KEY_PREVIOUS (Settings → Keys names it)."
        )
    if changing:
        value = "A change of key is " + ("stopped" if "failed" in changing.values() else "half-way")
    elif in_environment:
        value = "In the environment of the containers"
    elif unchecked:
        value = "A key of the audit log is missing"
    else:
        sources = {entry["source"] for entry in held if entry["set"]}
        value = "In files, none in the environment" if sources == {"file"} else "None was given to this server"
    if not said and changed:
        said.append("Last changed: " + "; ".join(changed) + ".")
    rows = [
        row(
            "keys.state",
            group,
            "Keys of the server",
            value,
            ATTENTION if said and (changing or in_environment or unchecked) else FINE,
            " ".join(said),
            link="/settings/system/keys",
            metrics=metrics,
        )
    ]

    found = key_rotation.store_encryption(db)
    left, total = found["left"], found["total"]
    metrics = [
        ("nik_store_encrypted", {}, 0 if found["clearRemains"] else 1),
        ("nik_store_files_in_clear", {}, left["files"]),
        ("nik_store_bytes_in_clear", {}, left["bytes"]),
        ("nik_store_files_stuck", {}, found["stuck"]),
        ("nik_store_files_damaged", {}, found["damaged"]),
    ]
    link = "/settings/system/storage"
    if found["damaged"]:
        state = PROBLEM
        value = f"{found['damaged']} file(s) failed their check"
        detail = (
            "A file of the store was changed, cut short or put in the place of another: it is not served. "
            "Settings → Storage names each one; put it back from a backup."
        )
    elif found["stuck"]:
        state = PROBLEM
        value = f"{found['stuck']} file(s) stay in clear"
        detail = (
            "The server could not seal them (Settings → Storage says why for each): they are readable on the disk "
            "until it can."
        )
    elif not found["clearRemains"]:
        state, value, detail = FINE, "Every file is sealed", ""
        if stamp(found["sealedSince"]):
            value += f", for {lasted(now - stamp(found['sealedSince']))}"
    elif found["state"] == "starting":
        state, value = UNKNOWN, "Not looked at yet"
        detail = "The server walks the store a few seconds after it starts."
    else:
        state = ATTENTION
        done = max(0, int(total["files"]) - int(left["files"]))
        value = f"{done} of {total['files']} files sealed, {size(left['bytes'])} still in clear"
        if found["state"] == "paused":
            detail = f"Paused by {found['pausedBy'] or 'an administrator'}: Settings → Storage takes it up again."
        elif found["secondsLeft"] is not None:
            detail = (
                "A store from before 6.8 is being sealed while the server is used: "
                f"about {lasted(found['secondsLeft'])} left."
            )
        else:
            detail = "A store from before 6.8 is being sealed while the server is used."
    rows.append(
        row("store.encryption", group, "Encryption of the store", value, state, detail, link=link, metrics=metrics)
    )
    return rows


# --------------------------------------------------------------------------- #
# The server                                                                  #
# --------------------------------------------------------------------------- #
def _server(db: OrmSession, now: float) -> list[dict[str, Any]]:
    from ..backups import runner, upgrade
    from ..core.models import Setting

    version = runner.nik_version()
    held = db.get(Setting, upgrade.SETTINGS_ID)
    since = stamp(((held.doc if held else None) or {}).get("since"))
    return [
        row(
            "server.version",
            "Server",
            "Version",
            f"Nik {version}" + (f", on this database for {lasted(now - since)}" if since else ""),
            metrics=[("nik_info", {"version": version}, 1)],
        )
    ]


def gather(
    db: OrmSession, limits: dict[str, int], kept: dict[str, Any] | None = None, now: float | None = None
) -> list[dict[str, Any]]:
    """Every row, in the order of the page. A part that cannot be read becomes a row that says so:
    one broken check never hides the others."""
    now = time.time() if now is None else now
    kept = kept or {}
    store, backups = str(Path(settings.SAMPLE_STORE)), str(Path(settings.BACKUP_DIR))
    parts = (
        ("disk", lambda: [
            _store_disk(db, store, kept, limits, now),
            _disk("backups", "Backup directory", backups, "/settings/system/backup", kept, limits, now),
        ]),
        ("database", lambda: _database(db, kept, limits, now)),
        ("queues", lambda: _queues(db, limits, now)),
        ("work", lambda: _work(db, now)),
        ("workers", lambda: _workers(db, limits, now)),
        ("backups", lambda: _backups(db, now)),
        ("recovery", lambda: _recovery(db, kept, limits, now)),
        ("certificate", lambda: _certificate(kept, limits, now)),
        ("audit", lambda: _audit(db, limits, now)),
        ("signin", lambda: _signin(db, now)),
        ("keys", lambda: keys_and_encryption(db, now)),
        ("server", lambda: _server(db, now)),
    )  # fmt: skip
    rows: list[dict[str, Any]] = []
    for name, part in parts:
        try:
            rows += part()
        except Exception as error:  # noqa: BLE001 - said on the page instead of failing it
            db.rollback()
            rows.append(
                row(
                    f"{name}.unreadable",
                    "Server",
                    f"The check of {name}",
                    "Could not be read",
                    UNKNOWN,
                    f"{type(error).__name__}: {error}"[:300],
                )
            )
    for found in rows:
        number = -1 if found["state"] == UNKNOWN else WORSE[found["state"]]
        found["metrics"].append(("nik_health_state", {"check": found["id"]}, number))
    # The clock belongs with the server, after its version.
    rows.sort(key=lambda found: found["id"] == "clock.skew")
    return rows


_recovery_metrics()

"""The loop of the API process: base backups, what is kept, the proof, the watch of the archive.

One pass (``tick``), under the ``recovery`` lease, every few seconds:

1. **What PostgreSQL says of its archive** is read and written down: the last
   segment archived, the last one that failed, how much log waits in
   ``pg_wal``. An archive that is stuck does not lose anything, but PostgreSQL
   keeps every segment it could not hand over, on the disk of the database:
   the watch tells the administrators long before that disk is full
   (``watch.py``).
2. **Base backups.** The rows are made to say what the archive volume holds
   and what the recovery service answered. A base backup is asked for when the
   schedule says so, when there is none, when somebody asks, and at once
   after the database started a new timeline (a recovery, a promotion): the
   log of the new timeline does not continue a base backup of the old one for
   a standby that is made later.
3. **What is kept** (``retention``): the base backups of the last days one
   can go back in, the one before them (a recovery to the first of those days
   starts from it), and every segment since the oldest kept. The rest is
   removed by the recovery service, which owns the files. Deleted files of
   the store that no recovery can reach any more are removed too.
4. **The proof.** Once a day, and after each new base backup, the recovery
   service is asked to bring the latest base backup up as a scratch server and
   replay the archive to a moment a few minutes ago. What it finds there is
   held against the server itself (``judge``): the audit log of the scratch
   server must end on an entry this server has, with the same hash, and no
   entry older than the moment may be missing from it.

A standby does none of this: its database is read-only and it takes what the
first host sends.
"""

from __future__ import annotations

import json
import logging
import shutil
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.orm import Session as OrmSession

from ..backups import config as backup_config
from ..backups import policy, runner
from ..core import audit
from ..core.models import AuditEntry, RecoveryBase
from . import agent, config, kept, layout, role

logger = logging.getLogger("nik.recovery")

LEASE = "recovery"
SYSTEM = runner.SYSTEM
# A request the recovery service has not answered after this long is counted as failed.
BASE_WAIT = 6 * 3600
TEST_WAIT = 900
PRUNE_EVERY = 600
# The proof replays to a moment this long before the last segment archived: there are changes
# after it in the archive, so the replay can tell that it reached it.
TEST_BEFORE_END = 60
# An entry of the audit log gets its time when it is recorded and is in the log of PostgreSQL
# when its transaction commits: a long transaction may be this late.
COMMIT_SLACK = 300
ROOM_FACTOR = 2
ROOM_MARGIN = 256 * 1024 * 1024


def label_time(label: str) -> float:
    try:
        moment = datetime.strptime(label, "base-%Y%m%d-%H%M%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return 0.0
    return moment.timestamp()


def new_label(db: OrmSession, now: float) -> str:
    while True:
        label = datetime.fromtimestamp(now, timezone.utc).strftime("base-%Y%m%d-%H%M%S")
        if db.get(RecoveryBase, label) is None and not (layout.folder("base") / label).exists():
            return label
        now += 1


# --------------------------------------------------------------------------- #
# What PostgreSQL says                                                        #
# --------------------------------------------------------------------------- #
def postgres(db: OrmSession) -> bool:
    return db.get_bind().dialect.name == "postgresql"


def archiver(db: OrmSession) -> dict[str, Any]:
    """The state of the archive as PostgreSQL knows it."""
    row = db.execute(
        text(
            "select current_setting('archive_mode'), archived_count, last_archived_wal,"
            " extract(epoch from last_archived_time), failed_count, last_failed_wal,"
            " extract(epoch from last_failed_time), extract(epoch from now()) from pg_stat_archiver"
        )
    ).one()
    waiting = db.execute(text("select count(*), coalesce(sum(size), 0) from pg_ls_waldir()")).one()
    ready = db.execute(text("select count(*) from pg_ls_archive_statusdir() where name like '%.ready'")).scalar()
    timeline = db.execute(text("select timeline_id from pg_control_checkpoint()")).scalar()
    current = db.execute(text("select pg_walfile_name(pg_current_wal_lsn())")).scalar()
    return {
        "mode": str(row[0]),
        "archived": int(row[1] or 0),
        "lastWal": str(row[2] or ""),
        "lastAt": float(row[3] or 0),
        "failed": int(row[4] or 0),
        "failedWal": str(row[5] or ""),
        "failedAt": float(row[6] or 0),
        "at": float(row[7] or 0),
        "walFiles": int(waiting[0] or 0),
        "walBytes": int(waiting[1] or 0),
        # The segments PostgreSQL has finished and not handed over yet.
        "waiting": int(ready or 0),
        "timeline": int(timeline or 0),
        "current": str(current or ""),
    }


def stuck(found: dict[str, Any]) -> bool:
    """Whether the last thing the archiver did was fail."""
    return bool(found.get("failedAt")) and float(found["failedAt"]) > float(found.get("lastAt") or 0)


def database_bytes(db: OrmSession) -> int:
    return int(db.execute(text("select pg_database_size(current_database())")).scalar() or 0)


# --------------------------------------------------------------------------- #
# The rows of the base backups                                                #
# --------------------------------------------------------------------------- #
def read_manifest(label: str, place: str = "base") -> dict[str, Any]:
    """What the manifest of a base backup says of the log it needs: the timeline and the first
    segment a recovery from it replays."""
    path = layout.folder(place) / label / "backup_manifest"
    with open(path, encoding="utf-8") as handle:
        manifest = json.load(handle)
    ranges = manifest.get("WAL-Ranges") or []
    if not ranges:
        raise ValueError("the manifest names no range of the log")
    first = min(ranges, key=lambda entry: (int(entry["Timeline"]), layout.lsn(entry["Start-LSN"])))
    last = max(ranges, key=lambda entry: (int(entry["Timeline"]), layout.lsn(entry["End-LSN"])))
    return {
        "timeline": int(first["Timeline"]),
        "endLsn": layout.lsn(last["End-LSN"]),
        "startWal": layout.segment_of(int(first["Timeline"]), first["Start-LSN"]),
        "endWal": layout.segment_of(int(last["Timeline"]), last["End-LSN"]),
        "endTimeline": int(last["Timeline"]),
    }


def folder_bytes(label: str, place: str = "base") -> int:
    total = 0
    try:
        for path in (layout.folder(place) / label).iterdir():
            total += path.stat().st_size
    except OSError:
        return 0
    return total


def _copies_wanted(db: OrmSession) -> bool:
    doc = backup_config.read(db)
    return bool(doc.get("passphrase")) and backup_config.ready(doc.get("destination") or {})


def sync(db: OrmSession, now: float) -> list[str]:
    """Make the rows say what the archive volume holds and what the recovery service answered
    (the caller commits). Returns what changed."""
    did: list[str] = []
    base = layout.folder("base")
    here = {path.name for path in base.iterdir() if path.is_dir() and layout.LABEL.match(path.name)}
    rows = {row.id: row for row in db.scalars(select(RecoveryBase))}
    wants_copy = _copies_wanted(db)
    for label, row in rows.items():
        if row.state == "requested":
            said = agent.answer(label)
            if said is not None and said.get("state") == "ok" and label in here:
                try:
                    facts = read_manifest(label)
                except (OSError, ValueError, KeyError) as error:
                    row.state, row.error = "failed", f"Its manifest cannot be read: {error}"[:900]
                    did.append(f"failed:{label}")
                    continue
                row.state, row.finished_at, row.error = "done", runner.iso(now), ""
                row.size = folder_bytes(label)
                row.timeline, row.start_wal = facts["timeline"], facts["startWal"]
                row.facts = {
                    "seconds": int(said.get("seconds") or 0),
                    "verified": said.get("verified") == "1",
                    "endWal": facts["endWal"],
                    "endLsn": facts["endLsn"],
                    "endTimeline": facts["endTimeline"],
                }
                row.local = True
                row.offsite_state = "pending" if wants_copy else ""
                audit.record(
                    db,
                    SYSTEM,
                    "recovery.base",
                    f"Took the base backup {label} ({row.size} bytes, checked against its manifest): "
                    f"a recovery from it replays the log from {row.start_wal}",
                    target=label,
                )
                did.append(f"done:{label}")
            elif said is not None or (
                not agent.asked(label) and now - runner.stamp(row.created_at) > 60 and label not in here
            ):
                row.state = "failed"
                row.error = (said or {}).get("error") or "The recovery service lost the request (it was restarted)"
                row.finished_at = runner.iso(now)
                audit.record(
                    db, SYSTEM, "recovery.base", f"The base backup {label} failed: {row.error}"[:900], target=label
                )
                did.append(f"failed:{label}")
            elif now - runner.stamp(row.created_at) > BASE_WAIT:
                row.state, row.finished_at = "failed", runner.iso(now)
                row.error = "The recovery service did not answer in six hours: is the `recovery` container running?"
                did.append(f"failed:{label}")
        elif row.state == "done" and row.local and label not in here:
            # Its folder is gone (the retention removed it, or an operator did).
            if row.offsite_state == "copied":
                row.local = False
            else:
                db.delete(row)
            did.append(f"gone:{label}")
        elif row.state == "done" and row.local and row.offsite_state == "" and wants_copy:
            row.offsite_state = "pending"
    for label in sorted(here - set(rows)):
        # A folder with no row: the database was put back to before this base backup was taken.
        try:
            facts = read_manifest(label)
        except (OSError, ValueError, KeyError):
            continue
        db.add(
            RecoveryBase(
                id=label,
                state="done",
                created_at=runner.iso(label_time(label)),
                finished_at=runner.iso(label_time(label)),
                size=folder_bytes(label),
                timeline=facts["timeline"],
                start_wal=facts["startWal"],
                facts={
                    "verified": True,
                    "endWal": facts["endWal"],
                    "endLsn": facts["endLsn"],
                    "endTimeline": facts["endTimeline"],
                    "adopted": True,
                },
                requested_by=SYSTEM,
                local=True,
                offsite_state="pending" if wants_copy else "",
                offsite={},
            )
        )
        did.append(f"adopted:{label}")
    db.flush()
    return did


def drop_off_history(db: OrmSession, current: int) -> list[str]:
    """After the database went back to a moment it writes a new timeline, and what it wrote
    after that moment on the old one never happened. A base backup taken in that stretch is of
    no use to this server any more: its row goes, and the retention removes its folder (the
    caller commits)."""
    did = []
    history = layout.read_history(current)
    for row in db.scalars(select(RecoveryBase).where(RecoveryBase.state == "done")):
        facts = row.facts or {}
        timeline = int(facts.get("endTimeline") or row.timeline or 0)
        if not timeline or layout.on_history(timeline, int(facts.get("endLsn") or 0), current, history):
            continue
        if row.offsite_state in ("copied", "delete") or (row.offsite or {}).get("remote"):
            row.local, row.offsite_state = False, "delete"
        else:
            db.delete(row)
        did.append(f"off-history:{row.id}")
    return did


def taken(db: OrmSession) -> list[policy.Taken]:
    """The base backups as the rules of the schedule read them."""
    states = {"requested": "running", "done": "done", "failed": "failed"}
    return [
        policy.Taken(row.id, runner.stamp(row.created_at), states.get(row.state, row.state), "passed")
        for row in db.scalars(select(RecoveryBase))
    ]


def request_base(db: OrmSession, by: str, now: float) -> str:
    """Ask the recovery service for a base backup (the caller commits). Raises ``AgentError``."""
    label = new_label(db, now)
    agent.ask(label)
    db.add(RecoveryBase(id=label, state="requested", created_at=runner.iso(now), requested_by=by, facts={}, offsite={}))
    # Seen by what follows in this pass: the retention must count it among the ones to keep.
    db.flush()
    return label


def room_for_base(db: OrmSession, usage=None) -> str | None:
    """Why a base backup cannot be taken as the disk stands, or None."""
    usage = usage or shutil.disk_usage
    last = db.scalars(
        select(RecoveryBase).where(RecoveryBase.state == "done").order_by(RecoveryBase.created_at.desc()).limit(1)
    ).first()
    # Compressed, a base backup is a fraction of the database: the last one says how much, and
    # before there is one the database itself is the bound.
    expected = last.size * ROOM_FACTOR if last is not None and last.size else database_bytes(db)
    try:
        free = usage(layout.folder("base")).free
    except OSError:
        return None
    if free < expected + ROOM_MARGIN:
        return (
            f"The archive volume has {free // 2**20} MB free and the next base backup needs about "
            f"{(expected + ROOM_MARGIN) // 2**20} MB: none is taken until there is room"
        )
    return None


# --------------------------------------------------------------------------- #
# What is kept                                                                #
# --------------------------------------------------------------------------- #
def retention(bases: list[tuple[str, float]], now: float, keep_days: int) -> tuple[list[str], list[str]]:
    """Which base backups are kept and which go. ``bases`` are the finished ones, as ``(label,
    when it finished)``. Kept: those of the last ``keep_days`` days, and the latest one before
    them (a recovery to the first moment of those days starts from it). There is always one."""
    ordered = sorted(bases, key=lambda entry: entry[1])
    horizon = now - keep_days * 86400
    inside = [label for label, at in ordered if at >= horizon]
    before = [label for label, at in ordered if at < horizon]
    keep = before[-1:] + inside
    return keep, before[:-1]


def apply_retention(db: OrmSession, state: dict[str, Any], now: float, force: bool = False) -> list[str]:
    """Drop the base backups the retention no longer keeps and ask the recovery service to remove
    them and the log before the oldest kept (the caller commits)."""
    doc = config.read(db)
    done = list(db.scalars(select(RecoveryBase).where(RecoveryBase.state == "done", RecoveryBase.local.is_(True))))
    keep, drop = retention(
        [(row.id, runner.stamp(row.finished_at or row.created_at)) for row in done], now, int(doc["keepDays"])
    )
    did = []
    for row in done:
        if row.id in drop:
            if row.offsite_state in ("copied", "delete") or (row.offsite or {}).get("remote"):
                row.local, row.offsite_state = False, "delete"
            else:
                db.delete(row)
            did.append(f"dropped:{row.id}")
    # Failed attempts are of no use after a week.
    for row in db.scalars(select(RecoveryBase).where(RecoveryBase.state == "failed")):
        if now - runner.stamp(row.created_at) > policy.FAILED_KEPT:
            db.delete(row)
    kept_rows = sorted((row for row in done if row.id in keep), key=lambda row: row.created_at)
    oldest = kept_rows[0] if kept_rows else None
    state["oldest"] = (
        {"base": oldest.id, "at": runner.stamp(oldest.finished_at or oldest.created_at), "wal": oldest.start_wal}
        if oldest is not None
        else None
    )
    if oldest is None:
        return did
    last = state.get("prune") or {}
    if not (did or force or now - float(last.get("at") or 0) >= PRUNE_EVERY):
        return did
    labels = [row.id for row in db.scalars(select(RecoveryBase).where(RecoveryBase.state != "failed"))]
    labels = [label for label in labels if label not in drop]
    number = uuid.uuid4().hex[:12]
    try:
        agent.ask(
            f"prune-{number}",
            [("wal_before", oldest.start_wal), *(("keep", label) for label in sorted(labels))],
        )
        state["prune"] = {"id": number, "at": now, "walBefore": oldest.start_wal}
    except agent.AgentError as error:
        logger.warning("The archive could not be pruned: %s", error)
    # A deleted file of the store is needed for as long as a recovery can go back to before its
    # deletion, and the oldest moment one can go back to is the end of the oldest base backup.
    removed = kept.purge(float(state["oldest"]["at"]))
    if removed:
        did.append(f"purged:{removed}")
    _sweep_arrivals(now)
    return did


def _sweep_arrivals(now: float) -> None:
    """What a restore left opened in the archive volume, a day after: this process owns those files."""
    for name in ("restore", "incoming"):
        try:
            entries = list(layout.folder(name).iterdir())
        except OSError:
            continue
        for path in entries:
            try:
                if now - path.stat().st_mtime < 86400:
                    continue
                if path.is_dir():
                    shutil.rmtree(path, ignore_errors=True)
                else:
                    path.unlink()
            except OSError:
                continue


# --------------------------------------------------------------------------- #
# The proof                                                                   #
# --------------------------------------------------------------------------- #
def test_due(
    state: dict[str, Any],
    latest: RecoveryBase | None,
    found: dict[str, Any],
    every: int,
    now: float,
    asked: bool = False,
) -> float | None:
    """The moment to replay to when a recovery test is due, or None. A test is due when the
    latest base backup was never tried, or when the last test is older than ``every`` hours; and
    only once the archive holds log written after that base backup was finished."""
    if latest is None:
        return None
    running = state.get("test") or {}
    if running.get("state") == "running":
        return None
    last = state.get("tested") or {}
    never = last.get("base") != latest.id
    old = now - float(last.get("at") or 0) >= every * 3600
    # After a failure the next try waits an hour, unless somebody asks.
    if last.get("state") == "failed" and now - float(last.get("at") or 0) < policy.RETRY_AFTER and not asked:
        return None
    if not (never or old or asked):
        return None
    target = float(found.get("lastAt") or 0) - TEST_BEFORE_END
    finished = runner.stamp(latest.finished_at or latest.created_at)
    if target <= finished:
        return None  # the archive has nothing after this base backup yet: at the next segment
    return target


def stamp_text(moment: float) -> str:
    """A moment as PostgreSQL reads it in ``recovery_target_time``."""
    return datetime.fromtimestamp(moment, timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f+00")


def ask_test(state: dict[str, Any], base: str, target: float, now: float) -> None:
    number = uuid.uuid4().hex[:12]
    agent.ask(f"test-{number}", [("base", base), ("target", stamp_text(target)), ("wait", "600")])
    state["test"] = {"id": number, "base": base, "target": target, "askedAt": now, "state": "running"}


def judge(db: OrmSession, running: dict[str, Any], said: dict[str, str]) -> tuple[bool, str, dict[str, Any]]:
    """Hold what the scratch server held against this server. Returns whether the recovery is
    proven, the sentence that says why not, and the facts to keep."""
    from ..auditlog import chain

    target = float(running.get("target") or 0)
    facts: dict[str, Any] = {"seconds": int(said.get("seconds") or 0)}
    if said.get("state") != "ok":
        return False, said.get("error") or "The recovery service said the test failed and not why", facts
    try:
        replayed = float(said.get("replayed") or 0)
        number = int(said.get("audit_seq") or 0)
    except ValueError:
        return False, "The answer of the recovery service cannot be read", facts
    hashed = said.get("audit_hash") or ""
    facts |= {"replayed": replayed, "auditSeq": number, "revision": said.get("revision") or ""}
    if not said.get("revision"):
        return False, "The scratch server holds no database of Nik: the base backup is not one of this server", facts
    if replayed and replayed > target + 1:
        return False, "The scratch server replayed past the moment asked for", facts
    if number:
        here = chain._hash_of(db, number)
        first = db.execute(
            select(AuditEntry.seq).where(AuditEntry.seq.is_not(None)).order_by(AuditEntry.seq).limit(1)
        ).scalar()
        if here is None and first is not None and number >= int(first):
            return (
                False,
                f"The audit log of the recovered database ends on entry {number}, which this server does not have",
                facts,
            )
        if here is not None and here != hashed:
            return (
                False,
                f"Entry {number} of the audit log is not the same in the recovered database and on this server",
                facts,
            )
    # Nothing older than the moment may be missing: the first entry this server has after the
    # head of the recovered log was made after the moment (or shortly before, and committed after).
    after = db.execute(select(AuditEntry.at).where(AuditEntry.seq > number).order_by(AuditEntry.seq).limit(1)).scalar()
    if after is not None and runner.stamp(after) and runner.stamp(after) < target - COMMIT_SLACK:
        return (
            False,
            f"The recovered database lacks entries of the audit log made before the moment (after entry {number})",
            facts,
        )
    return True, "", facts


def settle_test(db: OrmSession, state: dict[str, Any], now: float) -> str | None:
    """Read the answer to the test that is running, if it came (the caller commits)."""
    running = state.get("test") or {}
    if running.get("state") != "running":
        return None
    said = agent.answer(f"test-{running['id']}")
    if said is None:
        if now - float(running.get("askedAt") or 0) <= TEST_WAIT:
            return None
        said = {"state": "failed", "error": "The recovery service did not answer: is the `recovery` container running?"}
    passed, why, facts = judge(db, running, said)
    result = {
        "state": "passed" if passed else "failed",
        "at": now,
        "base": running.get("base"),
        "target": running.get("target"),
        "error": why[:600],
        **facts,
    }
    state["tested"] = result
    state["test"] = {}
    if passed:
        state["proven"] = result
        audit.record(
            db,
            SYSTEM,
            "recovery.test",
            f"Recovery proven: {running.get('base')} and the archive replayed to "
            f"{runner.iso(float(running.get('target') or 0))} in {facts.get('seconds', 0)} seconds; the audit log of "
            f"the recovered database ends on entry {facts.get('auditSeq', 0)}, as it did here at that moment",
            target=str(running.get("base") or ""),
        )
    else:
        audit.record(
            db, SYSTEM, "recovery.test", f"The recovery test failed: {why}"[:900], target=str(running.get("base") or "")
        )
        logger.warning("The recovery test failed: %s", why)
    return result["state"]


# --------------------------------------------------------------------------- #
# One pass                                                                    #
# --------------------------------------------------------------------------- #
def tick(now: float | None = None, holder: str = runner.HOLDER, usage=None) -> list[str]:
    """One pass of the API process. Returns what it did, for the tests and the log."""
    from ..core.db import SessionLocal

    usage = usage or shutil.disk_usage
    clock = time.time() if now is None else now
    did: list[str] = []
    if not layout.available():
        return did
    with SessionLocal() as db:
        if not postgres(db) or role.in_recovery(db):
            return did
        if not config.acquire(db, holder, now, LEASE):
            return did
        state = config.held(db, config.ARCHIVE_SETTINGS_ID)
        state.setdefault("since", clock)
        found = archiver(db)
        before = state.get("archiver") or {}
        # Since when the archive is stuck, kept across passes: the watch says for how long.
        if stuck(found):
            found["stuckSince"] = before.get("stuckSince") or found["failedAt"]
        state["archiver"] = found
        state["agentAlive"] = agent.alive(clock)
        did += sync(db, clock)
        did += drop_off_history(db, found["timeline"])
        db.flush()
        doc = config.read(db)
        rows = list(db.scalars(select(RecoveryBase).order_by(RecoveryBase.created_at.desc())))
        latest = next((row for row in rows if row.state == "done" and row.local), None)
        in_flight = any(row.state == "requested" for row in rows)
        # A new timeline: the server was recovered or promoted. The log now written does not
        # continue the base backups that are there for a standby made later: one more, at once.
        new_timeline = latest is not None and latest.timeline and found["timeline"] > latest.timeline
        owed = (
            found["mode"] in ("on", "always")
            and not in_flight
            and (
                latest is None
                or new_timeline
                or (
                    doc["base"].get("enabled")
                    and policy.due(doc["base"], taken(db), clock, float(doc.get("baseSetAt") or 0))
                )
            )
        )
        # After a failure the next attempt waits an hour, whatever asks for it.
        recent_failure = any(
            row.state == "failed" and clock - runner.stamp(row.created_at) < policy.RETRY_AFTER for row in rows
        )
        state["noRoom"] = None
        if owed and not recent_failure:
            lacking = room_for_base(db, usage)
            if lacking:
                state["noRoom"] = lacking
            elif agent.running(clock):
                try:
                    did.append(f"base:{request_base(db, 'schedule' if latest is not None else SYSTEM, clock)}")
                except agent.AgentError as error:
                    logger.warning("No base backup was asked for: %s", error)
        did += apply_retention(db, state, clock, force=any(entry.startswith("done:") for entry in did))
        settled = settle_test(db, state, clock)
        if settled:
            did.append(f"test:{settled}")
        last_try = max(
            float((state.get("tested") or {}).get("at") or 0), float((state.get("test") or {}).get("askedAt") or 0)
        )
        asked = float(doc.get("testAskedAt") or 0) > last_try
        target = test_due(state, latest, found, int(doc["testEveryHours"]), clock, asked)
        if target is not None and found["mode"] in ("on", "always") and agent.running(clock):
            try:
                ask_test(state, latest.id, target, clock)
                did.append(f"test-asked:{latest.id}")
            except agent.AgentError as error:
                logger.warning("No recovery test was asked for: %s", error)
        state["disk"] = disk(usage)
        state["at"] = clock
        config.keep(db, config.ARCHIVE_SETTINGS_ID, state)
        db.commit()
    return did


def disk(usage=None) -> dict[str, int]:
    """What the archive takes on its volume, and the room that is left."""
    usage = usage or shutil.disk_usage
    found = {"wal": 0, "walFiles": 0, "base": 0, "total": 0, "free": 0}
    try:
        for path in layout.folder("wal").iterdir():
            if path.name.endswith(layout.GZ):
                found["wal"] += path.stat().st_size
                found["walFiles"] += 1
        for folder in layout.folder("base").iterdir():
            if folder.is_dir():
                found["base"] += sum(path.stat().st_size for path in folder.iterdir())
        room = usage(layout.folder("wal"))
        found["total"], found["free"] = room.total, room.free
    except OSError:
        pass
    return found


def ask_base(db: OrmSession, by: str, now: float | None = None) -> str:
    """A base backup somebody asked for (the caller commits). Raises ``AgentError``."""
    now = time.time() if now is None else now
    if not layout.available():
        raise agent.AgentError("This server has no archive of its log: there is nothing to take a base backup for")
    if db.scalars(select(RecoveryBase.id).where(RecoveryBase.state == "requested").limit(1)).first():
        raise agent.AgentError("A base backup is being taken already")
    lacking = room_for_base(db)
    if lacking:
        raise agent.AgentError(lacking)
    if not agent.running(now):
        raise agent.AgentError(
            "The recovery service does not answer: start it (compose up -d recovery), then ask again"
        )
    return request_base(db, by, now)


def ask_test_now(db: OrmSession) -> None:
    """A recovery test somebody asked for: the next pass runs it (the caller commits)."""
    # Written in the row of the settings, which only requests write: the loop owns the other row.
    doc = config.held(db, config.SETTINGS_ID)
    doc["testAskedAt"] = time.time()
    config.keep(db, config.SETTINGS_ID, doc)

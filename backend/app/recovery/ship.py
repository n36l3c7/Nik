"""The copies of the archive and of the store on the second host.

Run by the process that has a way out (the automation worker, as for the
backups), under the ``recovery-ship`` lease, every few seconds. Nothing runs
until a backup passphrase and a destination with its pinned host key are set
(*Settings → Backup*): there is one passphrase and one destination for
everything that leaves the host.

One pass, over one SSH connection:

1. **Was this server replaced?** The file a promotion leaves on the second
   host is read first (``role.py``). A server that was replaced sends nothing
   more, writes it down, and stops.
2. **The log, in order.** Each segment the archive holds after the last one
   sent is sealed (``envelope.py``) into the memory-backed ``/tmp`` of this
   container, sent, read back and compared, and only then counted. A segment
   is never skipped: the next one waits for it.
3. **Base backups** that wait, sealed straight onto the other host (nothing
   that large is written here first).
4. **Files of the store**, as they are on the disk: sealed under the store
   key already, which this process does not hold. It does not see the store
   either: it asks the API process for each file it sends
   (``/api/internal/store-sealed``), and is given no file that is in clear.
5. **What is no longer kept** is removed from the other host: base backups the
   retention dropped, the log before the oldest one kept, and the copy of a
   deleted file once no recovery can reach back to before its deletion.
6. **The heartbeat**: a small file that says when this host last spoke and how
   far the copies are, for the standby to read.

**The delay.** What is safe on the second host is everything up to the end
of the last segment sent. The delay is how long ago the first change after
that was possible: nothing, when PostgreSQL has written nothing since that
segment; otherwise the time since it was closed. The watch tells the
administrators when it passes the threshold. The distance in the log is kept
with it, in bytes: an upper bound, because a segment the timer closed early
counts whole.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm.attributes import flag_modified

from .. import store_handover
from ..backups import config as backup_config
from ..backups import runner
from ..backups.offsite import OffsiteError
from ..core import audit, vault
from ..core.config import settings
from ..core.models import RecoveryBase, StoreCopy
from . import archive, config, envelope, files, layout, role
from .remote import Remote, Session, open_remote

logger = logging.getLogger("nik.recovery")

LEASE = "recovery-ship"
SYSTEM = runner.SYSTEM
# How long one pass sends segments and files before it lets the next one look again.
BUDGET = 45.0
RETRY_AFTER = 600
PRUNE_EVERY = 1800
# With nothing to send, the other host is still spoken to this often: to leave the heartbeat, and
# to learn that this server was replaced. A host that does not answer is tried again this often.
HEARTBEAT_EVERY = 60
LINK_RETRY = 30
HEARTBEAT = "heartbeat.json"
HAVE = "store.have"
STORE_BATCH = 200
SEALED_KIND = "sealed"
BLOCK = 256 * 1024

_sealer = envelope.Sealer()


# --------------------------------------------------------------------------- #
# The delay                                                                   #
# --------------------------------------------------------------------------- #
def position(db: OrmSession) -> tuple[str, int]:
    """The segment PostgreSQL writes now, and where in its log it is."""
    row = db.execute(text("select pg_walfile_name(pg_current_wal_lsn()), pg_current_wal_lsn() - '0/0'::pg_lsn")).one()
    return str(row[0] or ""), int(row[1] or 0)


def close_segment(db: OrmSession) -> str:
    """Have PostgreSQL close the segment it writes. Returns its name."""
    name = position(db)[0]
    db.execute(text("select pg_switch_wal()"))
    return name


def delay(shipped: dict[str, Any] | None, current: str, position: int, now: float) -> dict[str, Any]:
    """How far behind the second host is. ``shipped`` is the last segment sent and when it was
    closed; ``current`` the segment PostgreSQL writes now, ``position`` where in the log it is."""
    if not shipped or not shipped.get("wal"):
        return {"seconds": None, "bytes": None, "safeUntil": None}
    timeline, number = layout.parse(shipped["wal"])
    end = (number + 1) * layout.SEGMENT_BYTES
    closed = float(shipped.get("closedAt") or 0)
    if not layout.is_segment(current) or layout.parse(current)[0] != timeline:
        # Another timeline since: the bytes cannot be counted across it; the time can.
        return {"seconds": max(0.0, now - closed), "bytes": None, "safeUntil": closed}
    behind = max(0, position - end)
    # A segment that was just opened holds its header and nothing of anybody's yet.
    quiet = current == layout.next_name(shipped["wal"]) and behind <= 512
    return {
        "seconds": 0.0 if quiet else max(0.0, now - closed),
        "bytes": 0 if quiet else behind,
        "safeUntil": now if quiet else closed,
    }


# --------------------------------------------------------------------------- #
# The passphrase the envelopes are sealed under                               #
# --------------------------------------------------------------------------- #
def seal_state(db: OrmSession, state: dict[str, Any], current: str) -> tuple[dict[str, Any], str | None]:
    """Follow a change of the backup passphrase. Returns what is kept of it and the earlier
    passphrase (None when there is none to go on with). The segment that is being written when
    the change is seen is closed: it and those before it are still sealed under the earlier one,
    so that a standby, which learns the new passphrase from the log, can open the log that
    brings it."""
    mark = envelope.fingerprint(current)
    kept = dict(state.get("seal") or {})
    earlier_token = (backup_config.read(db).get("previous") or [None])[0]
    earlier = vault.decrypt(earlier_token) if earlier_token else None
    if kept.get("mark") and kept["mark"] != mark:
        kept = {"mark": mark, "upTo": close_segment(db), "earlier": kept["mark"]}
    elif not kept.get("mark"):
        kept = {"mark": mark}
    if earlier is None or envelope.fingerprint(earlier) != kept.get("earlier"):
        earlier = None
    return kept, earlier


# --------------------------------------------------------------------------- #
# The pieces of a pass                                                        #
# --------------------------------------------------------------------------- #
def _waiting_segments(state: dict[str, Any]) -> list[tuple[str, Path]]:
    """The files of ``wal/`` not sent yet, in the order they must arrive: the segments after the
    last one sent, and the small files that describe a timeline."""
    last = str((state.get("shipped") or {}).get("wal") or "")
    sent_histories = set(state.get("histories") or [])
    found = [(name, path) for name, path in layout.histories("wal").items() if name not in sent_histories]
    found += [(name, path) for name, path in sorted(layout.local_segments("wal").items()) if name > last]
    return found


def _send_segment(session: Session, name: str, path: Path, phrase: str, now: float) -> dict[str, Any]:
    about = {"kind": "wal", "name": name, "createdAt": runner.iso(now), "nik": runner.nik_version()}
    handle, sealed_path = tempfile.mkstemp(prefix="nik-wal-", suffix=layout.WAL_SUFFIX)
    os.close(handle)
    try:
        envelope.seal_file(path, Path(sealed_path), _sealer.key(phrase, now), about, path.name)
        return session.put_file(Path(sealed_path), f"wal/{name}{layout.WAL_SUFFIX}")
    finally:
        Path(sealed_path).unlink(missing_ok=True)


def _send_base(session: Session, label: str, phrase: str, now: float) -> dict[str, Any]:
    folder = layout.folder("base") / label
    facts = archive.read_manifest(label)
    about = {
        "kind": "base",
        "name": label,
        "createdAt": runner.iso(archive.label_time(label)),
        "finishedAt": (folder / "backup_manifest").stat().st_mtime,
        "nik": runner.nik_version(),
        "startWal": facts["startWal"],
        "endWal": facts["endWal"],
        "timeline": facts["timeline"],
        "endTimeline": facts["endTimeline"],
        "endLsn": facts["endLsn"],
    }
    parts = [(name, folder / name) for name in ("backup_manifest", "pg_wal.tar.gz", "base.tar.gz")]
    key = _sealer.key(phrase, now)
    return session.put_stream(f"base/{label}.nikbak", lambda out: envelope.seal(out, key, about, parts))


def _sealed_source(name: str):
    """The bytes of a file of the store as they are on the disk, a piece at a time. From the disk
    in a process that holds the store; asked of the API process everywhere else."""
    from ..core import store

    if store.local():
        path = store.root() / name
        if not store.is_sealed(path):
            raise FileNotFoundError(name)
        handle = open(path, "rb")  # noqa: SIM115 - closed by the caller, as the response is
        return handle
    if not settings.STORE_API_URL:
        raise store_handover.NotServed("This process was not told where to ask for the files of the store")
    request = urllib.request.Request(  # noqa: S310 - the address of the API container, from the configuration
        f"{settings.STORE_API_URL}/api/internal/store-sealed?name={urllib.parse.quote(name, safe='')}",
        headers={store_handover.HEADER: store_handover.token(SEALED_KIND, name)},
    )
    try:
        return urllib.request.urlopen(request, timeout=store_handover.TIMEOUT)  # noqa: S310
    except urllib.error.HTTPError as error:
        if error.code == 404:
            raise FileNotFoundError(name) from None
        raise store_handover.NotServed(f"The API process answered {error.code} for {name}") from None
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise store_handover.NotServed(f"The API process could not be asked for {name}: {error}") from None


def _send_store_file(session: Session, name: str) -> dict[str, Any]:
    source = _sealed_source(name)
    try:

        def copy(out) -> None:
            for piece in iter(lambda: source.read(BLOCK), b""):
                out.write(piece)

        return session.put_stream(f"store/{name}", copy)
    finally:
        source.close()


def _already_there(session: Session) -> dict[str, int]:
    """What a standby says it holds of the store already (``standby.py`` writes the list): after a
    promotion the old first host has nearly every file, and only those named by their content can
    be trusted to be the same."""
    raw = session.read_bytes(HAVE, limit=64 * 1024 * 1024)
    found: dict[str, int] = {}
    for line in (raw or b"").decode("utf-8", "replace").splitlines():
        size, _tab, name = line.partition("\t")
        if size.isdigit() and name:
            found[name] = int(size)
    return found


def _content_named(name: str) -> bool:
    stem, _dot, suffix = name.partition(".")
    return "/" not in name and len(stem) == 64 and suffix in ("bin", "mail")


# --------------------------------------------------------------------------- #
# One pass                                                                    #
# --------------------------------------------------------------------------- #
def _keep(db: OrmSession, state: dict[str, Any]) -> None:
    config.keep(db, config.SHIP_SETTINGS_ID, state)
    db.commit()


def ship(
    now: float | None = None,
    holder: str = runner.HOLDER,
    budget: float = BUDGET,
    stopping: Callable[[], bool] = lambda: False,
) -> list[str]:
    """One pass of the process that has a way out. Returns what it did. ``stopping`` says that
    the process was asked to stop: the file being sent is finished, and no other is started."""
    from ..core.db import SessionLocal

    clock = time.time() if now is None else now
    did: list[str] = []
    if not layout.available():
        return did
    with SessionLocal() as db:
        if not archive.postgres(db) or role.in_recovery(db) or role.superseded(db):
            return did
        if not config.acquire(db, holder, now, LEASE):
            return did
        state = config.held(db, config.SHIP_SETTINGS_ID)
        doc = backup_config.read(db)
        ready = backup_config.ready(doc.get("destination") or {})
        phrase = backup_config.passphrase(db) if doc.get("passphrase") else None
        if not ready or phrase is None:
            if state.get("on"):
                state["on"] = False
                _keep(db, state)
            return did
        try:
            remote = open_remote(db)
            trouble = "" if remote is not None else "The destination is not an SFTP account"
        except OffsiteError as error:
            remote, trouble = None, str(error)
        if remote is None:
            _link_down(db, state, trouble, clock)
            return did
        if state.get("where") != remote.where:
            # The copies go somewhere else from now on: everything is sent again, to there.
            _start_over(db, state, remote.where)
            did.append("destination:new")
        state["on"] = True
        seal, earlier = seal_state(db, state, phrase)
        state["seal"] = seal
        waits = work_waits(db, state, clock)
        if waits:
            state["connectedAt"] = clock
        _keep(db, state)
    if not waits:
        return did
    try:
        with runner.Renewing(holder, LEASE, config.LEASE_SECONDS), remote.session() as session:
            did += _pass(session, remote, phrase, earlier, clock, budget, stopping)
    except (OffsiteError, OSError, EOFError) as error:
        with SessionLocal() as db:
            state = config.held(db, config.SHIP_SETTINGS_ID)
            _link_down(db, state, str(error) or type(error).__name__, clock)
        did.append("link:down")
    except Exception as error:  # noqa: BLE001 - whatever the SSH library raises: said, and tried again
        logger.exception("A pass of the copies of the archive failed")
        with SessionLocal() as db:
            state = config.held(db, config.SHIP_SETTINGS_ID)
            _link_down(db, state, f"{type(error).__name__}: {error}", clock)
        did.append("link:down")
    return did


def work_waits(db: OrmSession, state: dict[str, Any], now: float) -> bool:
    """Whether this pass has a reason to open a connection: something to send or to remove, or the
    time to speak has come. An SSH sign-in every few seconds for nothing would fill the log of the
    other host."""
    link = state.get("link") or {}
    if link.get("ok") is False and now - float(state.get("connectedAt") or 0) < LINK_RETRY:
        return False
    if now - float(state.get("connectedAt") or 0) >= HEARTBEAT_EVERY:
        return True
    if state.get("hold"):
        return False  # nothing is sent while the copies point at this host itself: asked again at the next beat
    if _waiting_segments(state):
        return True
    if db.scalars(
        select(RecoveryBase.id)
        .where(RecoveryBase.offsite_state.in_(("pending", "delete")), RecoveryBase.state == "done")
        .limit(1)
    ).first():
        return True
    return bool(
        db.scalars(
            select(StoreCopy.name).where(StoreCopy.gone_at.is_(None), StoreCopy.state == "pending").limit(1)
        ).first()
    )


def _link_down(db: OrmSession, state: dict[str, Any], why: str, now: float) -> None:
    before = state.get("link") or {}
    state["link"] = {
        "ok": False,
        "error": why[:400],
        "since": before.get("since") if before.get("ok") is False else now,
        "okAt": before.get("okAt"),
    }
    role.note_unreachable(db, why, now)
    _keep(db, state)


def _start_over(db: OrmSession, state: dict[str, Any], where: str) -> None:
    for key in ("shipped", "histories", "pruned", "haveRead", "hold", "heartbeatAt"):
        state.pop(key, None)
    state["where"] = where
    for row in db.scalars(select(RecoveryBase).where(RecoveryBase.state == "done", RecoveryBase.local.is_(True))):
        row.offsite_state, row.offsite = "pending", {}
        flag_modified(row, "offsite")
    for row in db.scalars(select(RecoveryBase).where(RecoveryBase.local.is_(False))):
        db.delete(row)  # its copy is on the host that is no longer the destination
    files.send_again(db)


def _pass(
    session: Session,
    remote: Remote,
    phrase: str,
    earlier: str | None,
    clock: float,
    budget: float,
    stopping: Callable[[], bool] = lambda: False,
) -> list[str]:
    from ..core.db import SessionLocal

    did: list[str] = []
    started = time.monotonic()

    # 1. Was this server replaced?
    with SessionLocal() as db:
        verdict = role.note_marker(db, role.read_marker(session.read_bytes(role.MARKER)), clock)
        state = config.held(db, config.SHIP_SETTINGS_ID)
        before = state.get("link") or {}
        state["link"] = {"ok": True, "okAt": clock, "error": "", "since": None}
        # Its own marker where its copies go: a promoted standby, whose copies still point at its own
        # host. (A server recovered on a new host finds its marker on the second host, and sends.)
        held = verdict == "own" and bool(role.state(db).get("holdCopies", True))
        state["hold"] = "own" if held else "superseded" if verdict == "superseded" else None
        _keep(db, state)
        if verdict == "superseded":
            audit.record(
                db,
                SYSTEM,
                "standby.superseded",
                "The second host says its standby was promoted: this server was replaced and serves nothing more",
                target="server",
            )
            db.commit()
            return ["superseded"]
        if held:
            # This server was the standby and was promoted: the destination set in the database it
            # inherited is its own host. Nothing is sent until an administrator names the new one.
            return ["hold:own"]
        if before.get("ok") is False:
            did.append("link:up")

    # 2. The log, in order.
    seal = state.get("seal") or {}
    for name, path in _waiting_segments(state):
        if time.monotonic() - started > budget or stopping():
            break
        try:
            closed = path.stat().st_mtime
        except OSError:
            break  # removed under us: the next pass looks again
        used = envelope.passphrase_for(name, phrase, seal, earlier) if layout.is_segment(name) else phrase
        sent = _send_segment(session, name, path, used, clock)
        with SessionLocal() as db:
            state = config.held(db, config.SHIP_SETTINGS_ID)
            if layout.is_segment(name):
                state["shipped"] = {"wal": name, "closedAt": closed, "at": time.time(), "bytes": sent["bytes"]}
                state["sent"] = int(state.get("sent") or 0) + 1
                state["sentBytes"] = int(state.get("sentBytes") or 0) + int(sent["bytes"])
            else:
                state["histories"] = sorted({*(state.get("histories") or []), name})
            _keep(db, state)
        did.append(f"wal:{name}")

    # 3. Base backups.
    with SessionLocal() as db:
        waiting = [
            row.id
            for row in db.scalars(
                select(RecoveryBase)
                .where(RecoveryBase.state == "done", RecoveryBase.local.is_(True))
                .where(RecoveryBase.offsite_state.in_(("pending", "failed")))
                .order_by(RecoveryBase.created_at)
            )
            if row.offsite_state == "pending" or clock - float((row.offsite or {}).get("triedAt") or 0) >= RETRY_AFTER
        ]
        going = list(db.scalars(select(RecoveryBase.id).where(RecoveryBase.offsite_state == "delete")))
    for label in waiting:
        if stopping():
            break
        try:
            sent = _send_base(session, label, phrase, clock)
        except FileNotFoundError:
            continue  # the retention removed it meanwhile
        except (OffsiteError, OSError, ValueError, KeyError) as error:
            with SessionLocal() as db:
                row = db.get(RecoveryBase, label)
                if row is not None:
                    row.offsite_state = "failed"
                    row.offsite = {**(row.offsite or {}), "error": str(error)[:600], "triedAt": clock}
                    flag_modified(row, "offsite")
                    db.commit()
            did.append(f"base-failed:{label}")
            if isinstance(error, (OffsiteError, OSError)):
                raise
            continue
        with SessionLocal() as db:
            row = db.get(RecoveryBase, label)
            if row is not None:
                row.offsite_state = "copied"
                row.offsite = {"at": runner.iso(time.time()), "where": remote.where, "error": "", **sent}
                flag_modified(row, "offsite")
            audit.record(
                db,
                SYSTEM,
                "recovery.offsite",
                f"Copied the base backup {label} to {remote.where} ({sent['bytes']} bytes, sealed, checked after "
                "the upload)",
                target=label,
            )
            db.commit()
        did.append(f"base:{label}")
    for label in going:
        session.remove(f"base/{label}.nikbak")
        with SessionLocal() as db:
            row = db.get(RecoveryBase, label)
            if row is not None:
                db.delete(row)
                db.commit()
        did.append(f"base-removed:{label}")

    if stopping():
        # Asked to stop: what was sent is counted, the rest waits for the process that starts next.
        # A file that was cut half-way is a ``.partial`` on the other host, which nothing reads.
        return did

    # 4. Files of the store.
    did += _send_store(session, clock, started, budget, stopping)
    if stopping():
        return did

    # 5. What is no longer kept.
    did += _prune(session, clock)

    # 6. The heartbeat.
    with SessionLocal() as db:
        state = config.held(db, config.SHIP_SETTINGS_ID)
        if clock - float(state.get("heartbeatAt") or 0) >= HEARTBEAT_EVERY - 5 or did:
            # Signed, as the marker is (role.py): the standby believes no heartbeat that is not.
            said = role.sign("heartbeat", heartbeat(db, state, clock))
            session.put_bytes(HEARTBEAT, json.dumps(said, sort_keys=True).encode("utf-8"))
            state["heartbeatAt"] = clock
            _keep(db, state)
    return did


def heartbeat(db: OrmSession, state: dict[str, Any], now: float) -> dict[str, Any]:
    """What this host says of itself to the standby."""
    behind = delay(state.get("shipped"), *position(db), now)
    return {
        "at": now,
        "name": role.name(db),
        "generation": role.generation(db),
        "version": runner.nik_version(),
        "lastWal": (state.get("shipped") or {}).get("wal"),
        "closedAt": (state.get("shipped") or {}).get("closedAt"),
        "behindSeconds": behind["seconds"],
        "behindBytes": behind["bytes"],
        "storeWaiting": files.waiting(db)["files"],
        "archiveTimeout": settings.ARCHIVE_TIMEOUT,
    }


def _send_store(
    session: Session, clock: float, started: float, budget: float, stopping: Callable[[], bool] = lambda: False
) -> list[str]:
    from ..core.db import SessionLocal

    did: list[str] = []
    with SessionLocal() as db:
        state = config.held(db, config.SHIP_SETTINGS_ID)
        if not state.get("haveRead"):
            there = _already_there(session)
            matched = 0
            if there:
                for row in db.scalars(
                    select(StoreCopy).where(StoreCopy.state != "copied", StoreCopy.gone_at.is_(None))
                ):
                    if _content_named(row.name) and there.get(row.name) == row.size:
                        row.state, row.copied_at, row.error = "copied", clock, ""
                        matched += 1
            state["haveRead"] = True
            _keep(db, state)
            if matched:
                did.append(f"store-there:{matched}")
        rows = [
            row.name
            for row in db.scalars(
                select(StoreCopy)
                .where(StoreCopy.gone_at.is_(None), StoreCopy.state.in_(("pending", "failed")))
                .order_by(StoreCopy.seen_at)
                .limit(STORE_BATCH * 4)
            )
            if row.state == "pending" or clock - float(row.copied_at or row.seen_at or 0) >= RETRY_AFTER
        ][:STORE_BATCH]
    for name in rows:
        if time.monotonic() - started > budget or stopping():
            break
        try:
            _send_store_file(session, name)
            outcome, error = "copied", ""
        except FileNotFoundError:
            continue  # deleted, or not sealed yet: the scan of the API process says which
        except store_handover.NotServed as failure:
            outcome, error = "failed", str(failure)
        with SessionLocal() as db:
            row = db.get(StoreCopy, name)
            if row is not None:
                row.state, row.error = outcome, error[:600]
                row.copied_at = clock if outcome == "copied" else row.copied_at
                if outcome == "failed":
                    row.seen_at = clock
                db.commit()
        did.append(f"store:{name}" if outcome == "copied" else f"store-failed:{name}")
    return did


def _prune(session: Session, clock: float) -> list[str]:
    from ..core.db import SessionLocal

    did: list[str] = []
    with SessionLocal() as db:
        state = config.held(db, config.SHIP_SETTINGS_ID)
        oldest_copied = db.scalars(
            select(RecoveryBase)
            .where(RecoveryBase.state == "done", RecoveryBase.offsite_state == "copied")
            .order_by(RecoveryBase.created_at)
            .limit(1)
        ).first()
        horizon = (config.held(db, config.ARCHIVE_SETTINGS_ID).get("oldest") or {}).get("at")
        removals = files.due_removals(db, float(horizon)) if horizon else []
        due = clock - float(state.get("pruned") or 0) >= PRUNE_EVERY
        before = oldest_copied.start_wal if oldest_copied is not None else ""
    for name in removals:
        session.remove(f"store/{name}")
        with SessionLocal() as db:
            row = db.get(StoreCopy, name)
            if row is not None:
                row.removed_at = clock
                db.commit()
        did.append(f"store-removed:{name}")
    if due and before:
        removed = 0
        for name, _size in session.listing("wal"):
            stem = name[: -len(layout.WAL_SUFFIX)] if name.endswith(layout.WAL_SUFFIX) else ""
            # The log before the oldest base backup that is on the other host: no recovery starts there.
            if layout.is_segment(stem[:24]) and stem[:24] < before and session.remove(f"wal/{name}"):
                removed += 1
        with SessionLocal() as db:
            state = config.held(db, config.SHIP_SETTINGS_ID)
            state["pruned"] = clock
            _keep(db, state)
            files.forget_removed(db, clock - 30 * 86400)
            db.commit()
        if removed:
            did.append(f"wal-removed:{removed}")
    return did


def status(db: OrmSession, now: float | None = None) -> dict[str, Any]:
    """Where the copies stand, for the screen and the watch."""
    now = time.time() if now is None else now
    state = config.held(db, config.SHIP_SETTINGS_ID)
    behind = {"seconds": None, "bytes": None, "safeUntil": None}
    if state.get("on") and archive.postgres(db) and not role.in_recovery(db):
        behind = delay(state.get("shipped"), *position(db), now)
    return {
        "on": bool(state.get("on")),
        "where": state.get("where") or "",
        "shipped": state.get("shipped") or None,
        "link": state.get("link") or None,
        "hold": state.get("hold"),
        "sent": int(state.get("sent") or 0),
        "sentBytes": int(state.get("sentBytes") or 0),
        "behind": behind,
        "store": files.waiting(db),
    }

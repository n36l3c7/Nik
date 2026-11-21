"""What a standby does while it waits: take in what the first host sends.

The first host writes into a directory of this host over SFTP (the
destination of its backups); this stack mounts that directory
(``NIK_STANDBY_INBOX``). One pass (``intake``), every few seconds, by the one
process of a standby that runs (``gate.py``):

- **the log**: each sealed segment that arrived and was not replayed yet is
  opened with the backup passphrase and put in ``incoming/`` of the archive
  volume, where PostgreSQL finds it (``deploy/db/wal-restore.sh``). The
  passphrase is read from the database this standby replays: it is the one of
  the first host, and follows it when it is changed. Segments PostgreSQL no
  longer needs are removed from ``incoming/``;
- **the files of the store**: copied into the store of this stack as they
  are (sealed under the store key of the first host, which this host must
  hold to be its standby), and removed from the directory they arrived in
  when this process may; a file the first host has removed from its copies
  for good is removed here too;
- **the list of what is here** (``store.have``), for the day the roles are
  exchanged and the other host asks what it need not send again.

Nothing is written to the database: it is read-only, and stays so until
``deploy/standby.sh promote``.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import shutil
import time
from pathlib import Path
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.orm import Session as OrmSession

from ..backups import config as backup_config
from ..backups.container import BackupError, Secrets, WrongKey
from ..core.config import settings
from ..core.models import StoreCopy
from . import envelope, kept, layout

logger = logging.getLogger("nik.recovery")

HAVE = "store.have"
PROMOTING = ".promoting"
HAVE_EVERY = 600
NOTES = ".standby.json"
BATCH = 200
BLOCK = 1024 * 1024

_openers: dict[tuple, envelope.Opener] = {}
_last_have = 0.0


def inbox() -> Path | None:
    """The directory the first host sends to, as this process sees it; None when none is mounted."""
    if not settings.STANDBY_INBOX:
        return None
    found = Path(settings.STANDBY_INBOX) / layout.REMOTE
    return found if found.is_dir() else None


def opener(secrets: Secrets) -> envelope.Opener:
    mark = (secrets.passphrases, secrets.secret_keys)
    if mark not in _openers:
        _openers.clear()
        _openers[mark] = envelope.Opener(secrets)
    return _openers[mark]


def secrets_of(db: OrmSession | None) -> Secrets:
    """What the envelopes may be opened with: the passphrases the database knows, and the one an
    operator gave to the command that runs this (``NIK_BACKUP_PASSPHRASE``)."""
    given = os.environ.get("NIK_BACKUP_PASSPHRASE", "")
    known = backup_config.secrets(db) if db is not None else Secrets()
    phrases = tuple(dict.fromkeys(filter(None, (*known.passphrases, given))))
    return Secrets(passphrases=phrases, secret_keys=known.secret_keys)


def replay(db: OrmSession) -> dict[str, Any]:
    """Where the replay of this standby stands."""
    row = db.execute(
        text(
            "select pg_last_wal_replay_lsn() - '0/0'::pg_lsn, extract(epoch from pg_last_xact_replay_timestamp()),"
            " extract(epoch from now()), (select redo_wal_file from pg_control_checkpoint()),"
            " (select timeline_id from pg_control_checkpoint())"
        )
    ).one()
    return {
        "position": int(row[0] or 0),
        "lastChange": float(row[1]) if row[1] is not None else None,
        "at": float(row[2] or 0),
        "redo": str(row[3] or ""),
        "timeline": int(row[4] or 0),
    }


def open_segments(box: Path, secrets: Secrets, redo: str = "", limit: int = BATCH) -> dict[str, Any]:
    """Open the sealed segments of ``box/wal`` into ``incoming/``. Those before ``redo`` (the
    segment PostgreSQL would restart its replay from) are not needed any more and are left alone."""
    target = layout.folder("incoming")
    did = {"opened": 0, "waiting": 0, "error": "", "last": ""}
    try:
        names = sorted(path.name for path in (box / "wal").iterdir() if path.name.endswith(layout.WAL_SUFFIX))
    except OSError:
        return did
    opens = opener(secrets)
    for file_name in names:
        stem = file_name[: -len(layout.WAL_SUFFIX)]
        segment = layout.is_segment(stem)
        if not segment and not layout.HISTORY.match(stem):
            continue
        if segment and redo and stem < redo:
            continue
        if (target / (stem + layout.GZ)).exists():
            continue
        if did["opened"] >= limit:
            did["waiting"] += 1
            continue
        try:
            with open(box / "wal" / file_name, "rb") as source:
                envelope.unseal(source, opens, target, expect="wal")
        except WrongKey as error:
            # The passphrase was changed on the first host and this standby has not replayed the
            # change yet: this segment waits for the ones before it, and so do those after it.
            did["error"] = f"{file_name}: {error}"
            did["waiting"] += 1
            break
        except (BackupError, OSError) as error:
            did["error"] = f"{file_name}: {error}"
            did["waiting"] += 1
            break
        did["opened"] += 1
        did["last"] = stem
    return did


def sweep_incoming(redo: str) -> int:
    """Remove from ``incoming/`` the segments PostgreSQL no longer needs to restart its replay."""
    removed = 0
    if not layout.is_segment(redo):
        return 0
    for name, path in layout.local_segments("incoming").items():
        if name < redo:
            with contextlib.suppress(OSError):
                path.unlink()
                removed += 1
    return removed


def take_store(box: Path, root: Path | None = None, limit: int = BATCH, remove: bool = True) -> dict[str, int]:
    """Copy the files of the store that arrived into the store of this stack. ``remove``: take them
    out of the directory they arrived in (a standby does; a recovery leaves the copies as they are)."""
    root = Path(settings.SAMPLE_STORE) if root is None else root
    source_root = box / "store"
    did = {"taken": 0, "left": 0}
    if not source_root.is_dir():
        return did
    for folder, folders, names in os.walk(source_root):
        folders.sort()
        for name in sorted(names):
            if name.endswith(".partial"):
                continue
            source = Path(folder, name)
            relative = source.relative_to(source_root)
            if relative.parts[0] == kept.KEPT or ".." in relative.parts:
                continue
            target = root.joinpath(*relative.parts)
            try:
                size = source.stat().st_size
                same = (
                    target.exists()
                    and target.stat().st_size == size
                    and target.stat().st_mtime >= source.stat().st_mtime
                )
                if not same:
                    if did["taken"] >= limit:
                        did["left"] += 1
                        continue
                    target.parent.mkdir(parents=True, exist_ok=True)
                    part = target.with_name(target.name + ".part")
                    with open(source, "rb") as reading, open(part, "wb") as writing:
                        shutil.copyfileobj(reading, writing, BLOCK)
                        writing.flush()
                        os.fsync(writing.fileno())
                    os.chmod(part, 0o600)
                    os.replace(part, target)
                    did["taken"] += 1
                # Here once, when this process may remove what arrived; twice when it may not.
                if remove:
                    with contextlib.suppress(OSError):
                        source.unlink()
            except OSError as error:
                logger.warning("A file of the store that arrived could not be taken (%s): %s", relative, error)
                did["left"] += 1
    return did


def drop_removed(db: OrmSession, root: Path | None = None) -> int:
    """Remove the files the first host has removed from its copies for good."""
    root = Path(settings.SAMPLE_STORE) if root is None else root
    removed = 0
    for name in db.scalars(select(StoreCopy.name).where(StoreCopy.removed_at.is_not(None))):
        path = root / name
        if ".." in Path(name).parts or not path.is_file():
            continue
        with contextlib.suppress(OSError):
            path.unlink()
            removed += 1
    return removed


def write_have(box: Path, root: Path | None = None) -> bool:
    """Leave the list of what the store of this stack holds, where the other host can read it."""
    root = Path(settings.SAMPLE_STORE) if root is None else root
    lines = []
    if root.is_dir():
        with os.scandir(root) as entries:
            for entry in entries:
                # Only the files named by their content: the others are sent again anyway.
                if entry.is_file(follow_symlinks=False) and entry.name.endswith((".bin", ".mail")):
                    lines.append(f"{entry.stat(follow_symlinks=False).st_size}\t{entry.name}")
    try:
        part = box / (HAVE + ".partial")
        part.write_text("\n".join(sorted(lines)) + ("\n" if lines else ""), encoding="utf-8")
        os.chmod(part, 0o644)
        os.replace(part, box / HAVE)
        return True
    except OSError:
        return False


def mark_promoting(now: float | None = None) -> bool:
    """Write down that a promotion has started (``deploy/standby.sh promote`` does, just before it
    has PostgreSQL leave recovery). Until ``done_promoting`` this server is neither a standby
    nor the server: its database may be open, but nothing has yet made it the server."""
    try:
        path = layout.folder("incoming") / PROMOTING
        if not path.exists():
            path.write_text(json.dumps({"at": time.time() if now is None else now}), encoding="utf-8")
        return True
    except OSError:
        return False


def promoting() -> bool:
    try:
        return (layout.folder("incoming") / PROMOTING).exists()
    except OSError:
        return False


def done_promoting() -> None:
    with contextlib.suppress(OSError):
        (layout.folder("incoming") / PROMOTING).unlink()


def read_heartbeat(box: Path | None) -> dict[str, Any] | None:
    if box is None:
        return None
    try:
        found = json.loads((box / "heartbeat.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return found if isinstance(found, dict) else None


def notes() -> dict[str, Any]:
    """What the last pass wrote down (read by ``status`` from another process of the container)."""
    try:
        return json.loads((layout.folder("incoming") / NOTES).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _write_notes(found: dict[str, Any]) -> None:
    try:
        path = layout.folder("incoming") / NOTES
        part = path.with_name(NOTES + ".part")
        part.write_text(json.dumps(found), encoding="utf-8")
        os.replace(part, path)
    except OSError:
        pass


def intake(now: float | None = None) -> dict[str, Any]:
    """One pass of a standby. Returns what it did."""
    global _last_have
    from ..core.db import SessionLocal

    clock = time.time() if now is None else now
    box = inbox()
    did: dict[str, Any] = {"at": clock, "inbox": bool(box)}
    if box is None or not layout.available():
        _write_notes(did | {"error": "No directory of the first host is mounted (NIK_STANDBY_INBOX)"})
        return did
    redo = ""
    with SessionLocal() as db:
        try:
            found = replay(db)
            redo = found["redo"]
            secrets = secrets_of(db)
            did["dropped"] = drop_removed(db)
        except Exception as error:  # noqa: BLE001 - the database is starting, or is not there yet
            db.rollback()
            secrets = secrets_of(None)
            did["database"] = f"{type(error).__name__}"
    did["wal"] = open_segments(box, secrets, redo)
    did["swept"] = sweep_incoming(redo)
    did["store"] = take_store(box)
    if clock - _last_have >= HAVE_EVERY:
        _last_have = clock
        did["have"] = write_have(box)
    before = notes()
    did["lastOpened"] = did["wal"]["last"] or before.get("lastOpened") or ""
    did["lastOpenedAt"] = clock if did["wal"]["last"] else before.get("lastOpenedAt")
    did["error"] = did["wal"]["error"]
    _write_notes(did)
    return did


def status(db: OrmSession, now: float | None = None) -> dict[str, Any]:
    """Where this standby stands: how far it replayed, what the first host last said, what waits."""
    now = time.time() if now is None else now
    box = inbox()
    found = replay(db)
    beat = read_heartbeat(box)
    noted = notes()
    arrived = None
    waiting = 0
    if box is not None and (box / "wal").is_dir():
        with contextlib.suppress(OSError):
            names = [path for path in (box / "wal").iterdir() if path.name.endswith(layout.WAL_SUFFIX)]
            if names:
                newest = max(names, key=lambda path: path.stat().st_mtime)
                arrived = {"name": newest.name, "at": newest.stat().st_mtime}
            # What arrived and is not replayed yet: the segments from the one the replay stands in.
            at = layout.segment_of(found["timeline"], found["position"]) if found["position"] else ""
            waiting = (
                sum(1 for path in names if layout.is_segment(path.name[:24]) and path.name[:24] >= at) if at else 0
            )
    return {
        "inbox": box is not None,
        "replay": found,
        "heartbeat": beat,
        "arrived": arrived,
        "waiting": waiting,
        "intake": {key: noted.get(key) for key in ("at", "error", "lastOpened", "lastOpenedAt")},
        "behindSeconds": (now - found["lastChange"]) if found["lastChange"] else None,
    }

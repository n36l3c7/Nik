"""Sealing a store that was in clear, changing the key it is under, and saying when a file is damaged.

**The conversion.** A server from before 6.8 has a store of files in clear.
Its first start with 6.8 does not wait: new files are sealed from that
moment, old ones are read as they are, and a thread of the API process
(``key_rotation.start``) seals them one after the other:

- a file is read, sealed into a file beside it, read back through the
  reader and compared with what was read (its SHA-256); only then does the
  sealed file take the place of the clear one, in one move. A file is
  therefore whole and in clear, or whole and sealed, whenever the server
  stops;
- one file at a time: the room needed is that of the largest file, never a
  second copy of the store. A file there is no room for is left for later
  and said (``stuck``);
- throttled (``STORE_SEAL_MBPS``, 40 MB a second unless set) so that the
  server stays usable, a few seconds of work at a time, under a lease that
  one process holds;
- nothing is remembered but the counts: whether a file is sealed is read
  from the file, so a restart goes on where it stopped;
- it can be paused and taken up again (``set_paused``).

When a whole walk of the store finds no file in clear, the store is
**sealed**: the date is written down, the administrators are told, and from
then on a file found in clear is not one Nik wrote and is refused like a
damaged one (``core/store.py`` asks ``clear_allowed``).

**Changing the store key** (``rewrap``). While the server holds an earlier
store key beside the current one, the key of every file is put under the
current one: the head of each file, never its content. When a walk finds
every file under the current key alone, and has opened each with it, the
change is over and the earlier key is no longer needed.

**A damaged file** (``report_damaged``) is written to the audit log and told
to the administrators, once for each file.

Everything is kept in one row of ``settings`` (``SETTINGS_ID``).
"""

from __future__ import annotations

import contextlib
import errno
import hashlib
import logging
import os
import shutil
import time
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm.attributes import flag_modified

from .core import sealed, store
from .core.config import settings

logger = logging.getLogger("nik.store")

SETTINGS_ID = 50  # 40 to 46 are the audit log and the health page; 51 is key_rotation.py
LEASE = "store-seal"
LEASE_SECONDS = 45
HOLDER = f"{uuid.uuid4()}"
LINK = "/settings/system/storage"
SEALING = ".sealing"
PIECE = 1024 * 1024
# How long one pass works before it gives the lease a rest and looks at the state again.
PASS_SECONDS = 15.0
ROOM_SPARE = 16 * 1024 * 1024
# What an interrupted write or an interrupted export left behind is removed once it is this old.
LEFTOVER_AFTER = 3600.0
STUCK_KEPT = 50
DAMAGED_KEPT = 100
STRICT_TTL = 15.0
SYSTEM = "system"

CONVERTING, PAUSED, SEALED = "converting", "paused", "sealed"

RETRY_STUCK = 600.0
# How often, inside a pass, the row is read again to see whether the conversion was paused.
PAUSE_LOOK = 1.0
PROBE_FILES = 500

_strict: tuple[float, bool] | None = None
# How many files of the walk the last pass of this process looked at: the next one goes on from there.
_cursor = [0]


def _rate() -> float:
    """Bytes a second the conversion may read; 0 is as fast as the disk goes."""
    try:
        return max(0.0, float(os.environ.get("STORE_SEAL_MBPS", "40"))) * 1024 * 1024
    except ValueError:
        return 40.0 * 1024 * 1024


def _iso(at: float) -> str:
    from datetime import datetime, timezone

    return datetime.fromtimestamp(at, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------- #
# The row                                                                     #
# --------------------------------------------------------------------------- #
def read(db: OrmSession) -> dict[str, Any]:
    from .core.models import Setting

    row = db.get(Setting, SETTINGS_ID)
    return dict((row.doc if row else None) or {})


def _write(db: OrmSession, doc: dict[str, Any]) -> None:
    from .core.models import Setting

    row = db.get(Setting, SETTINGS_ID)
    if row is None:
        db.add(Setting(id=SETTINGS_ID, doc=doc))
        return
    row.doc = doc
    flag_modified(row, "doc")


def _update(**changes: Any) -> dict[str, Any]:
    """Change keys of the row in a transaction of its own; returns the row as written."""
    from .core.db import SessionLocal

    with SessionLocal() as db:
        doc = {**read(db), **changes}
        _write(db, doc)
        db.commit()
    return doc


def why(error: BaseException) -> str:
    """Why a file could not be put under a new key, in words chosen here from the kind of the
    error: what is kept with the progress of a change of key, shown on the Keys screen and printed
    by the command line. Never the text of the error itself, which is written by whatever raised
    it and may hold anything."""
    if isinstance(error, sealed.WrongKey):
        return "no key the server holds opens it"
    if isinstance(error, sealed.SealError):
        return "it is damaged: it fails its check"
    if isinstance(error, OSError):
        code = errno.errorcode.get(error.errno or 0, "")
        return "the system refused to read or write it" + (f" ({code})" if code else "")
    return f"an error of the kind {type(error).__name__}"


def clear_allowed() -> bool:
    """Whether a file in clear may still be a file of Nik: true until the store is sealed."""
    global _strict
    now = time.monotonic()
    if _strict is not None and now - _strict[0] < STRICT_TTL:
        return _strict[1]
    from .core.db import SessionLocal

    try:
        with SessionLocal() as db:
            allowed = read(db).get("state") != SEALED
    except Exception:  # noqa: BLE001 - the database does not answer: what was known last stands
        return _strict[1] if _strict is not None else True
    _strict = (now, allowed)
    return allowed


def forget() -> None:
    """Drop what this process remembers of the row (the tests; a change it made itself)."""
    global _strict
    _strict = None


# --------------------------------------------------------------------------- #
# Walking the store                                                           #
# --------------------------------------------------------------------------- #
def _files(root: Path) -> Iterator[tuple[str, Path]]:
    """Every regular file of the store as ``(name, path)``, in a steady order."""
    for folder, folders, names in os.walk(root, followlinks=False):
        folders.sort()
        for name in sorted(names):
            path = Path(folder, name)
            try:
                if path.is_symlink() or not path.is_file():
                    continue
            except OSError:
                continue
            yield path.relative_to(root).as_posix(), path


def _is_leftover(name: str) -> bool:
    """A file an interrupted write or an interrupted export left: never a file of the store."""
    return name.endswith((store.PART, SEALING)) or name.startswith("_transfer/")


def _sweep_leftover(path: Path, now: float) -> bool:
    try:
        if now - path.stat().st_mtime > LEFTOVER_AFTER:
            path.unlink()
            return True
    except OSError:
        pass
    return False


def _head(path: Path) -> bytes:
    with open(path, "rb") as handle:
        return handle.read(sealed.HEADER)


def census(root: Path | None = None) -> dict[str, int]:
    """What the store holds at this moment: files and bytes in clear, files and bytes sealed."""
    root = store.root() if root is None else root
    found = {"clearFiles": 0, "clearBytes": 0, "sealedFiles": 0, "sealedBytes": 0}
    if not root.is_dir():
        return found
    ring = store.keyring() if store.local() else None
    for name, path in _files(root):
        if _is_leftover(name):
            continue
        try:
            size = path.stat().st_size
            is_sealed = sealed.is_sealed(_head(path)) and (ring is None or _opens(path, name, ring))
            kind = "sealed" if is_sealed else "clear"
        except OSError:
            continue
        found[f"{kind}Files"] += 1
        found[f"{kind}Bytes"] += size
    return found


# --------------------------------------------------------------------------- #
# Sealing one file                                                            #
# --------------------------------------------------------------------------- #
class NoRoom(Exception):
    """The disk has no room for the sealed copy of this file beside it."""


class Changed(Exception):
    """The file changed, or went away, while it was being sealed: nothing was done."""


def _identity(path: Path) -> tuple[int, int, int]:
    found = path.stat()
    return found.st_ino, found.st_size, found.st_mtime_ns


def seal_file(path: Path, name: str, ring: sealed.Keyring, usage=shutil.disk_usage) -> int:
    """Seal the file in clear at ``path``. Returns how many bytes it held.

    Raises ``NoRoom``, ``Changed``, ``OSError`` or ``sealed.SealError``; in
    every case the file is as it was.
    """
    before = _identity(path)
    size = before[1]
    needed = sealed.sealed_size(size) + ROOM_SPARE
    if usage(path.parent).free < needed:
        raise NoRoom(f"it needs {needed // 2**20} MB free beside it")
    beside = path.with_name(path.name + SEALING)
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as source, open(beside, "wb") as out:
            writer = sealed.Writer(out, name, ring.current)
            while piece := source.read(PIECE):
                digest.update(piece)
                writer.write(piece)
            writer.close()
            out.flush()
            os.fsync(out.fileno())
        # Read back through the reader, as it will be read from now on, before the clear file goes.
        check = hashlib.sha256()
        with sealed.open_sealed(beside, name, ring) as handle:
            while piece := handle.read(PIECE):
                check.update(piece)
        if check.digest() != digest.digest() or writer.size != size:
            raise sealed.Damaged("what was sealed is not what was read")
        os.chmod(beside, store.MODE)
        with store.swapping():
            # Somebody wrote the file again, or deleted it, meanwhile: theirs stands.
            try:
                if _identity(path) != before:
                    raise Changed(name)
            except FileNotFoundError:
                raise Changed(name) from None
            with contextlib.suppress(OSError):
                os.chmod(path, 0o600)
            os.replace(beside, path)
    finally:
        with contextlib.suppress(OSError):
            beside.unlink()
    return size


def unseal_file(path: Path, name: str, ring: sealed.Keyring) -> int:
    """The reverse, for going back to a version before 6.8: the file in clear again, checked the same way."""
    beside = path.with_name(path.name + SEALING)
    digest = hashlib.sha256()
    try:
        with sealed.open_sealed(path, name, ring) as source, open(beside, "wb") as out:
            while piece := source.read(PIECE):
                digest.update(piece)
                out.write(piece)
            out.flush()
            os.fsync(out.fileno())
            size = out.tell()
        check = hashlib.sha256()
        with open(beside, "rb") as handle:
            while piece := handle.read(PIECE):
                check.update(piece)
        if check.digest() != digest.digest():
            raise sealed.Damaged("what was written is not what was read")
        # As versions before 6.8 kept them: readable by the workers, never executable.
        os.chmod(beside, 0o444)
        os.replace(beside, path)
    finally:
        with contextlib.suppress(OSError):
            beside.unlink()
    return size


# --------------------------------------------------------------------------- #
# The conversion                                                              #
# --------------------------------------------------------------------------- #
def _tell_admins(db: OrmSession, kind: str, text: str) -> None:
    from . import tasks
    from .core.models import User
    from .core.permissions import stored_roles

    for user in db.scalars(select(User).where(User.disabled.is_(False))):
        if "admin" in stored_roles(user.roles):
            tasks.notify(db, user.username, kind, text, LINK)


def _say(action: str, details: str, notice: tuple[str, str] | None = None, **changes: Any) -> dict[str, Any]:
    """An audit line, a notice to the administrators and a change of the row, in one transaction."""
    from .core import audit
    from .core.db import SessionLocal

    with SessionLocal() as db:
        doc = {**read(db), **changes}
        _write(db, doc)
        audit.record(db, SYSTEM, action, details, target="store")
        if notice:
            _tell_admins(db, *notice)
        db.commit()
    forget()
    return doc


def _acquire(now: float | None = None, holder: str = HOLDER) -> bool:
    """Take or renew the lease of the loop; False while another process holds it. It is short: a
    server that was killed (a restart is part of every change of key) is taken over from within
    ``LEASE_SECONDS``, not after minutes."""
    from .core import leases
    from .core.db import SessionLocal

    with SessionLocal() as db:
        return leases.take(db, LEASE, holder, LEASE_SECONDS, now)


class _Renewing:
    """Keeps the lease while a pass works in this thread."""

    def __init__(self, holder: str) -> None:
        import threading

        self._holder, self._stop = holder, threading.Event()
        self._thread = threading.Thread(target=self._run, name="nik-store-lease", daemon=True)

    def _run(self) -> None:
        while not self._stop.wait(LEASE_SECONDS / 4):
            try:
                _acquire(holder=self._holder)
            except Exception:  # noqa: BLE001 - the work goes on; the next renewal tries again
                logger.exception("The lease of the encryption of the store could not be renewed")

    def __enter__(self) -> _Renewing:
        self._thread.start()
        return self

    def __exit__(self, *_exc) -> None:
        self._stop.set()


def _problem(doc: dict[str, Any], name: str, text: str | None) -> dict[str, Any] | None:
    """One notice when a problem appears and one when it is gone, as the other watches do
    (``backups/watch.py``). Returns the notice to send, or None."""
    problems = dict(doc.get("problems") or {})
    if text and name not in problems:
        problems[name] = {"since": time.time(), "text": text}
        doc["problems"] = problems
        return {"kind": "store.problem", "text": text}
    if text:
        problems[name] = {**problems[name], "text": text}
        doc["problems"] = problems
        return None
    if name in problems:
        del problems[name]
        doc["problems"] = problems
        return {"kind": "store.solved", "text": SOLVED[name]}
    return None


SOLVED = {
    "stuck": "The files of the store that could not be encrypted now are.",
}


def convert_pass(
    now: float | None = None,
    holder: str = HOLDER,
    budget: float = PASS_SECONDS,
    usage=shutil.disk_usage,
    sleep=time.sleep,
) -> dict[str, Any]:
    """One pass of the conversion, when this process holds the lease. Returns the row as it left it
    (empty when another process holds the lease, or this process has no store key)."""
    if not store.local() or not _acquire(now, holder):
        return {}
    from .core.db import SessionLocal

    clock = time.time() if now is None else now
    root = store.root()
    with SessionLocal() as db:
        doc = read(db)
    state = doc.get("state")
    if state in (SEALED, PAUSED):
        return doc
    ring = store.keyring()
    if state != CONVERTING:
        # The first look of this server at its store.
        _cursor[0] = 0
        found = census(root)
        if not found["clearFiles"]:
            # Nothing to convert: a new server, or one restored from a backup. Said in the log only.
            logger.info("The store of files holds no file in clear: every file is sealed from the start")
            _update(state=SEALED, since=_iso(clock), keyId=ring.current.id.hex(), converted=None)
            forget()
            return _update()
        doc = _say(
            "store.seal.start",
            f"Encrypting the store of files: {found['clearFiles']} file(s), {found['clearBytes']} bytes in clear",
            state=CONVERTING,
            keyId=doc.get("keyId") or ring.current.id.hex(),
            retryAt=0,
            startedAt=_iso(clock),
            total={"files": found["clearFiles"], "bytes": found["clearBytes"]},
            done={"files": 0, "bytes": 0},
            stuck=[],
            seconds=0.0,
        )
    if float(doc.get("retryAt") or 0) > clock:
        return doc  # everything that is left is stuck: tried again later
    done = dict(doc.get("done") or {"files": 0, "bytes": 0})
    stuck: list[dict[str, str]] = []
    now_sealed: list[str] = []
    started = time.monotonic()
    worked = sealed_now = 0
    asked = started
    # Whether files this pass did not look at may still be in clear: it did not start at the first
    # file, it ran out of time, or a file changed under it.
    left = _cursor[0] > 0
    seen = 0
    with _Renewing(holder):
        for name, path in _files(root) if root.is_dir() else ():
            seen += 1
            if seen <= _cursor[0]:
                continue  # looked at by the pass before this one
            if _is_leftover(name):
                _sweep_leftover(path, time.time())
                continue
            try:
                if sealed.is_sealed(_head(path)) and _opens(path, name, ring):
                    continue
            except OSError:
                continue
            # A pass always seals one file at least, however small its time: it never stands still.
            if sealed_now and time.monotonic() - started > budget:
                left = True
                seen -= 1
                break
            # A pause is obeyed between two files, not at the end of the pass.
            if sealed_now and time.monotonic() - asked > PAUSE_LOOK:
                asked = time.monotonic()
                with SessionLocal() as db:
                    if read(db).get("state") != CONVERTING:
                        left = True
                        seen -= 1
                        break
            try:
                size = seal_file(path, name, ring, usage)
            except Changed:
                left = True  # written again or deleted meanwhile: the next walk sees what is there
                continue
            except NoRoom as error:
                stuck.append({"name": name, "reason": f"There is no room on the disk to encrypt it: {error}"})
                continue
            except (OSError, sealed.SealError) as error:
                stuck.append({"name": name, "reason": f"It could not be encrypted: {error}"})
                continue
            done["files"] += 1
            done["bytes"] += size
            worked += size
            now_sealed.append(name)
            sealed_now += 1
            rate = _rate()
            if rate:
                # Not faster than the rate, counted over this pass.
                ahead = worked / rate - (time.monotonic() - started)
                if ahead > 0:
                    sleep(min(ahead, 5.0))
        else:
            seen = 0  # the end of the store was reached: the next pass starts at its first file
    _cursor[0] = seen
    seconds = float(doc.get("seconds") or 0.0) + (time.monotonic() - started if worked else 0.0)
    with SessionLocal() as db:
        doc = read(db)
        if doc.get("state") != CONVERTING:
            # Paused meanwhile: what this pass sealed is counted, and nothing is concluded.
            doc.update(done=done, seconds=seconds)
            _write(db, doc)
            db.commit()
            return doc
        doc.update(done=done, seconds=seconds)
        if doc.get("damaged"):
            # A file that did not open while it was in clear (it starts like a sealed one) reads now.
            doc["damaged"] = {name: entry for name, entry in doc["damaged"].items() if name not in now_sealed}
        notices = []
        from .core import audit

        note = None
        if not left:
            # A whole walk, from the first file to the last.
            doc.update(stuck=stuck[:STUCK_KEPT], stuckCount=len(stuck))
            if stuck:
                # What is left cannot be sealed now: said once, and tried again in ten minutes.
                doc["retryAt"] = time.time() + RETRY_STUCK
                note = _problem(
                    doc,
                    "stuck",
                    f"{len(stuck)} file(s) of the store could not be encrypted and are still in clear (the first: "
                    f"{stuck[0]['name']}: {stuck[0]['reason']}). Nik tries again by itself; the list is in "
                    "Settings → Storage.",
                )
            else:
                # Nothing in clear was left: the check that ends the conversion.
                note = _problem(doc, "stuck", None)
                doc.update(state=SEALED, since=_iso(time.time()), keyId=ring.current.id.hex(), retryAt=0)
                doc["converted"] = {"files": done["files"], "bytes": done["bytes"], "seconds": round(seconds)}
                said = (
                    f"The store of files is encrypted: {done['files']} file(s) were sealed and none is in clear "
                    "any more."
                )
                audit.record(db, SYSTEM, "store.seal.done", said, target="store")
                notices.append({"kind": "store.sealed", "text": said})
        if note and note["kind"] == "store.problem":
            audit.record(db, SYSTEM, "store.seal.stuck", note["text"], target="store")
        if note:
            notices.append(note)
        _write(db, doc)
        for notice in notices:
            _tell_admins(db, notice["kind"], notice["text"])
        db.commit()
    forget()
    return doc


def _opens(path: Path, name: str, ring: sealed.Keyring) -> bool:
    """Whether a file that starts like a sealed one is one: a file in clear may start with the same
    eight bytes (somebody uploaded a sealed file as a sample before 6.8), and is then sealed too."""
    try:
        sealed.file_key(sealed.parse_head(_head(path)), name, ring)
        return True
    except sealed.SealError:
        # Not a head this server opens: damaged, or under a key it does not hold. A sample is named
        # by its SHA-256: when the bytes on the disk are that very sample, they are the sample in clear.
        stem = path.name.split(".", 1)[0]
        if len(stem) != 64:
            return True
        digest = hashlib.sha256()
        try:
            with open(path, "rb") as handle:
                while piece := handle.read(PIECE):
                    digest.update(piece)
        except OSError:
            return True
        return digest.hexdigest() != stem


def set_paused(db: OrmSession, paused: bool, actor: str) -> dict[str, Any]:
    """Pause the conversion, or take it up again (the caller commits)."""
    from .core import audit

    doc = read(db)
    state = doc.get("state")
    if paused and state == CONVERTING:
        doc.update(state=PAUSED, pausedBy=actor, pausedAt=_iso(time.time()))
        audit.record(db, actor, "store.seal.pause", "Paused the encryption of the store of files", target="store")
    elif not paused and state == PAUSED:
        doc.update(state=CONVERTING, pausedBy="", pausedAt="")
        audit.record(
            db, actor, "store.seal.resume", "Took up the encryption of the store of files again", target="store"
        )
    else:
        return doc
    doc["retryAt"] = 0
    _write(db, doc)
    return doc


def check_again(db: OrmSession, actor: str) -> dict[str, Any]:
    """Walk the whole store again: what is found in clear is sealed (files put back by hand from a
    copy made before 6.8). The caller commits."""
    from .core import audit

    doc = read(db)
    if doc.get("state") == SEALED:
        doc.update(state="", recheck=True)
        _write(db, doc)
        audit.record(db, actor, "store.seal.check", "Asked for the store of files to be walked again", target="store")
    return doc


# --------------------------------------------------------------------------- #
# Changing the store key                                                      #
# --------------------------------------------------------------------------- #
def rewrap_needed(doc: dict[str, Any]) -> bool:
    """Whether the server holds an earlier store key that files may still be under."""
    if not store.local() or not settings.STORE_KEY_PREVIOUS:
        return False
    return (doc.get("rewrap") or {}).get("verifiedFor") != store.keyring().current.id.hex()


def rewrap_pass(now: float | None = None, holder: str = HOLDER, budget: float = PASS_SECONDS) -> dict[str, Any]:
    """One pass of the change of store key, when this process holds the lease. Returns its progress."""
    from .core.db import SessionLocal

    with SessionLocal() as db:
        doc = read(db)
    if not rewrap_needed(doc) or not _acquire(now, holder):
        return doc.get("rewrap") or {}
    ring = store.keyring()
    root = store.root()
    progress = dict(doc.get("rewrap") or {})
    if progress.get("to") != ring.current.id.hex():
        found = census(root)
        progress = {
            "to": ring.current.id.hex(),
            "state": "running",
            "startedAt": _iso(time.time() if now is None else now),
            "total": found["sealedFiles"],
            "done": 0,
            "failed": [],
        }
        doc = _say(
            "store.key.rewrap.start",
            f"Putting the keys of {found['sealedFiles']} file(s) of the store under the new store key "
            f"({ring.current.fingerprint})",
            rewrap=progress,
        )
    was = progress.get("state")  # said once: when a pass is the first to fail
    started = time.monotonic()
    moved, failed, left = 0, [], False
    for name, path in _files(root) if root.is_dir() else ():
        if _is_leftover(name):
            continue
        try:
            head = _head(path)
            if not sealed.is_sealed(head):
                continue  # still in clear: the conversion seals it under the current key
            if not sealed.needs_rewrap(sealed.parse_head(head), ring):
                continue
            if moved and time.monotonic() - started > budget:
                left = True
                break
            with store.swapping():
                moved += int(sealed.rewrap(path, name, ring))
        except FileNotFoundError:
            continue
        except (OSError, sealed.SealError) as error:
            failed.append({"name": name, "reason": why(error)})
    progress["done"] = min(int(progress.get("total") or 0), int(progress.get("done") or 0) + moved)
    progress["failed"] = failed[:STUCK_KEPT]
    if left:
        _update(rewrap=progress)
        return progress
    # A whole walk moved everything it could. The proof: every sealed file opens with the current
    # key alone, and no head names another.
    alone = sealed.Keyring(ring.current)
    wrong = list(failed)
    checked = 0
    for name, path in _files(root) if root.is_dir() else ():
        if _is_leftover(name):
            continue
        try:
            head = _head(path)
            if not sealed.is_sealed(head):
                continue
            if sealed.parse_head(head).key_ids() != [ring.current.id]:
                raise sealed.WrongKey("its head still names another store key")
            sealed.open_sealed(path, name, alone).close()
            checked += 1
        except FileNotFoundError:
            continue
        except (OSError, sealed.SealError) as error:
            if not any(entry["name"] == name for entry in wrong):
                wrong.append({"name": name, "reason": why(error)})
    if wrong:
        progress.update(state="failed", failed=wrong[:STUCK_KEPT], failedCount=len(wrong))
        if was != "failed":
            _say(
                "store.key.rewrap.failed",
                f"{len(wrong)} file(s) of the store could not be put under the new store key "
                f"(the first: {wrong[0]['name']}: {wrong[0]['reason']}). Keep the earlier store key.",
                (
                    "store.problem",
                    f"{len(wrong)} file(s) of the store could not be put under the new store key. "
                    "Keep the earlier store key where it is; the list is in Settings → Keys.",
                ),
                rewrap=progress,
            )
        else:
            _update(rewrap=progress)
        return progress
    progress.update(
        state="verified",
        done=checked,
        total=checked,
        failed=[],
        failedCount=0,
        verifiedFor=ring.current.id.hex(),
        verifiedAt=_iso(time.time()),
    )
    said = (
        f"Every file of the store ({checked}) is under the new store key ({ring.current.fingerprint}) and was "
        "opened with it alone: the earlier store key is no longer needed by the server."
    )
    _say("store.key.rewrap.done", said, ("store.key", said), rewrap=progress, keyId=ring.current.id.hex())
    return progress


# --------------------------------------------------------------------------- #
# Damaged files                                                               #
# --------------------------------------------------------------------------- #
def report_damaged(name: str, reason: str) -> None:
    """Write a damaged file to the audit log and tell the administrators: once for each file."""
    from .core import audit
    from .core.db import SessionLocal

    logger.error("The file %s of the store is damaged and is not served: %s", name, reason)
    with SessionLocal() as db:
        doc = read(db)
        damaged = dict(doc.get("damaged") or {})
        if name in damaged:
            return
        damaged[name] = {"at": _iso(time.time()), "reason": reason[:300]}
        while len(damaged) > DAMAGED_KEPT:
            damaged.pop(next(iter(damaged)))
        doc["damaged"] = damaged
        _write(db, doc)
        said = f"The file {name} of the store is damaged and is not served: {reason}"
        audit.record(db, SYSTEM, "store.damaged", said, target=name[:200])
        _tell_admins(db, "store.damaged", said + ". Put it back from a backup.")
        db.commit()


def after_restore() -> None:
    """A backup was just put back into this store: every file in it was sealed under the store key
    of this server as it arrived, whatever the row that came with the database says. The next start
    walks the store and writes down that it is sealed."""
    _update(state="", since="", keyId=store.keyring().current.id.hex(), rewrap=None, damaged={}, problems={}, retryAt=0)
    forget()


def forget_damaged(db: OrmSession, name: str) -> None:
    """A file that was damaged is gone or was put back: it is no longer listed (the caller commits)."""
    doc = read(db)
    damaged = dict(doc.get("damaged") or {})
    if damaged.pop(name, None) is not None:
        doc["damaged"] = damaged
        _write(db, doc)


# --------------------------------------------------------------------------- #
# What the screens and the health page show                                   #
# --------------------------------------------------------------------------- #
def status(db: OrmSession) -> dict[str, Any]:
    """The state of the encryption of the store: what the Storage screen shows, and what a health
    page can show (``state`` is ``sealed`` once nothing is in clear)."""
    doc = read(db)
    state = doc.get("state") or CONVERTING
    total = doc.get("total") or {"files": 0, "bytes": 0}
    done = doc.get("done") or {"files": 0, "bytes": 0}
    seconds = float(doc.get("seconds") or 0.0)
    left_bytes = max(0, int(total.get("bytes") or 0) - int(done.get("bytes") or 0))
    rate = int(done.get("bytes") or 0) / seconds if seconds > 1 and done.get("bytes") else 0.0
    out: dict[str, Any] = {
        "state": state if doc.get("state") else "starting",
        "encrypted": state == SEALED,
        "since": doc.get("since") or "",
        "startedAt": doc.get("startedAt") or "",
        "total": total,
        "done": done,
        "left": {"files": max(0, int(total.get("files") or 0) - int(done.get("files") or 0)), "bytes": left_bytes},
        "secondsLeft": int(left_bytes / rate) if rate and state == CONVERTING else None,
        "bytesPerSecond": int(rate),
        "stuck": doc.get("stuck") or [],
        "stuckCount": int(doc.get("stuckCount") or 0),
        "pausedBy": doc.get("pausedBy") or "",
        "converted": doc.get("converted"),
        "damaged": [{"name": name, **entry} for name, entry in (doc.get("damaged") or {}).items()],
        "keyFingerprint": sealed.fingerprint("STORE_KEY", bytes.fromhex(doc["keyId"])) if doc.get("keyId") else "",
        # Where a change of store key stands. Which key it goes to is said by its fingerprint above,
        # never by its id.
        "rewrap": {k: v for k, v in (doc.get("rewrap") or {}).items() if k not in ("to", "verifiedFor")} or None,
    }
    if state == SEALED:
        out.update(left={"files": 0, "bytes": 0}, stuck=[], stuckCount=0)
    return out


def disk_seen(db: OrmSession) -> dict[str, Any] | None:
    """The room of the disk of the store as the API process last measured it, for a process that
    does not see the store (the automation worker)."""
    seen = read(db).get("disk")
    return seen if isinstance(seen, dict) else None


def _note_disk() -> None:
    try:
        disk = shutil.disk_usage(store.root())
    except OSError:
        return
    _update(disk={"total": disk.total, "free": disk.free, "at": time.time()})


# --------------------------------------------------------------------------- #
# The loop                                                                    #
# --------------------------------------------------------------------------- #
def install() -> None:
    """Make the store ask this module whether clear files are allowed and tell it of damaged ones."""
    store.clear_allowed = clear_allowed
    store.report_damaged = report_damaged


# --------------------------------------------------------------------------- #
# The key of the store against the store, before the server starts            #
# --------------------------------------------------------------------------- #
def key_problem() -> str | None:
    """Why this server must not start on this store with the store key it was given; None when it may.

    The row says which store key the store is under. A key that is neither
    that one nor (with the earlier keys the server holds) on its way from it
    would write files beside ones it cannot read, and everything already
    there would fail to open: the server stops instead, and says so.
    """
    from .core.db import SessionLocal

    ring = store.keyring()
    try:
        with SessionLocal() as db:
            recorded = read(db).get("keyId") or ""
    except Exception:  # noqa: BLE001 - no settings table yet: a new database
        recorded = ""
    held = {key.id.hex(): key for key in ring.all()}
    if recorded and recorded not in held:
        return (
            "STORE_KEY is not the key the store of files is sealed under (the store is under the key "
            f"{sealed.fingerprint('STORE_KEY', bytes.fromhex(recorded))}; the key given is "
            f"{ring.current.fingerprint}). Nothing was changed. Give the server the store key it had (from the "
            "secrets directory or the .env of this server, or from where you keep its copy). If the store key was "
            "changed on purpose, the earlier one must be given as STORE_KEY_PREVIOUS until the change is over "
            "(deploy/secrets.sh rotate store-key does it)"
        )
    # The row may be from another time than the files (a volume put back by hand): one file is asked too.
    root = store.root()
    if root.is_dir():
        looked = 0
        for name, path in _files(root):
            if _is_leftover(name):
                continue
            looked += 1
            if looked > PROBE_FILES:
                break  # a store still in clear: there is nothing sealed to compare the key with
            try:
                head = _head(path)
                if not sealed.is_sealed(head):
                    continue
                ids = sealed.parse_head(head).key_ids()
            except (OSError, sealed.SealError):
                continue
            if ids and not any(key_id.hex() in held for key_id in ids):
                return (
                    "STORE_KEY is not the key the files of the store are sealed under (the key given is "
                    f"{ring.current.fingerprint}; the file {name} is under "
                    f"{sealed.fingerprint('STORE_KEY', ids[0])}). Nothing was changed. Give the server the store key "
                    "these files were written with"
                )
            break
    return None


def main(argv: list[str] | None = None) -> int:
    """``python -m app.store_seal status | unseal``: what an operator runs with the stack stopped."""
    import argparse
    import json
    import sys

    parser = argparse.ArgumentParser(prog="python -m app.store_seal", description=__doc__.split("\n\n")[0])
    parser.add_argument("command", choices=("status", "unseal"))
    args = parser.parse_args(argv)
    root = store.root()
    if args.command == "status":
        print(json.dumps(census(root)))
        return 0
    # Back to a store in clear, for a version before 6.8 (deploy/rollback.sh runs it). The database is
    # told first: a server of this version that started on a store in clear while its row said
    # "sealed" would refuse every file of it.
    ring = store.keyring()
    try:
        _update(state="unsealing", since="", converted=None)
    except Exception as error:  # noqa: BLE001 - whatever keeps the row from being written
        sys.stderr.write(
            "unseal: the database cannot be reached, and it must be told that the store is being unsealed: "
            f"start it first (compose up -d db). Nothing was changed. ({type(error).__name__})\n"
        )
        return 1
    count = failed = 0
    for name, path in _files(root) if root.is_dir() else ():
        if _is_leftover(name):
            continue
        try:
            if not sealed.is_sealed(_head(path)):
                continue
            unseal_file(path, name, ring)
            count += 1
        except (OSError, sealed.SealError) as error:
            failed += 1
            sys.stderr.write(f"unseal: {name}: {error}\n")
    sys.stderr.write(
        f"unseal: {count} file(s) are in clear again" + (f", {failed} could not be opened\n" if failed else "\n")
    )
    if not failed:
        _update(state="", since="", keyId="", converted=None)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())

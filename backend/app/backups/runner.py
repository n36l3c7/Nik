"""Taking a backup, testing it, keeping the right ones.

**A backup is a file** in the backup directory, ``nik-YYYYMMDD-HHMMSS.nikbak``
(``nik-upgrade-…`` for a snapshot taken before an upgrade), with a small
``.json`` beside it that says in clear what the file is (when, how large,
which version of Nik, how its restore test went: nothing secret). It is
written under ``….nikbak.partial`` and renamed when its last byte is on the
disk, so a file with the name of a backup is always a whole one; what a run
that died left behind is removed by the next.

**The restore test** follows every backup at once, in the same run: the file
is read back from the directory, every chunk decrypted, the size and
checksum of every part compared, the database restored into a scratch
database (``database.Scratch``) where its schema, its revision and its
numbers of rows are compared and a few questions asked, and every file of
the store compared with its checksum. It takes about as long as the backup
did. The result is kept in the row of the backup and in its ``.json``.

**One at a time.** Everything here runs under the ``backup`` lease, held by
one API process and renewed while it works.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from ..core import audit
from ..core.config import settings
from ..core.models import Backup, Lease
from . import config, database, policy, store
from .container import PARTIAL, PASSPHRASE, SECRET_KEY, SUFFIX, BackupError, Key, Reader, Secrets, Writer, peek

logger = logging.getLogger("nik.backups")

LEASE = "backup"
LEASE_SECONDS = 120
HOLDER = f"{uuid.uuid4()}"
NAME = re.compile(r"^nik-(upgrade-)?\d{8}-\d{6}$")
SYSTEM = "system"
# Room asked for beyond what the database and the store measure.
MARGIN = 64 * 1024 * 1024
NOT_INCLUDED = [
    "the .env file and the secrets directory, with SECRET_KEY and the keys of the audit log (unless the "
    "administrator chose to include the key: both then travel inside the backup)",
    "the store key (STORE_KEY): the files are in the backup themselves, and a restore seals them under its own",
    "the TLS certificate and its key",
    "the Compose overrides and the other files of the deployment",
]


class NotReady(BackupError):
    """No backup can be taken as things are: what to do is in the message."""


# --------------------------------------------------------------------------- #
# Names, places, the version                                                  #
# --------------------------------------------------------------------------- #
def directory() -> Path:
    return Path(settings.BACKUP_DIR)


def file_of(name: str, folder: Path | None = None) -> Path:
    if not NAME.match(name):
        raise BackupError(f"{name!r} is not the name of a backup")
    return (folder or directory()) / f"{name}{SUFFIX}"


def note_of(name: str, folder: Path | None = None) -> Path:
    return file_of(name, folder).with_suffix(".json")


def iso(at: float) -> str:
    return datetime.fromtimestamp(at, timezone.utc).isoformat()


def stamp(text: str | None) -> float:
    try:
        return datetime.fromisoformat(str(text)).timestamp()
    except ValueError:
        return 0.0


def new_name(kind: str, now: float, folder: Path | None = None) -> str:
    """A name nothing in the directory has: the second it is taken at, the next one if that is taken."""
    while True:
        moment = datetime.fromtimestamp(now, timezone.utc).strftime("%Y%m%d-%H%M%S")
        name = f"nik-upgrade-{moment}" if kind == "upgrade" else f"nik-{moment}"
        target = file_of(name, folder)
        if not target.exists() and not Path(f"{target}{PARTIAL}").exists():
            return name
        now += 1


_version: str | None = None


def nik_version() -> str:
    """The version of Nik this code is. It is written once, where the API is declared
    (``app/main.py``); reading it there, as text, keeps this module usable before the
    application can be loaded (the snapshot before an upgrade)."""
    global _version
    if _version is None:
        source = Path(__file__).resolve().parents[1] / "main.py"
        found = re.search(r'^\s*version="([0-9][0-9A-Za-z.+-]*)"', source.read_text(encoding="utf-8"), re.MULTILINE)
        _version = found.group(1) if found else "unknown"
    return _version


def version_tuple(text: str) -> tuple[int, ...]:
    return tuple(int(piece) for piece in re.findall(r"\d+", str(text))[:3])


# --------------------------------------------------------------------------- #
# The lease                                                                   #
# --------------------------------------------------------------------------- #
def acquire(db: OrmSession, holder: str = HOLDER, now: float | None = None, name: str = LEASE) -> bool:
    """Take or renew the lease; False while another process holds it."""
    from ..core import leases

    return leases.take(db, name, holder, LEASE_SECONDS, now)


def release(db: OrmSession, holder: str = HOLDER, name: str = LEASE) -> None:
    from ..core import leases

    leases.release(db, name, holder)


def held_by_another(db: OrmSession, holder: str = HOLDER, now: float | None = None) -> bool:
    now = time.time() if now is None else now
    row = db.get(Lease, LEASE)
    return row is not None and row.holder != holder and row.expires_at >= now


class Renewing:
    """Keeps the lease while a long piece of work runs in this thread."""

    def __init__(self, holder: str, name: str = LEASE, seconds: float = LEASE_SECONDS) -> None:
        self._holder, self._name, self._seconds, self._stop = holder, name, seconds, threading.Event()
        self._thread = threading.Thread(target=self._run, name="nik-backup-lease", daemon=True)

    def _run(self) -> None:
        from ..core import leases
        from ..core.db import SessionLocal

        while not self._stop.wait(self._seconds / 4):
            try:
                with SessionLocal() as db:
                    leases.take(db, self._name, self._holder, self._seconds)
            except Exception:  # noqa: BLE001 - the work goes on; the next renewal tries again
                logger.exception("The lease of the backups could not be renewed")

    def __enter__(self) -> Renewing:
        self._thread.start()
        return self

    def __exit__(self, *_exc) -> None:
        self._stop.set()


# --------------------------------------------------------------------------- #
# Writing the file                                                            #
# --------------------------------------------------------------------------- #
def clear_partials(folder: Path | None = None) -> int:
    """Remove what a run that died left half-written. Returns how many files went."""
    folder = folder or directory()
    removed = 0
    if folder.is_dir():
        for path in folder.glob(f"*{SUFFIX}{PARTIAL}"):
            try:
                path.unlink()
                removed += 1
            except OSError:
                logger.warning("The half-written backup %s could not be removed", path.name)
    return removed


def room(folder: Path, needed: int) -> None:
    """Refuse to start a backup the disk has no room for."""
    try:
        free = shutil.disk_usage(folder).free
    except OSError as error:
        raise NotReady(f"The backup directory {folder} cannot be read: {error}") from None
    if free < needed + MARGIN:
        raise NotReady(
            f"The backup directory has {free // 2**20} MB free and the backup may need "
            f"{(needed + MARGIN) // 2**20} MB: nothing was written. Free some room, or keep fewer backups"
        )


def write_note(note: dict[str, Any], folder: Path | None = None) -> None:
    target = note_of(note["name"], folder)
    partial = Path(f"{target}{PARTIAL}")
    partial.write_text(json.dumps(note, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(partial, target)


def read_note(name: str, folder: Path | None = None) -> dict[str, Any] | None:
    try:
        note = json.loads(note_of(name, folder).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return note if isinstance(note, dict) and note.get("name") == name else None


def write_file(
    name: str,
    key: Key,
    *,
    kind: str = "full",
    label: str = "",
    include_key: bool = False,
    migrating: bool = False,
    upgrade: dict[str, Any] | None = None,
    folder: Path | None = None,
    now: float | None = None,
) -> dict[str, Any]:
    """Write one backup into the directory and its note beside it. Returns the note.

    A ``full`` backup holds the database and the store; an ``upgrade`` one
    the database alone (migrations do not touch the files).
    """
    folder = folder or directory()
    started = time.time() if now is None else now
    clock = time.monotonic()
    try:
        folder.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise NotReady(f"The backup directory {folder} cannot be made: {error}") from None
    target = file_of(name, folder)
    partial = Path(f"{target}{PARTIAL}")
    about = {"kind": kind, "name": name, "createdAt": iso(started), "nik": nik_version()}
    try:
        with open(partial, "wb") as out:
            writer = Writer(out, key, about)
            described = database.dump(writer, migrating=migrating)
            held = store.pack(writer, settings.SAMPLE_STORE) if kind == "full" else None
            audit_keys = _audit_keys() if include_key else []
            if include_key:
                with writer.part("secret-key") as part:
                    part.write(settings.SECRET_KEY.encode("utf-8"))
                # The keys the audit log was signed with go the same way: on the server that
                # restores they become earlier keys, and its log is checked with them.
                if audit_keys:
                    with writer.part(AUDIT_KEYS_PART) as part:
                        part.write("\n".join(audit_keys).encode("utf-8"))
            manifest = writer.finish(
                {
                    **about,
                    "label": label,
                    "revision": described.get("revision"),
                    "database": described,
                    "store": held,
                    "includesSecretKey": include_key,
                    "includesAuditKeys": len(audit_keys),
                    # The end of the audit log as this backup holds it (the id of a key, never a key).
                    "auditHead": described.get("auditHead"),
                    "upgrade": upgrade,
                    "notIncluded": NOT_INCLUDED[int(include_key) :],
                }
            )
            out.flush()
            os.fsync(out.fileno())
        os.replace(partial, target)
    except BaseException:
        try:
            partial.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    rows = described.get("rows") or {}
    note = {
        **about,
        "finishedAt": iso(time.time() if now is None else now),
        "size": target.stat().st_size,
        "label": label,
        "revision": described.get("revision") or "",
        "keyFrom": key.spec["from"],
        "upgrade": upgrade,
        # In clear beside the file, and sent with it off the server: what the verifier of the audit
        # log is given (--head SEQ:HASH) to hold a log against the one this backup was taken from.
        "auditHead": described.get("auditHead"),
        "summary": {
            "engine": described.get("engine"),
            "serverVersion": described.get("serverVersion"),
            "rows": sum(rows.values()),
            "tables": len(rows),
            "files": (held or {}).get("files"),
            "storeBytes": (held or {}).get("bytes"),
            "includesKey": include_key,
            "parts": len(manifest["parts"]),
            "seconds": round(time.monotonic() - clock, 1),
        },
    }
    write_note(note, folder)
    return note


AUDIT_KEYS_PART = "audit-keys"


def _audit_keys() -> list[str]:
    """The keys of the audit log a backup that carries ``SECRET_KEY`` carries too, as they are
    written in ``AUDIT_KEY_PREVIOUS``: the key the server was given, and the earlier ones. The key
    derived from ``SECRET_KEY`` is not among them: whoever has ``SECRET_KEY`` makes it again. The
    keys derived from an earlier ``SECRET_KEY`` that still signed entries are."""
    from ..auditlog import key as signing

    # A key that was typed with a comma in it cannot stand in a list separated by commas: it is
    # written as the bytes it is.
    texts = [
        "hex:" + text.encode("utf-8").hex() if "," in text or "\n" in text else text
        for text in (signing._configured(), *signing._previous())
        if text
    ]
    texts += ["hex:" + signing.derived(secret).hex() for secret in settings.SECRET_KEY_PREVIOUS]
    return list(dict.fromkeys(texts))


# --------------------------------------------------------------------------- #
# The restore test                                                            #
# --------------------------------------------------------------------------- #
def check_file(path: Path, secrets: Secrets) -> dict[str, Any]:
    """Restore the backup at ``path`` into a scratch database and compare everything it holds.

    Returns ``{"passed", "checks" | "error", "seconds"}``. The scratch
    database is dropped whatever happens; nothing else is written anywhere.
    """
    clock = time.monotonic()
    loader = None
    try:
        database.sweep("scratch")
        with database.Scratch("scratch") as scratch:
            loader = database.Loader(scratch.url)
            unpacker = store.Unpacker(None)
            try:
                with open(path, "rb") as source:
                    reader = Reader(source, secrets)
                    for part in reader.parts():
                        loader.take(part) or unpacker.take(part)  # noqa: B018 - the first that knows the part takes it
                manifest = reader.manifest
                checks = [f"every chunk decrypts, and the {len(reader.found)} parts have the size and checksum written"]
                checks += loader.finish(manifest)
                if manifest.get("store") is not None:
                    checks += unpacker.finish(manifest)
            finally:
                loader.close()
        return {"passed": True, "checks": checks, "seconds": round(time.monotonic() - clock, 1)}
    except (BackupError, OSError) as error:
        return {"passed": False, "error": str(error), "seconds": round(time.monotonic() - clock, 1)}
    except Exception as error:  # noqa: BLE001 - a database error is a failed test, with what the server said
        logger.exception("The restore test of %s failed in a way Nik did not expect", path.name)
        return {"passed": False, "error": f"{type(error).__name__}: {error}"[:1000], "seconds": 0}


def verify(name: str, by: str = SYSTEM, now: float | None = None) -> bool:
    """Run the restore test of a backup and keep its result. Says whether it passed."""
    from ..core.db import SessionLocal

    with SessionLocal() as db:
        row = db.get(Backup, name)
        if row is None or row.state != "done":
            return False
        row.verify_state = "running"
        secrets = config.secrets(db)
        db.commit()
    result = check_file(file_of(name), secrets)
    at = iso(time.time() if now is None else now)
    with SessionLocal() as db:
        row = db.get(Backup, name)
        if row is None:
            return False
        row.verify_state = "passed" if result["passed"] else "failed"
        row.verified_at = at
        row.verify = result
        if result["passed"]:
            audit.record(db, by, "backup.verify", f"The backup {name} passed its restore test", target=name)
        else:
            audit.record(
                db, by, "backup.verify", f"The backup {name} failed its restore test: {result['error']}", target=name
            )
            logger.warning("The backup %s failed its restore test: %s", name, result["error"])
        db.commit()
    note = read_note(name)
    if note is not None:
        try:
            write_note({**note, "verify": {**result, "at": at}})
        except OSError:
            logger.warning("The note of the backup %s could not be written", name)
    return bool(result["passed"])


# --------------------------------------------------------------------------- #
# The rows                                                                    #
# --------------------------------------------------------------------------- #
def taken(db: OrmSession) -> list[policy.Taken]:
    """The backups whose file is here, as the rules of ``policy`` read them."""
    return [
        policy.Taken(row.id, stamp(row.created_at), row.state, row.verify_state, row.kind)
        for row in db.scalars(select(Backup).where(Backup.local.is_(True)))
    ]


def _adopt(db: OrmSession, name: str) -> None:
    """A file with no row: a snapshot taken before the table existed, a file copied in, a database put back."""
    note = read_note(name) or {}
    try:
        header = peek(file_of(name))
    except (BackupError, OSError):
        return
    verified = note.get("verify") if isinstance(note.get("verify"), dict) else {}
    kind = str(note.get("kind") or header.get("kind") or ("upgrade" if "upgrade" in name else "full"))
    # A snapshot taken before an upgrade goes off the server like any backup, when a destination is
    # set: it is found here, after the upgrade, and never keeps the upgrade waiting. One that was not
    # rehearsed (and so not restored yet) is tested first, like every backup that is copied.
    wants_copy = kind == "upgrade" and config.ready(config.read(db).get("destination") or {})
    db.add(
        Backup(
            id=name,
            kind=kind,
            state="done",
            created_at=str(note.get("createdAt") or header.get("createdAt") or iso(file_of(name).stat().st_mtime)),
            finished_at=note.get("finishedAt"),
            size=file_of(name).stat().st_size,
            nik_version=str(note.get("nik") or header.get("nik") or ""),
            revision=str(note.get("revision") or ""),
            label=str(note.get("label") or ""),
            requested_by=SYSTEM,
            summary={**(note.get("summary") or {}), "keyFrom": note.get("keyFrom") or header["key"].get("from")},
            verify_state=("passed" if verified.get("passed") else "failed")
            if verified
            else ("queued" if wants_copy else ""),
            verified_at=verified.get("at"),
            verify={key: value for key, value in verified.items() if key != "at"},
            local=True,
            offsite_state="pending" if wants_copy else "",
        )
    )


def sync(db: OrmSession, now: float | None = None, holder: str = HOLDER) -> None:
    """Make the rows say what the directory holds (the caller commits).

    A file with no row gets one; a row whose file is gone is forgotten,
    unless a copy off the server is all that is left of it; a row that says
    "running" while nobody holds the lease is a run that died.
    """
    folder = directory()
    names = (
        {path.name[: -len(SUFFIX)] for path in folder.glob(f"*{SUFFIX}") if NAME.match(path.name[: -len(SUFFIX)])}
        if folder.is_dir()
        else set()
    )
    rows = {row.id: row for row in db.scalars(select(Backup))}
    for name in sorted(names - set(rows)):
        _adopt(db, name)
    busy = held_by_another(db, holder, now)
    for name, row in rows.items():
        here = name in names
        if row.state in ("queued", "running"):
            if row.state == "running" and not busy and not here:
                row.state, row.error = "failed", "The server stopped while this backup was being written"
                row.finished_at = iso(time.time() if now is None else now)
            continue
        if row.state != "done":
            continue  # a run that failed has no file: its row says why, until the retention removes it
        if row.verify_state == "running" and not busy:
            row.verify_state = "queued"  # a test that died with the server is run again
        if here != row.local:
            row.local = here
        if not here and row.kind == "upgrade" and row.offsite_state == "copied":
            # The upgrade keeps the latest few snapshots by itself, before this table can be read
            # (upgrade._prune): the copy of one it removed here is removed there too.
            row.offsite_state = "delete"
        elif not here and row.offsite_state not in ("copied", "delete"):
            db.delete(row)


def start_row(db: OrmSession, kind: str, by: str, now: float | None = None, state: str = "queued") -> Backup:
    now = time.time() if now is None else now
    row = Backup(
        id=new_name(kind, now), kind=kind, state=state, created_at=iso(now), requested_by=by, nik_version=nik_version()
    )
    db.add(row)
    return row


def remove(db: OrmSession, row: Backup, by: str, why: str = "") -> None:
    """Delete a backup: its file now, its copy off the server at the next pass (the caller commits)."""
    for path in (file_of(row.id), note_of(row.id)):
        try:
            path.unlink(missing_ok=True)
        except OSError as error:
            raise BackupError(f"The file of the backup {row.id} could not be removed: {error}") from None
    audit.record(db, by, "backup.delete", f"Deleted the backup {row.id}" + (f" ({why})" if why else ""), target=row.id)
    if row.offsite_state == "copied" or (row.offsite or {}).get("remote"):
        row.local, row.offsite_state = False, "delete"
    else:
        db.delete(row)


def apply_retention(db: OrmSession, now: float | None = None) -> list[str]:
    """Remove the backups the retention no longer keeps (the caller commits). Returns their names."""
    now = time.time() if now is None else now
    kept = config.read(db)["retention"]
    known = taken(db)
    _keep, gone = policy.retention(known, now, kept["last"], kept["weeks"])
    gone += policy.upgrade_retention(known, kept["upgrades"])
    for name in gone:
        row = db.get(Backup, name)
        if row is not None:
            remove(db, row, SYSTEM, "the retention")
    return gone


def space(db: OrmSession) -> dict[str, int]:
    """How much the backups that are here take, and how large the last good one is: what the screen
    reckons the room of the chosen settings from."""
    here = list(db.scalars(select(Backup).where(Backup.local.is_(True), Backup.state == "done")))
    good = last_good(db)
    return {
        "kept": sum(row.size for row in here),
        "count": len(here),
        "lastGood": good.size if good else 0,
    }


def last_good(db: OrmSession) -> Backup | None:
    return db.scalars(
        select(Backup)
        .where(Backup.kind == "full", Backup.state == "done", Backup.verify_state == "passed")
        .order_by(Backup.created_at.desc())
        .limit(1)
    ).first()


# --------------------------------------------------------------------------- #
# One backup, from start to end                                               #
# --------------------------------------------------------------------------- #
def needed_room() -> int:
    return database.about()["bytes"] + store.measure(settings.SAMPLE_STORE)


def take(name: str | None = None, by: str = SYSTEM, now: float | None = None) -> str:
    """Take a full backup, test it, apply the retention. Returns its name.

    The caller holds the lease. ``name``: the row a person queued with *Back
    up now*; None for a run of the schedule, which makes its own.
    """
    from ..core.db import SessionLocal

    with SessionLocal() as db:
        row = db.get(Backup, name) if name else start_row(db, "full", by, now)
        row.state, row.error = "running", ""
        name, by = row.id, row.requested_by or by
        phrase = config.passphrase(db)
        include_key = bool(config.read(db)["includeKey"])
        wants_copy = config.ready(config.read(db).get("destination") or {})
        db.commit()
    try:
        if not phrase:
            raise NotReady("No backup passphrase is set: set one in Settings → Backup")
        clear_partials()
        directory().mkdir(parents=True, exist_ok=True)
        room(directory(), needed_room())
        note = write_file(name, Key.new(PASSPHRASE, phrase), include_key=include_key, now=now)
    except Exception as error:  # noqa: BLE001 - whatever stopped it, the row says so and the administrators are told
        message = str(error) if isinstance(error, BackupError | OSError) else f"{type(error).__name__}: {error}"
        if not isinstance(error, BackupError | OSError):
            logger.exception("The backup %s failed", name)
        with SessionLocal() as db:
            row = db.get(Backup, name)
            row.state, row.error = "failed", message[:2000]
            row.finished_at = iso(time.time() if now is None else now)
            audit.record(db, by, "backup.run", f"The backup {name} failed: {message}"[:900], target=name)
            db.commit()
        logger.warning("The backup %s failed: %s", name, message)
        return name
    with SessionLocal() as db:
        row = db.get(Backup, name)
        row.state, row.finished_at, row.size = "done", note["finishedAt"], note["size"]
        row.revision, row.summary = note["revision"], {**note["summary"], "keyFrom": note["keyFrom"]}
        row.verify_state = "queued"
        row.offsite_state = "pending" if wants_copy else ""
        audit.record(
            db,
            by,
            "backup.run",
            f"Took the backup {name}: {note['summary']['rows']} rows, {note['summary']['files']} files, "
            f"{note['size']} bytes" + (", SECRET_KEY included" if include_key else ""),
            target=name,
        )
        db.commit()
    verify(name, by, now)
    with SessionLocal() as db:
        apply_retention(db, now)
        db.commit()
    return name


def snapshot_key(db: OrmSession | None) -> Key:
    """The key of a snapshot before an upgrade: the passphrase when one is set and readable, else ``SECRET_KEY``."""
    phrase = None
    if db is not None:
        try:
            phrase = config.passphrase(db)
        except Exception:  # noqa: BLE001 - a database from before the settings table: no passphrase can be there
            phrase = None
    return Key.new(PASSPHRASE, phrase) if phrase else Key.new(SECRET_KEY, settings.SECRET_KEY)

"""What the database knows of the pool of the backups (``pool.py`` is the files).

- ``record``: a backup was taken: the files of the pool it names, and the ones it wrote.
- ``reader``: which of those files a restore test reads whole. The ones never read (new in this
  backup), the ones not read for a week, and a few of the others taken at random: every file of
  the pool is read at least once a week, and a new one before its backup is called good.
- ``collect``: after the retention, the files no backup that is kept names any more go.
- ``sync``: the rows say what the directory holds, and a backup that was copied in gets its rows
  from its own ``store.pool`` part.

**Nothing is removed on a doubt.** A file of the pool is deleted only when every backup whose
file is here has its rows: while one has not (its passphrase cannot be read any more, its file
is damaged), ``collect`` removes nothing and says so.
"""

from __future__ import annotations

import logging
import random
import time
from collections.abc import Callable
from pathlib import Path

from sqlalchemy import delete, select
from sqlalchemy.orm import Session as OrmSession

from ..core.models import Backup, BackupBlob, BackupBlobRef
from . import pool
from .container import BackupError, Reader, Secrets

logger = logging.getLogger("nik.backups.pool")

READ_AGAIN_AFTER = 7 * 86400
SAMPLE_FILES = 20
SAMPLE_BYTES = 1024**3


def record(db: OrmSession, backup_id: str, target: pool.Target, wants_copy: bool, created_at: str) -> None:
    """The backup names ``target.named`` in the pool (the caller commits)."""
    gen = target.gen
    known = {row.sha256: row for row in db.scalars(select(BackupBlob).where(BackupBlob.gen == gen))}
    for sha256, size in target.named.items():
        row = known.get(sha256)
        if row is None:
            row = BackupBlob(gen=gen, sha256=sha256, size=size, created_at=created_at, local=True, offsite_state="")
            db.add(row)
        row.local = True
        if sha256 in target.written:
            # Written again (it was gone, or never there): what was known of the file before is not of this one.
            row.stored, row.verified_at = target.written[sha256], None
            if row.offsite_state in ("copied", "delete", "failed"):
                row.offsite_state = "pending" if wants_copy else ""
        if wants_copy and row.offsite_state in ("", "delete"):
            row.offsite_state = "pending"
        db.merge(BackupBlobRef(backup_id=backup_id, gen=gen, sha256=sha256))


def reader(db: OrmSession, gen: str, now: float | None = None) -> tuple[Callable[[str], bool], set[str]]:
    """``(read_pool, chosen)``: whether a restore test reads a file of the pool whole, and the set
    it fills with the ones it was asked about and said yes to."""
    now = time.time() if now is None else now
    rows = list(
        db.execute(select(BackupBlob.sha256, BackupBlob.size, BackupBlob.verified_at).where(BackupBlob.gen == gen))
    )
    due = {sha256 for sha256, _size, at in rows if at is None or at < now - READ_AGAIN_AFTER}
    others = [(sha256, size) for sha256, size, _at in rows if sha256 not in due]
    random.shuffle(others)
    room = SAMPLE_BYTES
    for sha256, size in others[:SAMPLE_FILES]:
        if size <= room:
            due.add(sha256)
            room -= size
    known = {sha256 for sha256, _size, _at in rows}
    chosen: set[str] = set()

    def read_pool(sha256: str) -> bool:
        # A file with no row (a backup that was copied in) is read: nothing says it ever was.
        if sha256 in due or sha256 not in known:
            chosen.add(sha256)
            return True
        return False

    return read_pool, chosen


def verified(db: OrmSession, gen: str, read: set[str], now: float | None = None) -> None:
    """These files of the pool were read whole and are what their names say (the caller commits)."""
    now = time.time() if now is None else now
    for row in db.scalars(select(BackupBlob).where(BackupBlob.gen == gen, BackupBlob.sha256.in_(read))) if read else ():
        row.verified_at = now


def names_of(path: Path, secrets: Secrets) -> tuple[str, list[dict]] | None:
    """The generation and the entries of the pool a backup file names, read from the file itself;
    None for a backup that names none. Reads the file up to its ``store.pool`` part."""
    key = ""
    with open(path, "rb") as source:
        for part in Reader(source, secrets).parts():
            if part.name == pool.KEY_PART:
                key = part.read(200).decode("ascii", errors="replace")
            elif part.name == pool.LIST_PART:
                return pool.generation(key), pool.entries(part)
            elif part.name.startswith("store."):
                return None
    return None


def _uses_pool(row: Backup) -> bool:
    return row.kind == "full" and row.state == "done" and bool((row.summary or {}).get("pooled"))


def sync(db: OrmSession, base: Path, secrets: Secrets, file_of: Callable[[str], Path]) -> None:
    """Make the rows say what the directory holds (the caller commits): a backup whose file is here
    and that names files of the pool without rows (it was copied in, or the database was put
    back) gets them from its file; a row whose file is gone says so."""
    have = {backup_id for (backup_id,) in db.execute(select(BackupBlobRef.backup_id).distinct())}
    for row in db.scalars(select(Backup).where(Backup.local.is_(True))):
        if row.id in have or not _uses_pool(row):
            continue
        try:
            found = names_of(file_of(row.id), secrets)
        except (BackupError, OSError, ValueError) as error:
            logger.warning("The files of the pool the backup %s names could not be read: %s", row.id, error)
            continue
        if found is None:
            continue
        gen, entries = found
        for entry in entries:
            if db.get(BackupBlob, (gen, entry["sha256"])) is None:
                db.add(
                    BackupBlob(
                        gen=gen, sha256=entry["sha256"], size=entry["size"], created_at=row.created_at, local=True
                    )
                )
            db.merge(BackupBlobRef(backup_id=row.id, gen=gen, sha256=entry["sha256"]))
        db.flush()
    for blob in db.scalars(select(BackupBlob)):
        here = pool.blob_path(base, blob.gen, blob.sha256).is_file()
        if here != blob.local:
            blob.local = here


def collect(db: OrmSession, base: Path) -> dict[str, int]:
    """Remove the files of the pool no backup that is kept names (the caller commits). A file no
    backup whose file is here names goes from the directory; one no backup at all names (not even
    one whose copy off the server is all that is left) has its copy there removed too."""
    done = {"removed": 0, "bytes": 0, "skipped": 0}
    have = {backup_id for (backup_id,) in db.execute(select(BackupBlobRef.backup_id).distinct())}
    unknown = [
        row.id
        for row in db.scalars(select(Backup).where(Backup.local.is_(True)))
        if _uses_pool(row) and row.id not in have
    ]
    if unknown:
        # Which files these backups need is not known: nothing is removed until it is.
        logger.warning("The pool is not cleaned: what %s need(s) of it is not known yet", ", ".join(unknown[:5]))
        done["skipped"] = len(unknown)
        return done
    named_here = set(
        db.execute(
            select(BackupBlobRef.gen, BackupBlobRef.sha256)
            .join(Backup, Backup.id == BackupBlobRef.backup_id)
            .where(Backup.local.is_(True))
        ).all()
    )
    named = set(db.execute(select(BackupBlobRef.gen, BackupBlobRef.sha256)).all())
    for blob in list(db.scalars(select(BackupBlob))):
        key = (blob.gen, blob.sha256)
        if key not in named_here and blob.local:
            path = pool.blob_path(base, blob.gen, blob.sha256)
            try:
                path.unlink(missing_ok=True)
            except OSError as error:
                raise BackupError(f"The file {path.name} of the pool could not be removed: {error}") from None
            blob.local = False
            done["removed"] += 1
            done["bytes"] += blob.stored
        if key not in named:
            if blob.offsite_state in ("copied", "failed", "delete"):
                blob.offsite_state = "delete"  # the process that sends removes the copy, then the row
            elif not blob.local:
                db.execute(delete(BackupBlob).where(BackupBlob.gen == blob.gen, BackupBlob.sha256 == blob.sha256))
    # What a backup that failed left there (a file with no row, a file half written), once it is a
    # day old: a backup being written now is not a day old. Then the folders nothing is left in.
    old = time.time() - 86400
    for folder in base.glob("pool-*") if base.is_dir() else ():
        found = pool.FOLDER.fullmatch(folder.name)
        if not found or not folder.is_dir():
            continue
        for inner in sorted(folder.iterdir()):
            if not inner.is_dir():
                continue
            for path in inner.iterdir():
                sha256 = path.name.split(".", 1)[0]
                if path.stat().st_mtime < old and db.get(BackupBlob, (found.group(1), sha256)) is None:
                    path.unlink(missing_ok=True)
            if not any(inner.iterdir()):
                inner.rmdir()
        if not any(folder.iterdir()):
            folder.rmdir()
    return done

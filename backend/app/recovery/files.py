"""The files of the store beside a database that can go back in time.

Two things.

**What the database names** (``named``): the files and folders a row stands
for. After a recovery to a moment the store is held against that list
(``reconcile``): a file that is named and was deleted since is put back from
where deletions are kept (``kept.py``); one that is named and is nowhere is
reported, by name, instead of being found missing by the analyst who opens
it.

**What the second host holds** (``scan``): one row of ``store_copies`` for
each file of the store, written by the loop of the API process, which is the
one that sees the store. A new file waits to be sent; a file that changed is
sent again; a file that is gone is noted with the moment, and its copy is
removed only when no recovery can reach back to before that moment
(``due_removals``). The process that sends reads these rows and sees no file
of the store but the ones it asks for (``ship.py``).

Files that are still in clear (a store from before 6.8 that is being
sealed) are not sent: nothing of the store leaves the host unsealed. They are
sent once the conversion reaches them.
"""

from __future__ import annotations

import os
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm import Session as OrmSession

from ..core import sealed
from ..core.config import settings
from ..core.models import EvidenceSource, FlirtSignature, Mail, Mailbox, NetworkCapture, Sample, StoreCopy, UrlScan
from . import kept

SKIPPED = ("_previews/", "_transfer/", "_uploads/", kept.KEPT + "/")
BATCH = 500


def named(db: OrmSession) -> Iterator[tuple[str, bool]]:
    """Every file or folder of the store a row of the database stands for, as ``(path, expected)``.
    ``expected`` is false for what a row may well not have (a screenshot, the mbox of a mailbox
    whose messages were all imported): those are put back when they were kept, never reported."""
    for (sha256,) in db.execute(select(Sample.sha256)):
        yield f"{sha256}.bin", True
    for (sha256,) in db.execute(select(Mail.sha256)):
        yield f"{sha256}.mail", True
    for capture, kind in db.execute(select(NetworkCapture.id, NetworkCapture.kind)):
        yield f"_captures/{capture}", kind == "pcap"
    for (mailbox,) in db.execute(select(Mailbox.id)):
        yield f"_mailboxes/{mailbox}", False
    for signature, kind in db.execute(select(FlirtSignature.id, FlirtSignature.kind)):
        yield f"_flirt/{signature}.{kind}", False
    # The originals of host evidence (7.0): one file for every distinct SHA-256 an incident holds.
    for (sha256,) in db.execute(select(EvidenceSource.sha256).where(EvidenceSource.sha256 != "").distinct()):
        yield f"_evidence/{sha256}.bin", True
    for (scan,) in db.execute(select(UrlScan.id)):
        yield f"_urls/{scan}.jpg", False
        yield f"_urls/{scan}.scripts.json", False


def reconcile(db: OrmSession, moment: float, root: Path | None = None) -> dict[str, Any]:
    """Hold the store against the database after a recovery to ``moment``: put back what was kept,
    name what is missing."""
    root = Path(settings.SAMPLE_STORE) if root is None else root
    back: list[str] = []
    missing: list[str] = []
    count = 0
    for name, expected in named(db):
        count += 1
        if (root / name).exists():
            continue
        if kept.put_back(name, moment):
            back.append(name)
        elif expected:
            missing.append(name)
    return {"named": count, "putBack": back, "missing": missing}


# --------------------------------------------------------------------------- #
# The rows of the copies                                                      #
# --------------------------------------------------------------------------- #
def _walk(root: Path) -> Iterator[tuple[str, int, float]]:
    for folder, folders, names in os.walk(root, followlinks=False):
        relative = Path(folder).relative_to(root).as_posix()
        prefix = "" if relative == "." else relative + "/"
        folders[:] = sorted(name for name in folders if not (prefix + name + "/").startswith(SKIPPED))
        for name in sorted(names):
            if name.endswith(kept.LEFTOVERS):
                continue
            try:
                found = os.lstat(os.path.join(folder, name))
            except OSError:
                continue
            yield prefix + name, found.st_size, found.st_mtime


def _sealed(path: Path) -> bool:
    try:
        with open(path, "rb") as handle:
            return sealed.is_sealed(handle.read(len(sealed.MAGIC)))
    except OSError:
        return False


def scan(db: OrmSession, now: float | None = None, root: Path | None = None) -> dict[str, int]:
    """Make the rows say what the store holds (the caller commits). Returns what changed."""
    now = time.time() if now is None else now
    root = Path(settings.SAMPLE_STORE) if root is None else root
    rows = {row.name: row for row in db.scalars(select(StoreCopy))}
    seen: set[str] = set()
    did = {"new": 0, "changed": 0, "gone": 0}
    for name, size, mtime in _walk(root) if root.is_dir() else ():
        if len(name) > 500:
            continue
        seen.add(name)
        row = rows.get(name)
        if row is None:
            if not _sealed(root / name):
                seen.discard(name)
                continue
            db.add(StoreCopy(name=name, size=size, mtime=mtime, state="pending", seen_at=now))
            did["new"] += 1
        elif row.gone_at is not None or row.size != size or abs(row.mtime - mtime) > 1e-3:
            # Written again under the same name (a log that grew, a sample uploaded again after
            # it was deleted): the copy is the old content, and is sent again.
            if not _sealed(root / name):
                continue
            row.size, row.mtime, row.state, row.error = size, mtime, "pending", ""
            row.gone_at = row.removed_at = None
            row.seen_at = now
            did["changed"] += 1
    for name, row in rows.items():
        if name not in seen and row.gone_at is None:
            row.gone_at = now
            did["gone"] += 1
    return did


def due_removals(db: OrmSession, before: float, limit: int = BATCH) -> list[str]:
    """The copies to remove from the second host: of files deleted before ``before`` (the oldest
    moment a recovery can go back to)."""
    return list(
        db.scalars(
            select(StoreCopy.name)
            .where(StoreCopy.gone_at.is_not(None), StoreCopy.gone_at < before, StoreCopy.removed_at.is_(None))
            .order_by(StoreCopy.gone_at)
            .limit(limit)
        )
    )


def forget_removed(db: OrmSession, before: float) -> int:
    """Drop the rows of files that are gone from both hosts for a good while (the caller commits)."""
    from sqlalchemy import delete

    return db.execute(
        delete(StoreCopy).where(StoreCopy.removed_at.is_not(None), StoreCopy.removed_at < before)
    ).rowcount


def set_aside_gone(db: OrmSession, root: Path | None = None) -> int:
    """On a server that takes the place of another: the files the old server had deleted and still
    kept on its copies arrived with the rest. They are kept here as deletions are, under the
    moment they were deleted, so that they go when no recovery can reach back to them."""
    root = Path(settings.SAMPLE_STORE) if root is None else root
    moved = 0
    for row in db.scalars(select(StoreCopy).where(StoreCopy.gone_at.is_not(None))):
        path = root / row.name
        if ".." in Path(row.name).parts or not path.is_file():
            continue
        moved += int(kept.keep(path, now=float(row.gone_at)))
    return moved


def send_again(db: OrmSession) -> int:
    """Everything is to be sent again: the copies go to another host from now on (the caller commits)."""
    return db.execute(
        update(StoreCopy).where(StoreCopy.gone_at.is_(None)).values(state="pending", copied_at=None, error="")
    ).rowcount


def waiting(db: OrmSession) -> dict[str, int]:
    from sqlalchemy import func

    count, size = db.execute(
        select(func.count(), func.coalesce(func.sum(StoreCopy.size), 0)).where(
            StoreCopy.state != "copied", StoreCopy.gone_at.is_(None)
        )
    ).one()
    copied = db.execute(
        select(func.count()).select_from(StoreCopy).where(StoreCopy.state == "copied", StoreCopy.gone_at.is_(None))
    ).scalar()
    return {"files": int(count or 0), "bytes": int(size or 0), "copied": int(copied or 0)}

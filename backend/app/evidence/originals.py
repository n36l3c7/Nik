"""The original files of host evidence (7.0).

Every file of host evidence an incident is given is kept as it came, whatever
reads it: an event log, a registry hive, a browser database, a $MFT, a
collection. It sits in the store as ``_evidence/<sha256>.bin``, sealed like the
rest of the store (``core/store.py``) and never changed once written, and it is
the artifact ``hostfile-<sha256>``: the same file given to two incidents is one
copy, held by two rows of ``evidence_sources``. The parse report, the viewer and
"Analyse again" all read this copy; the forensics worker is given it when it
reads the file (``workers/handover.py``), as the other workers are.

An original lives as long as its artifact. Nothing here opens a file as more
than bytes.
"""

from __future__ import annotations

import hashlib
import re
import shutil
from collections.abc import Iterable
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.orm import Session as OrmSession

from .. import artifacts
from ..core import store
from ..core.config import settings
from ..core.models import Artifact, EvidenceSource
from ..core.security import now_iso

FOLDER = "_evidence"
KIND = "hostfile"
SHA256_RE = re.compile(r"[0-9a-f]{64}")
# What is kept free on the disk of the store whatever is imported: a full disk stops the database too.
MARGIN = 2 * 1024**3


class EvidenceError(Exception):
    """An original that cannot be kept: a sentence a person can act on."""


def path_of(sha256: str) -> Path:
    if not SHA256_RE.fullmatch(sha256 or ""):
        raise EvidenceError("Not the SHA-256 of a file")
    return Path(settings.SAMPLE_STORE) / FOLDER / f"{sha256}.bin"


def has(sha256: str) -> bool:
    return path_of(sha256).is_file()


def room(needed: int, what: str = "the file") -> None:
    """Refuse an import the disk of the store has no room for: ``needed`` bytes, and the margin.
    Checked before anything is written, as a backup checks its own folder (``backups/runner.room``)."""
    folder = Path(settings.SAMPLE_STORE)
    try:
        free = shutil.disk_usage(folder if folder.exists() else folder.parent).free
    except OSError as error:
        raise EvidenceError(f"The store cannot be read: {error}") from None
    if free < needed + MARGIN:
        raise EvidenceError(
            f"The store has {free // 2**20} MB free and {what} needs {(needed + MARGIN) // 2**20} MB with the margin "
            "kept for the database: nothing was written. Free some room on the server first"
        )


def keep(pieces: Iterable[bytes], sha256: str) -> int:
    """Write an original whose SHA-256 is known (it was hashed as it came, or in a first pass): the
    pieces are hashed again as they are written, and a file that is not what was announced is not
    kept. A file already kept is not written twice. Returns its size."""
    path = path_of(sha256)
    if path.is_file():
        return store.size(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    with store.writing(path, mode=0o400) as out:
        for piece in pieces:
            digest.update(piece)
            out.write(piece)
        if digest.hexdigest() != sha256:
            # Raised inside the block: the half-written file is removed, nothing takes the place.
            raise EvidenceError("The file changed while it was kept: it was not kept, send it again")
        return out.size


def keep_bytes(data: bytes) -> str:
    """Keep an original held in memory (an upload of the API of before, up to its limit). Its SHA-256."""
    sha256 = hashlib.sha256(data).hexdigest()
    room(len(data))
    keep((data,), sha256)
    return sha256


def register(db: OrmSession, sha256: str, name: str, size: int, actor: str, detail: str = "") -> Artifact:
    """The artifact of an original: ``hostfile-<sha256>``, linked to the incidents that hold it
    through their ``evidence_sources`` (``artifacts.sync_links``)."""
    return artifacts._upsert(  # noqa: SLF001 - the registry's own writer, as each kind uses it
        db, KIND, sha256, name, actor, now_iso(), verdict="", score=None, detail=detail, size=size
    )


def holders(db: OrmSession, sha256: str) -> int:
    """How many incidents hold an original as evidence (through their ``evidence_sources``): while
    any does, the original is neither deleted nor left to expire."""
    counted = select(func.count(func.distinct(EvidenceSource.incident_id))).where(EvidenceSource.sha256 == sha256)
    return db.scalar(counted) or 0


def remove(sha256: str) -> None:
    """Delete an original, with its artifact (``artifact_expiry`` and the artifact's deletion call it)."""
    path = path_of(sha256)
    if path.is_file():
        store.remove(path)

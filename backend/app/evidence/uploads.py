"""Files of host evidence sent in parts (7.0): a $MFT, a $J, a collection of tens of gigabytes.

A request of the browser cannot carry such a file whole, and a cut connection
must not mean sending it all again. So the file is sent in parts, in order:

    POST   /api/uploads                {incidentId, fileName, size, sha256?, params}  -> {id, chunk}
    PUT    /api/uploads/{id}?offset=N  the bytes from N on (at most CHUNK)           -> {received}
    GET    /api/uploads/{id}           how much was received: where to go on from after a cut
    POST   /api/uploads/{id}/complete  the last part was sent: the file is kept and read
    DELETE /api/uploads/{id}           given up: the parts are removed

Each part is written to the store as it comes, sealed like everything there,
as ``_uploads/<id>/<offset>.chunk``; a part that does not start where the last
one ended is refused with what was received, so a part is never written twice
or out of order. ``_uploads/`` is in no backup and no copy to the standby: it
is not evidence yet.

Completing is work of its own (``work.py``, kind ``evidence-upload``, started
again after a restart: the parts are still there). The parts are read once to
hash them, then the original is written under its SHA-256
(``originals.keep``) unless it is already kept, and the session is complete:
the import takes the file from there (``imports.accept``). Sessions nobody
wrote to for a day expire, and their parts go.
"""

from __future__ import annotations

import hashlib
import logging
import time
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from .. import archive, work
from ..core import store
from ..core.config import settings
from ..core.models import Incident, UploadSession
from ..core.security import now_iso
from . import originals

logger = logging.getLogger("nik.evidence.uploads")

FOLDER = "_uploads"
CHUNK = 8 * 1024 * 1024
EXPIRE_AFTER = 86400
# Uploads one person may have in progress at once: each was promised room on the disk.
MAX_OPEN = 8
WORK = "evidence-upload"


class UploadError(Exception):
    """A part or a session that is refused: ``status`` is the HTTP status that says why."""

    def __init__(self, sentence: str, status: int = 400, received: int | None = None) -> None:
        super().__init__(sentence)
        self.status, self.received = status, received


def limit_of(params: dict[str, Any]) -> int:
    """The largest file a session may announce, in bytes: a collection has a limit of its own."""
    megabytes = settings.COLLECTION_MAX_MB if params.get("kind") == "collection" else settings.EVIDENCE_MAX_MB
    return megabytes * 1024 * 1024


def folder_of(upload_id: str) -> Path:
    return Path(settings.SAMPLE_STORE) / FOLDER / upload_id


def _chunk_path(upload_id: str, offset: int) -> Path:
    return folder_of(upload_id) / f"{offset:016d}.chunk"


def shown(db: OrmSession, row: UploadSession) -> dict[str, Any]:
    return {
        "id": row.id,
        "incidentId": row.incident_id,
        "fileName": row.file_name,
        "size": row.size,
        "received": row.received,
        "state": row.state,
        "sourceId": row.source_id,
        "error": (row.params or {}).get("error"),
        "chunk": CHUNK,
        "work": work.describe(db, WORK, row.id) if row.state == "finishing" else None,
    }


def open_session(
    db: OrmSession, actor: str, incident_id: str, file_name: str, size: int, sha256: str, params: dict[str, Any]
) -> UploadSession:
    held = db.get(Incident, incident_id)
    if held is None:
        raise UploadError("Incident not found", 404)
    if held.archived_at:
        raise UploadError(archive.SENTENCE, 409)
    if size <= 0:
        raise UploadError("The file is empty")
    if size > limit_of(params):
        raise UploadError(f"The file is larger than the limit of {limit_of(params) // 2**20} MB", 413)
    sha256 = (sha256 or "").strip().lower()
    if sha256 and not originals.SHA256_RE.fullmatch(sha256):
        raise UploadError("Not the SHA-256 of a file")
    going = db.scalars(
        select(UploadSession).where(UploadSession.actor == actor, UploadSession.state.in_(("open", "finishing")))
    ).all()
    if len(going) >= MAX_OPEN:
        raise UploadError(f"{MAX_OPEN} uploads of yours are in progress: finish or give up one first", 429)
    try:
        # The parts and the original are both on the disk for a moment: room for twice the file, and
        # for what the uploads already in progress were promised.
        promised = sum(2 * row.size - row.received for row in going)
        originals.room(2 * size + promised, "the file and its parts")
    except originals.EvidenceError as error:
        raise UploadError(str(error), 507) from None
    row = UploadSession(
        id=uuid.uuid4().hex,
        actor=actor,
        incident_id=incident_id,
        file_name=(file_name or "upload")[:500],
        size=size,
        received=0,
        sha256=sha256,
        state="open",
        params=params,
        created_at=now_iso(),
        updated_epoch=time.time(),
    )
    db.add(row)
    return row


def mine(db: OrmSession, upload_id: str, actor: str, *, lock: bool = False) -> UploadSession:
    query = select(UploadSession).where(UploadSession.id == upload_id)
    if lock:
        query = query.with_for_update()
    row = db.scalars(query).first()
    # Another person's session is not shown to be there.
    if row is None or row.actor != actor:
        raise UploadError("Upload not found", 404)
    return row


def write_part(db: OrmSession, row: UploadSession, offset: int, data: bytes) -> int:
    """Write one part (the caller holds the row locked, and commits). Returns what was received."""
    if row.state != "open":
        raise UploadError(f"The upload is {row.state}: it takes no more parts", 409, row.received)
    if offset != row.received:
        raise UploadError("The part does not start where the last one ended", 409, row.received)
    if not data or len(data) > CHUNK:
        raise UploadError(f"A part holds between 1 byte and {CHUNK // 2**20} MB")
    if row.received + len(data) > row.size:
        raise UploadError("The parts are larger than the file that was announced", 400, row.received)
    path = _chunk_path(row.id, offset)
    path.parent.mkdir(parents=True, exist_ok=True)
    store.write(path, data)
    row.received += len(data)
    row.updated_epoch = time.time()
    return row.received


def _parts(upload_id: str) -> Iterator[bytes]:
    for path in sorted(folder_of(upload_id).glob("*.chunk")):
        yield from store.pieces(path)


def complete(db: OrmSession, row: UploadSession) -> None:
    """The last part was sent: check the size, and want the work that keeps the file (the caller commits)."""
    if row.state == "finishing":
        return
    if row.state != "open":
        raise UploadError(f"The upload is {row.state}", 409, row.received)
    if row.received != row.size:
        raise UploadError(f"{row.received} of {row.size} bytes were received: send the rest first", 409, row.received)
    row.state = "finishing"
    work.want(db, WORK, row.id)


def finish(upload_id: str) -> None:
    """Keep the file the parts make: hashed once, then written under its SHA-256. Run held (``work``)."""
    from ..core.db import SessionLocal
    from . import imports

    with SessionLocal() as db:
        row = db.get(UploadSession, upload_id)
        if row is None or row.state != "finishing":
            return
        expected = row.sha256
    digest = hashlib.sha256()
    size = 0
    for piece in _parts(upload_id):
        digest.update(piece)
        size += len(piece)
    sha256 = digest.hexdigest()
    with SessionLocal() as db:
        row = db.get(UploadSession, upload_id)
        if row is None or row.state != "finishing":
            return
        if size != row.size or (expected and expected != sha256):
            row.state = "aborted"
            row.params = {**(row.params or {}), "error": "The file received is not the one announced: send it again"}
            db.commit()
            store.remove_tree(folder_of(upload_id))
            return
    originals.keep(_parts(upload_id), sha256)
    with SessionLocal() as db:
        row = db.get(UploadSession, upload_id)
        if row is None or row.state != "finishing":
            return
        try:
            source = imports.accept(db, row.incident_id, sha256, row.size, row.file_name, row.params or {}, row.actor)
        except archive.Archived as refused:  # archived while the file was being sent
            row.state = "aborted"
            row.params = {**(row.params or {}), "error": refused.message}
            db.commit()
            store.remove_tree(folder_of(upload_id))
            return
        row.state, row.sha256, row.source_id = "complete", sha256, source.id
        row.updated_epoch = time.time()
        wanted = source.state == "queued"
        source_id = source.id
        db.commit()
    store.remove_tree(folder_of(upload_id))
    if wanted:
        # The reading was written down with the source; it starts here, now, like any work a request asks for.
        from . import parse

        parse.start(source_id)


def start(upload_id: str) -> None:
    """Start keeping the file now, in this process (the request that completed it committed)."""
    _held_finish(upload_id)


def _held_finish(upload_id: str, _params: dict[str, Any] | None = None) -> bool:
    def run() -> None:
        try:
            with work.hold(WORK, upload_id):
                finish(upload_id)
        except work.Taken:
            return

    work.thread(run)
    return True


def _fail(db: OrmSession, upload_id: str, sentence: str) -> None:
    row = db.get(UploadSession, upload_id)
    if row is not None and row.state == "finishing":
        row.state = "aborted"
        row.params = {**(row.params or {}), "error": sentence}


work.register(work.Kind(WORK, "a file of host evidence being kept", "again", start=_held_finish, fail=_fail))


def abort(db: OrmSession, row: UploadSession) -> None:
    if row.state in ("complete", "finishing"):
        raise UploadError(f"The upload is {row.state}", 409, row.received)
    row.state = "aborted"
    row.updated_epoch = time.time()
    store.remove_tree(folder_of(row.id))


def _hourly(db: OrmSession, now: float) -> None:
    expire(db, now)


work.hourly.append(_hourly)


def expire(db: OrmSession, now: float | None = None) -> int:
    """Sessions nobody wrote to for a day: expired, their parts removed. Returns how many (the caller commits)."""
    now = time.time() if now is None else now
    rows = db.scalars(
        select(UploadSession).where(UploadSession.state == "open", UploadSession.updated_epoch < now - EXPIRE_AFTER)
    ).all()
    for row in rows:
        row.state = "expired"
        store.remove_tree(folder_of(row.id))
    return len(rows)

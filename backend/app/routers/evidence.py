"""The host evidence of an incident, read and kept by people (7.0).

The records are read out of the originals by ``evidence/parse.py``; here the screens list the
files and their parse reports, page through the records (``evidence/browse.py`` says how),
open one, flag and annotate it, acknowledge a file read in part, read a file again or remove it.
Readers may GET; the rest needs ``writer_principal``.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import delete, select
from sqlalchemy.orm import Session as OrmSession

from .. import artifacts, war_room, work
from ..core import audit
from ..core.db import get_db
from ..core.locking import lock_incident
from ..core.models import ArtifactLink, EvidenceMark, EvidenceSource, Incident, WorkClaim
from ..core.security import Principal, now_iso, reader_principal, writer_principal
from ..evidence import browse, imports, originals, parse

router = APIRouter(prefix="/incidents/{incident_id}/evidence", tags=["incidents/evidence"])

LEGACY = "This evidence was imported before 7.0: import the file again to have its report"
NO_ORIGINAL = "The original of this file is not kept: import the file again to have its report"


class SeenIn(BaseModel):
    note: str = Field(default="", max_length=1000)


class MarkIn(BaseModel):
    key: str = Field(min_length=1, max_length=300)
    flagged: bool = False
    note: str = Field(default="", max_length=5000)


def _incident(db: OrmSession, incident_id: str, *, lock: bool = False) -> Incident:
    row = lock_incident(db, incident_id) if lock else db.get(Incident, incident_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return row


def _source(db: OrmSession, incident_id: str, source_id: str) -> EvidenceSource:
    row = browse.source(db, incident_id, source_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Evidence file not found")
    return row


def _shown(db: OrmSession, row: EvidenceSource) -> dict[str, Any]:
    running = row.state in ("queued", "parsing")
    return browse.source_of(row, work.describe(db, imports.PARSE_WORK, row.id) if running else None)


def _whole(db: OrmSession, row: EvidenceSource) -> dict[str, Any]:
    answer = _shown(db, row)
    answer["report"] = row.report or {}
    answer["artifactId"] = artifacts.artifact_id(originals.KIND, row.sha256) if row.sha256 else None
    return answer


# --------------------------------------------------------------------------- #
# Files                                                                       #
# --------------------------------------------------------------------------- #
@router.get("/sources")
def list_sources(
    incident_id: str,
    kind: str = Query(default="", max_length=16),
    _caller: Principal = Depends(reader_principal),
    db: OrmSession = Depends(get_db),
):
    """The files of the incident, newest first, with their counts but not their reports."""
    _incident(db, incident_id)
    return {"sources": [_shown(db, row) for row in browse.sources(db, incident_id, kind or None)]}


@router.get("/sources/{source_id}")
def get_source(
    incident_id: str,
    source_id: str,
    _caller: Principal = Depends(reader_principal),
    db: OrmSession = Depends(get_db),
):
    """One file with its parse report."""
    _incident(db, incident_id)
    return _whole(db, _source(db, incident_id, source_id))


@router.post("/sources/{source_id}/again", status_code=202)
def read_again(
    incident_id: str,
    source_id: str,
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
):
    """Have the file read again (a new parser, or a file that failed): its records are replaced,
    the marks stay."""
    _incident(db, incident_id, lock=True)
    row = _source(db, incident_id, source_id)
    if row.legacy:
        raise HTTPException(status_code=409, detail=LEGACY)
    if not row.sha256 or not originals.has(row.sha256):
        raise HTTPException(status_code=409, detail=NO_ORIGINAL)
    if row.state in ("queued", "parsing"):
        raise HTTPException(status_code=409, detail="This file is already being read")
    parse.again(db, row)
    audit.record(db, caller.actor, "evidence.again", f"Read {row.file_name} again", None, target=row.file_name)
    db.commit()
    parse.start(source_id)
    db.refresh(row)
    return _shown(db, row)


@router.post("/sources/{source_id}/seen")
def acknowledge(
    incident_id: str,
    source_id: str,
    body: SeenIn,
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
):
    """Say a file read in part was looked at: the header stops showing it. The note goes to the
    audit log and to the War Room."""
    incident = _incident(db, incident_id, lock=True)
    row = _source(db, incident_id, source_id)
    if row.read != "partial":
        raise HTTPException(status_code=409, detail="Only a file that was read in part can be acknowledged")
    row.seen_by, row.seen_at, row.seen_note = caller.actor, now_iso(), body.note.strip()
    said = f"{caller.actor} acknowledged that {row.file_name} was read in part"
    audit.record(db, caller.actor, "evidence.seen", said + (f": {row.seen_note}" if row.seen_note else ""), incident)
    war_room.add(
        db,
        incident_id,
        "system",
        {"text": said + (f": {row.seen_note}" if row.seen_note else ""), "sourceId": row.id},
        caller.actor,
        tags=[war_room.EVIDENCE],
    )
    db.commit()
    db.refresh(row)
    return _shown(db, row)


@router.delete("/sources/{source_id}/seen")
def forget_seen(
    incident_id: str,
    source_id: str,
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
):
    """Take the acknowledgement back."""
    incident = _incident(db, incident_id, lock=True)
    row = _source(db, incident_id, source_id)
    if row.seen_at:
        row.seen_by, row.seen_at, row.seen_note = None, None, ""
        audit.record(
            db,
            caller.actor,
            "evidence.seen",
            f"{caller.actor} took back the acknowledgement of {row.file_name}",
            incident,
        )
        db.commit()
        db.refresh(row)
    return _shown(db, row)


@router.delete("/sources/{source_id}")
def remove_source(
    incident_id: str,
    source_id: str,
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
):
    """Remove a file and its records from the incident. The flags and notes stay (they are by
    key). The original stays in the store as its artifact until no incident holds it."""
    incident = _incident(db, incident_id, lock=True)
    row = _source(db, incident_id, source_id)
    # A collection goes with the files taken out of it.
    gone = [row, *db.scalars(select(EvidenceSource).where(EvidenceSource.collection_id == row.id))]
    if any(item.state == "parsing" for item in gone):
        raise HTTPException(status_code=409, detail="This file is being read: wait for it to end")
    for item in gone:
        parse.clear(db, item.id)
        db.execute(delete(WorkClaim).where(WorkClaim.kind == imports.PARSE_WORK, WorkClaim.ref == item.id))
    names = ", ".join(item.file_name for item in gone[:3])
    ids = {item.id for item in gone}
    hashes = {item.sha256 for item in gone if item.sha256}
    # Children first: the collection's own row owns the foreign key.
    for item in reversed(gone):
        db.delete(item)
    db.flush()
    for sha256 in hashes:
        kept = select(EvidenceSource.id).where(
            EvidenceSource.incident_id == incident_id, EvidenceSource.sha256 == sha256, EvidenceSource.id.notin_(ids)
        )
        if db.scalar(kept.limit(1)) is None:
            db.execute(
                delete(ArtifactLink).where(
                    ArtifactLink.incident_id == incident_id,
                    ArtifactLink.artifact_id == artifacts.artifact_id(originals.KIND, sha256),
                )
            )
    audit.record(db, caller.actor, "evidence.remove", f"Removed {names} and its records", incident)
    db.commit()
    return {"removed": len(gone)}


# --------------------------------------------------------------------------- #
# Records                                                                     #
# --------------------------------------------------------------------------- #
@router.get("/records")
def list_records(
    incident_id: str,
    kind: str = Query(default="", max_length=16),
    type: str = Query(default="", max_length=40),  # noqa: A002 - the API's own name
    sourceId: str = Query(default="", max_length=32),  # noqa: N803
    host: str = Query(default="", max_length=255),
    username: str = Query(default="", max_length=255),
    channel: str = Query(default="", max_length=120),
    eventId: int | None = Query(default=None),  # noqa: N803
    level: int | None = Query(default=None, ge=1, le=5),
    flagged: bool = False,
    q: str = Query(default="", max_length=200),
    from_: int | None = Query(default=None, alias="from"),
    to: int | None = None,
    order: str = "time",
    limit: int = Query(default=100, ge=1, le=browse.LIMIT_MAX),
    cursor: str = Query(default="", max_length=200),
    _caller: Principal = Depends(reader_principal),
    db: OrmSession = Depends(get_db),
):
    """One page of records, with the total of the first page (counted up to 100001). ``next`` is
    the cursor of the following page, null at the end."""
    _incident(db, incident_id)
    filters = {
        "kind": kind,
        "type": type,
        "sourceId": sourceId,
        "host": host,
        "username": username,
        "channel": channel,
        "eventId": eventId,
        "level": level,
        "flagged": flagged,
        "q": q,
        "from": from_,
        "to": to,
    }
    try:
        return browse.records(db, incident_id, filters, order, limit, cursor or None)
    except browse.BadQuery as error:
        raise HTTPException(status_code=400, detail=str(error)) from None


@router.get("/records/{record_id}")
def get_record(
    incident_id: str,
    record_id: int,
    _caller: Principal = Depends(reader_principal),
    db: OrmSession = Depends(get_db),
):
    """One record whole: its fields, its place in the original, its file and its detections."""
    _incident(db, incident_id)
    answer = browse.record(db, incident_id, record_id)
    if answer is None:
        raise HTTPException(status_code=404, detail="Record not found")
    return answer


@router.put("/marks")
def put_mark(
    incident_id: str,
    body: MarkIn,
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
):
    """Flag a record and annotate it. A mark with no flag and no note is removed."""
    incident = _incident(db, incident_id, lock=True)
    if not browse.key_exists(db, incident_id, body.key):
        raise HTTPException(status_code=404, detail="Record not found")
    mark = db.get(EvidenceMark, (incident_id, body.key))
    before = bool(mark and mark.flagged)
    note = body.note.strip()
    if not body.flagged and not note:
        if mark is not None:
            db.delete(mark)
    elif mark is None:
        db.add(
            EvidenceMark(
                incident_id=incident_id,
                key=body.key,
                flagged=body.flagged,
                note=note,
                updated_by=caller.actor,
                updated_at=now_iso(),
            )
        )
    else:
        mark.flagged, mark.note, mark.updated_by, mark.updated_at = body.flagged, note, caller.actor, now_iso()
    if before != body.flagged:
        verb = "flagged" if body.flagged else "unflagged"
        audit.record(db, caller.actor, "evidence.mark", f"{caller.actor} {verb} {body.key}", incident)
    db.commit()
    return {"key": body.key, "flagged": body.flagged, "note": note}


@router.get("/summary")
def get_summary(
    incident_id: str,
    _caller: Principal = Depends(reader_principal),
    db: OrmSession = Depends(get_db),
):
    """What the header and the side list show: per section, its files, records and what needs a look."""
    _incident(db, incident_id)
    return browse.summary(db, incident_id)

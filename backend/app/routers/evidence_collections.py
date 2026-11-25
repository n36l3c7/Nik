"""Collections of host evidence (7.0): a triage zip listed, then imported on request (``evidence/collections.py``).

    GET  /incidents/{id}/evidence/collections/{source}           the collection and a page of its members
    POST /incidents/{id}/evidence/collections/{source}/import    import the members chosen (in the background)
    POST /incidents/{id}/evidence/collections/{source}/analyse   send a program of the collection to Malware Analysis

The collection itself is a source (``GET .../evidence/sources``, kind ``collection``, source ``collection.zip``) that
came
in through ``/api/uploads``. Readers may GET; the rest needs ``writer_principal``, as uploading a sample does.
"""

from __future__ import annotations

import hashlib
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as OrmSession

from .. import archive, artifacts
from ..core import audit
from ..core.config import settings
from ..core.db import get_db
from ..core.locking import lock_incident
from ..core.models import EvidenceSource, Incident
from ..core.security import Principal, reader_principal, writer_principal
from ..evidence import browse, collections, imports, originals
from . import samples

router = APIRouter(prefix="/incidents/{incident_id}/evidence/collections", tags=["incidents/evidence"])

PAGE_DEFAULT = 100


class ImportIn(BaseModel):
    members: list[int] | None = Field(default=None, max_length=50_000)
    all: bool = False
    kinds: list[str] | None = Field(default=None, max_length=10)


class AnalyseIn(BaseModel):
    member: int = Field(ge=0)


def _incident(db: OrmSession, incident_id: str, *, lock: bool = False) -> Incident:
    row = lock_incident(db, incident_id) if lock else db.get(Incident, incident_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    if lock:  # a lock is taken to write: an archived incident is read-only
        archive.guard(row)
    return row


def _collection(db: OrmSession, incident_id: str, source_id: str) -> EvidenceSource:
    row = browse.source(db, incident_id, source_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Evidence file not found")
    if not collections.is_collection(row):
        raise HTTPException(status_code=409, detail=collections.NOT_A_COLLECTION)
    return row


def _shown(db: OrmSession, row: EvidenceSource) -> dict[str, Any]:
    answer = browse.source_of(row, collections.work_of(db, row))
    answer["report"] = row.report or {}
    answer["artifactId"] = artifacts.artifact_id(originals.KIND, row.sha256) if row.sha256 else None
    return answer


@router.get("/{source_id}")
def get_collection(
    incident_id: str,
    source_id: str,
    status: str = Query(default="all", max_length=16),
    kind: str = Query(default="", max_length=120),
    q: str = Query(default="", max_length=200),
    limit: int = Query(default=PAGE_DEFAULT, ge=1, le=collections.PAGE_MAX),
    cursor: str = Query(default="", max_length=20),
    _caller: Principal = Depends(reader_principal),
    db: OrmSession = Depends(get_db),
):
    """The collection (its row, with the report) and one page of its members in the order of the zip: ``members``
    (``n``,
    ``path``, ``fileName``, ``size``, ``sha256``, ``kind``, ``source``, ``parser``, ``host``, ``username``, ``profile``,
    ``executable``, ``skip``, ``importable``, ``imported``, ``alreadyImported``, ``sourceId``, ``state``), ``next`` (the
    cursor of the following page, null at the end), ``total`` of what the filter keeps and ``counts`` of the whole list.
    ``status`` is ``all``, ``importable``, ``imported``, ``skipped``, ``executables`` or ``unrecognised``; ``kind`` the
    sections (comma-separated); ``q`` a part of the path."""
    _incident(db, incident_id)
    row = _collection(db, incident_id, source_id)
    if status not in collections.STATUSES:
        raise HTTPException(status_code=400, detail="status is one of " + ", ".join(collections.STATUSES))
    kinds = [item for item in (part.strip() for part in kind.split(",")) if item]
    if any(item not in imports.KINDS for item in kinds):
        raise HTTPException(status_code=400, detail="kind is one or more of " + ", ".join(imports.KINDS))
    if cursor and not cursor.isdigit():
        raise HTTPException(status_code=400, detail="Not a cursor of this list")
    page = collections.members_page(db, row, status, kinds, q.strip(), limit, int(cursor) if cursor else None)
    return {"collection": _shown(db, row), **page}


@router.post("/{source_id}/import", status_code=202)
def import_members(
    incident_id: str,
    source_id: str,
    body: ImportIn,
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
):
    """Import the members chosen: ``{"members": [n, ...]}`` or ``{"all": true}``, optionally limited to ``kinds``. A
    file the
    incident already holds is "already imported"; a program or a file Nik does not read is left out. The files are
    kept and read one after the other in the background: the row of the collection says how far it is
    (``state`` ``importing``, ``report.collection.importing``: ``total``, ``done``, ``already``, ``failed``,
    ``current``).
    Answers the collection and ``selected``, how many members were chosen. 409 when nothing chosen can be imported or
    the
    collection is not listed (or is being imported)."""
    if body.members is None and not body.all:
        raise HTTPException(status_code=400, detail="Say which members (members) or all of them (all)")
    if body.members is not None and body.all:
        raise HTTPException(status_code=400, detail="Give members or all, not both")
    if body.kinds and any(item not in imports.KINDS for item in body.kinds):
        raise HTTPException(status_code=400, detail="kinds are of " + ", ".join(imports.KINDS))
    incident = _incident(db, incident_id, lock=True)
    row = _collection(db, incident_id, source_id)
    try:
        selected = collections.want_import(
            db, row, None if body.all else body.members, body.kinds or None, caller.actor
        )
    except ValueError as error:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(error)) from None
    audit.record(
        db,
        caller.actor,
        "evidence.collection",
        f"Imported {selected} file{'' if selected == 1 else 's'} of {row.file_name}",
        incident,
        target=row.file_name,
    )
    db.commit()
    collections.start_import(source_id)
    db.refresh(row)
    return {"collection": _shown(db, row), "selected": selected}


@router.post("/{source_id}/analyse", status_code=201)
def analyse_member(
    incident_id: str,
    source_id: str,
    body: AnalyseIn,
    background_tasks: BackgroundTasks,
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
):
    """Send a program of the collection to Malware Analysis (``{"member": n}``): it is taken out of the zip, analysed
    and
    attached to the incident as a sample, as an uploaded sample is. Answers like the upload of a sample
    (``sample``, ``iocs``, ``strings``). 404 for a member the list does not have, 409 for one that is not a program,
    413 for one larger than a sample may be."""
    incident = _incident(db, incident_id)
    archive.guard(incident)
    row = _collection(db, incident_id, source_id)
    member = collections.member_of(db, row, body.member)
    if member is None:
        raise HTTPException(status_code=404, detail="The collection has no such member")
    if not member.executable or not member.sha256:
        raise HTTPException(status_code=409, detail="Only a program of the collection can be sent to Malware Analysis")
    limit = settings.SAMPLE_MAX_MB * 1024 * 1024
    if member.size > limit:
        raise HTTPException(status_code=413, detail=f"The file exceeds the {settings.SAMPLE_MAX_MB} MB sample limit.")
    path, sha256, zip_sha256, name = member.path, member.sha256, row.sha256, row.file_name
    try:
        data = collections.fetch(zip_sha256, sha256, path, limit)
    except collections.CollectionError as error:
        raise HTTPException(status_code=502, detail=str(error)) from None
    if hashlib.sha256(data).hexdigest() != sha256:
        raise HTTPException(status_code=502, detail="The file the worker gave is not the one the list names")
    sample, ref = samples.store_sample(
        db,
        incident,
        data,
        collections.name_of(path),
        caller,
        background_tasks,
        origin=f"{name}: {path}"[:300],
        parent=(artifacts.artifact_id(originals.KIND, zip_sha256), "extracted"),
    )
    return {
        "sample": ref,
        "iocs": len(sample.analysis.get("iocs", [])),
        "strings": sample.analysis.get("stringsTotal", 0),
    }

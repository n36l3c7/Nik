"""The views of host evidence (7.0): its time, its rare values, its fields, and the original behind a record.

All of it is read-only and by incident, with the filters of the list of records. The page of bytes and
the viewer need the original to be in the store. Downloading the original is a permission of its own,
``evidence.download``: the file is what the machine held, and is sent in an encrypted zip.
"""

from __future__ import annotations

import uuid
from typing import Any, Literal

import pyzipper
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session as OrmSession
from starlette.background import BackgroundTask

from .. import artifact_transfer
from ..core import audit, store
from ..core.db import get_db
from ..core.files import safe_name, stored_response
from ..core.models import EvidenceRecord, EvidenceSource, Incident
from ..core.permissions import EVIDENCE_DOWNLOAD
from ..core.security import Principal, reader_principal, require
from ..evidence import browse, originals, parse, views
from ..malware.samples import DEFAULT_ZIP_PASSWORD
from .evidence_filters import filters

router = APIRouter(prefix="/incidents/{incident_id}/evidence", tags=["incidents/evidence"])

download_principal = require(EVIDENCE_DOWNLOAD)
FIXED = {404, 422, 503, 504}


def _incident(db: OrmSession, incident_id: str) -> Incident:
    row = db.get(Incident, incident_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return row


def _source(db: OrmSession, incident_id: str, source_id: str) -> EvidenceSource:
    row = browse.source(db, incident_id, source_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Evidence file not found")
    return row


def _original(row: EvidenceSource) -> str:
    try:
        return views.original_of(row)
    except views.NoOriginal as error:
        raise HTTPException(status_code=404, detail=str(error)) from None


# --------------------------------------------------------------------------- #
# From above                                                                  #
# --------------------------------------------------------------------------- #
@router.get("/histogram")
def get_histogram(
    incident_id: str,
    buckets: int = Query(default=120, ge=10, le=500),
    gapMinutes: int = Query(default=120, ge=1, le=100000),  # noqa: N803
    burstFactor: int = Query(default=5, ge=2, le=1000),  # noqa: N803
    f: dict[str, Any] = Depends(filters),
    _caller: Principal = Depends(reader_principal),
    db: OrmSession = Depends(get_db),
):
    """The records of the filter per slice of time, the gaps with none, and the bursts."""
    _incident(db, incident_id)
    return views.histogram(db, incident_id, f, buckets, gapMinutes, burstFactor)


@router.get("/stack")
def get_stack(
    incident_id: str,
    field: str = Query(max_length=100),
    order: str = Query(default="rare", max_length=10),
    limit: int = Query(default=100, ge=1, le=1000),
    f: dict[str, Any] = Depends(filters),
    _caller: Principal = Depends(reader_principal),
    db: OrmSession = Depends(get_db),
):
    """The values of a field with their counts, the rare ones first or the common ones."""
    _incident(db, incident_id)
    try:
        return views.stack(db, incident_id, f, field, order, limit)
    except browse.BadQuery as error:
        raise HTTPException(status_code=400, detail=str(error)) from None


@router.get("/fields")
def get_fields(
    incident_id: str,
    kind: str = Query(default="", max_length=16),
    type: str = Query(default="", max_length=40),  # noqa: A002 - the API's own name
    sourceId: str = Query(default="", max_length=32),  # noqa: N803
    _caller: Principal = Depends(reader_principal),
    db: OrmSession = Depends(get_db),
):
    """The fields the records have (from the first 500), with how many of them have each."""
    _incident(db, incident_id)
    return views.fields(db, incident_id, {"kind": kind, "type": type, "sourceId": sourceId})


# --------------------------------------------------------------------------- #
# The original                                                                #
# --------------------------------------------------------------------------- #
@router.get("/records/{record_id}/view")
def get_view(
    incident_id: str,
    record_id: int,
    _caller: Principal = Depends(reader_principal),
    db: OrmSession = Depends(get_db),
):
    """What the viewer of the worker shows of a record: its place in the original, read from the file."""
    _incident(db, incident_id)
    record = db.get(EvidenceRecord, record_id)
    if record is None or record.incident_id != incident_id:
        raise HTTPException(status_code=404, detail="Record not found")
    source = _source(db, incident_id, record.source_id)
    sha256 = _original(source)
    if not parse.configured():
        raise HTTPException(status_code=503, detail=parse.NOT_CONFIGURED)
    body = {"parser": source.parser or None, "source": source.source or None, "loc": record.locator or {}}
    code, answer = views.ask_view(sha256, body)
    if code == 200:
        return {**answer, "sourceId": source.id, "fileName": source.file_name}
    detail = answer.get("detail") if isinstance(answer, dict) else None
    if code in FIXED:
        raise HTTPException(status_code=code, detail=str(detail or f"The forensics worker answered {code}"))
    raise HTTPException(
        status_code=502, detail=str(detail or f"The forensics worker could not show this record ({code})")
    )


@router.get("/sources/{source_id}/page")
def get_page(
    incident_id: str,
    source_id: str,
    offset: int = Query(default=0, ge=0),
    length: int = Query(default=65536, ge=1, le=1048576),
    as_: Literal["hex", "text"] = Query(default="hex", alias="as"),
    _caller: Principal = Depends(reader_principal),
    db: OrmSession = Depends(get_db),
):
    """Bytes ``[offset, offset + length)`` of the original, as hex or as text."""
    _incident(db, incident_id)
    sha256 = _original(_source(db, incident_id, source_id))
    return views.page(sha256, offset, length, as_)


@router.get("/sources/{source_id}/find")
def get_find(
    incident_id: str,
    source_id: str,
    q: str = Query(min_length=1, max_length=1024),
    as_: Literal["hex", "text"] = Query(default="text", alias="as"),
    from_: int = Query(default=0, ge=0, alias="from"),
    limit: int = Query(default=100, ge=1, le=200),
    _caller: Principal = Depends(reader_principal),
    db: OrmSession = Depends(get_db),
):
    """Where a text (as UTF-8 and UTF-16LE, any case) or some bytes (hex) are in the original, from an offset
    on: the matches, ``next`` to go on from (null at the end) and ``cut`` when the limit or the worker's clock
    stopped the search before the end. The worker reads the file; a needle it refuses is a 400."""
    _incident(db, incident_id)
    sha256 = _original(_source(db, incident_id, source_id))
    if not parse.configured():
        raise HTTPException(status_code=503, detail=parse.NOT_CONFIGURED)
    code, answer = views.find(sha256, q, as_, from_, limit)
    if code == 200:
        return answer
    detail = answer.get("detail") if isinstance(answer, dict) else None
    if code in FIXED or code == 400:
        raise HTTPException(status_code=code, detail=str(detail or f"The forensics worker answered {code}"))
    raise HTTPException(status_code=502, detail=str(detail or f"The forensics worker could not search ({code})"))


@router.get("/sources/{source_id}/download")
def download_original(
    incident_id: str,
    source_id: str,
    caller: Principal = Depends(download_principal),
    db: OrmSession = Depends(get_db),
):
    """The original inside an AES-256 zip (password ``infected``, as a malware sample is). The zip is put
    together on the disk of the store, sealed, and sent a piece at a time: a file of gigabytes is never
    in memory."""
    incident = _incident(db, incident_id)
    source = _source(db, incident_id, source_id)
    sha256 = _original(source)
    path = originals.path_of(sha256)
    try:
        originals.room(store.size(path), "the zip of the file")
    except originals.EvidenceError as error:
        raise HTTPException(status_code=507, detail=str(error)) from None
    inner = safe_name(source.file_name, "evidence")
    zipped = artifact_transfer.workdir() / f"nik-evidence-{uuid.uuid4().hex}.zip"
    try:
        with (
            store.writing(zipped) as sealed_out,
            pyzipper.AESZipFile(
                artifact_transfer._Sealing(sealed_out),  # noqa: SLF001 - the sealed writer the exports use
                "w",
                compression=pyzipper.ZIP_DEFLATED,
                encryption=pyzipper.WZ_AES,
            ) as archive,
        ):
            archive.setpassword(DEFAULT_ZIP_PASSWORD.encode("utf-8"))
            with archive.open(inner, "w", force_zip64=True) as packed:
                for piece in store.pieces(path):
                    packed.write(piece)
        audit.record(
            db,
            caller.actor,
            "evidence.download",
            f"Downloaded the original of {source.file_name} ({sha256})",
            incident,
        )
        db.commit()
        response = stored_response(zipped, "application/zip", f"{inner}.zip")
    except BaseException:
        zipped.unlink(missing_ok=True)
        raise
    response.background = BackgroundTask(lambda: zipped.unlink(missing_ok=True))
    return response

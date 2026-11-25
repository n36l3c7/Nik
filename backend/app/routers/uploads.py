"""Files of host evidence sent in parts (``evidence/uploads.py`` says how).

Accepts a browser session or an ``X-API-Key`` (``writer_principal``), like the
upload of before. A session belongs to who opened it: nobody else sees it or
writes to it.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as OrmSession

from ..core.db import get_db
from ..core.security import Principal, writer_principal
from ..evidence import imports, parse, uploads  # noqa: F401 - parse registers its work

router = APIRouter(prefix="/uploads", tags=["incidents/upload"])


class UploadIn(BaseModel):
    incidentId: str = Field(min_length=1, max_length=64)  # noqa: N815 - the API's own casing
    fileName: str = Field(default="", max_length=500)  # noqa: N815
    size: int = Field(gt=0)
    sha256: str = Field(default="", max_length=64)
    params: dict[str, Any] = Field(default_factory=dict)


def _refused(error: uploads.UploadError) -> JSONResponse:
    body: dict[str, Any] = {"detail": str(error)}
    if error.received is not None:
        body["received"] = error.received
    return JSONResponse(body, status_code=error.status)


@router.post("", status_code=201)
def open_upload(body: UploadIn, caller: Principal = Depends(writer_principal), db: OrmSession = Depends(get_db)):
    """Open a session for a file of ``size`` bytes. ``params.kind`` is the section (``eventlog``,
    ``endpoint``, ``browser``, ``commands``, ``disk``, ``syslog``, ``collection``) or ``auto`` (or none): a file sent
    without a section is recognised by the server when it is whole and filed under its section and source, a zip is a
    collection, and anything else ends the session with ``recognised`` false and a sentence in ``error``. ``source``,
    ``host``, ``user`` and ``profile`` are optional. Give ``sha256`` to have the file checked when it is whole.
    Once it is filed the session says where the file went: ``kind``, ``source``, ``sourceId``."""
    if str(body.params.get("kind") or "") not in ("", "auto", *imports.KINDS):
        raise HTTPException(status_code=400, detail="params.kind must be one of " + ", ".join(("auto", *imports.KINDS)))
    try:
        row = uploads.open_session(
            db, caller.actor, body.incidentId, body.fileName, body.size, body.sha256, dict(body.params)
        )
    except uploads.UploadError as error:
        return _refused(error)
    db.commit()
    return uploads.shown(db, row)


@router.get("/{upload_id}")
def read_upload_session(
    upload_id: str, caller: Principal = Depends(writer_principal), db: OrmSession = Depends(get_db)
):
    """How much was received: a client that was cut goes on from ``received``."""
    try:
        return uploads.shown(db, uploads.mine(db, upload_id, caller.actor))
    except uploads.UploadError as error:
        return _refused(error)


@router.put("/{upload_id}")
async def put_part(
    upload_id: str,
    request: Request,
    offset: int = Query(..., ge=0),
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
):
    """One part: the raw bytes of the file from ``offset`` on, at most ``chunk`` bytes."""
    data = bytearray()
    async for piece in request.stream():
        data += piece
        if len(data) > uploads.CHUNK:
            return _refused(uploads.UploadError(f"A part holds at most {uploads.CHUNK // 2**20} MB", 413))

    def write() -> int:
        row = uploads.mine(db, upload_id, caller.actor, lock=True)
        received = uploads.write_part(db, row, offset, bytes(data))
        db.commit()
        return received

    try:
        received = await run_in_threadpool(write)
    except uploads.UploadError as error:
        db.rollback()
        return _refused(error)
    return {"received": received}


@router.post("/{upload_id}/complete", status_code=202)
def complete_upload(upload_id: str, caller: Principal = Depends(writer_principal), db: OrmSession = Depends(get_db)):
    """Every part was sent: the file is checked, kept and read in the background. Ask
    ``GET /uploads/{id}`` until ``state`` is ``complete`` (``sourceId`` is then its report)."""
    try:
        row = uploads.mine(db, upload_id, caller.actor, lock=True)
        uploads.complete(db, row)
    except uploads.UploadError as error:
        db.rollback()
        return _refused(error)
    db.commit()
    uploads.start(row.id)
    return uploads.shown(db, row)


@router.delete("/{upload_id}", status_code=204)
def abort_upload(upload_id: str, caller: Principal = Depends(writer_principal), db: OrmSession = Depends(get_db)):
    try:
        uploads.abort(db, uploads.mine(db, upload_id, caller.actor, lock=True))
    except uploads.UploadError as error:
        db.rollback()
        return _refused(error)
    db.commit()

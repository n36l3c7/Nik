"""Network Analysis: packet captures (pcap / pcapng) and isolated browser sessions.

Nothing here reads a packet: the packet capture worker does, with
Wireshark's engine (``workers/pcap/``). The routes store the files, proxy a fixed
set of the worker's calls (packet list, protocol tree, Follow Stream,
Export Objects, filter checks), and serve the captures, exported objects
and browser logs (HAR). Downloads are audited.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import uuid
from typing import Any, Literal

from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, Query, Request, UploadFile, status
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from .. import artifacts
from ..core import vault
from ..core.config import settings
from ..core.db import get_db
from ..core.files import attachment_headers, safe_name
from ..core.models import AuditEntry, Incident, NetworkCapture
from ..core.security import Principal, now_iso, principal, writer_principal
from ..malware.samples import DEFAULT_ZIP_PASSWORD, zip_sample
from ..network import har, service, store
from ..workers import previews
from .samples import store_sample

router = APIRouter(tags=["network"])

CHUNK = 1024 * 1024
KEYLOG_MAX = 5 * 1024 * 1024
# Lines of an NSS key log (SSLKEYLOGFILE): a label, then hex fields.
_KEYLOG_LINE = re.compile(r"^(#.*|[A-Z_0-9]+ [0-9a-fA-F]+ [0-9a-fA-F]+|)$")
RPC_METHODS = {"status", "frames", "frame", "follow", "tap", "check", "complete"}


def _audit(db: OrmSession, caller: Principal, action: str, details: str, incident: Incident | None) -> None:
    doc = (incident.doc if incident is not None else {}) or {}
    db.add(
        AuditEntry(
            id=str(uuid.uuid4()),
            at=now_iso(),
            actor=caller.actor,
            action=action,
            target=doc.get("name"),
            details=details,
            incident_id=incident.id if incident is not None else None,
            incident_name=doc.get("name"),
        )
    )


def _incident_or_404(db: OrmSession, incident_id: str) -> Incident:
    row = db.get(Incident, incident_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return row


def _incident_of(db: OrmSession, row: NetworkCapture) -> Incident | None:
    return db.get(Incident, row.incident_id) if row.incident_id else None


def _capture_or_404(db: OrmSession, capture_id: str, incident_id: str | None = None) -> NetworkCapture:
    row = db.get(NetworkCapture, capture_id) if store.is_capture_id(capture_id) else None
    if row is None or (incident_id is not None and row.incident_id != incident_id):
        raise HTTPException(status_code=404, detail="Capture not found")
    return row


def _worker_error(exc: previews.WorkerError) -> HTTPException:
    return HTTPException(status_code=exc.status, detail=str(exc))


def _detail(row: NetworkCapture) -> dict[str, Any]:
    return {**service.reference(row), "incidentId": row.incident_id, "meta": row.meta, "summary": row.summary}


def _needs_file(row: NetworkCapture) -> None:
    if row.status == "live":
        raise HTTPException(status_code=409, detail="The browser session is still open: close it first.")
    if not service.configured():
        raise HTTPException(status_code=503, detail="The packet capture worker is not configured (PCAP_URL).")


def _keylog_text(data: bytes) -> str:
    """A TLS key log (NSS format), checked line by line."""
    if not data or len(data) > KEYLOG_MAX:
        raise HTTPException(status_code=422, detail="The key log must be a non-empty text file of 5 MB at most.")
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=422, detail="Not a TLS key log (SSLKEYLOGFILE).") from exc
    lines = text.splitlines()
    if not any(line and not line.startswith("#") for line in lines) or not all(
        _KEYLOG_LINE.match(line.strip()) for line in lines
    ):
        raise HTTPException(status_code=422, detail="Not a TLS key log (SSLKEYLOGFILE).")
    return text


async def store_capture(
    db: OrmSession,
    incident: Incident | None,
    file: UploadFile,
    keylog: UploadFile | None,
    caller: Principal,
    background_tasks: BackgroundTasks | None,
) -> NetworkCapture:
    """Store an uploaded capture, in the incident or on its own, and queue its analysis."""
    head = await file.read(CHUNK)
    ext = store.capture_format(head)
    if ext is None:
        raise HTTPException(status_code=422, detail="Not a pcap or pcapng file.")
    keys = _keylog_text(await keylog.read(KEYLOG_MAX + 1)) if keylog is not None else None
    capture_id = uuid.uuid4().hex
    limit = settings.PCAP_MAX_MB * 1024 * 1024
    digest, size = hashlib.sha256(), 0
    part = store.capture_path(capture_id, ext).with_suffix(".part")
    try:
        with open(part, "wb") as handle:
            chunk = head
            while chunk:
                size += len(chunk)
                if size > limit:
                    raise HTTPException(status_code=413, detail=f"The capture exceeds {settings.PCAP_MAX_MB} MB.")
                digest.update(chunk)
                await run_in_threadpool(handle.write, chunk)
                chunk = await file.read(CHUNK)
    except HTTPException:
        store.remove(capture_id)
        raise
    store.seal(part, store.capture_path(capture_id, ext))
    row = NetworkCapture(
        id=capture_id,
        incident_id=incident.id if incident is not None else None,
        kind="pcap",
        file_name=(file.filename or f"capture.{ext}")[:255],
        size=size,
        sha256=digest.hexdigest(),
        created_at=now_iso(),
        created_by=caller.actor,
        meta={},
        summary={},
        keylog=vault.encrypt(keys) if keys else None,
    )
    db.add(row)
    _audit(db, caller, "capture.upload", f"Uploaded capture {row.file_name} ({size} bytes)", incident)
    service.queue_analysis(db, row, background_tasks)
    return row


# --------------------------------------------------------------------------- #
# Captures                                                                    #
# --------------------------------------------------------------------------- #
@router.post("/incidents/{incident_id}/captures", status_code=status.HTTP_201_CREATED)
async def upload_capture(
    incident_id: str,
    file: UploadFile = File(..., description="A pcap or pcapng file (optionally gzip-compressed)."),
    keylog: UploadFile | None = File(None, description="Optional TLS key log (SSLKEYLOGFILE) to decrypt HTTPS."),
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
    background_tasks: BackgroundTasks = None,
) -> dict:
    """Store a packet capture in the incident and analyse it in the background
    (``status``: indexing, then ready or error). Up to ``PCAP_MAX_MB``."""
    incident = _incident_or_404(db, incident_id)
    row = await store_capture(db, incident, file, keylog, caller, background_tasks)
    return {"capture": service.reference(row)}


@router.get("/incidents/{incident_id}/captures")
def list_captures(
    incident_id: str,
    _caller: Principal = Depends(principal),
    db: OrmSession = Depends(get_db),
    background_tasks: BackgroundTasks = None,
) -> dict:
    """The incident's captures (references, oldest first), including isolated
    browser sessions opened by any analyst; ended sessions are finalized here."""
    _incident_or_404(db, incident_id)
    rows = db.scalars(
        select(NetworkCapture).where(NetworkCapture.incident_id == incident_id).order_by(NetworkCapture.created_at)
    ).all()
    for row in rows:
        service.refresh_live(db, row, background_tasks)
    return {"captures": [service.reference(row) for row in rows]}


@router.get("/captures/{capture_id}")
def get_capture(
    capture_id: str,
    _caller: Principal = Depends(principal),
    db: OrmSession = Depends(get_db),
    background_tasks: BackgroundTasks = None,
) -> dict:
    """The capture's state and summary (an ended browser session is finalized here)."""
    row = _capture_or_404(db, capture_id)
    service.refresh_live(db, row, background_tasks)
    return _detail(row)


class RpcIn(BaseModel):
    method: Literal["status", "frames", "frame", "follow", "tap", "check", "complete"]
    params: dict[str, Any] = Field(default_factory=dict)


@router.post("/captures/{capture_id}/rpc")
async def capture_rpc(
    capture_id: str, body: RpcIn, _caller: Principal = Depends(principal), db: OrmSession = Depends(get_db)
) -> dict:
    """A read-only call to Wireshark's engine on the capture: ``frames`` (the
    packet list, with ``filter``, ``skip``, ``limit``), ``frame`` (protocol
    tree and bytes), ``follow`` (``follow``: TCP, UDP, HTTP, TLS…, and a
    ``filter``), ``tap`` (``eo:http`` … export object lists, ``expert``),
    ``check`` (a display filter), ``complete`` (field names), ``status``."""
    row = _capture_or_404(db, capture_id)
    _needs_file(row)
    try:
        result = await run_in_threadpool(service.rpc, row, body.method, body.params)
    except previews.WorkerError as exc:
        raise _worker_error(exc) from exc
    return result


@router.get("/captures/{capture_id}/objects/download")
async def download_object(
    capture_id: str,
    token: str = Query(..., pattern=r"^eo:[a-z-]+_\d{1,6}$"),
    password: str = Query(DEFAULT_ZIP_PASSWORD, min_length=1, max_length=128),
    caller: Principal = Depends(principal),
    db: OrmSession = Depends(get_db),
):
    """An exported object (Export Objects) inside an AES-256 zip (default password ``infected``). Audited."""
    row = _capture_or_404(db, capture_id)
    _needs_file(row)
    try:
        item = await run_in_threadpool(service.rpc, row, "download", {"token": token})
    except previews.WorkerError as exc:
        raise _worker_error(exc) from exc
    inner = safe_name(item.get("name"), "object")
    archive = zip_sample(base64.b64decode(item.get("data") or ""), inner, password)
    _audit(db, caller, "capture.object.download", f"Downloaded {inner} from capture {row.file_name}", None)
    db.commit()
    return Response(archive, media_type="application/zip", headers=attachment_headers(f"{inner}.zip"))


class ObjectIn(BaseModel):
    token: str = Field(pattern=r"^eo:[a-z-]+_\d{1,6}$")


@router.post("/incidents/{incident_id}/captures/{capture_id}/objects/sample", status_code=status.HTTP_201_CREATED)
async def object_to_sample(
    incident_id: str,
    capture_id: str,
    body: ObjectIn,
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
    background_tasks: BackgroundTasks = None,
) -> dict:
    """Send an exported object to Malware Analysis as a sample of the incident."""
    incident = _incident_or_404(db, incident_id)
    row = _capture_or_404(db, capture_id, incident_id)
    _needs_file(row)
    try:
        item = await run_in_threadpool(service.rpc, row, "download", {"token": body.token})
    except previews.WorkerError as exc:
        raise _worker_error(exc) from exc
    data = base64.b64decode(item.get("data") or "")
    sample, ref = await run_in_threadpool(
        store_sample,
        db,
        incident,
        data,
        str(item.get("name") or "object")[:255],
        caller,
        background_tasks,
        f"capture {row.file_name}",
        (artifacts.artifact_id("pcap", row.id), "extracted"),
    )
    return {"sample": ref, "iocs": len(sample.analysis.get("iocs", []))}


@router.get("/captures/{capture_id}/file")
def download_capture(capture_id: str, caller: Principal = Depends(principal), db: OrmSession = Depends(get_db)):
    """The capture file as stored (pcap, pcapng or gzip). Audited."""
    row = _capture_or_404(db, capture_id)
    path = store.find_capture(row.id)
    if path is None:
        raise HTTPException(status_code=404, detail="The capture file is not in the store (session still open?)")
    _audit(db, caller, "capture.download", f"Downloaded capture {row.file_name}", None)
    db.commit()
    name = re.sub(r'[\\/"\x00-\x1f]', "_", row.file_name) or path.name
    return FileResponse(path, media_type="application/vnd.tcpdump.pcap", filename=name)


@router.get("/captures/{capture_id}/har")
def download_har(
    capture_id: str, request: Request, caller: Principal = Depends(principal), db: OrmSession = Depends(get_db)
):
    """An isolated browser session's network log as HAR 1.2. Audited."""
    row = _capture_or_404(db, capture_id)
    if row.kind != "browser":
        raise HTTPException(status_code=404, detail="Only isolated browser sessions have a HAR")
    document = har.build(store.read_log(row.id), request.app.version, (row.meta or {}).get("label") or "")
    _audit(db, caller, "capture.download", f"Downloaded the HAR of {row.file_name}", None)
    db.commit()
    name = re.sub(r"\.pcapng$", "", row.file_name) + ".har"
    return Response(
        json.dumps(document),
        media_type="application/json",
        headers=attachment_headers(name),
    )


@router.get("/captures/{capture_id}/requests")
def list_requests(
    capture_id: str,
    _caller: Principal = Depends(principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """An isolated browser session's requests, without bodies (the Network panel's list)."""
    row = _capture_or_404(db, capture_id)
    if row.kind != "browser":
        raise HTTPException(status_code=404, detail="Only isolated browser sessions have a request log")
    if row.status == "live":
        try:
            service.sync(db, row)
        except previews.WorkerError:
            pass  # the copy already kept is shown
    entries = store.read_log(row.id)
    return {
        "live": row.status == "live",
        "releasePosts": bool((row.meta or {}).get("releasePosts")),
        "network": bool((row.meta or {}).get("network")),
        "entries": [store.light(e) for e in entries],
    }


@router.get("/captures/{capture_id}/requests/{entry_id}")
def get_request(
    capture_id: str, entry_id: int, _caller: Principal = Depends(principal), db: OrmSession = Depends(get_db)
) -> dict:
    """One request in full: headers, bodies (base64), timings, WebSocket messages."""
    row = _capture_or_404(db, capture_id)
    entry = next((e for e in store.read_log(row.id) if e.get("id") == entry_id), None)
    if entry is None:
        raise HTTPException(status_code=404, detail="Request not found")
    return entry


@router.put("/captures/{capture_id}/keylog", status_code=status.HTTP_202_ACCEPTED)
async def set_keylog(
    capture_id: str,
    file: UploadFile = File(..., description="A TLS key log (SSLKEYLOGFILE)."),
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
    background_tasks: BackgroundTasks = None,
) -> dict:
    """Attach a TLS key log (stored encrypted) and analyse the capture again, decrypted."""
    row = _capture_or_404(db, capture_id)
    if row.status == "live":
        raise HTTPException(status_code=409, detail="The browser session is still open.")
    row.keylog = vault.encrypt(_keylog_text(await file.read(KEYLOG_MAX + 1)))
    _audit(
        db,
        caller,
        "capture.keylog",
        f"Added a TLS key log to capture {row.file_name}",
        _incident_of(db, row),
    )
    service.queue_analysis(db, row, background_tasks)
    return service.reference(row)


@router.delete("/captures/{capture_id}/keylog", status_code=status.HTTP_202_ACCEPTED)
def delete_keylog(
    capture_id: str,
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
    background_tasks: BackgroundTasks = None,
) -> dict:
    row = _capture_or_404(db, capture_id)
    if not row.keylog:
        raise HTTPException(status_code=404, detail="The capture has no key log")
    row.keylog = None
    _audit(
        db,
        caller,
        "capture.keylog",
        f"Removed the TLS key log of capture {row.file_name}",
        _incident_of(db, row),
    )
    service.queue_analysis(db, row, background_tasks)
    return service.reference(row)


@router.post("/captures/{capture_id}/reanalyse", status_code=status.HTTP_202_ACCEPTED)
def reanalyse_capture(
    capture_id: str,
    _caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
    background_tasks: BackgroundTasks = None,
) -> dict:
    row = _capture_or_404(db, capture_id)
    if row.status == "live":
        raise HTTPException(status_code=409, detail="The browser session is still open.")
    service.queue_analysis(db, row, background_tasks)
    return service.reference(row)


@router.delete("/incidents/{incident_id}/captures/{capture_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_capture(
    incident_id: str,
    capture_id: str,
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
) -> Response:
    """Take the capture out of the incident. It stays as an artifact
    (`DELETE /api/artifacts/pcap-<id>` deletes it). A browser session that is
    still open is closed and deleted."""
    incident = _incident_or_404(db, incident_id)
    row = _capture_or_404(db, capture_id, incident_id)
    _audit(db, caller, "capture.delete", f"Removed capture {row.file_name} from the incident", incident)
    if row.status == "live":
        service.remove_capture(db, row)
    else:
        service.detach(db, row)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


def remove_incident_captures(db: OrmSession, incident_id: str) -> None:
    """Called when an incident is deleted: its captures go with it."""
    for row in db.scalars(select(NetworkCapture).where(NetworkCapture.incident_id == incident_id)).all():
        service.remove_capture(db, row, update_incident=False)

"""Incident document-store routes.

The backend stores the full frontend incident object in ``doc`` and mirrors a
few scalar fields into columns for listing/sorting. ``POST`` upserts a full
document; ``PATCH`` shallow-merges only the changed top-level keys.

These endpoints accept EITHER a browser session or an ``X-API-Key`` header (the
``principal`` dependency), so the same operations are available to external API
clients. Actions performed with an API key are recorded in the audit log
server-side (browser actions are logged by the frontend).
"""

from __future__ import annotations

import json
import uuid
from typing import Any

from fastapi import APIRouter, Body, Depends, File, Header, HTTPException, Query, Response, UploadFile, status
from fastapi.responses import JSONResponse
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm.attributes import flag_modified

from ..db import get_db
from ..models import AuditEntry, Incident, IdempotencyRecord
from ..parsing.registry import apply_upload
from ..schemas import NoteIn
from ..security import Principal, now_iso, principal, writer_principal

router = APIRouter(prefix="/incidents", tags=["incidents"])


def _sync_columns(incident: Incident) -> None:
    """Refresh the mirrored scalar columns from the incident ``doc``."""
    doc = incident.doc or {}
    incident.name = str(doc.get("name") or "")
    incident.host = str(doc.get("host") or "")
    incident.username = str(doc.get("username") or "")
    incident.updated_at = str(doc.get("updatedAt") or "")
    incident.created_at = str(doc.get("createdAt") or "")


def _audit(
    db: OrmSession,
    caller: Principal,
    action: str,
    details: str,
    incident: Incident | None = None,
    *,
    always: bool = False,
) -> None:
    """Record an audit entry.

    By default only API-key callers are logged here (browser actions are logged
    by the frontend, to avoid double entries); pass ``always=True`` for the
    API-only endpoints (notes, upload) the frontend never calls.
    """
    if caller.kind != "apikey" and not always:
        return
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


def _get_or_404(db: OrmSession, incident_id: str) -> Incident:
    row = db.get(Incident, incident_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return row


def _etag(doc: dict | None) -> str:
    """Weak version tag for an incident (changes on every write via updatedAt)."""
    return '"' + str((doc or {}).get("updatedAt") or "") + '"'


def _idempotent_replay(db: OrmSession, key: str | None):
    """Return the stored response for a seen Idempotency-Key, or None."""
    if not key:
        return None
    rec = db.get(IdempotencyRecord, key)
    if rec is None:
        return None
    return JSONResponse(content=json.loads(rec.response_json), status_code=rec.status_code)


def _idempotent_save(db: OrmSession, key: str | None, status_code: int, body: Any) -> None:
    if not key or db.get(IdempotencyRecord, key) is not None:
        return
    db.add(
        IdempotencyRecord(
            key=key, created_at=now_iso(), status_code=status_code, response_json=json.dumps(body)
        )
    )
    db.commit()


@router.get("")
def list_incidents(
    response: Response,
    _caller: Principal = Depends(principal),
    db: OrmSession = Depends(get_db),
    limit: int | None = Query(None, ge=1, le=1000, description="Page size (default: all)."),
    offset: int = Query(0, ge=0),
    q: str | None = Query(None, description="Match name/host/username."),
    host: str | None = Query(None),
    username: str | None = Query(None),
    view: str = Query("full", pattern="^(full|summary)$", description="full = whole documents; summary = light rows (no data)."),
) -> dict:
    """List incidents newest-updated first, filterable and paginated.

    ``view=summary`` returns light rows (id/name/host/username/timestamps) WITHOUT
    the heavy document body — use it for lists at scale, then fetch a single
    incident's full document from ``GET /incidents/{id}``. Backward compatible:
    with no params it returns every full document. Total count is also in the
    ``X-Total-Count`` header.
    """
    conditions = []
    if q:
        like = f"%{q}%"
        conditions.append(
            or_(Incident.name.ilike(like), Incident.host.ilike(like), Incident.username.ilike(like))
        )
    if host:
        conditions.append(Incident.host.ilike(f"%{host}%"))
    if username:
        conditions.append(Incident.username.ilike(f"%{username}%"))

    total = db.scalar(select(func.count()).select_from(Incident).where(*conditions)) or 0
    response.headers["X-Total-Count"] = str(total)
    order = Incident.updated_at.desc()

    if view == "summary":
        stmt = select(
            Incident.id, Incident.name, Incident.host, Incident.username,
            Incident.created_at, Incident.updated_at,
        ).where(*conditions).order_by(order)
        stmt = stmt.offset(offset).limit(limit) if limit is not None else stmt.offset(offset)
        incidents = [
            {"id": r.id, "name": r.name, "host": r.host, "username": r.username,
             "createdAt": r.created_at, "updatedAt": r.updated_at}
            for r in db.execute(stmt).all()
        ]
    else:
        stmt = select(Incident).where(*conditions).order_by(order)
        stmt = stmt.offset(offset).limit(limit) if limit is not None else stmt.offset(offset)
        incidents = [row.doc for row in db.scalars(stmt).all()]

    return {"incidents": incidents, "total": total}


@router.get("/{incident_id}")
def get_incident(
    incident_id: str,
    response: Response,
    _caller: Principal = Depends(principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Return a single incident's full document; 404 if missing.

    The response carries an ``ETag`` (the incident version); pass it back as
    ``If-Match`` on PATCH for optimistic concurrency.
    """
    row = _get_or_404(db, incident_id)
    response.headers["ETag"] = _etag(row.doc)
    return row.doc


@router.post("", status_code=status.HTTP_201_CREATED)
def create_incident(
    doc: dict[str, Any] = Body(...),
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Create (or upsert) an incident from a full client-built document.

    The server stamps ``createdBy`` from the caller (username, or ``api:<label>``).
    """
    doc = dict(doc)
    # Guarantee a v4 UUID id: use the client's if present, else generate one.
    incident_id = doc.get("id") or str(uuid.uuid4())
    doc["id"] = incident_id
    doc["createdBy"] = caller.actor

    existing = db.get(Incident, incident_id)
    if existing is None:
        incident = Incident(id=str(incident_id), doc=doc)
        _sync_columns(incident)
        db.add(incident)
    else:
        existing.doc = doc
        _sync_columns(existing)
        incident = existing

    _audit(db, caller, "incident.create", f'Created incident "{doc.get("name") or incident_id}"', incident)
    db.commit()
    return incident.doc


@router.patch("/{incident_id}")
def patch_incident(
    incident_id: str,
    response: Response,
    partial: dict[str, Any] = Body(...),
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
    if_match: str | None = Header(None, alias="If-Match"),
) -> dict:
    """Shallow-merge changed top-level keys into the stored document.

    Any incident field can be edited this way: ``host``, ``username``, ``os``,
    ``suspiciousStart``/``suspiciousEnd``, ``notes``, ``flags``, ``data``, …

    Optimistic concurrency: if an ``If-Match`` header is sent it must equal the
    incident's current ``ETag`` (from GET), else ``412 Precondition Failed`` —
    so a stale writer can't silently clobber a newer version.
    """
    row = _get_or_404(db, incident_id)
    if if_match is not None and if_match.strip() != _etag(row.doc):
        raise HTTPException(status_code=412, detail="Incident was modified by someone else (ETag mismatch)")
    merged = dict(row.doc or {})
    for key, value in partial.items():
        merged[key] = value
    row.doc = merged
    flag_modified(row, "doc")
    _sync_columns(row)
    _audit(db, caller, "incident.update", f'Updated attributes of "{merged.get("name") or incident_id}"', row)
    db.commit()
    response.headers["ETag"] = _etag(row.doc)
    return row.doc


@router.delete("/{incident_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_incident(
    incident_id: str,
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
):
    """Delete an incident (idempotent-ish; 204 regardless if it existed)."""
    row = db.get(Incident, incident_id)
    if row is not None:
        _audit(db, caller, "incident.delete", f'Deleted incident "{(row.doc or {}).get("name") or incident_id}"', row)
        db.delete(row)
        db.commit()
    # 204 No Content


# ---------------------------------------------------------------------------
# File upload (server-side parsing) — API clients send raw artifact files
# ---------------------------------------------------------------------------
_UPLOAD_ACTIONS = {"browser": "browser.upload", "commands": "command.upload", "endpoint": "endpoint.upload"}


@router.post("/{incident_id}/upload", tags=["incidents/upload"])
async def upload_artifact(
    incident_id: str,
    file: UploadFile = File(..., description="The raw artifact file."),
    tab: str = Query(..., description="browser | commands | endpoint"),
    browser: str | None = Query(None, description="Browser id (tab=browser), e.g. chrome/firefox"),
    source: str | None = Query(None, description="Source key (browser/endpoint), e.g. history"),
    shell: str | None = Query(None, description="Shell id (tab=commands), e.g. bash"),
    category: str | None = Query(None, description="Category id (tab=endpoint), e.g. persistence"),
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
    idempotency_key: str | None = Header(None, alias="Idempotency-Key"),
) -> dict:
    """Upload a raw artifact file; the server parses it and merges the result.

    Routing (query params) mirrors the app's tabs:
    - `tab=browser&browser=chrome&source=history` → a Chromium `History` DB
    - `tab=commands&shell=bash` → a `.bash_history`
    - `tab=endpoint&category=persistence&source=cron` → a cron file / tool CSV

    Send an ``Idempotency-Key`` header to make retries safe.
    """
    replay = _idempotent_replay(db, idempotency_key)
    if replay is not None:
        return replay
    row = _get_or_404(db, incident_id)
    data = await file.read()
    doc = dict(row.doc or {})
    params = {"browser": browser, "shell": shell, "category": category, "source": source}
    try:
        summary = apply_upload(doc, tab, params, data, file.filename or "upload")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    doc["updatedAt"] = now_iso()
    row.doc = doc
    flag_modified(row, "doc")
    _sync_columns(row)
    _audit(
        db,
        caller,
        _UPLOAD_ACTIONS.get(tab, "upload"),
        f"Uploaded {file.filename} → {summary['target']} ({summary['rows']} rows)",
        row,
        always=True,
    )
    db.commit()
    _idempotent_save(db, idempotency_key, 200, summary)
    return summary


# ---------------------------------------------------------------------------
# Notes (dedicated API endpoints; the frontend uses PATCH doc.notes directly)
# ---------------------------------------------------------------------------
def _notes(doc: dict) -> list:
    notes = doc.get("notes")
    return notes if isinstance(notes, list) else []


def _save_doc(db: OrmSession, row: Incident, doc: dict) -> None:
    doc["updatedAt"] = now_iso()
    row.doc = doc
    flag_modified(row, "doc")
    _sync_columns(row)


@router.post("/{incident_id}/notes", tags=["incidents/notes"], status_code=status.HTTP_201_CREATED)
def add_note(
    incident_id: str,
    body: NoteIn,
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
    idempotency_key: str | None = Header(None, alias="Idempotency-Key"),
) -> dict:
    """Append a free-form note to the incident timeline.

    Send an ``Idempotency-Key`` header to make retries safe (a repeated request
    returns the first result instead of adding a second note).
    """
    replay = _idempotent_replay(db, idempotency_key)
    if replay is not None:
        return replay
    text = body.text.strip()
    if not text:
        raise HTTPException(status_code=400, detail="Note text is required")
    row = _get_or_404(db, incident_id)
    doc = dict(row.doc or {})
    now = now_iso()
    note = {"id": str(uuid.uuid4()), "text": text, "createdAt": now, "updatedAt": now, "author": caller.actor}
    doc["notes"] = [*_notes(doc), note]
    _save_doc(db, row, doc)
    _audit(db, caller, "note.add", "Added a note", row, always=True)
    db.commit()
    _idempotent_save(db, idempotency_key, 201, note)
    return note


@router.patch("/{incident_id}/notes/{note_id}", tags=["incidents/notes"])
def edit_note(
    incident_id: str,
    note_id: str,
    body: NoteIn,
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Edit the text of an existing note."""
    text = body.text.strip()
    if not text:
        raise HTTPException(status_code=400, detail="Note text is required")
    row = _get_or_404(db, incident_id)
    doc = dict(row.doc or {})
    notes = _notes(doc)
    target = next((n for n in notes if n.get("id") == note_id), None)
    if target is None:
        raise HTTPException(status_code=404, detail="Note not found")
    doc["notes"] = [
        {**n, "text": text, "updatedAt": now_iso()} if n.get("id") == note_id else n
        for n in notes
    ]
    _save_doc(db, row, doc)
    _audit(db, caller, "note.update", "Edited a note", row, always=True)
    db.commit()
    return next(n for n in doc["notes"] if n.get("id") == note_id)


@router.delete("/{incident_id}/notes/{note_id}", tags=["incidents/notes"], status_code=status.HTTP_204_NO_CONTENT)
def delete_note(
    incident_id: str,
    note_id: str,
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
):
    """Remove a note from the incident."""
    row = _get_or_404(db, incident_id)
    doc = dict(row.doc or {})
    notes = _notes(doc)
    if not any(n.get("id") == note_id for n in notes):
        raise HTTPException(status_code=404, detail="Note not found")
    doc["notes"] = [n for n in notes if n.get("id") != note_id]
    _save_doc(db, row, doc)
    _audit(db, caller, "note.remove", "Removed a note", row, always=True)
    db.commit()
    # 204 No Content

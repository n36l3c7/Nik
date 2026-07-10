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

import uuid
from typing import Any

from fastapi import APIRouter, Body, Depends, File, HTTPException, Query, UploadFile, status
from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm.attributes import flag_modified

from ..db import get_db
from ..models import AuditEntry, Incident
from ..parsing.registry import apply_upload
from ..schemas import NoteIn
from ..security import Principal, now_iso, principal

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


@router.get("")
def list_incidents(
    _caller: Principal = Depends(principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Return all incidents as full documents, newest-updated first."""
    rows = db.scalars(select(Incident).order_by(Incident.updated_at.desc())).all()
    return {"incidents": [row.doc for row in rows]}


@router.get("/{incident_id}")
def get_incident(
    incident_id: str,
    _caller: Principal = Depends(principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Return a single incident's full document; 404 if missing."""
    return _get_or_404(db, incident_id).doc


@router.post("", status_code=status.HTTP_201_CREATED)
def create_incident(
    doc: dict[str, Any] = Body(...),
    caller: Principal = Depends(principal),
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
    partial: dict[str, Any] = Body(...),
    caller: Principal = Depends(principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Shallow-merge changed top-level keys into the stored document.

    Any incident field can be edited this way: ``host``, ``username``, ``os``,
    ``suspiciousStart``/``suspiciousEnd``, ``notes``, ``flags``, ``data``, …
    """
    row = _get_or_404(db, incident_id)
    merged = dict(row.doc or {})
    for key, value in partial.items():
        merged[key] = value
    row.doc = merged
    flag_modified(row, "doc")
    _sync_columns(row)
    _audit(db, caller, "incident.update", f'Updated attributes of "{merged.get("name") or incident_id}"', row)
    db.commit()
    return row.doc


@router.delete("/{incident_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_incident(
    incident_id: str,
    caller: Principal = Depends(principal),
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
    caller: Principal = Depends(principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Upload a raw artifact file; the server parses it and merges the result.

    Routing (query params) mirrors the app's tabs:
    - `tab=browser&browser=chrome&source=history` → a Chromium `History` DB
    - `tab=commands&shell=bash` → a `.bash_history`
    - `tab=endpoint&category=persistence&source=cron` → a cron file / tool CSV
    """
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
    caller: Principal = Depends(principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Append a free-form note to the incident timeline."""
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
    return note


@router.patch("/{incident_id}/notes/{note_id}", tags=["incidents/notes"])
def edit_note(
    incident_id: str,
    note_id: str,
    body: NoteIn,
    caller: Principal = Depends(principal),
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
    caller: Principal = Depends(principal),
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

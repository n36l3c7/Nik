"""Incident document-store routes.

The backend stores the full frontend incident object in ``doc`` and mirrors a
few scalar fields into columns for listing/sorting. ``POST`` upserts a full
document; ``PATCH`` shallow-merges only the changed top-level keys.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm.attributes import flag_modified

from ..db import get_db
from ..models import Incident, User
from ..security import current_user

router = APIRouter(prefix="/incidents", tags=["incidents"])


def _sync_columns(incident: Incident) -> None:
    """Refresh the mirrored scalar columns from the incident ``doc``."""
    doc = incident.doc or {}
    incident.name = str(doc.get("name") or "")
    incident.host = str(doc.get("host") or "")
    incident.username = str(doc.get("username") or "")
    incident.updated_at = str(doc.get("updatedAt") or "")
    incident.created_at = str(doc.get("createdAt") or "")


@router.get("")
def list_incidents(
    _user: User = Depends(current_user), db: OrmSession = Depends(get_db)
) -> dict:
    """Return all incidents as full documents, newest-updated first."""
    rows = db.scalars(select(Incident).order_by(Incident.updated_at.desc())).all()
    return {"incidents": [row.doc for row in rows]}


@router.get("/{incident_id}")
def get_incident(
    incident_id: str,
    _user: User = Depends(current_user),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Return a single incident's full document; 404 if missing."""
    row = db.get(Incident, incident_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return row.doc


@router.post("", status_code=status.HTTP_201_CREATED)
def create_incident(
    doc: dict[str, Any] = Body(...),
    user: User = Depends(current_user),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Create (or upsert) an incident from a full client-built document.

    The server stamps ``createdBy`` from the session username, ignoring any
    client-supplied value.
    """
    incident_id = doc.get("id")
    if not incident_id:
        raise HTTPException(status_code=400, detail="Incident id is required")

    # Server-authoritative createdBy.
    doc = dict(doc)
    doc["createdBy"] = user.username

    existing = db.get(Incident, incident_id)
    if existing is None:
        incident = Incident(id=str(incident_id), doc=doc)
        _sync_columns(incident)
        db.add(incident)
    else:
        # Upsert semantics: replace the stored document wholesale.
        existing.doc = doc
        _sync_columns(existing)
        incident = existing

    db.commit()
    return incident.doc


@router.patch("/{incident_id}")
def patch_incident(
    incident_id: str,
    partial: dict[str, Any] = Body(...),
    _user: User = Depends(current_user),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Shallow-merge changed top-level keys into the stored document."""
    row = db.get(Incident, incident_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    # Shallow-merge: replace each provided top-level key.
    merged = dict(row.doc or {})
    for key, value in partial.items():
        merged[key] = value
    row.doc = merged
    # SQLAlchemy needs an explicit dirty flag when reassigning JSON contents.
    flag_modified(row, "doc")
    _sync_columns(row)

    db.commit()
    return row.doc


@router.delete("/{incident_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_incident(
    incident_id: str,
    _user: User = Depends(current_user),
    db: OrmSession = Depends(get_db),
):
    """Delete an incident (idempotent-ish; 204 regardless if it existed)."""
    row = db.get(Incident, incident_id)
    if row is not None:
        db.delete(row)
        db.commit()
    # 204 No Content

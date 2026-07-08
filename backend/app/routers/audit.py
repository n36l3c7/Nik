"""Audit-log routes.

Entries are append-only from the client's perspective. The server stamps the
id, timestamp, and actor (from the session), ignoring any client-supplied actor.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, status
from sqlalchemy import delete as sa_delete
from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from ..db import get_db
from ..models import AuditEntry, User
from ..schemas import AuditEnvelope, AuditIn, AuditOut
from ..security import current_user, now_iso, require_admin

router = APIRouter(prefix="/audit", tags=["audit"])

# Maximum number of entries returned by the list endpoint.
MAX_ENTRIES = 5000


def _entry_to_dict(entry: AuditEntry) -> dict:
    """Convert an AuditEntry ORM object into the API representation."""
    return {
        "id": entry.id,
        "at": entry.at,
        "actor": entry.actor,
        "action": entry.action,
        "target": entry.target,
        "details": entry.details,
        "incidentId": entry.incident_id,
        "incidentName": entry.incident_name,
    }


@router.get("", response_model=AuditEnvelope)
def list_audit(
    _user: User = Depends(current_user), db: OrmSession = Depends(get_db)
) -> dict:
    """Return audit entries newest-first, capped at ``MAX_ENTRIES``."""
    rows = db.scalars(
        select(AuditEntry).order_by(AuditEntry.at.desc()).limit(MAX_ENTRIES)
    ).all()
    return {"entries": [_entry_to_dict(r) for r in rows]}


@router.post("", response_model=AuditOut, status_code=status.HTTP_201_CREATED)
def create_audit(
    body: AuditIn,
    user: User = Depends(current_user),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Create an audit entry with server-stamped id/at/actor."""
    entry = AuditEntry(
        id=str(uuid.uuid4()),
        at=now_iso(),
        actor=user.username,  # server-authoritative
        action=body.action,
        target=body.target,
        details=body.details or "",
        incident_id=body.incidentId,
        incident_name=body.incidentName,
    )
    db.add(entry)
    db.commit()
    return _entry_to_dict(entry)


@router.delete("", status_code=status.HTTP_204_NO_CONTENT)
def clear_audit(
    _admin: User = Depends(require_admin), db: OrmSession = Depends(get_db)
):
    """Clear the entire audit log (admin only)."""
    db.execute(sa_delete(AuditEntry))
    db.commit()
    # 204 No Content

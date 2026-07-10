"""Audit-log routes.

Entries are append-only from the client's perspective. The server stamps the
id, timestamp, and actor (from the session), ignoring any client-supplied actor.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Response, status
from sqlalchemy import delete as sa_delete
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session as OrmSession

from ..db import get_db
from ..models import AuditEntry, User
from ..schemas import AuditEnvelope, AuditIn, AuditOut
from ..security import Principal, admin_principal, current_user, now_iso, principal

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
    response: Response,
    _caller: Principal = Depends(principal),
    db: OrmSession = Depends(get_db),
    limit: int | None = Query(None, ge=1, le=MAX_ENTRIES, description="Page size (default: up to MAX_ENTRIES)."),
    offset: int = Query(0, ge=0),
    q: str | None = Query(None, description="Match actor/action/details/incident."),
    actor: str | None = Query(None),
    incident_id: str | None = Query(None, alias="incidentId"),
) -> dict:
    """Return audit entries newest-first, filterable and paginated.

    Backward compatible: with no params it returns up to ``MAX_ENTRIES`` entries.
    The total matching count is in the ``X-Total-Count`` header.
    """
    conditions = []
    if q:
        like = f"%{q}%"
        conditions.append(
            or_(
                AuditEntry.actor.ilike(like),
                AuditEntry.action.ilike(like),
                AuditEntry.details.ilike(like),
                AuditEntry.incident_name.ilike(like),
            )
        )
    if actor:
        conditions.append(AuditEntry.actor.ilike(f"%{actor}%"))
    if incident_id:
        conditions.append(AuditEntry.incident_id == incident_id)

    total = db.scalar(select(func.count()).select_from(AuditEntry).where(*conditions)) or 0
    response.headers["X-Total-Count"] = str(total)

    stmt = select(AuditEntry).where(*conditions).order_by(AuditEntry.at.desc())
    stmt = stmt.offset(offset).limit(limit if limit is not None else MAX_ENTRIES)
    rows = db.scalars(stmt).all()
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
    _admin: Principal = Depends(admin_principal), db: OrmSession = Depends(get_db)
):
    """Clear the entire audit log (admin session or admin key)."""
    db.execute(sa_delete(AuditEntry))
    db.commit()
    # 204 No Content

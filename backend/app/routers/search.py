"""Global search (the app's Ctrl/Cmd+K palette).

One query across what every analyst can see: incidents (name, host, user),
indicators of compromise from every incident (the ``ioc_index`` table) and
malware samples (by hash prefix or file type). The open incident's own
events and notes are searched in the browser, which already holds them.

On PostgreSQL the ``ILIKE '%…%'`` filters use the trigram (``pg_trgm``) GIN
indexes of migration 0012; on SQLite they scan, which is fine at that size.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import false, func, or_, select
from sqlalchemy.orm import Session as OrmSession

from ..core.db import get_db
from ..core.models import Incident, IocEntry, Sample
from ..core.security import Principal, reader_principal

router = APIRouter(prefix="/search", tags=["search"])


def _like(text: str) -> str:
    """A ``%…%`` pattern with the LIKE wildcards of ``text`` escaped."""
    escaped = text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


@router.get("")
def search(
    q: str = Query(..., min_length=2, max_length=200),
    limit: int = Query(8, ge=1, le=50),
    _caller: Principal = Depends(reader_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Incidents, indicators and samples matching ``q`` (case-insensitive substring)."""
    text = q.strip()
    pattern = _like(text)

    # "#42" or "42" is also the incident with that number.
    digits = text[1:] if text.startswith("#") else text
    numbered = digits.isdigit() and len(digits) <= 9
    by_number = Incident.number == int(digits) if numbered else false()
    # The incident with the number first, then the latest changed.
    order = (by_number.desc(), Incident.updated_at.desc()) if numbered else (Incident.updated_at.desc(),)
    incidents = db.execute(
        select(
            Incident.id,
            Incident.name,
            Incident.host,
            Incident.username,
            Incident.os,
            Incident.updated_at,
            Incident.number,
        )
        .where(
            or_(
                by_number,
                Incident.ticket_id.ilike(pattern, escape="\\"),
                Incident.name.ilike(pattern, escape="\\"),
                Incident.host.ilike(pattern, escape="\\"),
                Incident.username.ilike(pattern, escape="\\"),
            )
        )
        .order_by(*order)
        .limit(limit)
    ).all()

    iocs = []
    if len(text) >= 3:
        iocs = db.execute(
            select(IocEntry.type, IocEntry.value, func.count(IocEntry.incident_id))
            .where(IocEntry.value.ilike(pattern, escape="\\"))
            .group_by(IocEntry.type, IocEntry.value)
            .order_by(func.count(IocEntry.incident_id).desc(), IocEntry.value)
            .limit(limit)
        ).all()

    samples = []
    digest = text.lower()
    if len(digest) >= 6 and all(c in "0123456789abcdef" for c in digest):
        hash_match = or_(
            Sample.sha256.startswith(digest), Sample.sha1.startswith(digest), Sample.md5.startswith(digest)
        )
    else:
        hash_match = Sample.type_label.ilike(pattern, escape="\\")
    samples = db.execute(
        select(Sample.sha256, Sample.type_label, Sample.size, Sample.created_at)
        .where(hash_match)
        .order_by(Sample.created_at.desc())
        .limit(limit)
    ).all()

    return {
        "query": text,
        "incidents": [
            {
                "id": i,
                "number": number,
                "name": name,
                "host": host,
                "username": user,
                "os": os,
                "updatedAt": updated,
            }
            for i, name, host, user, os, updated, number in incidents
        ],
        "iocs": [{"type": kind, "value": value, "incidents": n} for kind, value, n in iocs],
        "samples": [
            {"sha256": sha, "type": label, "size": size, "createdAt": created} for sha, label, size, created in samples
        ],
    }

"""Global search (the app's Ctrl/Cmd+K palette).

One query across what every analyst can see: incidents (name, host, user),
indicators of compromise from every incident (the ``ioc_index`` table),
malware samples (by hash prefix or file type) and the records of host
evidence of the incidents that are not archived (the ``evidence`` group:
the words in the one-line summary of a record, the newest 20). The open
incident's own events and notes are searched in the browser, which already
holds them.

On PostgreSQL the ``ILIKE '%…%'`` filters use the trigram (``pg_trgm``) GIN
indexes of migrations 0012 and 0056 (0059 tries the second again); on SQLite
they scan, which is fine at that size. A database may hold ten million
records, so the search of evidence is bounded: PostgreSQL stops the query
after ``EVIDENCE_SECONDS``; SQLite looks at the newest ``EVIDENCE_ROWS``
records only. Either way the answer says ``evidenceCut`` and what was found
is given.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import false, func, or_, select
from sqlalchemy import text as sql_text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session as OrmSession

from ..core.db import get_db
from ..core.models import EvidenceRecord, EvidenceSource, Incident, IocEntry, Sample
from ..core.security import Principal, reader_principal

router = APIRouter(prefix="/search", tags=["search"])

EVIDENCE_SHOWN = 20
EVIDENCE_SECONDS = 3
EVIDENCE_ROWS = 500_000
EVIDENCE_MIN = 3  # a trigram index needs three characters


def _like(text: str) -> str:
    """A ``%…%`` pattern with the LIKE wildcards of ``text`` escaped."""
    escaped = text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def _evidence(db: OrmSession, pattern: str) -> tuple[list[dict[str, Any]], bool]:
    """The records of host evidence whose summary holds the words, newest first (at most ``EVIDENCE_SHOWN``),
    of the incidents that are not archived; and whether the search was cut short. Bounded in time."""
    record = EvidenceRecord
    query = (
        select(
            record.id,
            record.incident_id,
            Incident.name,
            Incident.number,
            record.kind,
            record.source_id,
            EvidenceSource.file_name,
            record.ts,
            record.summary,
        )
        .join(Incident, Incident.id == record.incident_id)
        .join(EvidenceSource, EvidenceSource.id == record.source_id)
        .where(Incident.archived_at.is_(None), record.summary.ilike(pattern, escape="\\"))
        .order_by(record.ts.is_(None), record.ts.desc(), record.id.desc())
        .limit(EVIDENCE_SHOWN)
    )
    cut = False
    postgres = db.get_bind().dialect.name == "postgresql"
    if postgres:
        db.execute(sql_text(f"SET LOCAL statement_timeout = {EVIDENCE_SECONDS * 1000}"))
    else:
        newest = db.scalar(select(func.max(record.id))) or 0
        if newest > EVIDENCE_ROWS:
            query = query.where(record.id > newest - EVIDENCE_ROWS)
            cut = True
    try:
        rows = db.execute(query).all()
    except DBAPIError:  # the query was cancelled at its limit of time
        db.rollback()
        if not postgres:
            return [], True
        # A word that most records hold, in a database too large for the time given: the newest records only.
        try:
            db.execute(sql_text(f"SET LOCAL statement_timeout = {EVIDENCE_SECONDS * 1000}"))
            newest = db.scalar(select(func.max(record.id))) or 0
            rows = db.execute(query.where(record.id > newest - EVIDENCE_ROWS)).all()
        except DBAPIError:
            db.rollback()
            return [], True
        cut = True
    return (
        [
            {
                "recordId": record_id,
                "incidentId": incident_id,
                "incidentName": name,
                "incidentNumber": number,
                "section": kind,
                "sourceId": source_id,
                "source": file_name,
                "ts": ts,
                "summary": summary,
            }
            for record_id, incident_id, name, number, kind, source_id, file_name, ts, summary in rows
        ],
        cut,
    )


@router.get("")
def search(
    q: str = Query(..., min_length=2, max_length=200),
    limit: int = Query(8, ge=1, le=50),
    _caller: Principal = Depends(reader_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Incidents, indicators, samples and records of host evidence matching ``q`` (case-insensitive substring).
    ``evidence`` holds at most 20 records, newest first, each with its incident, section, file, time and summary
    (from three characters of ``q``; archived incidents hold none); ``evidenceCut`` is true when the search was
    stopped at its limit of time or of records."""
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
            Incident.archived_at,
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

    found, cut = _evidence(db, pattern) if len(text) >= EVIDENCE_MIN else ([], False)

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
                # The archived incidents are found here, and marked.
                "archived": bool(archived_at),
            }
            for i, name, host, user, os, updated, number, archived_at in incidents
        ],
        "iocs": [{"type": kind, "value": value, "incidents": n} for kind, value, n in iocs],
        "samples": [
            {"sha256": sha, "type": label, "size": size, "createdAt": created} for sha, label, size, created in samples
        ],
        "evidence": found,
        "evidenceCut": cut,
    }

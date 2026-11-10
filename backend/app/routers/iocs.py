"""Indicators of compromise: per incident, across incidents, and export.

The index (``ioc_index``) is rebuilt from the incident document whenever its
data changes (see ``iocs.py``); these routes only read it. The allowlist from
Settings marks well-known values (``allowlisted``); exports leave them out.
"""

from __future__ import annotations

import csv
import io
import json
import re
import uuid
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session as OrmSession

from ..db import get_db
from ..iocs import TYPES, Allowlist, incident_iocs, misp_event, normalize, stix_bundle
from ..models import AuditEntry, Incident, IocEntry
from ..security import Principal, now_iso, principal
from .settings import read_settings

router = APIRouter(tags=["iocs"])


def _allowlist(db: OrmSession) -> Allowlist:
    return Allowlist(read_settings(db).get("iocAllowlist") or [])


def _incident_or_404(db: OrmSession, incident_id: str) -> Incident:
    row = db.get(Incident, incident_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return row


@router.get("/incidents/{incident_id}/iocs")
def listincident_iocs(
    incident_id: str,
    _caller: Principal = Depends(principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Every indicator of the incident: where it was seen, how often, when, and
    in how many other incidents. ``allowlisted`` marks well-known values."""
    _incident_or_404(db, incident_id)
    iocs = incident_iocs(db, incident_id, _allowlist(db))
    iocs.sort(key=lambda i: (-i["otherIncidents"], i["type"], i["value"]))
    return {"iocs": iocs, "total": len(iocs)}


@router.get("/iocs/lookup")
def lookup_ioc(
    type: Literal["ip", "domain", "url", "email", "md5", "sha1", "sha256"] = Query(...),
    value: str = Query(..., min_length=1, max_length=1024),
    _caller: Principal = Depends(principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Every incident an indicator was seen in (any analyst's)."""
    lookup = normalize(type, value)
    if lookup is None:
        raise HTTPException(status_code=400, detail=f"Not a valid {type}.")
    rows = db.execute(
        select(IocEntry, Incident.name, Incident.host, Incident.updated_at)
        .join(Incident, Incident.id == IocEntry.incident_id)
        .where(IocEntry.type == type, IocEntry.value == lookup)
        .order_by(Incident.updated_at.desc())
    ).all()
    return {
        "type": type,
        "value": lookup,
        "allowlisted": _allowlist(db).matches(type, lookup),
        "incidents": [
            {
                "id": entry.incident_id,
                "name": name,
                "host": host,
                "updatedAt": updated_at,
                "sources": entry.sources,
                "count": entry.count,
                "firstSeen": entry.first_seen,
                "lastSeen": entry.last_seen,
            }
            for entry, name, host, updated_at in rows
        ],
    }


@router.get("/iocs/shared")
def shared_iocs(
    limit: int = Query(100, ge=1, le=1000),
    _caller: Principal = Depends(principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Indicators seen in two or more incidents, most widespread first."""
    allowlist = _allowlist(db)
    rows = db.execute(
        select(IocEntry.type, IocEntry.value, func.count(IocEntry.incident_id).label("n"))
        .group_by(IocEntry.type, IocEntry.value)
        .having(func.count(IocEntry.incident_id) > 1)
        .order_by(func.count(IocEntry.incident_id).desc(), IocEntry.type, IocEntry.value)
    ).all()
    shared = [
        {"type": kind, "value": value, "incidents": n} for kind, value, n in rows if not allowlist.matches(kind, value)
    ]
    return {"iocs": shared[:limit], "total": len(shared)}


_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


@router.get("/incidents/{incident_id}/iocs/export")
def exportincident_iocs(
    incident_id: str,
    format: Literal["csv", "stix", "misp"] = Query("csv"),
    types: str | None = Query(None, description="Comma-separated types to keep, e.g. ip,domain,sha256"),
    include_allowlisted: bool = Query(False, alias="allowlisted"),
    caller: Principal = Depends(principal),
    db: OrmSession = Depends(get_db),
) -> Response:
    """Download the incident's indicators as CSV, a STIX 2.1 bundle or a MISP
    event. Allowlisted values are left out unless ``allowlisted=true``."""
    row = _incident_or_404(db, incident_id)
    wanted = {t.strip() for t in (types or "").split(",") if t.strip() in TYPES} or set(TYPES)
    iocs = [
        ioc
        for ioc in incident_iocs(db, incident_id, _allowlist(db))
        if ioc["type"] in wanted and (include_allowlisted or not ioc["allowlisted"])
    ]
    iocs.sort(key=lambda i: (i["type"], i["value"]))
    incident = row.doc or {}
    now = now_iso()
    base = _SAFE_NAME.sub("_", str(incident.get("name") or incident_id)).strip("_") or "incident"

    if format == "csv":
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(["type", "value", "sources", "count", "first_seen", "last_seen", "other_incidents"])
        for ioc in iocs:
            writer.writerow(
                [
                    ioc["type"],
                    ioc["value"],
                    ";".join(ioc["sources"]),
                    ioc["count"],
                    ioc["firstSeen"] or "",
                    ioc["lastSeen"] or "",
                    ioc["otherIncidents"],
                ]
            )
        body, media, ext = buffer.getvalue(), "text/csv", "csv"
    elif format == "stix":
        body, media, ext = json.dumps(stix_bundle(incident, iocs, now), indent=2), "application/json", "stix.json"
    else:
        body, media, ext = json.dumps(misp_event(incident, iocs, now), indent=2), "application/json", "misp.json"

    db.add(
        AuditEntry(
            id=str(uuid.uuid4()),
            at=now,
            actor=caller.actor,
            action="ioc.export",
            target=incident.get("name"),
            details=f"Exported {len(iocs)} indicators as {format.upper()}",
            incident_id=incident_id,
            incident_name=incident.get("name"),
        )
    )
    db.commit()
    return Response(
        content=body,
        media_type=media,
        headers={"Content-Disposition": f'attachment; filename="{base}-iocs.{ext}"'},
    )

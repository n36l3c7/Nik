"""URL analysis: scan an address with the isolated browser, read the result.

``POST /api/artifacts/urls`` starts (or finds) the scan of an address, on its
own or in an incident; the scan itself runs in the background
(``urlscan.run_scan``). Linking, tagging and deleting go through
``/api/artifacts/url-<id>`` like every other artifact.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm.attributes import flag_modified

from .. import artifacts, urlscan
from ..core.db import get_db
from ..core.models import AuditEntry, Incident, UrlScan
from ..core.security import Principal, now_iso, principal, writer_principal

router = APIRouter(tags=["artifacts"])
STALE_AFTER = timedelta(minutes=5)


def _audit(db: OrmSession, caller: Principal, action: str, details: str, incident: Incident | None = None) -> None:
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


def _scan_or_404(db: OrmSession, scan: str) -> UrlScan:
    row = db.get(UrlScan, scan) if urlscan.is_scan_id(scan) else None
    if row is None:
        raise HTTPException(status_code=404, detail="URL scan not found")
    return row


def _stale(row: UrlScan) -> bool:
    """A scan left queued or running by a restart."""
    if row.status not in ("queued", "running"):
        return False
    started = (row.result or {}).get("startedAt") or row.created_at
    try:
        when = datetime.fromisoformat(str(started).replace("Z", "+00:00"))
    except ValueError:
        return True
    return datetime.now(timezone.utc) - when > STALE_AFTER


def _detail(db: OrmSession, row: UrlScan) -> dict[str, Any]:
    stale = _stale(row)
    return {
        **urlscan.reference(row),
        "status": "error" if stale else row.status,
        "error": "The scan was interrupted; run it again." if stale else row.error,
        "captureId": row.capture_id,
        "result": row.result or {},
        "incidents": [
            {"id": incident.id, "name": incident.name} for incident in urlscan.incidents_referencing(db, row.id)
        ],
    }


def _queue(db: OrmSession, row: UrlScan, actor: str, background_tasks: BackgroundTasks) -> None:
    row.status, row.error = "queued", None
    row.verdict, row.score = "", 0
    row.result = {"startedAt": now_iso()}
    flag_modified(row, "result")
    artifacts.register_url(db, row)
    db.commit()
    background_tasks.add_task(urlscan.run_scan, row.id, actor)


class UrlIn(BaseModel):
    url: str = Field(min_length=4, max_length=urlscan.URL_MAX)
    incident: Optional[str] = Field(default=None, max_length=64)


@router.post("/artifacts/urls", status_code=status.HTTP_201_CREATED)
def analyse_url(
    body: UrlIn,
    background_tasks: BackgroundTasks,
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Scan an address with the isolated browser, on its own or in an incident.

    The browser visits it with network access (never private addresses),
    types and submits nothing, and Nik keeps a screenshot, the redirect
    chain, the page's forms and the network log, weighed into a verdict. An
    address already scanned is returned as it is: use ``…/rescan`` to visit
    it again. Defanged text (``hxxp``, ``[.]``) is accepted.
    """
    incident = None
    if body.incident:
        incident = db.get(Incident, body.incident)
        if incident is None:
            raise HTTPException(status_code=404, detail="Incident not found")
    try:
        url = urlscan.normalise(body.url)
    except urlscan.UrlError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    known = db.get(UrlScan, urlscan.scan_id(url)) is not None
    row = urlscan.register(db, url, caller.actor)
    if incident is not None:
        urlscan.attach(db, incident, row, caller.actor)
    _audit(db, caller, "url.scan", f"Scan of {urlscan.display(url)}" + (" (already known)" if known else ""), incident)
    if not known or _stale(row) or row.status == "error":
        _queue(db, row, caller.actor, background_tasks)
    else:
        db.commit()
    return {"artifactId": artifacts.artifact_id("url", row.id), "known": known, **_detail(db, row)}


@router.get("/urls/{scan_id}")
def get_scan(scan_id: str, _caller: Principal = Depends(principal), db: OrmSession = Depends(get_db)) -> dict:
    """The scan's state and result: final address, redirect chain, forms, findings, verdict."""
    return _detail(db, _scan_or_404(db, scan_id))


@router.post("/urls/{scan_id}/rescan", status_code=status.HTTP_202_ACCEPTED)
def rescan(
    scan_id: str,
    background_tasks: BackgroundTasks,
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Visit the address again; the new result replaces the previous one."""
    row = _scan_or_404(db, scan_id)
    if row.status in ("queued", "running") and not _stale(row):
        raise HTTPException(status_code=409, detail="A scan of this address is already running.")
    _audit(db, caller, "url.scan", f"Scan of {urlscan.display(row.url)} (again)")
    _queue(db, row, caller.actor, background_tasks)
    return _detail(db, row)


@router.get("/urls/{scan_id}/screenshot")
def screenshot(scan_id: str, _caller: Principal = Depends(principal), db: OrmSession = Depends(get_db)):
    """The screenshot of the last visit (JPEG)."""
    row = _scan_or_404(db, scan_id)
    path = urlscan.screenshot_path(row.id)
    if not path.is_file():
        raise HTTPException(status_code=404, detail="No screenshot for this scan")
    return FileResponse(path, media_type="image/jpeg", headers={"Cache-Control": "no-store"})

"""Previews of mail attachments: document pages and the isolated browser.

Nothing here renders anything: the document viewer worker turns documents
into page images, the isolated browser worker runs pages and sends back
screenshots (``previews.py``). Opening a browser session is audited, with
whether it had network access; a session opened from an incident keeps its
network log there (``network/service.py``).
"""

from __future__ import annotations

import re
from typing import Literal, Optional
from urllib.parse import quote, urlsplit

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import Response
from pydantic import BaseModel, Field, model_validator
from sqlalchemy.orm import Session as OrmSession

from ..core.db import get_db
from ..core.models import Incident, NetworkCapture
from ..core.security import Principal, now_iso, principal, writer_principal
from ..enrichment.service import internal_host
from ..network import service as network_service
from ..network import store as network_store
from ..parsing.malware import detect_type, hashes
from ..workers import previews
from .mails import _attachment, _audit, _mail_or_404, _parsed

router = APIRouter(tags=["previews"])
_SESSION_ID = re.compile(r"^[0-9a-f]{32}$")


def _worker_error(exc: previews.WorkerError) -> HTTPException:
    return HTTPException(status_code=exc.status, detail=str(exc))


@router.get("/previews/status")
def status(_caller: Principal = Depends(principal)) -> dict:
    """Which preview workers are configured."""
    return {"documents": previews.docview_configured(), "browser": previews.browser_configured()}


@router.post("/mails/{sha256}/attachments/{path}/preview")
async def preview_attachment(
    sha256: str, path: str, caller: Principal = Depends(principal), db: OrmSession = Depends(get_db)
) -> dict:
    """The attachment's first pages as PNG (PDF, Office, OpenDocument, RTF,
    images), rendered by the document viewer worker and kept for next time."""
    if not previews.docview_configured():
        raise HTTPException(status_code=503, detail="The document viewer is not configured (DOCVIEW_URL).")
    _mail_or_404(db, sha256)
    item = _attachment(_parsed(sha256), path)
    data = item.get("data") or b""
    name = item.get("name") or "attachment"
    if previews.kind(name, detect_type(data)["id"]) != "document":
        raise HTTPException(status_code=422, detail="Not a document Nik can preview.")
    try:
        result = await run_in_threadpool(previews.render_document, name, data, hashes(data)["sha256"])
    except previews.WorkerError as exc:
        raise _worker_error(exc) from exc
    return {"name": name, **result}


class SessionIn(BaseModel):
    """Open an HTML attachment (``mail`` + ``path``) or a link (``url``)."""

    mail: Optional[str] = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    path: Optional[str] = Field(default=None, max_length=32, pattern=r"^\d+(\.\d+)*$")
    url: Optional[str] = Field(default=None, max_length=4096)
    network: bool = False
    # Keep the session's network log in this incident (Network Analysis).
    incident: Optional[str] = Field(default=None, max_length=200)

    @model_validator(mode="after")
    def _one_source(self):
        if (self.url is None) == (self.mail is None or self.path is None):
            raise ValueError("Send either mail and path, or url")
        return self


def _check_url(url: str) -> str:
    parts = urlsplit(url.strip())
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise HTTPException(status_code=422, detail="Only http and https addresses can be opened.")
    reason = internal_host(parts.hostname)
    if reason:
        raise HTTPException(status_code=422, detail=f"Not opened: {reason}.")
    return url.strip()


def _capture(db: OrmSession, session_id: str) -> NetworkCapture | None:
    row = db.get(NetworkCapture, session_id)
    return row if row is not None and row.kind == "browser" else None


@router.post("/browser/sessions", status_code=201)
async def open_session(
    body: SessionIn,
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Open a page in the isolated browser. Without ``network`` only the
    attachment itself loads; with it the page reaches the internet (never
    private addresses) and submissions are held until released. With
    ``incident`` the session's network log is kept in that incident (Network
    Analysis) and rebuilt as a capture when the session ends. Audited."""
    if not previews.browser_configured():
        raise HTTPException(status_code=503, detail="The isolated browser is not configured (BROWSER_URL).")
    incident = db.get(Incident, body.incident) if body.incident else None
    if body.incident and incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    html, url, target = None, None, ""
    if body.url is not None:
        url = _check_url(body.url)
        target = url[:300]
        source: dict = {"url": url[:2000]}
    else:
        _mail_or_404(db, body.mail)
        item = _attachment(_parsed(body.mail), body.path)
        name = item.get("name") or "attachment"
        if previews.kind(name, detect_type(item.get("data") or b"")["id"]) != "html":
            raise HTTPException(status_code=422, detail="Only HTML attachments open in the browser.")
        html = item.get("data") or b""
        target = f"attachment {name} of e-mail {body.mail[:12]}…"
        source = {"mail": body.mail, "path": body.path, "name": name}
    try:
        state = await run_in_threadpool(previews.open_session, caller.actor, body.network, html, url)
    except previews.WorkerError as exc:
        raise _worker_error(exc) from exc
    _audit(
        db,
        caller,
        "browser.open",
        f"Opened {target} in the isolated browser " + ("WITH network access" if body.network else "without network"),
        incident,
    )
    if incident is not None:
        stamp = now_iso()
        row = NetworkCapture(
            id=state["id"],
            incident_id=incident.id,
            kind="browser",
            file_name=f"isolated-browser-{stamp[:19].replace(':', '').replace('-', '')}.pcapng",
            status="live",
            created_at=stamp,
            created_by=caller.actor,
            meta={"owner": caller.actor, "label": target, "source": source, "network": body.network, "cursor": 0},
            summary={},
        )
        db.add(row)
        await run_in_threadpool(_sync_and_save, db, row)
        state["captureId"] = row.id
    db.commit()
    return state


def _sync_and_save(db: OrmSession, row: NetworkCapture) -> None:
    db.flush()
    try:
        network_service.sync(db, row)
    except previews.WorkerError:
        pass  # the next action copies it
    network_service.save_reference(db, row)
    db.commit()


class ActionIn(BaseModel):
    type: Literal[
        "click",
        "dblclick",
        "move",
        "type",
        "key",
        "scroll",
        "navigate",
        "back",
        "forward",
        "reload",
        "refresh",
        "policy",
    ]
    x: Optional[float] = None
    y: Optional[float] = None
    text: Optional[str] = Field(default=None, max_length=2000)
    key: Optional[str] = Field(default=None, max_length=32)
    dy: Optional[float] = None
    url: Optional[str] = Field(default=None, max_length=4096)
    releasePosts: Optional[bool] = None


@router.post("/browser/sessions/{session_id}/action")
async def session_action(
    session_id: str,
    body: ActionIn,
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Replay a click, typing, a key, a scroll or a navigation, or change the
    session's policy (``releasePosts``: send the page's submissions instead of
    holding them; audited); returns the new screenshot."""
    if not _SESSION_ID.match(session_id):
        raise HTTPException(status_code=404, detail="No such session")
    action = body.model_dump(exclude_none=True)
    if body.type == "navigate":
        action["url"] = _check_url(body.url or "")
    try:
        state = await run_in_threadpool(previews.act, caller.actor, session_id, action)
    except previews.WorkerError as exc:
        raise _worker_error(exc) from exc
    row = _capture(db, session_id)
    if body.type == "policy":
        incident = db.get(Incident, row.incident_id) if row is not None else None
        _audit(
            db,
            caller,
            "browser.policy",
            "Isolated browser: submissions "
            + ("RELEASED (sent to the site)" if body.releasePosts else "held again")
            + f" in session {session_id[:12]}…",
            incident,
        )
        if row is not None:
            row.meta = {**(row.meta or {}), "releasePosts": bool(body.releasePosts)}
        db.commit()
    if row is not None:
        try:
            await run_in_threadpool(network_service.sync, db, row)
        except previews.WorkerError:
            pass
        state["captureId"] = row.id
    return state


@router.get("/browser/sessions/{session_id}/network")
async def session_network(
    session_id: str, caller: Principal = Depends(principal), db: OrmSession = Depends(get_db)
) -> dict:
    """The session's requests without bodies (the live Network panel)."""
    if not _SESSION_ID.match(session_id):
        raise HTTPException(status_code=404, detail="No such session")
    row = _capture(db, session_id)
    if row is None:
        try:
            result = await run_in_threadpool(
                previews._browser, "GET", f"/sessions/{session_id}/network?owner={quote(caller.actor)}"
            )
        except previews.WorkerError as exc:
            raise _worker_error(exc) from exc
        return {"captureId": None, "entries": result.get("entries") or []}
    try:
        await run_in_threadpool(network_service.sync, db, row)
    except previews.WorkerError:
        pass
    return {"captureId": row.id, "entries": [network_store.light(e) for e in network_store.read_log(row.id)]}


@router.delete("/browser/sessions/{session_id}", status_code=204)
async def close_session(
    session_id: str,
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
    background_tasks: BackgroundTasks = None,
) -> Response:
    """Close the session; its network log becomes a capture of the incident."""
    if not _SESSION_ID.match(session_id):
        raise HTTPException(status_code=404, detail="No such session")
    row = _capture(db, session_id)
    if row is not None:
        try:
            await run_in_threadpool(network_service.sync, db, row)
        except previews.WorkerError:
            pass
    try:
        await run_in_threadpool(previews.close_session, caller.actor, session_id)
    except previews.WorkerError as exc:
        if exc.status != 404:
            raise _worker_error(exc) from exc
    if row is not None:
        try:
            await run_in_threadpool(network_service.sync, db, row)
        except previews.WorkerError:
            pass
        await run_in_threadpool(network_service.finalize, db, row, background_tasks)
    return Response(status_code=204)

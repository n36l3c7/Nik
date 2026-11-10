"""Previews of mail attachments: document pages and the isolated browser.

Nothing here renders anything: the document viewer worker turns documents
into page images, the isolated browser worker runs pages and sends back
screenshots (``previews.py``). Opening a browser session is audited, with
whether it had network access.
"""

from __future__ import annotations

import re
from typing import Literal, Optional
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import Response
from pydantic import BaseModel, Field, model_validator
from sqlalchemy.orm import Session as OrmSession

from .. import previews
from ..db import get_db
from ..enrichment.service import internal_host
from ..parsing.malware import detect_type, hashes
from ..security import Principal, principal, writer_principal
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


@router.post("/browser/sessions", status_code=201)
async def open_session(
    body: SessionIn, caller: Principal = Depends(writer_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Open a page in the isolated browser. Without ``network`` only the
    attachment itself loads; with it the page reaches the internet (never
    private addresses). Audited."""
    if not previews.browser_configured():
        raise HTTPException(status_code=503, detail="The isolated browser is not configured (BROWSER_URL).")
    html, url, target = None, None, ""
    if body.url is not None:
        url = _check_url(body.url)
        target = url[:300]
    else:
        _mail_or_404(db, body.mail)
        item = _attachment(_parsed(body.mail), body.path)
        name = item.get("name") or "attachment"
        if previews.kind(name, detect_type(item.get("data") or b"")["id"]) != "html":
            raise HTTPException(status_code=422, detail="Only HTML attachments open in the browser.")
        html = item.get("data") or b""
        target = f"attachment {name} of e-mail {body.mail[:12]}…"
    try:
        state = await run_in_threadpool(previews.open_session, caller.actor, body.network, html, url)
    except previews.WorkerError as exc:
        raise _worker_error(exc) from exc
    _audit(
        db,
        caller,
        "browser.open",
        f"Opened {target} in the isolated browser " + ("WITH network access" if body.network else "without network"),
        None,
    )
    db.commit()
    return state


class ActionIn(BaseModel):
    type: Literal[
        "click", "dblclick", "move", "type", "key", "scroll", "navigate", "back", "forward", "reload", "refresh"
    ]
    x: Optional[float] = None
    y: Optional[float] = None
    text: Optional[str] = Field(default=None, max_length=2000)
    key: Optional[str] = Field(default=None, max_length=32)
    dy: Optional[float] = None
    url: Optional[str] = Field(default=None, max_length=4096)


@router.post("/browser/sessions/{session_id}/action")
async def session_action(session_id: str, body: ActionIn, caller: Principal = Depends(writer_principal)) -> dict:
    """Replay a click, typing, a key, a scroll or a navigation; returns the new screenshot."""
    if not _SESSION_ID.match(session_id):
        raise HTTPException(status_code=404, detail="No such session")
    action = body.model_dump(exclude_none=True)
    if body.type == "navigate":
        action["url"] = _check_url(body.url or "")
    try:
        return await run_in_threadpool(previews.act, caller.actor, session_id, action)
    except previews.WorkerError as exc:
        raise _worker_error(exc) from exc


@router.delete("/browser/sessions/{session_id}", status_code=204)
async def close_session(session_id: str, caller: Principal = Depends(writer_principal)) -> Response:
    if not _SESSION_ID.match(session_id):
        raise HTTPException(status_code=404, detail="No such session")
    try:
        await run_in_threadpool(previews.close_session, caller.actor, session_id)
    except previews.WorkerError as exc:
        if exc.status != 404:
            raise _worker_error(exc) from exc
    return Response(status_code=204)

"""Mail Analysis: phishing triage of ``.eml`` and Outlook ``.msg`` files.

A message is stored once in the sample store (``<sha256>.mail``), analysed
once (``mail/analyze.py``) and referenced by any number of incidents under
``doc.data.mail.messages``. Attachments are never opened by the program they
are meant for: they are read as bytes (hex view), downloaded inside a
password-protected zip, or sent to Malware Analysis as samples.
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, Query, UploadFile, status
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import Response
from sqlalchemy import String, cast, select
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm.attributes import flag_modified

from .. import artifacts
from ..core.config import settings
from ..core.db import get_db
from ..core.models import AuditEntry, Incident, Mail
from ..core.security import Principal, now_iso, principal, writer_principal
from ..events import emit
from ..iocs import Allowlist, reindex_incident
from ..mail.analyze import ANALYSIS_VERSION, analyse_mail
from ..mail.parse import MailError, parse_mail
from ..malware.samples import DEFAULT_ZIP_PASSWORD, delete_mail, is_sha256, read_mail, write_mail, zip_sample
from ..parsing.malware import hashes
from ..workers import previews
from .incidents import _sync_columns
from .samples import store_sample
from .settings import read_settings

router = APIRouter(tags=["mail"])

HEX_CHUNK_MAX = 64 * 1024
SOURCE_MAX = 5 * 1024 * 1024


def _audit(db: OrmSession, caller: Principal, action: str, details: str, incident: Incident | None) -> None:
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


def _incident_or_404(db: OrmSession, incident_id: str) -> Incident:
    row = db.get(Incident, incident_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return row


def _mail_or_404(db: OrmSession, sha256: str) -> Mail:
    row = db.get(Mail, sha256) if is_sha256(sha256) else None
    if row is None:
        raise HTTPException(status_code=404, detail="Message not found")
    return row


def _refs(doc: dict) -> list[dict[str, Any]]:
    mail = doc.setdefault("data", {}).setdefault("mail", {})
    refs = mail.get("messages")
    if not isinstance(refs, list):
        refs = []
        mail["messages"] = refs
    return refs


def _summary(row: Mail) -> dict[str, Any]:
    """What an incident reference carries (the sidebar, the list, the timeline)."""
    return {
        "sha256": row.sha256,
        "format": row.format,
        "size": row.size,
        "subject": row.subject,
        "from": row.sender,
        "date": row.sent_at,
        "verdict": row.verdict,
        "score": row.score,
    }


def _save_doc(db: OrmSession, row: Incident, doc: dict) -> None:
    doc["updatedAt"] = now_iso()
    row.doc = doc
    flag_modified(row, "doc")
    _sync_columns(row)
    db.flush()
    reindex_incident(db, row)


def _incidents_referencing(db: OrmSession, sha256: str) -> list[Incident]:
    candidates = db.scalars(select(Incident).where(cast(Incident.doc, String).like(f"%{sha256}%"))).all()
    return [row for row in candidates if any(ref.get("sha256") == sha256 for ref in _refs(dict(row.doc or {})))]


def _analyse(db: OrmSession, data: bytes) -> dict[str, Any]:
    shared = read_settings(db)
    return analyse_mail(data, shared.get("mail") or {}, Allowlist(shared.get("iocAllowlist") or []))


def _apply(row: Mail, result: dict[str, Any]) -> None:
    who = result["sender"]["from"]
    row.format = result["format"]
    row.size = result["size"]
    row.subject = (result["subject"] or "")[:1000]
    row.sender = (who["address"] or who["name"] or "")[:500]
    row.sent_at = result["date"]
    row.verdict = result["verdict"]
    row.score = result["score"]
    row.analysis = result
    flag_modified(row, "analysis")


def _attachment(parsed: dict[str, Any], path: str) -> dict[str, Any]:
    """The attachment at ``path`` ("2", or "2.0" inside an attached message)."""
    node: dict[str, Any] | None = parsed
    item: dict[str, Any] | None = None
    try:
        for part in path.split("."):
            item = (node or {}).get("attachments", [])[int(part)]
            node = item.get("nested")
    except (ValueError, IndexError):
        item = None
    if item is None:
        raise HTTPException(status_code=404, detail="Attachment not found")
    return item


def _parsed(sha256: str) -> dict[str, Any]:
    try:
        return parse_mail(read_mail(sha256))
    except (OSError, MailError) as exc:
        raise HTTPException(status_code=404, detail="The stored message cannot be read") from exc


def _forget_previews(sha256: str) -> None:
    """Drop the rendered pages of the message's attachments (they show its content)."""
    try:
        parsed = parse_mail(read_mail(sha256))
    except (OSError, MailError):
        return

    def walk(node: dict[str, Any]) -> None:
        for item in node.get("attachments") or []:
            if item.get("data"):
                previews.forget_document(hashes(item["data"])["sha256"])
            if item.get("nested"):
                walk(item["nested"])

    walk(parsed)


async def store_mail(
    db: OrmSession,
    incident: Incident | None,
    data: bytes,
    file_name: str,
    caller: Principal,
    background_tasks: BackgroundTasks | None,
) -> tuple[Mail, dict[str, Any] | None]:
    """Analyse and store an e-mail: in the incident, or on its own when
    ``incident`` is None. Returns the row and the incident's reference."""
    if not data:
        raise HTTPException(status_code=400, detail="The file is empty.")
    if len(data) > settings.SAMPLE_MAX_MB * 1024 * 1024:
        raise HTTPException(status_code=413, detail=f"The file exceeds the {settings.SAMPLE_MAX_MB} MB limit.")
    sha256 = hashes(data)["sha256"]
    row = db.get(Mail, sha256)
    if row is None:
        try:
            # DNS lookups (SPF, DKIM, DMARC) block: keep them off the event loop.
            result = await run_in_threadpool(_analyse, db, data)
        except MailError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        row = Mail(sha256=sha256, created_at=now_iso(), created_by=caller.actor)
        _apply(row, result)
        db.add(row)
    write_mail(sha256, data)
    file_name = file_name or f"{sha256[:12]}.{row.format}"
    db.flush()
    artifacts.register_mail(db, row, file_name)
    ref = attach_mail(db, incident, row, file_name, caller.actor) if incident is not None else None
    _audit(db, caller, "mail.upload", f"Analysed e-mail {file_name} ({row.verdict}, score {row.score})", incident)
    db.commit()
    if incident is not None:
        emit(
            db, background_tasks, "upload.completed", {"incidentId": incident.id, "target": f"mail/{sha256}", "rows": 1}
        )
    return row, ref


def attach_mail(db: OrmSession, incident: Incident, row: Mail, file_name: str, actor: str) -> dict[str, Any]:
    """Reference the message from the incident (kept once); returns the reference."""
    doc = dict(incident.doc or {})
    refs = _refs(doc)
    ref = next((item for item in refs if item.get("sha256") == row.sha256), None)
    if ref is None:
        ref = {
            **_summary(row),
            "fileName": file_name or f"{row.sha256[:12]}.{row.format}",
            "importedAt": now_iso(),
            "importedBy": actor,
        }
        refs.append(ref)
        _save_doc(db, incident, doc)
    return ref


def detach_mail(db: OrmSession, incident: Incident, sha256: str) -> bool:
    """Drop the incident's reference; False when it had none. The message stays."""
    doc = dict(incident.doc or {})
    refs = _refs(doc)
    kept = [ref for ref in refs if ref.get("sha256") != sha256]
    if len(kept) == len(refs):
        return False
    doc["data"]["mail"]["messages"] = kept
    _save_doc(db, incident, doc)
    return True


def delete_mail_data(db: OrmSession, row: Mail) -> None:
    """Delete the message everywhere: every incident's reference, the file, its previews."""
    for incident in _incidents_referencing(db, row.sha256):
        detach_mail(db, incident, row.sha256)
    _forget_previews(row.sha256)
    delete_mail(row.sha256)
    artifacts.forget(db, "mail", row.sha256)
    db.delete(row)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@router.post("/incidents/{incident_id}/mails", status_code=status.HTTP_201_CREATED)
async def upload_mail(
    incident_id: str,
    file: UploadFile = File(..., description="The message as an .eml or Outlook .msg file."),
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
    background_tasks: BackgroundTasks = None,
) -> dict:
    """Analyse an e-mail and attach it to the incident.

    Headers and route, SPF/DKIM/DMARC (checked through DNS and as reported by
    the receiving servers), sender mismatches, links, attachments and the
    body are weighed into a verdict: `phishing` (score ≥ 70), `suspicious`
    (40–69) or `clean`. The file is kept in the sample store; uploading the
    same message again reuses its analysis.
    """
    incident = _incident_or_404(db, incident_id)
    _row, ref = await store_mail(db, incident, await file.read(), file.filename or "", caller, background_tasks)
    return {"message": ref}


@router.get("/mails/{sha256}")
def get_mail(sha256: str, _caller: Principal = Depends(principal), db: OrmSession = Depends(get_db)) -> dict:
    """The message's full analysis and the incidents that reference it."""
    row = _mail_or_404(db, sha256)
    incidents = [{"id": inc.id, "name": (inc.doc or {}).get("name", "")} for inc in _incidents_referencing(db, sha256)]
    return {
        **_summary(row),
        "createdAt": row.created_at,
        "createdBy": row.created_by,
        "analysis": row.analysis,
        "stale": (row.analysis or {}).get("analysisVersion") != ANALYSIS_VERSION,
        "incidents": incidents,
    }


@router.post("/mails/{sha256}/reanalyse")
async def reanalyse_mail(
    sha256: str, caller: Principal = Depends(writer_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Analyse the stored message again (after a Nik upgrade, a Settings → Mail
    change, or to repeat the DNS checks)."""
    row = _mail_or_404(db, sha256)
    try:
        result = await run_in_threadpool(_analyse, db, read_mail(sha256))
    except (OSError, MailError) as exc:
        raise HTTPException(status_code=422, detail=f"The stored message cannot be analysed: {exc}") from exc
    _apply(row, result)
    artifacts.register_mail(db, row)
    for incident in _incidents_referencing(db, sha256):
        doc = dict(incident.doc or {})
        for ref in _refs(doc):
            if ref.get("sha256") == sha256:
                ref.update(_summary(row))
        _save_doc(db, incident, doc)
    _audit(db, caller, "mail.reanalyse", f"Re-analysed e-mail {sha256[:12]}… ({row.verdict})", None)
    db.commit()
    return get_mail(sha256, caller, db)


@router.get("/mails/{sha256}/source")
def mail_source(sha256: str, _caller: Principal = Depends(principal), db: OrmSession = Depends(get_db)) -> dict:
    """The message as text (an ``.eml`` as received; a ``.msg`` has no such text)."""
    row = _mail_or_404(db, sha256)
    if row.format != "eml":
        return {"available": False, "text": "", "truncated": False}
    data = read_mail(sha256)
    return {
        "available": True,
        "text": data[:SOURCE_MAX].decode("utf-8", "replace"),
        "truncated": len(data) > SOURCE_MAX,
    }


@router.get("/mails/{sha256}/attachments/{path}/bytes")
def attachment_bytes(
    sha256: str,
    path: str,
    offset: int = Query(0, ge=0),
    length: int = Query(4096, ge=1, le=HEX_CHUNK_MAX),
    _caller: Principal = Depends(principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """A slice of an attachment's bytes, base64-encoded, for the hex view."""
    import base64

    _mail_or_404(db, sha256)
    data = _attachment(_parsed(sha256), path).get("data") or b""
    chunk = data[offset : offset + length]
    return {"size": len(data), "offset": offset, "data": base64.b64encode(chunk).decode()}


@router.get("/mails/{sha256}/attachments/{path}/download")
def attachment_download(
    sha256: str,
    path: str,
    password: str = Query(DEFAULT_ZIP_PASSWORD, min_length=1, max_length=128),
    caller: Principal = Depends(principal),
    db: OrmSession = Depends(get_db),
):
    """The attachment inside an AES-256 zip protected by `password` (default `infected`)."""
    _mail_or_404(db, sha256)
    item = _attachment(_parsed(sha256), path)
    inner = str(item.get("name") or "attachment").replace("/", "_").replace("\\", "_")
    archive = zip_sample(item.get("data") or b"", inner, password)
    _audit(db, caller, "mail.attachment.download", f"Downloaded attachment {inner} of e-mail {sha256[:12]}…", None)
    db.commit()
    return Response(
        archive,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{inner}.zip"'},
    )


@router.post("/incidents/{incident_id}/mails/{sha256}/attachments/{path}/sample", status_code=status.HTTP_201_CREATED)
def attachment_to_sample(
    incident_id: str,
    sha256: str,
    path: str,
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
    background_tasks: BackgroundTasks = None,
) -> dict:
    """Send an attachment to Malware Analysis as a sample of the incident."""
    incident = _incident_or_404(db, incident_id)
    row = _mail_or_404(db, sha256)
    item = _attachment(_parsed(sha256), path)
    origin = f"e-mail “{row.subject[:80]}”" if row.subject else f"e-mail {sha256[:12]}…"
    sample, ref = store_sample(
        db,
        incident,
        item.get("data") or b"",
        item.get("name") or "",
        caller,
        background_tasks,
        origin,
        parent=(artifacts.artifact_id("mail", sha256), "attachment"),
    )
    return {"sample": ref, "iocs": len(sample.analysis.get("iocs", []))}


@router.delete("/incidents/{incident_id}/mails/{sha256}", status_code=status.HTTP_204_NO_CONTENT)
def remove_mail(
    incident_id: str,
    sha256: str,
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
) -> Response:
    """Detach the message from the incident. It stays as an artifact
    (`DELETE /api/artifacts/mail-<sha256>` deletes it)."""
    incident = _incident_or_404(db, incident_id)
    _mail_or_404(db, sha256)
    if not detach_mail(db, incident, sha256):
        raise HTTPException(status_code=404, detail="The incident does not reference this message")
    _audit(db, caller, "mail.delete", f"Removed e-mail {sha256[:12]}… from the incident", incident)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)

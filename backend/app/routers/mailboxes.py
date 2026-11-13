"""Mailboxes: a file of many e-mails (mbox, Maildir archive, Outlook PST).

Uploading one stores it and indexes its messages in the background; nothing
is analysed yet. The analyst then chooses what to import (500 messages at a
time): each becomes an e-mail artifact, analysed as an ``.eml`` is, and the
mailbox keeps them together with the graph of who answered whom.
"""

from __future__ import annotations

import logging
import os
import uuid
from typing import Any, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, Query, UploadFile, status
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, or_, select
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm.attributes import flag_modified

from .. import artifacts, mailboxes
from ..core.config import settings
from ..core.db import SessionLocal, get_db
from ..core.models import Artifact, AuditEntry, Incident, Mail, Mailbox, MailboxMessage
from ..core.security import Principal, now_iso, principal, writer_principal
from ..mail.parse import MailError
from ..malware.samples import write_mail
from ..workers import previews
from . import mails as mail_routes

router = APIRouter(tags=["mailboxes"])
logger = logging.getLogger("nik.mailboxes")
PAGE_MAX = 500


def _audit(db: OrmSession, caller: Principal, action: str, details: str, target: str | None = None) -> None:
    db.add(
        AuditEntry(
            id=str(uuid.uuid4()), at=now_iso(), actor=caller.actor, action=action, target=target, details=details
        )
    )


def _or_404(db: OrmSession, mailbox_id: str) -> Mailbox:
    row = db.get(Mailbox, mailbox_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Mailbox not found")
    return row


def _refresh(db: OrmSession, row: Mailbox) -> None:
    """Recount what was imported and refresh the registry entry."""
    found = mailboxes.imported(db, row.id)
    verdicts: dict[str, int] = {}
    for mail in found.values():
        verdicts[mail.verdict] = verdicts.get(mail.verdict, 0) + 1
    row.meta = {**(row.meta or {}), "imported": len(found), "verdicts": verdicts}
    flag_modified(row, "meta")
    artifacts.register_mailbox(db, row)


def _detail(db: OrmSession, row: Mailbox) -> dict[str, Any]:
    meta = row.meta or {}
    return {
        "id": row.id,
        "artifactId": artifacts.artifact_id("mailbox", row.id),
        "fileName": row.file_name,
        "format": row.format,
        "size": row.size,
        "status": row.status,
        "error": row.error,
        "total": row.total,
        "threads": meta.get("threads", 0),
        "from": meta.get("from"),
        "to": meta.get("to"),
        "attachments": meta.get("attachments", 0),
        "duplicates": meta.get("duplicates", 0),
        "imported": meta.get("imported", 0),
        "verdicts": meta.get("verdicts") or {},
        "progress": meta.get("progress"),
        "pending": meta.get("pending"),
        "createdAt": row.created_at,
        "createdBy": row.created_by,
        "topSenders": mailboxes.top_senders(db, row.id) if row.status in ("ready", "importing") else [],
        "importMax": mailboxes.IMPORT_MAX,
    }


# --------------------------------------------------------------------------- #
# Upload and index                                                            #
# --------------------------------------------------------------------------- #
def prepare(mailbox_id: str) -> None:
    """Background task: turn what was uploaded into the stored mbox, then index it."""
    with SessionLocal() as db:
        row = db.get(Mailbox, mailbox_id)
        if row is None:
            return
        folder = mailboxes.directory(row.id)
        upload, target = folder / "upload.bin", mailboxes.mbox_path(row.id)
        try:
            if upload.exists():
                if row.format == "pst":
                    previews.convert_pst(upload, target)
                elif row.format == "maildir":
                    mailboxes.maildir_to_mbox(upload, target, settings.MAILBOX_MAX_MB * 1024 * 1024)
                else:
                    os.replace(upload, target)
                upload.unlink(missing_ok=True)
            mailboxes.index(db, row)
            row.status, row.error = "ready", None
        except (mailboxes.MailboxError, previews.WorkerError, OSError) as exc:
            db.rollback()
            row = db.get(Mailbox, mailbox_id)
            row.status, row.error = "error", str(exc)[:500]
            upload.unlink(missing_ok=True)
            logger.info("Mailbox %s could not be read: %s", mailbox_id, exc)
        _refresh(db, row)
        db.commit()


@router.post("/artifacts/mailboxes", status_code=status.HTTP_201_CREATED)
async def upload_mailbox(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Store a mailbox and index its messages in the background (``status``:
    ``indexing``, then ``ready`` or ``error``). An mbox, a zip or tar archive
    of a Maildir (up to ``MAILBOX_MAX_MB``), or an Outlook PST (up to
    ``PST_MAX_MB``). Nothing is analysed until messages are imported."""
    head = await file.read(600)
    kind = mailboxes.detect(head, file.filename or "")
    if kind is None:
        raise HTTPException(status_code=422, detail="Not an mbox, a Maildir archive (zip, tar) or a PST file.")
    limit_mb = settings.PST_MAX_MB if kind == "pst" else settings.MAILBOX_MAX_MB
    mailbox_id = uuid.uuid4().hex
    upload = mailboxes.directory(mailbox_id) / "upload.bin"
    size = len(head)
    try:
        with open(upload, "wb") as out:
            out.write(head)
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if size > limit_mb * 1024 * 1024:
                    raise HTTPException(status_code=413, detail=f"The mailbox exceeds {limit_mb} MB.")
                out.write(chunk)
    except HTTPException:
        mailboxes.remove(mailbox_id)
        raise
    row = Mailbox(
        id=mailbox_id,
        file_name=(file.filename or f"mailbox.{kind}")[:255],
        format=kind,
        size=size,
        status="indexing",
        created_at=now_iso(),
        created_by=caller.actor,
        meta={},
    )
    db.add(row)
    db.flush()
    artifacts.register_mailbox(db, row)
    _audit(db, caller, "mailbox.upload", f"Uploaded mailbox {row.file_name} ({size} bytes, {kind})", row.file_name)
    db.commit()
    background_tasks.add_task(prepare, mailbox_id)
    return _detail(db, row)


@router.get("/mailboxes/{mailbox_id}")
def get_mailbox(mailbox_id: str, _caller: Principal = Depends(principal), db: OrmSession = Depends(get_db)) -> dict:
    """The mailbox: its state, how many messages and conversations it holds,
    the dates they span, the main senders, and what was imported."""
    return _detail(db, _or_404(db, mailbox_id))


@router.get("/mailboxes/{mailbox_id}/messages")
def list_messages(
    mailbox_id: str,
    q: str = Query("", max_length=200),
    scope: str = Query("imported", pattern="^(imported|all)$"),
    flagged: bool = Query(False, description="Only phishing and suspicious"),
    thread: Optional[int] = Query(None),
    offset: int = Query(0, ge=0),
    limit: int = Query(200, ge=1, le=PAGE_MAX),
    _caller: Principal = Depends(principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """The messages, newest first, each with the one it answers (``parent``)
    and its conversation (``thread``): what the graph draws. ``scope=imported``
    (the default) keeps the conversations with at least one imported message,
    whole: their other messages are listed too, as not imported yet."""
    row = _or_404(db, mailbox_id)
    found = mailboxes.imported(db, row.id)
    base = [MailboxMessage.mailbox_id == row.id, MailboxMessage.duplicate_of.is_(None)]
    query = select(MailboxMessage).where(*base)
    if thread is not None:
        query = query.where(MailboxMessage.thread == thread)
    elif scope == "imported":
        threads = select(MailboxMessage.thread).where(*base, MailboxMessage.sha256.in_(select(Mail.sha256)))
        query = query.where(MailboxMessage.thread.in_(threads))
    if flagged:
        bad = [sha for sha, mail in found.items() if mail.verdict in ("phishing", "suspicious")]
        query = query.where(MailboxMessage.sha256.in_(bad))
    if q.strip():
        text = q.strip().lower()
        query = query.where(
            or_(
                func.lower(MailboxMessage.subject).contains(text, autoescape=True),
                func.lower(MailboxMessage.sender).contains(text, autoescape=True),
                func.lower(MailboxMessage.recipients).contains(text, autoescape=True),
            )
        )
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = db.scalars(
        query.order_by(MailboxMessage.date_ms.desc().nulls_last(), MailboxMessage.seq.desc())
        .offset(offset)
        .limit(limit)
    ).all()
    return {
        "total": total,
        "messages": [
            {
                "seq": item.seq,
                "parent": item.parent,
                "thread": item.thread,
                "subject": item.subject,
                "sender": item.sender,
                "recipients": item.recipients,
                "date": item.date_ms,
                "attachments": item.attachments,
                "imported": item.sha256 in found,
                "artifactId": artifacts.artifact_id("mail", item.sha256) if item.sha256 in found else None,
                "verdict": found[item.sha256].verdict if item.sha256 in found else None,
                "score": found[item.sha256].score if item.sha256 in found else None,
            }
            for item in rows
        ],
    }


# --------------------------------------------------------------------------- #
# Import                                                                      #
# --------------------------------------------------------------------------- #
class ImportIn(BaseModel):
    seqs: Optional[list[int]] = Field(default=None, max_length=5000)
    dateFrom: Optional[int] = None
    dateTo: Optional[int] = None
    sender: str = Field(default="", max_length=200)
    subject: str = Field(default="", max_length=200)
    attachments: bool = False
    threads: bool = True
    dryRun: bool = False
    # Go on with the last filter: the messages it left waiting.
    next: bool = False


def _plan(db: OrmSession, row: Mailbox, body: ImportIn) -> dict[str, Any]:
    kwargs = {
        "seqs": body.seqs,
        "date_from": body.dateFrom,
        "date_to": body.dateTo,
        "sender": body.sender,
        "subject": body.subject,
        "attachments": body.attachments,
    }
    matches = mailboxes.select_messages(db, row.id, **kwargs)
    wanted = mailboxes.select_messages(db, row.id, **kwargs, whole_threads=True) if body.threads else matches
    known = set(db.scalars(select(Mail.sha256).where(Mail.sha256.in_([m.sha256 for m in wanted[:5000]]))))
    fresh = [m for m in wanted if m.sha256 not in known]
    too_big = [m for m in fresh if m.length > settings.SAMPLE_MAX_MB * 1024 * 1024]
    fresh = [m for m in fresh if m.length <= settings.SAMPLE_MAX_MB * 1024 * 1024]
    return {
        "matches": len(matches),
        "conversations": len({m.thread for m in matches}),
        "withConversations": len(wanted),
        "alreadyInNik": len(wanted) - len(fresh) - len(too_big),
        "tooLarge": len(too_big),
        "toImport": min(len(fresh), mailboxes.IMPORT_MAX),
        "waiting": max(0, len(fresh) - mailboxes.IMPORT_MAX),
        "max": mailboxes.IMPORT_MAX,
        "seqs": [m.seq for m in fresh[: mailboxes.IMPORT_MAX]],
        "linkOnly": [m.seq for m in wanted if m.sha256 in known],
    }


def import_messages(mailbox_id: str, seqs: list[int], actor: str) -> None:
    """Background task: analyse each message as an e-mail and make it an artifact."""
    with SessionLocal() as db:
        row = db.get(Mailbox, mailbox_id)
        if row is None:
            return
        path = mailboxes.mbox_path(row.id)
        parent = artifacts.artifact_id("mailbox", row.id)
        done = failed = 0
        for seq in seqs:
            item = db.get(MailboxMessage, (row.id, seq))
            if item is None:
                continue
            try:
                data = mailboxes.read_message(path, item.offset, item.length)
                mail = db.get(Mail, item.sha256)
                if mail is None:
                    result = mail_routes._analyse(db, data)
                    mail = Mail(sha256=item.sha256, created_at=now_iso(), created_by=actor)
                    mail_routes._apply(mail, result)
                    # Marks where it comes from: a mailbox holds much ordinary mail,
                    # and only its flagged messages give indicators (see iocs.extract).
                    mail.analysis = {**(mail.analysis or {}), "mailbox": row.id}
                    db.add(mail)
                write_mail(item.sha256, data)
                db.flush()
                entry = artifacts.register_mail(db, mail, item.subject or f"{item.sha256[:12]}.eml")
                artifacts.relate(db, parent, entry.id, "message")
                done += 1
            except (MailError, OSError, ValueError) as exc:
                db.rollback()
                failed += 1
                logger.info("Message %s of mailbox %s was not imported: %s", seq, mailbox_id, exc)
            row = db.get(Mailbox, mailbox_id)
            row.meta = {**(row.meta or {}), "progress": {"done": done + failed, "total": len(seqs), "failed": failed}}
            flag_modified(row, "meta")
            db.commit()
        row = db.get(Mailbox, mailbox_id)
        row.status = "ready"
        _refresh(db, row)
        db.commit()


@router.post("/mailboxes/{mailbox_id}/import")
def import_mailbox(
    mailbox_id: str,
    body: ImportIn,
    background_tasks: BackgroundTasks,
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Choose messages by ``seqs`` or by a filter (dates in Unix milliseconds,
    sender, subject, with attachments), with the rest of their conversations
    when ``threads`` is true, and import them: 500 at most, the newest first;
    the others wait, and ``next`` goes on with them. ``dryRun`` only counts."""
    row = _or_404(db, mailbox_id)
    if row.status != "ready":
        raise HTTPException(status_code=409, detail=f"The mailbox is {row.status}: wait until it is ready.")
    if body.next:
        pending = (row.meta or {}).get("pending")
        if not pending:
            raise HTTPException(status_code=409, detail="No import is waiting to go on.")
        body = ImportIn(**pending["filter"], dryRun=body.dryRun)
    plan = _plan(db, row, body)
    seqs = plan.pop("seqs")
    plan.pop("linkOnly")
    if body.dryRun:
        return {**plan, "started": False}
    meta = dict(row.meta or {})
    if body.seqs is None:
        # A filter that matches more than one import takes is remembered, so
        # that the rest can follow without choosing again.
        meta.pop("pending", None)
        if seqs and plan["waiting"]:
            meta["pending"] = {
                "filter": body.model_dump(exclude={"seqs", "dryRun", "next"}),
                "waiting": plan["waiting"],
            }
        row.meta = meta
        flag_modified(row, "meta")
    if not seqs:
        db.commit()
        return {**plan, "started": False}
    row.status = "importing"
    row.meta = {**meta, "progress": {"done": 0, "total": len(seqs), "failed": 0}}
    flag_modified(row, "meta")
    artifacts.register_mailbox(db, row)
    _audit(db, caller, "mailbox.import", f"Importing {len(seqs)} message(s) of {row.file_name}", row.file_name)
    db.commit()
    background_tasks.add_task(import_messages, row.id, seqs, caller.actor)
    return {**plan, "started": True}


# --------------------------------------------------------------------------- #
# Incidents                                                                   #
# --------------------------------------------------------------------------- #
class LinkIn(BaseModel):
    incidentId: str = Field(min_length=1, max_length=64)
    # The messages to put in the incident; all the imported ones when omitted.
    seqs: Optional[list[int]] = Field(default=None, max_length=5000)


@router.post("/mailboxes/{mailbox_id}/link")
def link_messages(
    mailbox_id: str,
    body: LinkIn,
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Put imported messages of the mailbox in an incident: all of them, or
    the chosen ones. They show in its Mail Analysis tab like any e-mail."""
    row = _or_404(db, mailbox_id)
    incident = db.get(Incident, body.incidentId)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    query = (
        select(MailboxMessage, Mail)
        .join(Mail, Mail.sha256 == MailboxMessage.sha256)
        .where(MailboxMessage.mailbox_id == row.id, MailboxMessage.duplicate_of.is_(None))
    )
    if body.seqs is not None:
        query = query.where(MailboxMessage.seq.in_(body.seqs))
    linked = 0
    for item, mail in db.execute(query).all():
        mail_routes.attach_mail(db, incident, mail, item.subject or f"{mail.sha256[:12]}.eml", caller.actor)
        linked += 1
    _audit(db, caller, "mailbox.link", f"Put {linked} message(s) of {row.file_name} in the incident", row.file_name)
    db.commit()
    return {"linked": linked, "incident": {"id": incident.id, "name": incident.name}}


def delete_mailbox_data(db: OrmSession, row: Mailbox) -> None:
    """Remove the mailbox and its file. The messages imported from it stay,
    as e-mail artifacts of their own."""
    from ..core.db import after_commit

    mailbox_id = row.id
    db.execute(delete(MailboxMessage).where(MailboxMessage.mailbox_id == mailbox_id))
    artifact = db.get(Artifact, artifacts.artifact_id("mailbox", mailbox_id))
    if artifact is not None:
        db.delete(artifact)
    db.delete(row)
    after_commit(db, lambda: mailboxes.remove(mailbox_id))

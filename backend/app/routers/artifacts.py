"""Artifacts: analyse a file, an e-mail, a packet capture or a URL on its own.

An artifact exists without an incident; it can be linked to incidents later
(files and e-mails to several, a capture to one), tagged, and related to the
artifact it was taken out of. The analyses themselves stay where they are:
``/api/samples``, ``/api/mails``, ``/api/captures`` and ``/api/urls``
(URL scans start in ``routers/urls.py``).
"""

from __future__ import annotations

import base64
import uuid
from typing import Any, Literal, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, HTTPException, Query, Response, UploadFile, status
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field
from sqlalchemy import String, cast, func, select
from sqlalchemy.orm import Session as OrmSession

from .. import analysis_links, archive, artifact_convert, artifact_expiry, artifact_transfer, artifacts, query, urlscan
from ..core import audit
from ..core.config import settings
from ..core.db import after_commit, get_db
from ..core.models import (
    Artifact,
    ArtifactLink,
    ArtifactRelation,
    EvidenceSource,
    Incident,
    Mail,
    Mailbox,
    NetworkCapture,
    Sample,
    UrlScan,
)
from ..core.security import Principal, admin_principal, now_iso, reader_principal, writer_principal
from ..evidence import originals
from ..network import service as captures
from ..workers import previews
from . import mails as mail_routes
from . import network as capture_routes
from . import samples as sample_routes

router = APIRouter(tags=["artifacts"])


def _audit(db: OrmSession, caller: Principal, action: str, details: str, incident: Incident | None = None) -> None:
    audit.record(db, caller.actor, action, details, incident)


def _artifact_or_404(db: OrmSession, artifact_id: str) -> Artifact:
    row = db.get(Artifact, artifact_id) if artifacts.is_artifact_id(artifact_id) else None
    if row is None:
        raise HTTPException(status_code=404, detail="Artifact not found")
    return row


def _incident_or_404(db: OrmSession, incident_id: str | None) -> Incident | None:
    if not incident_id:
        return None
    row = db.get(Incident, incident_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return row


def _incidents_of(db: OrmSession, ids: list[str]) -> dict[str, list[dict[str, str]]]:
    """``artifact id → [{id, name}]`` for the incidents that reference each artifact."""
    out: dict[str, list[dict[str, str]]] = {item: [] for item in ids}
    if not ids:
        return out
    rows = db.execute(
        select(ArtifactLink.artifact_id, Incident.id, Incident.name)
        .join(Incident, Incident.id == ArtifactLink.incident_id)
        .where(ArtifactLink.artifact_id.in_(ids))
        .order_by(Incident.updated_at.desc())
    ).all()
    for artifact_id, incident_id, name in rows:
        out[artifact_id].append({"id": incident_id, "name": name})
    return out


def _summary(row: Artifact, incidents: list[dict[str, str]]) -> dict[str, Any]:
    return {
        "id": row.id,
        "kind": row.kind,
        "ref": row.ref,
        "name": row.name or f"{row.ref[:16]}…",
        "verdict": row.verdict,
        "score": row.score,
        "detail": row.detail,
        "size": row.size,
        "tags": row.tags or [],
        "createdAt": row.created_at,
        "createdBy": row.created_by,
        "incidents": incidents,
        # The day it is deleted on, when someone gave it one (artifact_expiry.py).
        **artifact_expiry.out(row),
        # What a file could be analysed as besides a file, by its name: "mail", "capture" (artifact_convert.py).
        "analyseAs": artifact_convert.by_name(row),
    }


def _one(db: OrmSession, row: Artifact) -> dict[str, Any]:
    # ``indicator``: the value this artifact is the analysis of (see analysis_links).
    return {
        **_summary(row, _incidents_of(db, [row.id])[row.id]),
        "indicator": analysis_links.indicator_of(db, row),
        # One artifact is looked at: what it can be analysed as is read from its first bytes, not its name.
        "analyseAs": artifact_convert.fitting(row),
    }


def _related(db: OrmSession, row: Artifact) -> dict[str, list[dict[str, Any]]]:
    """The artifacts this one was taken out of (``parents``) and those taken out of it (``children``)."""

    def side(mine, other) -> list[dict[str, Any]]:
        pairs = db.execute(
            select(ArtifactRelation.relation, Artifact).join(Artifact, Artifact.id == other).where(mine == row.id)
        ).all()
        return [
            {"relation": relation, "id": item.id, "kind": item.kind, "name": item.name, "verdict": item.verdict}
            for relation, item in pairs
        ]

    return {
        "parents": side(ArtifactRelation.child_id, ArtifactRelation.parent_id),
        "children": side(ArtifactRelation.parent_id, ArtifactRelation.child_id),
    }


# --------------------------------------------------------------------------- #
# Reading                                                                     #
# --------------------------------------------------------------------------- #
def matching(
    db: OrmSession, caller: Principal, q: str = "", tag: str = "", mine: bool = False, linked: bool | None = None
) -> list:
    """The conditions a filter keeps artifacts by, without their kind: what the list shows for it,
    and what a bulk action on "all that match" works on (bulk_artifacts.py)."""
    # `q` is the query language (app/query); the older parameters add their conditions.
    conditions = query.sql("artifacts", q, caller) if q.strip() else []
    if conditions:
        query.statement_timeout(db)
    if tag.strip():
        conditions.append(func.lower(cast(Artifact.tags, String)).like(f'%"{tag.strip().lower()}"%'))
    if mine:
        conditions.append(Artifact.created_by == caller.actor)
    if linked is not None:
        has_link = select(ArtifactLink.artifact_id).where(ArtifactLink.artifact_id == Artifact.id).exists()
        conditions.append(has_link if linked else ~has_link)
    return conditions


@router.get("/artifacts")
def list_artifacts(
    kind: Optional[Literal["file", "mail", "pcap", "url", "mailbox", "hostfile"]] = None,
    q: str = Query(
        "",
        max_length=2000,
        description="A query: `kind:mail verdict:phishing created:>=now-7d`; plain words match name, hash, detail, tags"
        ".",
    ),
    tag: str = Query("", max_length=40),
    mine: bool = Query(False, description="Only the artifacts the caller created."),
    linked: Optional[bool] = Query(None, description="true: linked to an incident; false: on their own."),
    limit: int = Query(100, ge=1, le=200),
    offset: int = Query(0, ge=0),
    caller: Principal = Depends(reader_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """The artifacts every analyst can see, newest first, with the incidents that reference each."""
    conditions = matching(db, caller, q, tag, mine, linked)
    counts = dict(db.execute(select(Artifact.kind, func.count()).where(*conditions).group_by(Artifact.kind)).all())
    if kind:
        conditions.append(Artifact.kind == kind)
    rows = db.scalars(
        select(Artifact).where(*conditions).order_by(Artifact.created_at.desc()).limit(limit).offset(offset)
    ).all()
    incidents = _incidents_of(db, [row.id for row in rows])
    return {
        "artifacts": [_summary(row, incidents[row.id]) for row in rows],
        "total": counts.get(kind, 0) if kind else sum(counts.values()),
        "counts": {name: counts.get(name, 0) for name in artifacts.KINDS},
    }


@router.get("/artifacts/lookup")
def lookup_artifact(
    sha256: str = Query(..., pattern=r"^[0-9a-f]{64}$", description="SHA-256 of a file, computed before uploading it."),
    _caller: Principal = Depends(reader_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Is this file already known? The artifacts with that digest (a file, an e-mail), if any."""
    rows = db.scalars(select(Artifact).where(Artifact.ref == sha256, Artifact.kind.in_(("file", "mail")))).all()
    incidents = _incidents_of(db, [row.id for row in rows])
    return {"artifacts": [_summary(row, incidents[row.id]) for row in rows]}


@router.get("/artifacts/{artifact_id}")
def get_artifact(
    artifact_id: str,
    _caller: Principal = Depends(reader_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """One artifact: its summary, the incidents that reference it and its relations."""
    row = _artifact_or_404(db, artifact_id)
    return {**_one(db, row), **_related(db, row)}


# --------------------------------------------------------------------------- #
# Starting an analysis                                                        #
# --------------------------------------------------------------------------- #
@router.post("/artifacts/files", status_code=status.HTTP_201_CREATED)
async def analyse_file(
    file: UploadFile = File(..., description="The suspicious file, as is."),
    incident: Optional[str] = Form(None, description="Incident to link it to (optional)."),
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
    background_tasks: BackgroundTasks = None,
) -> dict:
    """Analyse a file on its own (or link it to an incident at once). Stored
    under its SHA-256, never executed; a file already known reuses its analysis."""
    target = _incident_or_404(db, incident)
    archive.guard(target)
    data = await file.read()
    sample, _ref = await run_in_threadpool(
        sample_routes.store_sample, db, target, data, file.filename or "", caller, background_tasks
    )
    return _one(db, _artifact_or_404(db, artifacts.artifact_id("file", sample.sha256)))


@router.post("/artifacts/mails", status_code=status.HTTP_201_CREATED)
async def analyse_mail(
    file: UploadFile = File(..., description="The message as an .eml or Outlook .msg file."),
    incident: Optional[str] = Form(None, description="Incident to link it to (optional)."),
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
    background_tasks: BackgroundTasks = None,
) -> dict:
    """Analyse an e-mail on its own (or link it to an incident at once)."""
    target = _incident_or_404(db, incident)
    archive.guard(target)
    mail, _ref = await mail_routes.store_mail(
        db, target, await file.read(), file.filename or "", caller, background_tasks
    )
    return _one(db, _artifact_or_404(db, artifacts.artifact_id("mail", mail.sha256)))


@router.post("/artifacts/captures", status_code=status.HTTP_201_CREATED)
async def analyse_capture(
    file: UploadFile = File(..., description="A pcap or pcapng file (optionally gzip-compressed)."),
    keylog: UploadFile | None = File(None, description="Optional TLS key log (SSLKEYLOGFILE)."),
    incident: Optional[str] = Form(None, description="Incident to link it to (optional)."),
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
    background_tasks: BackgroundTasks = None,
) -> dict:
    """Store a packet capture on its own (or in an incident) and analyse it in the background."""
    target = _incident_or_404(db, incident)
    archive.guard(target)
    capture = await capture_routes.store_capture(db, target, file, keylog, caller, background_tasks)
    return _one(db, _artifact_or_404(db, artifacts.artifact_id("pcap", capture.id)))


# --------------------------------------------------------------------------- #
# Taking an artifact out of another                                           #
# --------------------------------------------------------------------------- #
@router.post("/artifacts/{artifact_id}/attachments/{path}/sample", status_code=status.HTTP_201_CREATED)
def attachment_to_file(
    artifact_id: str,
    path: str,
    incident: Optional[str] = Query(None, description="Incident to link the new file to (optional)."),
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
    background_tasks: BackgroundTasks = None,
) -> dict:
    """Analyse an attachment of an e-mail artifact as a file artifact, related to the e-mail."""
    row = _artifact_or_404(db, artifact_id)
    if row.kind != "mail":
        raise HTTPException(status_code=422, detail="Only e-mails have attachments.")
    target = _incident_or_404(db, incident)
    mail = mail_routes._mail_or_404(db, row.ref)
    item = mail_routes._attachment(mail_routes._parsed(row.ref), path)
    origin = f"e-mail “{mail.subject[:80]}”" if mail.subject else f"e-mail {row.ref[:12]}…"
    sample, _ref = sample_routes.store_sample(
        db,
        target,
        item.get("data") or b"",
        item.get("name") or "",
        caller,
        background_tasks,
        origin,
        parent=(row.id, "attachment"),
    )
    return _one(db, _artifact_or_404(db, artifacts.artifact_id("file", sample.sha256)))


class ObjectIn(BaseModel):
    token: str = Field(pattern=r"^eo:[a-z-]+_\d{1,6}$")


@router.post("/artifacts/{artifact_id}/objects/sample", status_code=status.HTTP_201_CREATED)
async def object_to_file(
    artifact_id: str,
    body: ObjectIn,
    incident: Optional[str] = Query(None, description="Incident to link the new file to (optional)."),
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
    background_tasks: BackgroundTasks = None,
) -> dict:
    """Analyse an object exported from a capture artifact as a file artifact, related to the capture."""
    row = _artifact_or_404(db, artifact_id)
    if row.kind != "pcap":
        raise HTTPException(status_code=422, detail="Only captures carry exported objects.")
    target = _incident_or_404(db, incident)
    capture = capture_routes._capture_or_404(db, row.ref)
    capture_routes._needs_file(capture)
    try:
        item = await run_in_threadpool(captures.rpc, capture, "download", {"token": body.token})
    except previews.WorkerError as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc)) from exc
    sample, _ref = await run_in_threadpool(
        sample_routes.store_sample,
        db,
        target,
        base64.b64decode(item.get("data") or ""),
        str(item.get("name") or "object")[:255],
        caller,
        background_tasks,
        f"capture {capture.file_name}",
        (row.id, "extracted"),
    )
    return _one(db, _artifact_or_404(db, artifacts.artifact_id("file", sample.sha256)))


class AnalyseAsIn(BaseModel):
    # What the file is analysed as: an e-mail (.eml, .msg) or a packet capture (.pcap, .pcapng).
    kind: Literal["mail", "capture"] = Field(alias="as")
    incident: Optional[str] = Field(default=None, max_length=64)


@router.post("/artifacts/{artifact_id}/analyse-as", status_code=status.HTTP_201_CREATED)
def analyse_file_as(
    artifact_id: str,
    body: AnalyseAsIn,
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
    background_tasks: BackgroundTasks = None,
) -> dict:
    """Analyse a file artifact as an e-mail or as a packet capture: the artifact an upload of the
    same file would have made, recorded as made from the file. It goes to the incident that is
    named, or to those the file is in (a capture to the one incident, when there is just one).
    Nothing is run or opened; the file stays as it is."""
    row = _artifact_or_404(db, artifact_id)
    try:
        if body.kind == "mail":
            made = artifact_convert.as_mail(db, row, caller.actor, body.incident or "")
        else:
            made = artifact_convert.as_capture(db, row, caller.actor, background_tasks, body.incident or "")
    except artifact_convert.ConvertError as error:
        db.rollback()
        raise HTTPException(status_code=error.status, detail=error.message) from None
    what = "an e-mail" if body.kind == "mail" else "a capture"
    _audit(db, caller, "artifact.analyse_as", f"Analysed the file {row.name or row.ref[:12]} as {what}")
    db.commit()
    return _one(db, made)


# --------------------------------------------------------------------------- #
# Incidents, tags, deletion                                                   #
# --------------------------------------------------------------------------- #
class LinkIn(BaseModel):
    incidentId: str = Field(min_length=1, max_length=64)


@router.post("/artifacts/{artifact_id}/links", status_code=status.HTTP_201_CREATED)
def link_artifact(
    artifact_id: str,
    body: LinkIn,
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Link the artifact to an incident: it appears in the incident's tab,
    indicators, timeline and report. A capture belongs to one incident at most."""
    row = _artifact_or_404(db, artifact_id)
    incident = _incident_or_404(db, body.incidentId)
    link_to(db, row, incident, caller)
    db.commit()
    return _one(db, row)


def link_to(db: OrmSession, row: Artifact, incident: Incident, caller: Principal) -> None:
    """Link an artifact to an incident (the caller commits). What the route does, and what a bulk
    action does for each artifact. An archived incident is read-only: ``Archived``."""
    archive.guard(incident)
    if row.kind == originals.KIND:
        raise HTTPException(
            status_code=422, detail="Host evidence is given to an incident when it is imported there, not linked"
        )
    if row.kind == "file":
        sample_routes.attach_sample(db, incident, db.get(Sample, row.ref), row.name, caller.actor)
    elif row.kind == "mail":
        mail_routes.attach_mail(db, incident, db.get(Mail, row.ref), row.name, caller.actor)
    elif row.kind == "url":
        urlscan.attach(db, incident, db.get(UrlScan, row.ref), caller.actor)
    else:
        capture = db.get(NetworkCapture, row.ref)
        if capture.incident_id and capture.incident_id != incident.id:
            raise HTTPException(
                status_code=409, detail="The capture is in another incident: remove it from there first."
            )
        if capture.status == "live":
            raise HTTPException(status_code=409, detail="The browser session is still open: close it first.")
        captures.attach(db, capture, incident)
    _audit(db, caller, "artifact.link", f"Linked {row.kind} {row.name or row.ref[:12]} to the incident", incident)


@router.delete("/artifacts/{artifact_id}/links/{incident_id}", status_code=status.HTTP_204_NO_CONTENT)
def unlink_artifact(
    artifact_id: str,
    incident_id: str,
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
) -> Response:
    """Take the artifact out of the incident; the artifact and its analysis stay."""
    row = _artifact_or_404(db, artifact_id)
    incident = _incident_or_404(db, incident_id)
    unlink_from(db, row, incident, caller)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


def unlink_from(db: OrmSession, row: Artifact, incident: Incident, caller: Principal) -> None:
    """Take an artifact out of an incident (the caller commits); ``404`` when it is not in it.
    An archived incident is read-only: ``Archived``."""
    archive.guard(incident)
    if row.kind == originals.KIND:
        raise HTTPException(
            status_code=422, detail="Host evidence is taken out of an incident from its evidence, not unlinked"
        )
    if row.kind == "file":
        found = sample_routes.detach_sample(db, incident, row.ref)
    elif row.kind == "mail":
        found = mail_routes.detach_mail(db, incident, row.ref)
    elif row.kind == "url":
        found = urlscan.detach(db, incident, row.ref)
    else:
        capture = db.get(NetworkCapture, row.ref)
        found = capture.incident_id == incident.id
        if found:
            captures.detach(db, capture)
    if not found:
        raise HTTPException(status_code=404, detail="The incident does not reference this artifact")
    _audit(db, caller, "artifact.unlink", f"Removed {row.kind} {row.name or row.ref[:12]} from the incident", incident)


class TagsIn(BaseModel):
    tags: list[str] = Field(max_length=artifacts.TAGS_MAX)


@router.put("/artifacts/{artifact_id}/tags")
def tag_artifact(
    artifact_id: str,
    body: TagsIn,
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Replace the artifact's tags (lower case; letters, digits and ``. _ : -``; 12 at most)."""
    row = _artifact_or_404(db, artifact_id)
    tag(db, row, body.tags, caller)
    db.commit()
    return _one(db, row)


def tag(db: OrmSession, row: Artifact, tags: list[str], caller: Principal) -> list[str]:
    """Replace the tags of an artifact (the caller commits). Returns what it holds afterwards."""
    tags = artifacts.set_tags(db, row, tags)
    _audit(db, caller, "artifact.tags", f"Tagged {row.kind} {row.name or row.ref[:12]}: {', '.join(tags) or 'none'}")
    return tags


class ExpiryIn(BaseModel):
    # The day the artifact is deleted on (YYYY-MM-DD), or null for no date.
    expiresAt: str | None = Field(default=None, max_length=40)


@router.put("/artifacts/{artifact_id}/expiry")
def set_artifact_expiry(
    artifact_id: str,
    body: ExpiryIn,
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Give an artifact a day to be deleted on, or take the date away (``expiresAt: null``). Nothing
    has a date unless someone sets it. The worker deletes it once the day has come, unless an incident
    that is not closed still references it: then the date is put off by a week."""
    row = _artifact_or_404(db, artifact_id)
    expire(db, row, body.expiresAt, caller)
    db.commit()
    return _one(db, row)


def expire(db: OrmSession, row: Artifact, day: str | None, caller: Principal) -> str | None:
    """Give an artifact its day, or take it away (the caller commits); ``400`` for a day that is not one."""
    try:
        day = artifact_expiry.set_expiry(db, row, day)
    except artifact_expiry.ExpiryError as error:
        raise HTTPException(status_code=400, detail=error.message) from None
    what = f"expires on {day}" if day else "has no expiry any more"
    _audit(db, caller, "artifact.expiry", f"{row.kind} {row.name or row.ref[:12]} {what}")
    return day


def _refuse_held(db: OrmSession, row: Artifact) -> None:
    held = originals.holders(db, row.ref)
    if held:
        raise HTTPException(
            status_code=409, detail=f"{held} incident(s) hold this file as evidence: remove it from them first"
        )


def _forget_original(db: OrmSession, row: Artifact) -> None:
    """Drop the artifact of an original and, once the commit is made, the file."""
    sha256 = row.ref
    after_commit(db, lambda: originals.remove(sha256))
    artifacts.forget(db, originals.KIND, sha256)


def delete_artifact_data(db: OrmSession, row: Artifact) -> None:
    """Delete the artifact everywhere: its incidents' references, files and analyses. An original of
    host evidence goes only when no incident holds it: ``409`` with how many do."""
    if row.kind == originals.KIND:
        _refuse_held(db, row)
        _forget_original(db, row)
    elif row.kind == "file":
        sample_routes.delete_sample_data(db, db.get(Sample, row.ref))
    elif row.kind == "mail":
        mail_routes.delete_mail_data(db, db.get(Mail, row.ref))
    elif row.kind == "url":
        urlscan.delete(db, db.get(UrlScan, row.ref))
    elif row.kind == "mailbox":
        from . import mailboxes as mailbox_routes

        mailbox_routes.delete_mailbox_data(db, db.get(Mailbox, row.ref))
    else:
        captures.remove_capture(db, db.get(NetworkCapture, row.ref))


@router.delete("/artifacts/{artifact_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_artifact(
    artifact_id: str,
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
) -> Response:
    """Delete the artifact: its file and analyses, and its reference in every incident."""
    row = _artifact_or_404(db, artifact_id)
    remove(db, row, caller)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


def remove(db: OrmSession, row: Artifact, caller: Principal) -> None:
    """Delete an artifact everywhere, and say so in the audit log (the caller commits)."""
    if row.kind == originals.KIND:
        _refuse_held(db, row)
    _audit(db, caller, "artifact.delete", f"Deleted {row.kind} {row.name or row.ref[:12]} ({row.ref[:12]}…)")
    delete_artifact_data(db, row)


def remove_incident_artifacts(db: OrmSession, incident_id: str) -> None:
    """Called when an incident is deleted: the artifacts only that incident
    references go with it; those another incident also references stay."""
    others = select(ArtifactLink.artifact_id).where(ArtifactLink.incident_id != incident_id)
    rows = db.scalars(
        select(Artifact)
        .join(ArtifactLink, ArtifactLink.artifact_id == Artifact.id)
        .where(ArtifactLink.incident_id == incident_id, Artifact.id.not_in(others))
    ).all()
    for row in rows:
        if row.kind == originals.KIND:
            # The sources of this incident are going with it: only another incident's keep the original.
            if not db.scalar(
                select(func.count())
                .select_from(EvidenceSource)
                .where(EvidenceSource.sha256 == row.ref, EvidenceSource.incident_id != incident_id)
            ):
                _forget_original(db, row)
        elif row.kind == "pcap":
            captures.remove_capture(db, db.get(NetworkCapture, row.ref), update_incident=False)
        elif row.kind == "file":
            sample_routes.delete_sample_data(db, db.get(Sample, row.ref))
        elif row.kind == "url":
            urlscan.delete(db, db.get(UrlScan, row.ref))
        else:
            mail_routes.delete_mail_data(db, db.get(Mail, row.ref))


# --------------------------------------------------------------------------- #
# Export and import                                                           #
# --------------------------------------------------------------------------- #
class ExportIn(BaseModel):
    ids: list[str] = Field(min_length=1, max_length=artifact_transfer.MAX_ARTIFACTS)
    # The original files are live malware: asked for at each export, never the default.
    files: bool = False


@router.post("/artifacts/export")
def export_artifacts(
    body: ExportIn,
    caller: Principal = Depends(reader_principal),
    db: OrmSession = Depends(get_db),
):
    """Download artifacts as a zip another Nik can import: the registry entries
    and the analyses, and with ``files`` the original files too, inside an
    AES-encrypted ``files.zip`` (password ``infected``)."""
    from starlette.background import BackgroundTask

    from ..core.files import stored_response

    rows = [row for row in (db.get(Artifact, artifact_id) for artifact_id in dict.fromkeys(body.ids)) if row]
    if not rows:
        raise HTTPException(status_code=404, detail="No such artifact")
    if all(row.kind in artifact_transfer.LEFT_OUT for row in rows):
        raise HTTPException(status_code=422, detail="The original of host evidence is not part of an export")
    allowed = artifact_transfer.files_limit(rows)
    if body.files and sum(row.size or 0 for row in rows) > allowed:
        raise HTTPException(
            status_code=413,
            detail=f"These files exceed {allowed // (1024 * 1024)} MB together: export fewer at a time.",
        )
    now = now_iso()
    path = artifact_transfer.export_archive(db, rows, body.files, now, request_version())
    _audit(
        db,
        caller,
        "artifact.export",
        f"Exported {len(rows)} artifact(s) {'with their files' if body.files else 'without the files'}",
    )
    db.commit()
    name = f"nik-artifacts-{now[:10]}{'-with-files' if body.files else ''}.zip"
    try:
        response = stored_response(path, "application/zip", name)
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    response.background = BackgroundTask(lambda: path.unlink(missing_ok=True))
    return response


def request_version() -> str:
    from ..main import app

    return app.version


@router.post("/artifacts/import")
async def import_artifacts(
    file: UploadFile = File(...),
    caller: Principal = Depends(admin_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Add the artifacts of an export that this server does not have
    (**admin**). A file is stored only when its SHA-256 is the one its
    artifact is named by; nothing is run and no analysis is started."""
    from pathlib import Path

    from ..core import store

    # Twice an upload, and room for a mailbox: an export with one in it is as large as the mailbox.
    limit = (settings.ARTIFACT_MAX_MB * 2 + settings.MAILBOX_MAX_MB) * 1024 * 1024
    # Sealed as it arrives, like every file of the store: the archive holds files in clear.
    path = artifact_transfer.workdir() / f"nik-import-{uuid.uuid4().hex}.zip"
    try:
        size = 0
        with store.writing(path) as handle:
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if size > limit:
                    raise HTTPException(status_code=413, detail=f"The archive exceeds {limit // (1024 * 1024)} MB.")
                handle.write(chunk)
        try:
            result = await run_in_threadpool(artifact_transfer.import_archive, db, path, caller.actor)
        except artifact_transfer.TransferError as exc:
            db.rollback()
            raise HTTPException(status_code=422, detail=str(exc)) from None
    finally:
        path.unlink(missing_ok=True)
        Path(str(path) + ".files").unlink(missing_ok=True)  # the files of the archive, taken out to be read
    _audit(
        db,
        caller,
        "artifact.import",
        f"Imported {result['added']} artifact(s); {result['existing']} already here, {len(result['skipped'])} skipped",
    )
    db.commit()
    return result

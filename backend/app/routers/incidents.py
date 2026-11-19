"""Incident document-store routes.

The backend stores the full frontend incident object in ``doc`` and mirrors a
few scalar fields into columns for listing/sorting. ``POST`` upserts a full
document; ``PATCH`` shallow-merges only the changed top-level keys.

These endpoints accept EITHER a browser session or an ``X-API-Key`` header (the
``principal`` dependency), so the same operations are available to external API
clients. Every change is recorded in the audit log here, whoever makes it.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Body,
    Depends,
    File,
    Header,
    HTTPException,
    Query,
    Response,
    UploadFile,
    status,
)
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm import defer
from sqlalchemy.orm.attributes import flag_modified

from .. import fields as field_registry
from .. import incident_quick, query
from ..automation import triggers
from ..browser_profiles import normalize_browser_data
from ..core import audit
from ..core.config import settings
from ..core.db import SessionLocal, get_db
from ..core.files import read_upload
from ..core.locking import lock_incident
from ..core.models import AuditEntry, IdempotencyRecord, Incident, IocEntry, Job
from ..core.schemas import NoteIn
from ..core.security import Principal, now_iso, reader_principal, writer_principal
from ..events import emit, emit_now
from ..iocs import reindex_incident
from ..parsing.registry import apply_upload

router = APIRouter(prefix="/incidents", tags=["incidents"])

SEVERITIES = ("low", "medium", "high", "critical")
# Where the work on an incident stands; an incident with no status is open.
STATUSES = ("open", "in_progress", "closed")


def _timers(db: OrmSession, incident: Incident) -> None:
    """The SLA timers of the incident follow what was just saved (an owner, a closing)."""
    import time

    from .. import timers

    timers.sync(db, incident, time.time())


def _sync_columns(incident: Incident) -> None:
    """Refresh the mirrored scalar columns from the incident ``doc``."""
    doc = incident.doc or {}
    incident.name = str(doc.get("name") or "")
    incident.host = str(doc.get("host") or "")
    incident.username = str(doc.get("username") or "")
    incident.os = str(doc.get("os") or "")
    incident.ticket_id = str(doc.get("ticketId") or "")
    severity = str(doc.get("severity") or "")
    incident.severity = severity if severity in SEVERITIES else ""
    state = str(doc.get("status") or "")
    incident.status = state if state in STATUSES else "open"
    incident.assignee = str(doc.get("assignee") or "").strip()
    mail = (doc.get("data") or {}).get("mail") if isinstance(doc.get("data"), dict) else None
    incident.has_mail = bool(isinstance(mail, dict) and mail.get("messages"))
    incident.updated_at = str(doc.get("updatedAt") or "")
    incident.created_at = str(doc.get("createdAt") or "")
    # When it was closed: stamped as it closes, cleared when it is opened again.
    if incident.status == "closed":
        incident.closed_at = incident.closed_at or now_iso()
    else:
        incident.closed_at = None


def _source(db: OrmSession, connection_id: str | None, known: dict | None = None) -> dict[str, Any] | None:
    """What brought an incident in: the instance, its connector and the connector's logo; None for an
    incident made here. ``known`` is ``logos_by_connection`` when many incidents are shown."""
    if not connection_id:
        return None
    from ..automation import connector_actions

    found = (known if known is not None else connector_actions.logos_by_connection(db)).get(connection_id)
    # Its instance was deleted: it still came from outside, and nothing more is known.
    return found or {"connection": "", "connector": "", "logo": None}


def _shown(row: Incident, source: dict[str, Any] | None = None) -> dict[str, Any]:
    """The document as the API gives it: with the incident's type and its custom fields, which
    are kept beside the document and written only through the field registry."""
    return {
        **(row.doc or {}),
        "source": source,
        # ``id`` is the uuid; ``uuid`` says so by name. ``number`` is what people call it by.
        "uuid": row.id,
        "number": row.number,
        "type": row.type_id or field_registry.UNCLASSIFIED,
        "fields": field_registry.stored_fields(row),
    }


def _summary(r: Any, source: dict[str, Any] | None) -> dict[str, Any]:
    """The light row of a list: what the columns of ``incidents`` hold, nothing of the document."""
    return {
        "id": r.id,
        "number": r.number,
        "name": r.name,
        "host": r.host,
        "username": r.username,
        "os": r.os,
        "ticketId": r.ticket_id,
        "severity": r.severity or None,
        "status": r.status or "open",
        "assignee": r.assignee,
        "hasMail": bool(r.has_mail),
        "type": r.type_id or field_registry.UNCLASSIFIED,
        # What brought it in, with the logo of its connector; null for one made here.
        "source": source,
        "createdAt": r.created_at,
        "updatedAt": r.updated_at,
    }


def _own_number(doc: dict[str, Any], *, new: bool) -> None:
    """The number is given by this Nik, never by the document. One that comes with a number (an
    export of another Nik) keeps it as ``importedNumber``, to be found by it."""
    given = doc.pop("number", None)
    doc.pop("uuid", None)
    if new and isinstance(given, int) and not isinstance(given, bool) and given > 0:
        doc.setdefault("importedNumber", given)


def _field_changes(partial: dict[str, Any]) -> dict[str, Any]:
    """Take ``type`` and ``fields`` out of what a client sent: they go through the registry."""
    changes: dict[str, Any] = {}
    if "fields" in partial:
        sent = partial.pop("fields")
        if sent is not None and not isinstance(sent, dict):
            raise HTTPException(status_code=400, detail="fields is an object: a value for each name")
        changes.update(sent or {})
    if "type" in partial:
        changes["type"] = partial.pop("type")
    return changes


def _set_fields(db: OrmSession, row: Incident, changes: dict[str, Any], caller: Principal) -> list[str]:
    try:
        return field_registry.update(db, row, changes, caller.actor, f"user:{caller.actor}")
    except field_registry.FieldError as error:
        raise HTTPException(status_code=400, detail=error.message) from None


def _audit(db: OrmSession, caller: Principal, action: str, details: str, incident: Incident | None = None) -> None:
    """Record an audit entry for the caller, a session or a key alike."""
    audit.record(db, caller.actor, action, details, incident)


def _get_or_404(db: OrmSession, incident_id: str, *, lock: bool = False) -> Incident:
    """The incident; with ``lock`` it is locked for writing and read fresh."""
    row = lock_incident(db, incident_id) if lock else db.get(Incident, incident_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return row


def _etag(rev: int | None) -> str:
    """Version tag of an incident: its revision, one more at every write."""
    return f'"{rev or 0}"'


def _idempotent_replay(db: OrmSession, key: str | None):
    """Return the stored response for a seen Idempotency-Key, or None."""
    if not key:
        return None
    rec = db.get(IdempotencyRecord, key)
    if rec is None:
        return None
    return JSONResponse(content=json.loads(rec.response_json), status_code=rec.status_code)


def _idempotent_save(db: OrmSession, key: str | None, status_code: int, body: Any) -> None:
    if not key or db.get(IdempotencyRecord, key) is not None:
        return
    db.add(IdempotencyRecord(key=key, created_at=now_iso(), status_code=status_code, response_json=json.dumps(body)))
    db.commit()


@router.get("")
def list_incidents(
    response: Response,
    caller: Principal = Depends(reader_principal),
    db: OrmSession = Depends(get_db),
    limit: int | None = Query(None, ge=1, le=1000, description="Page size (default: all)."),
    offset: int = Query(0, ge=0),
    q: str | None = Query(
        None,
        max_length=2000,
        description='A query: `status:open severity:>=high owner:""`; plain words match name, host, user, ticket.',
    ),
    host: str | None = Query(None),
    username: str | None = Query(None),
    state: str | None = Query(
        None, alias="status", pattern="^(open|in_progress|closed)$", description="Only incidents in this status."
    ),
    assignee: str | None = Query(None, description="Only incidents assigned to this user; empty = unassigned."),
    view: str = Query(
        "full", pattern="^(full|summary)$", description="full = whole documents; summary = light rows (no data)."
    ),
    fields: str | None = Query(
        None,
        max_length=1500,
        description="With view=summary: names of fields of the registry, comma-separated; each row then "
        "carries `fields` with the values it holds for them.",
    ),
) -> dict:
    """List incidents newest-updated first, filterable and paginated.

    ``q`` takes the query language (``GET /api/query/schema?entity=incidents``
    lists the fields); a query that cannot be read is answered ``422`` with
    the position and the reason.

    ``view=summary`` returns light rows (id/name/host/username/os/ticketId/severity/
    status/assignee/hasMail/timestamps) WITHOUT
    the heavy document body — use it for lists at scale, then fetch a single
    incident's full document from ``GET /incidents/{id}``. Backward compatible:
    with no params it returns every full document. Total count is also in the
    ``X-Total-Count`` header.
    """
    # `q` is the query language (app/query); the older parameters below are kept
    # for API clients and add their conditions to it.
    conditions = query.sql("incidents", q, caller, db=db) if q and q.strip() else []
    if conditions:
        query.statement_timeout(db)
    if host:
        conditions.append(Incident.host.ilike(f"%{host}%"))
    if username:
        conditions.append(Incident.username.ilike(f"%{username}%"))
    if state:
        conditions.append(Incident.status == state)
    if assignee is not None:
        conditions.append(func.lower(Incident.assignee) == assignee.strip().lower())

    total = db.scalar(select(func.count()).select_from(Incident).where(*conditions)) or 0
    response.headers["X-Total-Count"] = str(total)
    order = Incident.updated_at.desc()
    from ..automation import connector_actions

    sources = connector_actions.logos_by_connection(db)

    if view == "summary" and fields and fields.strip():
        # The columns of a list that are fields of the registry: the rows are read with what they
        # hold for those names, and still without their documents.
        wanted = [name for name in dict.fromkeys(part.strip() for part in fields.split(",")) if name][:30]
        stmt = select(Incident).options(defer(Incident.doc)).where(*conditions).order_by(order)
        stmt = stmt.offset(offset).limit(limit) if limit is not None else stmt.offset(offset)
        incidents = []
        for row in db.scalars(stmt).all():
            held = field_registry.stored_fields(row)
            incidents.append(
                {
                    **_summary(row, _source(db, row.source_connection_id, sources)),
                    "fields": {name: held[name] for name in wanted if name in held},
                }
            )
    elif view == "summary":
        stmt = (
            select(
                Incident.id,
                Incident.number,
                Incident.name,
                Incident.host,
                Incident.username,
                Incident.os,
                Incident.ticket_id,
                Incident.severity,
                Incident.status,
                Incident.assignee,
                Incident.has_mail,
                Incident.created_at,
                Incident.updated_at,
                Incident.type_id,
                Incident.source_connection_id,
            )
            .where(*conditions)
            .order_by(order)
        )
        stmt = stmt.offset(offset).limit(limit) if limit is not None else stmt.offset(offset)
        incidents = [_summary(r, _source(db, r.source_connection_id, sources)) for r in db.execute(stmt).all()]
    else:
        stmt = select(Incident).where(*conditions).order_by(order)
        stmt = stmt.offset(offset).limit(limit) if limit is not None else stmt.offset(offset)
        incidents = [_shown(row, _source(db, row.source_connection_id, sources)) for row in db.scalars(stmt).all()]

    return {"incidents": incidents, "total": total}


@router.get("/by-number/{number}")
def incident_by_number(
    number: int,
    _caller: Principal = Depends(reader_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """The incident people call ``#number``: its uuid (``id``), its number and its name. The
    address of an incident and every other route take the uuid."""
    row = db.execute(select(Incident.id, Incident.number, Incident.name).where(Incident.number == number)).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return {"id": row.id, "uuid": row.id, "number": row.number, "name": row.name}


@router.get("/{incident_id}", response_model=None)
def get_incident(
    incident_id: str,
    response: Response,
    _caller: Principal = Depends(reader_principal),
    db: OrmSession = Depends(get_db),
    if_none_match: str | None = Header(None, alias="If-None-Match"),
) -> dict | Response:
    """Return a single incident's full document; 404 if missing.

    The response carries an ``ETag`` (the incident version); pass it back as
    ``If-Match`` on PATCH for optimistic concurrency, or as ``If-None-Match``
    here to get ``304 Not Modified`` (no body) while your copy is current. The
    304 check reads only the version column, never the document body.
    """
    if if_none_match is not None:
        rev = db.scalar(select(Incident.rev).where(Incident.id == incident_id))
        if rev is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        etag = _etag(rev)
        if etag in {tag.strip() for tag in if_none_match.split(",")}:
            return Response(status_code=status.HTTP_304_NOT_MODIFIED, headers={"ETag": etag})
    row = _get_or_404(db, incident_id)
    # A document still in the pre-2.0.0 browser shape (e.g. a database that was
    # not migrated) is converted and saved once, so clients always diff their
    # merge patches against the current shape.
    doc = dict(row.doc or {})
    if normalize_browser_data(doc):
        row = _get_or_404(db, incident_id, lock=True)
        doc = dict(row.doc or {})
        normalize_browser_data(doc)
        row.doc = doc
        flag_modified(row, "doc")
        db.commit()
    response.headers["ETag"] = _etag(row.rev)
    return _shown(row, _source(db, row.source_connection_id))


@router.get("/{incident_id}/quick")
def quick_view(
    incident_id: str,
    _caller: Principal = Depends(reader_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """What the quick view of the list shows of an incident, without its evidence: its type and
    ``fields``, ``counts`` (how much evidence it holds), its ``timers`` and ``last``, the last three
    entries of its War Room, oldest first."""
    return incident_quick.quick(db, _get_or_404(db, incident_id))


@router.post("", status_code=status.HTTP_201_CREATED)
def create_incident(
    response: Response,
    doc: dict[str, Any] = Body(...),
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
    background_tasks: BackgroundTasks = None,
) -> dict:
    """Create (or upsert) an incident from a full client-built document.

    The server stamps ``createdBy`` from the caller (username, or ``api:<label>``).
    The response carries the new incident's ``ETag``.
    """
    doc = dict(doc)
    # Accept pre-2.0.0 documents (e.g. old exports): one profile per browser.
    normalize_browser_data(doc)
    # Guarantee a v4 UUID id: use the client's if present, else generate one.
    incident_id = doc.get("id") or str(uuid.uuid4())
    doc["id"] = incident_id
    doc["createdBy"] = caller.actor
    # Its type and its custom fields are not part of the document: they are checked by the registry.
    field_changes = _field_changes(doc)

    existing = lock_incident(db, str(incident_id))
    _own_number(doc, new=existing is None)
    if existing is None:
        incident = Incident(id=str(incident_id), doc=doc)
        _sync_columns(incident)
        db.add(incident)
    else:
        existing.doc = doc
        _sync_columns(existing)
        incident = existing
    db.flush()
    _timers(db, incident)
    reindex_incident(db, incident)

    _audit(db, caller, "incident.create", f'Created incident "{doc.get("name") or incident_id}"', incident)
    # For the playbooks: in the transaction of the change, so the event exists exactly when it does.
    triggers.incident_changed(db, incident, "incident.created")
    if field_changes:
        _set_fields(db, incident, field_changes, caller)
    db.commit()
    emit(db, background_tasks, "incident.created", {"id": incident_id, "name": doc.get("name")})
    response.headers["ETag"] = _etag(incident.rev)
    return _shown(incident)


MERGE_PATCH_MEDIA_TYPE = "application/merge-patch+json"


def merge_patch(target: Any, patch: Any) -> Any:
    """Apply an RFC 7396 JSON Merge Patch to ``target`` and return the result.

    Objects are merged recursively, ``null`` removes a member, and any other
    value (arrays included) replaces the target value. ``target`` is not mutated.
    """
    if not isinstance(patch, dict):
        return patch
    result = dict(target) if isinstance(target, dict) else {}
    for key, value in patch.items():
        if value is None:
            result.pop(key, None)
        else:
            result[key] = merge_patch(result.get(key), value)
    return result


@router.patch("/{incident_id}")
def patch_incident(
    incident_id: str,
    response: Response,
    partial: dict[str, Any] = Body(...),
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
    background_tasks: BackgroundTasks = None,
    if_match: str | None = Header(None, alias="If-Match"),
    content_type: str | None = Header(None, alias="Content-Type"),
) -> dict:
    """Update an incident document, in one of two modes chosen by ``Content-Type``.

    - ``application/json`` (default): shallow-merge the given top-level keys —
      each key replaces the stored value as a whole.
    - ``application/merge-patch+json``: apply an RFC 7396 JSON Merge Patch —
      nested objects are merged recursively and ``null`` removes a member, so
      a client can send only the part of ``data`` that actually changed.

    Any incident field can be edited this way: ``host``, ``username``, ``os``,
    ``suspiciousStart``/``suspiciousEnd``, ``notes``, ``flags``, ``data``, …

    Optimistic concurrency: if an ``If-Match`` header is sent it must equal the
    incident's current ``ETag`` (from GET, or from the last write), else
    ``412 Precondition Failed`` — so a stale writer can't silently clobber a
    newer version: it reads the incident again, merges and retries. The
    check and the write happen under the incident's row lock, and the
    response carries the new ``ETag``.
    """
    row = _get_or_404(db, incident_id, lock=True)
    if if_match is not None and if_match.strip() != _etag(row.rev):
        raise HTTPException(status_code=412, detail="Incident was modified by someone else (ETag mismatch)")
    # The type and the custom fields first, through the registry; what is left is the document.
    partial = dict(partial)
    field_changes = _field_changes(partial)
    was_closed = row.status == "closed"
    if field_changes:
        _set_fields(db, row, field_changes, caller)
        if not partial:
            db.commit()
            emit(db, background_tasks, "incident.updated", {"id": incident_id, "name": row.name})
            response.headers["ETag"] = _etag(row.rev)
            return _shown(row, _source(db, row.source_connection_id))
    previous = row.doc or {}
    media_type = (content_type or "").split(";")[0].strip().lower()
    if media_type == MERGE_PATCH_MEDIA_TYPE:
        merged = merge_patch(row.doc or {}, partial)
        merged["id"] = row.id
    else:
        merged = dict(row.doc or {})
        for key, value in partial.items():
            merged[key] = value
    normalize_browser_data(merged)
    row.doc = merged
    flag_modified(row, "doc")
    _sync_columns(row)
    _timers(db, row)
    # Who set each field of the document last, for what a fetch or a mirror may write over.
    edited = [
        name
        for key, name in field_registry.DOC_FIELDS.items()
        if name not in ("created", "modified") and previous.get(key) != merged.get(key)
    ]
    if edited:
        import time

        from .. import mirror

        db.flush()
        field_registry.note_source(db, row, edited, f"user:{caller.actor}")
        mirror.on_fields_changed(db, row, edited, f"user:{caller.actor}", time.time())
    if row.status == "closed" and not was_closed:
        problem = field_registry.closing_problem(db, row)
        if problem:
            raise HTTPException(status_code=400, detail=problem)
    # Flags, notes and the suspicious window leave the indicators unchanged.
    if "data" in partial:
        reindex_incident(db, row)
    # What the patch means (a flag, a note, the status, an evidence file), one entry each.
    for action, details in audit.describe_patch(previous, merged, partial):
        _audit(db, caller, action, details, row)
    changed = [key for key in partial if previous.get(key) != merged.get(key)]
    if changed:
        triggers.incident_changed(db, row, "incident.updated", changed)
    db.commit()
    emit(db, background_tasks, "incident.updated", {"id": incident_id, "name": merged.get("name")})
    response.headers["ETag"] = _etag(row.rev)
    return _shown(row, _source(db, row.source_connection_id))


@router.delete("/{incident_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_incident(
    incident_id: str,
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
    background_tasks: BackgroundTasks = None,
):
    """Delete an incident (idempotent-ish; 204 regardless if it existed)."""
    row = lock_incident(db, incident_id)
    if row is not None:
        name = (row.doc or {}).get("name") or incident_id
        _audit(db, caller, "incident.delete", f'Deleted incident "{name}"', row)
        db.execute(delete(IocEntry).where(IocEntry.incident_id == incident_id))
        from .artifacts import remove_incident_artifacts
        from .network import remove_incident_captures

        # What only this incident references goes with it; shared artifacts stay.
        remove_incident_artifacts(db, incident_id)
        remove_incident_captures(db, incident_id)
        # Its context and its War Room go with it.
        from .. import context as incident_context
        from ..core.models import WarRoomEntry

        incident_context.forget(db, incident_id)
        db.execute(delete(WarRoomEntry).where(WarRoomEntry.incident_id == incident_id))
        db.delete(row)
        db.commit()
        emit(db, background_tasks, "incident.deleted", {"id": incident_id, "name": name})
    # 204 No Content


# ---------------------------------------------------------------------------
# File upload (server-side parsing) — API clients send raw artifact files
# ---------------------------------------------------------------------------
_UPLOAD_ACTIONS = {
    "browser": "browser.upload",
    "commands": "command.upload",
    "endpoint": "endpoint.upload",
    "eventlogs": "eventlog.upload",
}


def _process_upload_job(job_id, incident_id, tab, params, data, filename, actor):
    """Background worker for an async upload: parse + merge, then record result.

    Runs after the 202 response, with its OWN DB session (the request's is
    already closed). Sets the Job to done/error and fires the webhook.
    """
    db = SessionLocal()
    try:
        job = db.get(Job, job_id)
        if job is not None:
            job.status = "running"
            job.updated_at = now_iso()
            db.commit()
        # Locked while the file is parsed into the document: nothing saved
        # meanwhile can be lost, it waits for this write and merges after it.
        row = lock_incident(db, incident_id)
        if row is None:
            raise ValueError("Incident not found")
        doc = dict(row.doc or {})
        summary = apply_upload(doc, tab, params, data, filename)
        doc["updatedAt"] = now_iso()
        row.doc = doc
        flag_modified(row, "doc")
        _sync_columns(row)
        reindex_incident(db, row)
        db.add(
            AuditEntry(
                id=str(uuid.uuid4()),
                at=now_iso(),
                actor=actor,
                action=_UPLOAD_ACTIONS.get(tab, "upload"),
                target=(doc.get("name")),
                details=f"Uploaded {filename} → {summary['target']} ({summary['rows']} rows)",
                incident_id=incident_id,
                incident_name=doc.get("name"),
            )
        )
        job = db.get(Job, job_id)
        if job is not None:
            job.status = "done"
            job.result_json = json.dumps(summary)
            job.updated_at = now_iso()
        db.commit()
        emit_now(db, "upload.completed", {"incidentId": incident_id, **summary})
    except Exception as exc:  # pragma: no cover - defensive
        db.rollback()
        job = db.get(Job, job_id)
        if job is not None:
            job.status = "error"
            job.error = str(exc)
            job.updated_at = now_iso()
            db.commit()
    finally:
        db.close()


@router.post("/{incident_id}/upload", tags=["incidents/upload"])
async def upload_artifact(
    incident_id: str,
    file: UploadFile = File(..., description="The raw artifact file."),
    tab: str = Query(..., description="browser | commands | endpoint | eventlogs"),
    browser: str | None = Query(None, description="Browser id (tab=browser), e.g. chrome/firefox"),
    profile: str | None = Query(
        None, description='Browser profile NAME (tab=browser); created if missing. Default: "Default".'
    ),
    source: str | None = Query(None, description="Source key (browser/endpoint), e.g. history"),
    shell: str | None = Query(None, description="Shell id (tab=commands), e.g. bash"),
    category: str | None = Query(None, description="Category id (tab=endpoint), e.g. persistence"),
    async_: bool = Query(False, alias="async", description="Return 202 + a jobId; parse in the background."),
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
    background_tasks: BackgroundTasks = None,
    idempotency_key: str | None = Header(None, alias="Idempotency-Key"),
):
    """Upload a raw artifact file; the server parses it and merges the result.

    Routing (query params) mirrors the app's tabs:
    - `tab=browser&browser=chrome&source=history` → a Chromium `History` DB
      (add `&profile=Work` for a non-default browser profile)
    - `tab=commands&shell=bash` → a `.bash_history`
    - `tab=endpoint&category=persistence&source=cron` → a cron file / tool CSV
    - `tab=eventlogs` → a Windows `.evtx` log (curated event IDs are kept)

    With `async=true` the file is parsed in the background: the call returns
    `202 { jobId }` immediately — poll `GET /api/jobs/{jobId}` for the result
    (good for large files). Send an `Idempotency-Key` header to make retries safe.
    """
    replay = _idempotent_replay(db, idempotency_key)
    if replay is not None:
        return replay
    _get_or_404(db, incident_id)
    data = await read_upload(file, settings.ARTIFACT_MAX_MB, "file")
    params = {"browser": browser, "profile": profile, "shell": shell, "category": category, "source": source}

    if async_:
        now = now_iso()
        job = Job(
            id=str(uuid.uuid4()),
            kind="upload",
            status="queued",
            incident_id=incident_id,
            created_at=now,
            updated_at=now,
        )
        db.add(job)
        db.commit()
        background_tasks.add_task(
            _process_upload_job, job.id, incident_id, tab, params, data, file.filename or "upload", caller.actor
        )
        return JSONResponse({"jobId": job.id, "status": "queued"}, status_code=202)

    row = _get_or_404(db, incident_id, lock=True)
    doc = dict(row.doc or {})
    try:
        # Parsing a database or an event log takes a while: off the event loop.
        summary = await run_in_threadpool(apply_upload, doc, tab, params, data, file.filename or "upload")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    doc["updatedAt"] = now_iso()
    row.doc = doc
    flag_modified(row, "doc")
    _sync_columns(row)
    reindex_incident(db, row)
    _audit(
        db,
        caller,
        _UPLOAD_ACTIONS.get(tab, "upload"),
        f"Uploaded {file.filename} → {summary['target']} ({summary['rows']} rows)",
        row,
    )
    db.commit()
    emit(db, background_tasks, "upload.completed", {"incidentId": incident_id, **summary})
    _idempotent_save(db, idempotency_key, 200, summary)
    return summary


# ---------------------------------------------------------------------------
# Notes (dedicated API endpoints; the frontend uses PATCH doc.notes directly)
# ---------------------------------------------------------------------------
def _notes(doc: dict) -> list:
    notes = doc.get("notes")
    return notes if isinstance(notes, list) else []


def _save_doc(db: OrmSession, row: Incident, doc: dict) -> None:
    doc["updatedAt"] = now_iso()
    row.doc = doc
    flag_modified(row, "doc")
    _sync_columns(row)


@router.post("/{incident_id}/notes", tags=["incidents/notes"], status_code=status.HTTP_201_CREATED)
def add_note(
    incident_id: str,
    body: NoteIn,
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
    background_tasks: BackgroundTasks = None,
    idempotency_key: str | None = Header(None, alias="Idempotency-Key"),
) -> dict:
    """Append a free-form note to the incident timeline.

    Send an ``Idempotency-Key`` header to make retries safe (a repeated request
    returns the first result instead of adding a second note).
    """
    replay = _idempotent_replay(db, idempotency_key)
    if replay is not None:
        return replay
    text = body.text.strip()
    if not text:
        raise HTTPException(status_code=400, detail="Note text is required")
    row = _get_or_404(db, incident_id, lock=True)
    doc = dict(row.doc or {})
    now = now_iso()
    note = {"id": str(uuid.uuid4()), "text": text, "createdAt": now, "updatedAt": now, "author": caller.actor}
    doc["notes"] = [*_notes(doc), note]
    _save_doc(db, row, doc)
    _audit(db, caller, "note.add", "Added a note", row)
    db.commit()
    emit(db, background_tasks, "note.added", {"incidentId": incident_id, "noteId": note["id"]})
    _idempotent_save(db, idempotency_key, 201, note)
    return note


@router.patch("/{incident_id}/notes/{note_id}", tags=["incidents/notes"])
def edit_note(
    incident_id: str,
    note_id: str,
    body: NoteIn,
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Edit the text of an existing note."""
    text = body.text.strip()
    if not text:
        raise HTTPException(status_code=400, detail="Note text is required")
    row = _get_or_404(db, incident_id, lock=True)
    doc = dict(row.doc or {})
    notes = _notes(doc)
    target = next((n for n in notes if n.get("id") == note_id), None)
    if target is None:
        raise HTTPException(status_code=404, detail="Note not found")
    doc["notes"] = [{**n, "text": text, "updatedAt": now_iso()} if n.get("id") == note_id else n for n in notes]
    _save_doc(db, row, doc)
    _audit(db, caller, "note.update", "Edited a note", row)
    db.commit()
    return next(n for n in doc["notes"] if n.get("id") == note_id)


@router.delete("/{incident_id}/notes/{note_id}", tags=["incidents/notes"], status_code=status.HTTP_204_NO_CONTENT)
def delete_note(
    incident_id: str,
    note_id: str,
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
):
    """Remove a note from the incident."""
    row = _get_or_404(db, incident_id, lock=True)
    doc = dict(row.doc or {})
    notes = _notes(doc)
    if not any(n.get("id") == note_id for n in notes):
        raise HTTPException(status_code=404, detail="Note not found")
    doc["notes"] = [n for n in notes if n.get("id") != note_id]
    _save_doc(db, row, doc)
    _audit(db, caller, "note.remove", "Removed a note", row)
    db.commit()
    # 204 No Content

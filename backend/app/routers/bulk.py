"""Bulk actions: one action on many incidents, artifacts or indicators (``app/bulk.py``).

The three lists have the same two routes:

- ``POST /api/<things>/bulk/plan`` says what an action would do to a selection,
  and changes nothing;
- ``POST /api/<things>/bulk`` makes the job. A small one is done before the
  answer (``200``, with its result); a larger one goes on in the background
  (``202``) and is read at ``GET /api/bulk/{id}``.

``<things>`` is ``incidents``, ``artifacts`` or ``iocs``. The body is
``{action, params, ids | query, confirm}``: ``ids`` names the items one by
one, ``query`` is what the list was filtered by (everything it keeps is
selected). With ``query`` the count the plan gave is sent back as
``confirm.count``; an action that cannot be undone, or that closes many
incidents, wants ``confirm.typed`` too, the words the plan gives.
"""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from .. import bulk, bulk_incidents
from ..core import audit
from ..core.db import get_db
from ..core.models import BulkJob
from ..core.permissions import ADMIN, AUDIT_READ, AUTOMATION_RUN, WRITE
from ..core.security import Principal, admin_principal, reader_principal, require

router = APIRouter(tags=["bulk actions"])

# Whoever may change things, or run playbooks: each action then asks for its own permission.
actor_principal = require(WRITE, AUTOMATION_RUN)
# The address of a list → its name in bulk.py.
LISTS = {"incidents": "incidents", "artifacts": "artifacts", "iocs": "indicators"}
Things = Literal["incidents", "artifacts", "iocs"]
IDS_MAX = 50_000


class Confirm(BaseModel):
    count: int | None = None
    typed: str | None = Field(default=None, max_length=80)


class BulkIn(BaseModel):
    action: str = Field(min_length=1, max_length=40)
    params: dict[str, Any] = Field(default_factory=dict)
    ids: list[str] | None = Field(default=None, max_length=IDS_MAX)
    query: dict[str, Any] | None = None
    confirm: Confirm | None = None


class SettingsIn(BaseModel):
    maxItems: int | None = None
    inlineItems: int | None = None
    typedAbove: int | None = None


def _refused(error: bulk.BulkError) -> HTTPException:
    return HTTPException(status_code=error.status, detail=error.message)


def _job(db: OrmSession, job_id: str, caller: Principal) -> BulkJob:
    """A job, for who asked for it and for who reads everybody's (an administrator, the audit)."""
    job = db.get(BulkJob, job_id)
    if job is None or (job.actor != caller.actor and not caller.has(ADMIN, AUDIT_READ)):
        raise HTTPException(status_code=404, detail="There is no such bulk job")
    return job


def _plan(things: str, body: BulkIn, caller: Principal, db: OrmSession) -> dict:
    try:
        return bulk.plan(db, LISTS[things], body.action, body.params, caller, body.ids, body.query)
    except bulk.BulkError as error:
        raise _refused(error) from None


def _start(things: str, body: BulkIn, caller: Principal, db: OrmSession, background_tasks: BackgroundTasks):
    confirm = body.confirm.model_dump() if body.confirm else None
    try:
        job = bulk.start(db, LISTS[things], body.action, body.params, caller, body.ids, body.query, confirm)
    except bulk.BulkError as error:
        db.rollback()
        raise _refused(error) from None
    return _go(db, job, background_tasks)


def _go(db: OrmSession, job: BulkJob, background_tasks: BackgroundTasks):
    if job.total <= bulk.config(db)["inlineItems"]:
        job_id = job.id
        bulk.run_held(job_id)
        db.expire_all()
        job = db.get(BulkJob, job_id)
        return {**bulk.out(db, job), "items": bulk.items_out(db, job, limit=500)}
    background_tasks.add_task(bulk.run_held, job.id)
    return JSONResponse(bulk.out(db, job), status_code=202)


# One pair of routes for each list, at the address of the list.
@router.post("/incidents/bulk/plan")
def plan_incidents(
    body: BulkIn, caller: Principal = Depends(actor_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """What a bulk action on incidents would do: ``{count, applies, notes, typed, limit, over,
    inline, label, refs}``. ``query`` is ``{q}``, the query of the list. Nothing is changed."""
    return _plan("incidents", body, caller, db)


@router.post("/incidents/bulk", response_model=None)
def bulk_incidents_route(
    body: BulkIn,
    background_tasks: BackgroundTasks,
    caller: Principal = Depends(actor_principal),
    db: OrmSession = Depends(get_db),
):
    """Do one action to many incidents. Actions: ``set`` (``params.changes``: a value for each
    field, as ``PATCH /incidents/{id}/fields`` takes them; closing is ``status: closed`` with its
    reason), ``tags`` (``add``, ``remove``), ``delete``, ``playbook`` (``playbook``: its id),
    ``mirror`` (``direction``: in, out, both, none), ``find_indicators``."""
    return _start("incidents", body, caller, db, background_tasks)


@router.post("/artifacts/bulk/plan")
def plan_artifacts(
    body: BulkIn, caller: Principal = Depends(actor_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """What a bulk action on artifacts would do. ``query`` is ``{q, kind, tag, mine, linked}``, as
    the list takes them."""
    return _plan("artifacts", body, caller, db)


@router.post("/artifacts/bulk", response_model=None)
def bulk_artifacts_route(
    body: BulkIn,
    background_tasks: BackgroundTasks,
    caller: Principal = Depends(actor_principal),
    db: OrmSession = Depends(get_db),
):
    """Do one action to many artifacts. Actions: ``tags`` (``add``, ``remove``), ``reanalyse``,
    ``link`` and ``unlink`` (``incident``: its id), ``expiry`` (``expiresAt``: a day, or null),
    ``delete``."""
    return _start("artifacts", body, caller, db, background_tasks)


@router.post("/iocs/bulk/plan")
def plan_indicators(
    body: BulkIn, caller: Principal = Depends(actor_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """What a bulk action on indicators would do; for ``check``, how many requests it costs each
    source. An indicator is named ``type:value``; ``query`` is the filter of the Indicators page
    (``{q, type, verdict, origin, analysis, list, expired}``), or ``{incident}`` for those of an
    incident, with the same filter."""
    return _plan("iocs", body, caller, db)


@router.post("/iocs/bulk", response_model=None)
def bulk_indicators_route(
    body: BulkIn,
    background_tasks: BackgroundTasks,
    caller: Principal = Depends(actor_principal),
    db: OrmSession = Depends(get_db),
):
    """Do one action to many indicators. Actions: ``check`` (``force``), ``tags`` (``add``,
    ``remove``), ``tlp`` (``tlp``), ``list_add`` and ``list_remove`` (``list``: its id),
    ``allowlist``, ``incident_remove`` (``incident``: its id), ``delete``."""
    return _start("iocs", body, caller, db, background_tasks)


# --------------------------------------------------------------------------- #
# The jobs                                                                    #
# --------------------------------------------------------------------------- #
@router.get("/bulk")
def list_jobs(
    everybody: bool = Query(False, description="Every account's jobs (an administrator, or who reads the audit log)."),
    limit: int = Query(50, ge=1, le=200),
    caller: Principal = Depends(reader_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """The bulk jobs of the caller, the newest first; ``actions`` is what each list offers."""
    wanted = select(BulkJob).order_by(BulkJob.created_at.desc()).limit(limit)
    if not (everybody and caller.has(ADMIN, AUDIT_READ)):
        wanted = wanted.where(BulkJob.actor == caller.actor)
    return {
        "jobs": [bulk.out(db, job) for job in db.scalars(wanted)],
        "actions": {
            name: [
                {"name": action.name, "label": action.label, "permission": action.permission}
                for action in listing.actions.values()
            ]
            for name, listing in bulk.listings().items()
        },
        "limits": bulk.config(db),
    }


@router.get("/bulk/fields")
def settable_fields(_caller: Principal = Depends(reader_principal), db: OrmSession = Depends(get_db)) -> dict:
    """The fields of an incident a bulk action may set, with their type and their choices."""
    return {"fields": bulk_incidents.settable(db)}


@router.get("/bulk/settings")
def get_settings(_caller: Principal = Depends(admin_principal), db: OrmSession = Depends(get_db)) -> dict:
    """How many items a job takes, up to how many are done in the request, and above how many a
    closing is confirmed by typing."""
    return {**bulk.config(db), "defaults": dict(bulk.DEFAULTS)}


@router.put("/bulk/settings")
def put_settings(
    body: SettingsIn, caller: Principal = Depends(admin_principal), db: OrmSession = Depends(get_db)
) -> dict:
    try:
        doc = bulk.save_config(db, body.model_dump())
    except bulk.BulkError as error:
        raise _refused(error) from None
    said = ", ".join(f"{key} {value}" for key, value in doc.items())
    audit.record(db, caller.actor, "bulk.settings", f"Changed the limits of the bulk actions: {said}")
    db.commit()
    return {**doc, "defaults": dict(bulk.DEFAULTS)}


@router.get("/bulk/{job_id}")
def get_job(job_id: str, caller: Principal = Depends(reader_principal), db: OrmSession = Depends(get_db)) -> dict:
    """A bulk job: its state, how many of its items are done, skipped, refused, failed, pending."""
    return bulk.out(db, _job(db, job_id, caller))


@router.get("/bulk/{job_id}/items")
def get_items(
    job_id: str,
    state: Literal["pending", "done", "skipped", "refused", "failed"] | None = Query(None),
    offset: int = Query(0, ge=0),
    limit: int = Query(200, ge=1, le=1000),
    caller: Principal = Depends(reader_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """What became of each item of a job, in the order of the selection."""
    job = _job(db, job_id, caller)
    return {"items": bulk.items_out(db, job, state, offset, limit)}


@router.get("/bulk/{job_id}/result.csv")
def get_csv(job_id: str, caller: Principal = Depends(reader_principal), db: OrmSession = Depends(get_db)) -> Response:
    """What the job did, item by item, as CSV: ``item, name, result, note``."""
    job = _job(db, job_id, caller)
    return Response(
        bulk.result_csv(db, job),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="bulk-{job.id[:8]}.csv"', "Cache-Control": "no-store"},
    )


@router.post("/bulk/{job_id}/cancel")
def cancel_job(job_id: str, caller: Principal = Depends(actor_principal), db: OrmSession = Depends(get_db)) -> dict:
    """Stop a running job after the item it is on: what was done stays."""
    job = _job(db, job_id, caller)
    bulk.cancel(db, job, caller.actor)
    db.commit()
    return bulk.out(db, job)


@router.post("/bulk/{job_id}/retry", response_model=None)
def retry_job(
    job_id: str,
    background_tasks: BackgroundTasks,
    caller: Principal = Depends(actor_principal),
    db: OrmSession = Depends(get_db),
):
    """A new job on what an ended one did not do: the items that failed, and those it never
    reached. Refused items are not tried again: the rule that refused them is still there."""
    job = _job(db, job_id, caller)
    try:
        made = bulk.retry(db, job, caller)
    except bulk.BulkError as error:
        db.rollback()
        raise _refused(error) from None
    return _go(db, made, background_tasks)

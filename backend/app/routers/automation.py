"""Automation: playbooks, their versions, runs and the general switch.

Who may do what (``core/permissions.py``): running a playbook, reading runs
and stopping one need ``automation.run`` (analysts have it); building
playbooks needs ``automation.edit``; the general switch is the admin's.
Every body is validated with explicit limits and every error is a fixed
sentence.
"""

from __future__ import annotations

import time
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm.attributes import flag_modified

from ..automation import catalog, engine, graph, state, triggers
from ..core import audit
from ..core.db import get_db
from ..core.models import Playbook, PlaybookVersion, Run, RunStep
from ..core.security import Principal, admin_principal, editor_principal, now_iso, runner_principal

router = APIRouter(prefix="/automation", tags=["automation"])

MAX_GRAPH_BYTES = 1_000_000


# --------------------------------------------------------------------------- #
# Bodies                                                                      #
# --------------------------------------------------------------------------- #
class PlaybookIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=2000)


class PlaybookPatch(BaseModel):
    """What ``PUT`` changes: any of the name, the description, the draft and the limits."""

    name: str | None = Field(default=None, min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=2000)
    draft: dict[str, Any] | None = None
    maxRunsPerHour: int | None = Field(default=None, ge=1, le=10_000)
    onePerObject: bool | None = None
    maxSeconds: int | None = Field(default=None, ge=60, le=7 * 86400)
    approvalDefault: bool | None = None


class VersionIn(BaseModel):
    """Save a version: of ``graph`` when given, of the draft otherwise."""

    graph: dict[str, Any] | None = None
    note: str = Field(default="", max_length=500)


class EnabledIn(BaseModel):
    enabled: bool


class RunIn(BaseModel):
    objectKind: Literal["", "incident"] = ""
    objectId: str = Field(default="", max_length=200)
    dryRun: bool = False
    inputs: dict[str, Any] = Field(default_factory=dict)


class StateIn(BaseModel):
    enabled: bool


class ImportIn(BaseModel):
    playbook: dict[str, Any]


# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #
def _size_ok(shape: dict | None) -> None:
    import json

    if shape is not None and len(json.dumps(shape)) > MAX_GRAPH_BYTES:
        raise HTTPException(status_code=413, detail="The playbook is too large")


def _get(db: OrmSession, playbook_id: str) -> Playbook:
    row = db.get(Playbook, playbook_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return row


def _name_taken(db: OrmSession, name: str, except_id: str | None = None) -> bool:
    found = db.scalars(select(Playbook).where(func.lower(Playbook.name) == name.strip().lower())).first()
    return found is not None and found.id != except_id


def _warnings(db: OrmSession, row: Playbook, shape: dict | None) -> list[str]:
    out = []
    if row.egress_mode == "any":
        out.append("any host")
    if row.data_allow:
        out.append("data opened")
    if shape and catalog.updates(db, shape):
        out.append("updates available")
    return out


def _summary(db: OrmSession, row: Playbook) -> dict[str, Any]:
    version = db.get(PlaybookVersion, (row.id, row.current_version)) if row.current_version else None
    shape = version.graph if version else None
    trigger = (graph.trigger_of(shape) or {}).get("config") or {} if shape else {}
    last = db.scalars(select(Run).where(Run.playbook_id == row.id).order_by(Run.started_at.desc()).limit(1)).first()
    since = engine.iso(time.time() - 7 * 86400)
    counts = dict(
        db.execute(
            select(Run.status, func.count())
            .where(Run.playbook_id == row.id, Run.started_at >= since)
            .group_by(Run.status)
        ).all()
    )
    return {
        "id": row.id,
        "name": row.name,
        "description": row.description,
        "enabled": bool(row.enabled),
        "builtin": bool(row.builtin),
        "version": row.current_version,
        "hasDraft": row.draft is not None,
        "trigger": triggers.describe(trigger),
        "triggerConfig": trigger,
        "lastRun": {"id": last.id, "status": last.status, "startedAt": last.started_at} if last else None,
        "week": {"done": counts.get("done", 0), "failed": counts.get("failed", 0), "total": sum(counts.values())},
        "warnings": _warnings(db, row, shape),
        "updatedAt": row.updated_at,
        "updatedBy": row.updated_by,
    }


def _detail(db: OrmSession, row: Playbook) -> dict[str, Any]:
    version = db.get(PlaybookVersion, (row.id, row.current_version)) if row.current_version else None
    shape = version.graph if version else None
    return {
        **_summary(db, row),
        "graph": shape,
        "draft": row.draft,
        "updates": catalog.updates(db, row.draft or shape or {}),
        "egressMode": row.egress_mode,
        "egressHosts": row.egress_hosts or [],
        "dataAllow": row.data_allow or [],
        "maxRunsPerHour": row.max_runs_per_hour,
        "onePerObject": bool(row.one_per_object),
        "maxSeconds": row.max_seconds,
        "approvalDefault": bool(row.approval_default),
        "createdAt": row.created_at,
        "createdBy": row.created_by,
    }


def _run_summary(run: Run) -> dict[str, Any]:
    return {
        "id": run.id,
        "playbookId": run.playbook_id,
        "playbook": (run.trigger or {}).get("playbook", ""),
        "version": run.version,
        "status": run.status,
        "trigger": (run.trigger or {}).get("kind", ""),
        "dryRun": bool(run.dry_run),
        "objectKind": run.object_kind,
        "objectId": run.object_id,
        "incidentId": run.incident_id,
        "artifactId": run.artifact_id,
        "startedAt": run.started_at,
        "finishedAt": run.finished_at,
        "startedBy": run.started_by,
        "error": run.error,
        "parentRunId": run.parent_run_id,
    }


def _step(step: RunStep) -> dict[str, Any]:
    return {
        "id": step.id,
        "node": step.node_id,
        "seq": step.seq,
        "kind": step.kind,
        "status": step.status,
        "port": step.port,
        "attempt": step.attempt,
        "maxAttempts": step.max_attempts,
        "itemIndex": step.item_index,
        "input": step.input,
        "output": step.output,
        "request": step.request,
        "error": step.error,
        "log": step.log,
        "waiting": (step.waiting or {}).get("kind"),
        "nextAt": step.next_at,
        "startedAt": step.started_at,
        "finishedAt": step.finished_at,
    }


def _problems(found: list[graph.Problem]) -> JSONResponse:
    return JSONResponse(
        status_code=422,
        content={
            "detail": "The playbook cannot be saved as a version yet: " + found[0].message,
            "problems": [problem.as_dict() for problem in found],
        },
    )


# --------------------------------------------------------------------------- #
# Playbooks                                                                   #
# --------------------------------------------------------------------------- #
@router.get("/playbooks")
def list_playbooks(_caller: Principal = Depends(runner_principal), db: OrmSession = Depends(get_db)) -> dict:
    """Every playbook, with its trigger, its last run, a week of counts and what to watch."""
    rows = db.scalars(select(Playbook).order_by(func.lower(Playbook.name))).all()
    return {"playbooks": [_summary(db, row) for row in rows], "workerAlive": state.worker_alive(db), **state.read(db)}


@router.post("/playbooks", status_code=status.HTTP_201_CREATED)
def create_playbook(
    body: PlaybookIn, caller: Principal = Depends(editor_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Create an empty playbook: off, with a draft that holds a trigger run by hand."""
    name = body.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="A name is required")
    if _name_taken(db, name):
        raise HTTPException(status_code=400, detail="A playbook with this name exists already")
    now = now_iso()
    row = Playbook(
        id=engine.new_id(),
        name=name,
        description=body.description.strip(),
        draft={
            "nodes": [
                {
                    "id": "start",
                    "kind": "trigger",
                    "name": "Trigger",
                    "position": {"x": 40, "y": 40},
                    "config": {"manual": True},
                }
            ],
            "edges": [],
        },
        created_at=now,
        created_by=caller.actor,
        updated_at=now,
        updated_by=caller.actor,
    )
    db.add(row)
    audit.record(db, caller.actor, "playbook.create", f'Created the playbook "{name}"', target=name)
    db.commit()
    return _detail(db, row)


@router.get("/playbooks/{playbook_id}")
def get_playbook(
    playbook_id: str, _caller: Principal = Depends(runner_principal), db: OrmSession = Depends(get_db)
) -> dict:
    return _detail(db, _get(db, playbook_id))


@router.put("/playbooks/{playbook_id}")
def update_playbook(
    playbook_id: str,
    body: PlaybookPatch,
    caller: Principal = Depends(editor_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Save the draft (it need not be valid) and the limits. Nothing a run uses changes
    until a version is saved, except the limits, which apply from the next run."""
    row = _get(db, playbook_id)
    changes = []
    if body.name is not None and body.name.strip() != row.name:
        name = body.name.strip()
        if not name:
            raise HTTPException(status_code=400, detail="A name is required")
        if _name_taken(db, name, except_id=row.id):
            raise HTTPException(status_code=400, detail="A playbook with this name exists already")
        changes.append(f'renamed from "{row.name}"')
        row.name = name
    if body.description is not None:
        row.description = body.description.strip()
    if body.draft is not None:
        _size_ok(body.draft)
        row.draft = body.draft
        flag_modified(row, "draft")
    for field, column in (
        ("maxRunsPerHour", "max_runs_per_hour"),
        ("onePerObject", "one_per_object"),
        ("maxSeconds", "max_seconds"),
        ("approvalDefault", "approval_default"),
    ):
        value = getattr(body, field)
        if value is not None and value != getattr(row, column):
            changes.append(f"{field} {getattr(row, column)} → {value}")
            setattr(row, column, value)
    row.updated_at = now_iso()
    row.updated_by = caller.actor
    if changes:
        audit.record(
            db,
            caller.actor,
            "playbook.update",
            f'Changed the playbook "{row.name}": {", ".join(changes)}',
            target=row.name,
        )
    db.commit()
    return _detail(db, row)


@router.delete("/playbooks/{playbook_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_playbook(
    playbook_id: str, caller: Principal = Depends(editor_principal), db: OrmSession = Depends(get_db)
) -> Response:
    """Delete a playbook with its versions and its runs. One with a run in progress is refused."""
    row = _get(db, playbook_id)
    active = db.scalar(
        select(func.count()).select_from(Run).where(Run.playbook_id == row.id, Run.status.notin_(engine.FINISHED))
    )
    if active:
        raise HTTPException(status_code=409, detail="A run of this playbook is in progress: stop it first")
    audit.record(db, caller.actor, "playbook.delete", f'Deleted the playbook "{row.name}"', target=row.name)
    # Its versions, runs, steps and schedule go with it (ON DELETE CASCADE).
    db.delete(row)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/playbooks/{playbook_id}/versions", status_code=status.HTTP_201_CREATED, response_model=None)
def save_version(
    playbook_id: str,
    body: VersionIn,
    caller: Principal = Depends(editor_principal),
    db: OrmSession = Depends(get_db),
) -> dict | JSONResponse:
    """Validate the graph and save it as the next version. ``422`` with every
    problem (the node and the field of each) when it is not valid yet."""
    row = _get(db, playbook_id)
    shape = body.graph if body.graph is not None else row.draft
    if shape is None:
        raise HTTPException(status_code=400, detail="There is no draft to save")
    _size_ok(shape)
    found = graph.validate(shape, catalog.Library(db), row.name)
    if found:
        return _problems(found)
    number = (
        db.scalar(select(func.max(PlaybookVersion.version)).where(PlaybookVersion.playbook_id == row.id)) or 0
    ) + 1
    now = now_iso()
    db.add(
        PlaybookVersion(
            playbook_id=row.id,
            version=number,
            graph=shape,
            note=body.note.strip(),
            created_at=now,
            created_by=caller.actor,
        )
    )
    row.current_version = number
    row.draft = None
    row.updated_at = now
    row.updated_by = caller.actor
    db.flush()
    triggers.sync_schedule(db, row, time.time())
    audit.record(
        db, caller.actor, "playbook.version", f'Saved version {number} of the playbook "{row.name}"', target=row.name
    )
    db.commit()
    return _detail(db, row)


@router.post("/playbooks/{playbook_id}/validate", response_model=None)
def validate_graph(
    playbook_id: str,
    body: VersionIn,
    _caller: Principal = Depends(editor_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """What keeps a graph (the one sent, or the draft) from being saved, without saving it."""
    row = _get(db, playbook_id)
    shape = body.graph if body.graph is not None else (row.draft or {})
    _size_ok(shape)
    return {"problems": [problem.as_dict() for problem in graph.validate(shape, catalog.Library(db), row.name)]}


@router.get("/playbooks/{playbook_id}/versions")
def list_versions(
    playbook_id: str, _caller: Principal = Depends(runner_principal), db: OrmSession = Depends(get_db)
) -> dict:
    row = _get(db, playbook_id)
    versions = db.scalars(
        select(PlaybookVersion).where(PlaybookVersion.playbook_id == row.id).order_by(PlaybookVersion.version.desc())
    ).all()
    return {
        "current": row.current_version,
        "versions": [
            {
                "version": v.version,
                "note": v.note,
                "createdAt": v.created_at,
                "createdBy": v.created_by,
                "nodes": len((v.graph or {}).get("nodes") or []),
            }
            for v in versions
        ],
    }


@router.get("/playbooks/{playbook_id}/versions/{number}")
def get_version(
    playbook_id: str, number: int, _caller: Principal = Depends(runner_principal), db: OrmSession = Depends(get_db)
) -> dict:
    version = db.get(PlaybookVersion, (_get(db, playbook_id).id, number))
    if version is None:
        raise HTTPException(status_code=404, detail="Version not found")
    return {"version": version.version, "graph": version.graph, "note": version.note, "createdAt": version.created_at}


@router.post("/playbooks/{playbook_id}/versions/{number}/restore", response_model=None)
def restore_version(
    playbook_id: str, number: int, caller: Principal = Depends(editor_principal), db: OrmSession = Depends(get_db)
) -> dict | JSONResponse:
    """Make an older version the current one, as a new version (history is never rewritten)."""
    row = _get(db, playbook_id)
    version = db.get(PlaybookVersion, (row.id, number))
    if version is None:
        raise HTTPException(status_code=404, detail="Version not found")
    return save_version(playbook_id, VersionIn(graph=version.graph, note=f"Restored from version {number}"), caller, db)


@router.put("/playbooks/{playbook_id}/enabled")
def set_enabled(
    playbook_id: str, body: EnabledIn, caller: Principal = Depends(editor_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Turn a playbook on or off. Off: its triggers start nothing; runs in progress go on."""
    row = _get(db, playbook_id)
    if body.enabled and not row.current_version:
        raise HTTPException(status_code=400, detail="Save a version before turning the playbook on")
    if bool(row.enabled) != body.enabled:
        row.enabled = body.enabled
        row.updated_at = now_iso()
        row.updated_by = caller.actor
        db.flush()
        triggers.sync_schedule(db, row, time.time())
        word = "on" if body.enabled else "off"
        audit.record(db, caller.actor, "playbook.enable", f'Turned the playbook "{row.name}" {word}', target=row.name)
        db.commit()
    return _detail(db, row)


@router.post("/playbooks/{playbook_id}/run", status_code=status.HTTP_201_CREATED)
def run_playbook(
    playbook_id: str, body: RunIn, caller: Principal = Depends(runner_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Run a playbook by hand, on an object or on nothing. A dry run sends nothing
    outside and changes nothing in Nik: each step shows what it would have done."""
    row = _get(db, playbook_id)
    if not row.current_version:
        raise HTTPException(status_code=400, detail="The playbook has no saved version")
    config = triggers.trigger_config(db, row)
    if not body.dryRun and not config.get("manual"):
        raise HTTPException(status_code=400, detail="This playbook is not meant to be run by hand")
    if not state.enabled(db):
        raise HTTPException(status_code=409, detail="Automation is stopped: an admin can start it again in Settings")
    found = triggers.manual_object(db, body.objectKind, body.objectId, caller.actor)
    if found is None:
        raise HTTPException(status_code=404, detail="The object to run the playbook on does not exist")
    data, classes, incident_id = found
    now = time.time()
    if not body.dryRun:
        why = triggers.refusal(db, row, body.objectKind, body.objectId, now)
        if why:
            raise HTTPException(status_code=429, detail=why)
    run = engine.start_run(
        db,
        row,
        kind="manual",
        payload=data,
        classes=classes,
        object_kind=body.objectKind,
        object_id=body.objectId,
        incident_id=incident_id,
        dry_run=body.dryRun,
        started_by=caller.actor,
        inputs=body.inputs,
        now=now,
    )
    what = "a dry run of" if body.dryRun else ""
    audit.record(
        db,
        caller.actor,
        "playbook.run",
        f'Started {what} the playbook "{row.name}"'.replace("  ", " "),
        target=row.name,
    )
    db.commit()
    return _run_summary(run)


@router.get("/playbooks/{playbook_id}/export")
def export_playbook(
    playbook_id: str, _caller: Principal = Depends(editor_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """The playbook as a file: its current version (or its draft) and its limits.
    Never what it may reach or send: those are opened again, by an admin, where it is imported."""
    row = _get(db, playbook_id)
    version = db.get(PlaybookVersion, (row.id, row.current_version)) if row.current_version else None
    return {
        "app": "Nik",
        "type": "playbook",
        "version": 1,
        "playbook": {
            "name": row.name,
            "description": row.description,
            "graph": version.graph if version else row.draft,
            "maxRunsPerHour": row.max_runs_per_hour,
            "onePerObject": bool(row.one_per_object),
            "maxSeconds": row.max_seconds,
            "approvalDefault": bool(row.approval_default),
        },
    }


@router.post("/playbooks/import", status_code=status.HTTP_201_CREATED)
def import_playbook(
    body: ImportIn, caller: Principal = Depends(editor_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Bring a playbook in from a file: as a draft, off, reaching only listed hosts and
    sending no class of data. ``problems`` says what is missing here (an action, a script)."""
    source = body.playbook
    shape = source.get("graph")
    name = str(source.get("name") or "").strip()[:120]
    if not name or not isinstance(shape, dict):
        raise HTTPException(status_code=400, detail="Not a playbook file")
    _size_ok(shape)
    base, counter = name, 2
    while _name_taken(db, name):
        name = f"{base} ({counter})"[:120]
        counter += 1
    now = now_iso()

    def number(key: str, default: int, low: int, high: int) -> int:
        value = source.get(key)
        return value if isinstance(value, int) and not isinstance(value, bool) and low <= value <= high else default

    row = Playbook(
        id=engine.new_id(),
        name=name,
        description=str(source.get("description") or "")[:2000],
        draft=shape,
        max_runs_per_hour=number("maxRunsPerHour", 60, 1, 10_000),
        one_per_object=bool(source.get("onePerObject", True)),
        max_seconds=number("maxSeconds", 86400, 60, 7 * 86400),
        approval_default=bool(source.get("approvalDefault", True)),
        created_at=now,
        created_by=caller.actor,
        updated_at=now,
        updated_by=caller.actor,
    )
    db.add(row)
    audit.record(db, caller.actor, "playbook.import", f'Imported the playbook "{name}"', target=name)
    db.commit()
    found = graph.validate(shape, catalog.Library(db), name)
    return {**_detail(db, row), "problems": [problem.as_dict() for problem in found]}


# --------------------------------------------------------------------------- #
# The library, runs, the switch                                               #
# --------------------------------------------------------------------------- #
@router.get("/catalog")
def get_catalog(_caller: Principal = Depends(runner_principal), db: OrmSession = Depends(get_db)) -> dict:
    """Every node of the library with what it takes and gives, and what a trigger can wait for."""
    return {
        "nodes": catalog.entries(db),
        "events": list(graph.EVENTS),
        "operators": list(graph.OPERATORS),
        "ports": {kind: list(ports) for kind, ports in graph.PORTS.items()},
    }


@router.get("/runs")
def list_runs(
    playbook: str | None = Query(None, max_length=32),
    run_status: str | None = Query(None, alias="status", pattern="^(running|waiting|done|failed|stopped)$"),
    incident: str | None = Query(None, max_length=200),
    artifact: str | None = Query(None, max_length=80),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    _caller: Principal = Depends(runner_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    conditions = []
    if playbook:
        conditions.append(Run.playbook_id == playbook)
    if run_status:
        conditions.append(Run.status == run_status)
    if incident:
        conditions.append(Run.incident_id == incident)
    if artifact:
        conditions.append(Run.artifact_id == artifact)
    total = db.scalar(select(func.count()).select_from(Run).where(*conditions)) or 0
    rows = db.scalars(select(Run).where(*conditions).order_by(Run.started_at.desc()).offset(offset).limit(limit)).all()
    return {"runs": [_run_summary(run) for run in rows], "total": total}


@router.get("/runs/{run_id}")
def get_run(run_id: str, _caller: Principal = Depends(runner_principal), db: OrmSession = Depends(get_db)) -> dict:
    """A run with the graph of the version it uses and every step: what went in, what
    came out, what was sent, the tries."""
    run = db.get(Run, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    steps = db.scalars(select(RunStep).where(RunStep.run_id == run.id).order_by(RunStep.seq)).all()
    return {**_run_summary(run), "graph": engine.graph_of(db, run), "steps": [_step(step) for step in steps]}


@router.post("/runs/{run_id}/stop")
def stop_run(run_id: str, caller: Principal = Depends(runner_principal), db: OrmSession = Depends(get_db)) -> dict:
    """Stop a run: what was still to do is skipped; a step in flight finishes and is discarded."""
    run = db.get(Run, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    if engine.stop(db, run_id, caller.actor, time.time()):
        name = (run.trigger or {}).get("playbook", "")
        audit.record(db, caller.actor, "playbook.stop", f'Stopped a run of the playbook "{name}"', target=name)
    db.commit()
    db.refresh(run)
    return _run_summary(run)


@router.get("/state")
def get_state(_caller: Principal = Depends(runner_principal), db: OrmSession = Depends(get_db)) -> dict:
    """Whether automation is on, and whether its worker is alive."""
    current = state.read(db)
    return {"enabled": bool(current["enabled"]), "workerAlive": state.worker_alive(db)}


@router.put("/state")
def put_state(body: StateIn, caller: Principal = Depends(admin_principal), db: OrmSession = Depends(get_db)) -> dict:
    """The general switch. Off: no new run starts and no step is taken; runs keep
    their state and go on when it is turned on again."""
    if state.enabled(db) != body.enabled:
        state.write(db, enabled=body.enabled)
        word = "Started" if body.enabled else "Stopped"
        audit.record(db, caller.actor, "automation.switch", f"{word} all automation")
        db.commit()
    return {"enabled": state.enabled(db), "workerAlive": state.worker_alive(db)}

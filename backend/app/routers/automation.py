"""Automation: playbooks, their versions, runs, approvals and the general switch.

Who may do what (``core/permissions.py``): running a playbook, reading runs,
stopping one and answering an approval need ``automation.run`` (analysts have it); building
playbooks needs ``automation.edit``; the general switch is the admin's.
Every body is validated with explicit limits and every error is a fixed
sentence.

One route here has no caller: ``POST /automation/hooks/{token}``, the address
a system outside starts a playbook at. The token in its path is the whole
credential: 32 random bytes, shown once, stored as their SHA-256. The route
never reads a cookie or an API key, takes at most 256 kB, and is limited per
token.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm.attributes import flag_modified

from ..automation import (
    catalog,
    debugger,
    egress,
    engine,
    graph,
    guard,
    outbound,
    payloads,
    scripts,
    shipped,
    state,
    triggers,
)
from ..commands import ADHOC_ID
from ..core import audit, vault
from ..core.config import settings as app_settings
from ..core.db import get_db
from ..core.models import (
    Approval,
    Incident,
    Playbook,
    PlaybookBranch,
    PlaybookVersion,
    Run,
    RunStep,
    Script,
    ScriptVersion,
)
from ..core.permissions import AUTOMATION_DEBUG, AUTOMATION_EDIT, AUTOMATION_RUN
from ..core.ratelimit import limiter
from ..core.security import Principal, admin_principal, editor_principal, now_iso, require, runner_principal

router = APIRouter(prefix="/automation", tags=["automation"])
# What automation adds to an incident (its runs), under the incident's own address.
incident_router = APIRouter(prefix="/incidents", tags=["automation"])

MAX_GRAPH_BYTES = 1_000_000
debug_principal = require(AUTOMATION_DEBUG)


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


class BranchIn(BaseModel):
    """A new branch: of ``graph`` when given; otherwise of the branch ``from_`` names, of the draft
    (``"draft"``) or of the version in use (``"main"``, the default)."""

    model_config = ConfigDict(populate_by_name=True)

    name: str = Field(min_length=1, max_length=80)
    from_: str = Field(default="main", alias="from", max_length=40)
    graph: dict[str, Any] | None = None


class BranchPatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=80)
    graph: dict[str, Any] | None = None


class PushIn(BaseModel):
    note: str = Field(default="", max_length=500)
    # Push although the playbook has a newer version than the one the branch started from.
    overwrite: bool = False


class VersionIn(BaseModel):
    """Save a version: of ``graph`` when given, of the draft otherwise."""

    graph: dict[str, Any] | None = None
    note: str = Field(default="", max_length=500)


class EnabledIn(BaseModel):
    enabled: bool
    # Never accepted: a branch is not turned on. Named so that asking is answered, not ignored.
    branch: str | None = Field(default=None, max_length=32)


class RunIn(BaseModel):
    # Never accepted: a branch runs only in the debugger. Named so that asking is answered, not ignored.
    branch: str | None = Field(default=None, max_length=32)
    # An artifact by its id (mail-…, file-…, url-…); an indicator as "type:value".
    objectKind: Literal["", "incident", "artifact", "indicator"] = ""
    objectId: str = Field(default="", max_length=1100)
    dryRun: bool = False
    inputs: dict[str, Any] = Field(default_factory=dict)


class DebugStartIn(BaseModel):
    objectKind: Literal["", "incident", "artifact", "indicator"] = ""
    objectId: str = Field(default="", max_length=1100)
    inputs: dict[str, Any] = Field(default_factory=dict)
    # The nodes to stop before; with stepMode it stops before every node.
    breakpoints: list[str] = Field(default_factory=list, max_length=200)
    stepMode: bool = True
    # The draft of the playbook, as it is being drawn, instead of its saved version.
    draft: bool = False
    # A branch of the playbook, by its id, as it was last saved: the only way a branch runs.
    branch: str | None = Field(default=None, max_length=32)


class DebugIn(BaseModel):
    action: Literal["step", "continue", "skip", "stop", "rerun", "set"]
    stepId: str | None = Field(default=None, max_length=32)
    # Arguments to give the node instead of the ones its templates give: {name: value}.
    overrides: dict[str, Any] | None = None
    # Let this one node really send what it sends (with the approval it normally needs).
    sendForReal: bool = False
    # What the nodes after read: {"<node id>": its output, "inputs": {...}}.
    contextPatch: dict[str, Any] | None = None
    breakpoints: list[str] | None = Field(default=None, max_length=200)


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
    # What the commands of the War Room run as is not a playbook to open, edit or run.
    if row is None or row.id == ADHOC_ID:
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
    last = db.scalars(
        select(Run).where(Run.playbook_id == row.id, Run.debug.is_(False)).order_by(Run.started_at.desc()).limit(1)
    ).first()
    since = engine.iso(time.time() - 7 * 86400)
    counts = dict(
        db.execute(
            select(Run.status, func.count())
            .where(Run.playbook_id == row.id, Run.started_at >= since, Run.debug.is_(False))
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
        "runsOn": triggers.object_of(trigger),
        "lastRun": {"id": last.id, "status": last.status, "startedAt": last.started_at} if last else None,
        "week": {"done": counts.get("done", 0), "failed": counts.get("failed", 0), "total": sum(counts.values())},
        "warnings": _warnings(db, row, shape),
        "updatedAt": row.updated_at,
        "updatedBy": row.updated_by,
    }


MAX_BRANCHES = 20


def _branch(row: PlaybookBranch, playbook: Playbook, *, graph_too: bool = False) -> dict[str, Any]:
    out = {
        "id": row.id,
        "name": row.name,
        "baseVersion": row.base_version,
        # The playbook has a version newer than the one this branch started from.
        "behind": row.base_version != playbook.current_version,
        "createdBy": row.created_by,
        "updatedAt": row.updated_at,
        "updatedBy": row.updated_by,
    }
    if graph_too:
        out["graph"] = row.graph
        out["playbookId"] = playbook.id
    return out


def _branches(db: OrmSession, playbook: Playbook) -> list[dict[str, Any]]:
    rows = db.scalars(
        select(PlaybookBranch)
        .where(PlaybookBranch.playbook_id == playbook.id)
        .order_by(func.lower(PlaybookBranch.name))
    ).all()
    return [_branch(row, playbook) for row in rows]


def _get_branch(db: OrmSession, playbook_id: str, branch_id: str) -> tuple[Playbook, PlaybookBranch]:
    playbook = _get(db, playbook_id)
    row = db.get(PlaybookBranch, branch_id)
    if row is None or row.playbook_id != playbook.id:
        raise HTTPException(status_code=404, detail="Branch not found")
    return playbook, row


def _own_branch(row: PlaybookBranch, caller: Principal) -> None:
    """A branch is changed, pushed and deleted by who made it, or by an admin."""
    if row.created_by != caller.actor and not caller.has("admin"):
        raise HTTPException(status_code=403, detail=f"This branch is {row.created_by}'s: make one of your own from it")


def _branch_name(db: OrmSession, playbook: Playbook, name: str, except_id: str | None = None) -> str:
    cleaned = " ".join(name.split())
    if not cleaned or cleaned.lower() in ("main", "draft"):
        raise HTTPException(status_code=400, detail='A branch needs a name of its own: not "main" nor "draft"')
    taken = db.scalars(
        select(PlaybookBranch).where(
            PlaybookBranch.playbook_id == playbook.id, func.lower(PlaybookBranch.name) == cleaned.lower()
        )
    ).first()
    if taken is not None and taken.id != except_id:
        raise HTTPException(status_code=400, detail="This playbook has a branch with this name already")
    return cleaned


def _detail(db: OrmSession, row: Playbook) -> dict[str, Any]:
    version = db.get(PlaybookVersion, (row.id, row.current_version)) if row.current_version else None
    shape = version.graph if version else None
    return {
        **_summary(db, row),
        "graph": shape,
        "draft": row.draft,
        "branches": _branches(db, row),
        "updates": catalog.updates(db, row.draft or shape or {}),
        "egressMode": row.egress_mode,
        "egressHosts": row.egress_hosts or [],
        "dataAllow": row.data_allow or [],
        "maxRunsPerHour": row.max_runs_per_hour,
        "onePerObject": bool(row.one_per_object),
        "maxSeconds": row.max_seconds,
        "approvalDefault": bool(row.approval_default),
        "hook": {"since": row.hook_created_at} if row.hook_hash else None,
        "createdAt": row.created_at,
        "createdBy": row.created_by,
    }


BRANCH_ONLY_DEBUG = "A branch runs only in the debugger: push it to main to run it, turn it on or schedule it"


def _run_summary(run: Run) -> dict[str, Any]:
    return {
        "id": run.id,
        "playbookId": run.playbook_id,
        "playbook": (run.trigger or {}).get("playbook", ""),
        "version": run.version,
        "status": run.status,
        "trigger": (run.trigger or {}).get("kind", ""),
        "dryRun": bool(run.dry_run),
        "debug": bool(run.debug),
        # The branch a debug run was started on, as it was called then; no other run has one.
        "branch": debugger.branch_of(run),
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


def _approval(db: OrmSession, approval: Approval) -> dict[str, Any]:
    run = db.get(Run, approval.run_id)
    step = db.get(RunStep, approval.step_id)
    return {
        "id": approval.id,
        "runId": approval.run_id,
        "playbookId": run.playbook_id if run else None,
        "playbook": (run.trigger or {}).get("playbook", "") if run else "",
        "incidentId": run.incident_id if run else None,
        "node": step.node_id if step else None,
        # Asked by an approval node, or before a node that changes something outside.
        "inline": bool(step and step.kind != "approval"),
        "question": approval.question,
        "detail": approval.detail or {},
        "status": approval.status,
        "onExpire": approval.on_expire,
        "askedAt": approval.asked_at,
        "expiresAt": engine.iso(approval.expires_at) if approval.expires_at else None,
        "answeredAt": approval.answered_at,
        "answeredBy": approval.answered_by,
        "comment": approval.comment,
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
    rows = db.scalars(select(Playbook).where(Playbook.id != ADHOC_ID).order_by(func.lower(Playbook.name))).all()
    # The branches of every playbook, read once: the list and the editor show them under it.
    by_id = {row.id: row for row in rows}
    branches: dict[str, list[dict[str, Any]]] = {}
    for branch in db.scalars(select(PlaybookBranch).order_by(func.lower(PlaybookBranch.name))).all():
        if branch.playbook_id in by_id:
            branches.setdefault(branch.playbook_id, []).append(_branch(branch, by_id[branch.playbook_id]))
    return {
        "playbooks": [{**_summary(db, row), "branches": branches.get(row.id, [])} for row in rows],
        "workerAlive": state.worker_alive(db),
        **state.read(db),
    }


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


@router.delete("/playbooks/{playbook_id}/draft", status_code=status.HTTP_204_NO_CONTENT)
def discard_draft(
    playbook_id: str, caller: Principal = Depends(editor_principal), db: OrmSession = Depends(get_db)
) -> Response:
    """Throw the draft away: the playbook is its version in use again. One that has no version yet is
    only its draft, and is deleted as a playbook instead."""
    row = _get(db, playbook_id)
    if row.draft is None:
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    if not row.current_version:
        raise HTTPException(status_code=409, detail="This playbook is only a draft: delete the playbook instead")
    row.draft = None
    row.updated_at, row.updated_by = now_iso(), caller.actor
    audit.record(db, caller.actor, "playbook.draft_discard", f'Discarded the draft of "{row.name}"', target=row.name)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --------------------------------------------------------------------------- #
# Branches                                                                    #
# --------------------------------------------------------------------------- #
@router.get("/playbooks/{playbook_id}/branches")
def list_branches(
    playbook_id: str, _caller: Principal = Depends(editor_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """The branches of a playbook, by name: who made each, and whether the playbook moved on since."""
    return {"branches": _branches(db, _get(db, playbook_id))}


@router.post("/playbooks/{playbook_id}/branches", status_code=status.HTTP_201_CREATED)
def create_branch(
    playbook_id: str,
    body: BranchIn,
    caller: Principal = Depends(editor_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Make a branch: a copy of the version in use, of the draft, of another branch, or of a graph."""
    playbook = _get(db, playbook_id)
    name = _branch_name(db, playbook, body.name)
    count = db.scalar(select(func.count()).select_from(PlaybookBranch).where(PlaybookBranch.playbook_id == playbook.id))
    if (count or 0) >= MAX_BRANCHES:
        raise HTTPException(status_code=409, detail=f"A playbook has {MAX_BRANCHES} branches at most: delete one")
    base = playbook.current_version
    if body.graph is not None:
        shape = body.graph
    elif body.from_ == "draft":
        shape = playbook.draft
    elif body.from_ == "main":
        version = db.get(PlaybookVersion, (playbook.id, base)) if base else None
        shape = version.graph if version else playbook.draft
    else:
        _playbook, source = _get_branch(db, playbook.id, body.from_)
        shape, base = source.graph, source.base_version
    if shape is None:
        raise HTTPException(status_code=400, detail="There is nothing to make a branch from")
    _size_ok(shape)
    now = now_iso()
    row = PlaybookBranch(
        id=engine.new_id(),
        playbook_id=playbook.id,
        name=name,
        graph=shape,
        base_version=base,
        created_at=now,
        created_by=caller.actor,
        updated_at=now,
        updated_by=caller.actor,
    )
    db.add(row)
    audit.record(
        db, caller.actor, "playbook.branch", f'Made the branch "{name}" of "{playbook.name}"', target=playbook.name
    )
    db.commit()
    return _branch(row, playbook, graph_too=True)


@router.get("/playbooks/{playbook_id}/branches/{branch_id}")
def get_branch(
    playbook_id: str,
    branch_id: str,
    _caller: Principal = Depends(editor_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    playbook, row = _get_branch(db, playbook_id, branch_id)
    return {**_branch(row, playbook, graph_too=True), "updates": catalog.updates(db, row.graph or {})}


@router.put("/playbooks/{playbook_id}/branches/{branch_id}")
def update_branch(
    playbook_id: str,
    branch_id: str,
    body: BranchPatch,
    caller: Principal = Depends(editor_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Save a branch (its graph need not be valid) or rename it. Nothing a run uses changes."""
    playbook, row = _get_branch(db, playbook_id, branch_id)
    _own_branch(row, caller)
    if body.name is not None:
        row.name = _branch_name(db, playbook, body.name, except_id=row.id)
    if body.graph is not None:
        _size_ok(body.graph)
        row.graph = body.graph
        flag_modified(row, "graph")
    row.updated_at, row.updated_by = now_iso(), caller.actor
    db.commit()
    return _branch(row, playbook, graph_too=True)


@router.delete("/playbooks/{playbook_id}/branches/{branch_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_branch(
    playbook_id: str,
    branch_id: str,
    caller: Principal = Depends(editor_principal),
    db: OrmSession = Depends(get_db),
) -> Response:
    playbook, row = _get_branch(db, playbook_id, branch_id)
    _own_branch(row, caller)
    audit.record(
        db,
        caller.actor,
        "playbook.branch_delete",
        f'Deleted the branch "{row.name}" of "{playbook.name}"',
        target=playbook.name,
    )
    db.delete(row)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/playbooks/{playbook_id}/branches/{branch_id}/push", response_model=None)
def push_branch(
    playbook_id: str,
    branch_id: str,
    body: PushIn,
    caller: Principal = Depends(editor_principal),
    db: OrmSession = Depends(get_db),
) -> dict | JSONResponse:
    """Make the branch the next version of the playbook, over the one in use. ``422`` with the
    problems when its graph is not valid; ``409`` with ``moved`` when the playbook has a newer
    version than the one the branch started from, unless ``overwrite`` says to go on. Graphs are
    not merged: the branch replaces what is there."""
    playbook, row = _get_branch(db, playbook_id, branch_id)
    _own_branch(row, caller)
    found = graph.validate(row.graph, catalog.Library(db), playbook.name)
    if found:
        return _problems(found)
    if row.base_version != playbook.current_version and not body.overwrite:
        return JSONResponse(
            status_code=409,
            content={
                "detail": (
                    f"The playbook is at version {playbook.current_version or 0} and this branch started from "
                    f"{row.base_version or 0}: pushing it replaces what was saved since"
                ),
                "moved": True,
                "baseVersion": row.base_version,
                "currentVersion": playbook.current_version,
            },
        )
    number = (
        db.scalar(select(func.max(PlaybookVersion.version)).where(PlaybookVersion.playbook_id == playbook.id)) or 0
    ) + 1
    now = now_iso()
    note = body.note.strip() or f'From the branch "{row.name}"'
    db.add(
        PlaybookVersion(
            playbook_id=playbook.id, version=number, graph=row.graph, note=note[:500], created_at=now,
            created_by=caller.actor,
        )
    )  # fmt: skip
    playbook.current_version = number
    playbook.updated_at, playbook.updated_by = now, caller.actor
    # The branch is now what the playbook is: it stays, to go on from.
    row.base_version = number
    row.updated_at, row.updated_by = now, caller.actor
    db.flush()
    triggers.sync_schedule(db, playbook, time.time())
    audit.record(
        db,
        caller.actor,
        "playbook.version",
        f'Pushed the branch "{row.name}" as version {number} of the playbook "{playbook.name}"',
        target=playbook.name,
    )
    db.commit()
    return _detail(db, playbook)


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
    """Turn a playbook on or off. Off: its triggers start nothing; runs in progress go on. What is
    turned on is the version in use: the trigger and the schedule drawn on a branch start nothing."""
    row = _get(db, playbook_id)
    if body.branch is not None:
        raise HTTPException(status_code=400, detail=BRANCH_ONLY_DEBUG)
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
    if body.branch is not None:
        raise HTTPException(status_code=400, detail=BRANCH_ONLY_DEBUG)
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
    data, classes, what, incident_id = found
    wrong = triggers.manual_problem(config, what)
    if wrong:
        raise HTTPException(status_code=400, detail=wrong)
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
        incident_id=incident_id or None,
        artifact_id=body.objectId if body.objectKind == "artifact" else None,
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


# --------------------------------------------------------------------------- #
# The address a playbook is started at from outside                           #
# --------------------------------------------------------------------------- #
HOOK_MAX_BYTES = 256 * 1024
HOOK_LIMIT = "60/minute"
# What of a request's headers a playbook reads: how the body is written, who says they sent it,
# and the headers a sender adds of its own. Never a credential, a cookie or what a proxy added.
_HOOK_HEADERS = ("content-type", "user-agent")
_HOOK_NEVER = ("x-forwarded-", "x-real-ip", "x-api-key", "x-nik-", "x-csrf", "x-amz-security", "x-auth")
_HOOK_SECRET_WORDS = ("token", "secret", "key", "auth", "password", "cookie", "signature")


def _hook_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _hook_key(request: Request) -> str:
    """The limit is per token: one noisy sender does not use up another's."""
    return "hook:" + _hook_hash(str(request.path_params.get("token") or ""))


def hook_headers(headers) -> dict[str, str]:
    kept: dict[str, str] = {}
    for name, value in headers.items():
        name = name.lower()
        custom = (
            name.startswith("x-")
            and not name.startswith(_HOOK_NEVER)
            and not any(word in name for word in _HOOK_SECRET_WORDS)
        )
        if (name in _HOOK_HEADERS or custom) and len(kept) < 30:
            kept[name] = str(value)[:500]
    return kept


@router.post("/playbooks/{playbook_id}/hook", status_code=status.HTTP_201_CREATED)
def create_hook(
    playbook_id: str, caller: Principal = Depends(editor_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Give the playbook an address to be started at from outside, or a new one
    (the old one stops working). The token is in this answer and nowhere else."""
    row = _get(db, playbook_id)
    token = secrets.token_urlsafe(32)
    again = bool(row.hook_hash)
    row.hook_hash, row.hook_created_at = _hook_hash(token), now_iso()
    audit.record(
        db,
        caller.actor,
        "playbook.hook",
        f'{"Replaced" if again else "Created"} the webhook address of the playbook "{row.name}"',
        target=row.name,
    )
    db.commit()
    return {"token": token, "path": f"/api/automation/hooks/{token}", "since": row.hook_created_at}


@router.delete("/playbooks/{playbook_id}/hook", status_code=status.HTTP_204_NO_CONTENT)
def delete_hook(
    playbook_id: str, caller: Principal = Depends(editor_principal), db: OrmSession = Depends(get_db)
) -> Response:
    row = _get(db, playbook_id)
    if row.hook_hash:
        row.hook_hash, row.hook_created_at = None, None
        audit.record(
            db,
            caller.actor,
            "playbook.hook",
            f'Removed the webhook address of the playbook "{row.name}"',
            target=row.name,
        )
        db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/hooks/{token}", status_code=status.HTTP_202_ACCEPTED)
@limiter.limit(HOOK_LIMIT, key_func=_hook_key)
async def inbound_hook(token: str, request: Request, response: Response, db: OrmSession = Depends(get_db)) -> dict:
    """Start the playbook this token belongs to. No caller: the token is the
    credential, and nothing else of the request (a cookie, an API key) is read.
    The answer says only that the request was taken, never what the playbook did."""
    missing = HTTPException(status_code=404, detail="Not found")
    if not 20 <= len(token) <= 100:
        raise missing
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > HOOK_MAX_BYTES:
        raise HTTPException(status_code=413, detail="The body is larger than 256 kB")
    raw = b""
    async for chunk in request.stream():
        raw += chunk
        if len(raw) > HOOK_MAX_BYTES:
            raise HTTPException(status_code=413, detail="The body is larger than 256 kB")
    row = db.scalars(select(Playbook).where(Playbook.hook_hash == _hook_hash(token))).first()
    # One answer for every reason a token starts nothing, so that it says nothing of what exists.
    if row is None or not row.enabled or not row.current_version or not state.enabled(db):
        raise missing
    if not triggers.trigger_config(db, row).get("webhook"):
        raise missing
    text = raw.decode("utf-8", errors="replace")
    body: Any = text
    if "json" in (request.headers.get("content-type") or "").lower():
        try:
            body = json.loads(text) if text.strip() else None
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="The body is not valid JSON") from exc
    query = {name: value[:2000] for name, value in list(request.query_params.items())[:50]}
    data, classes = payloads.webhook(body, hook_headers(request.headers), query)
    now = time.time()
    why = triggers.refusal(db, row, "webhook", row.id, now)
    if why:
        raise HTTPException(status_code=429, detail="The playbook cannot start now")
    engine.start_run(
        db,
        row,
        kind="webhook",
        payload=data,
        classes=classes,
        object_kind="webhook",
        object_id="",
        started_by="webhook",
        now=now,
    )
    db.commit()
    return {"accepted": True}


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
    # A script node that names no version (the files Nik ships) takes the one the script has here.
    shape = shipped.with_script_versions(db, shape)
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
def get_catalog(
    prefix: str | None = Query(None, max_length=100, description="Only the commands whose name starts so."),
    _caller: Principal = Depends(runner_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Every node of the library with what it takes and gives, and what a trigger can wait for.
    ``commands`` is the same library as the command line of the War Room types it."""
    from .. import commands as command_line

    if prefix is not None:
        return {"commands": command_line.catalog(db, prefix)}
    return {
        "commands": command_line.catalog(db),
        "nodes": catalog.entries(db),
        # The connections there are, by connector: what a node of a connector chooses from.
        "instances": catalog.connections(db),
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
    debug: bool = Query(False, description="The debug runs instead: one's own, or everyone's for an admin."),
    caller: Principal = Depends(runner_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    conditions = [Run.debug.is_(debug)]
    if debug and not caller.has("admin"):
        conditions.append(Run.started_by == caller.actor)
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
def get_run(run_id: str, caller: Principal = Depends(runner_principal), db: OrmSession = Depends(get_db)) -> dict:
    """A run with the graph of the version it uses and every step: what went in, what
    came out, what was sent, the tries. A debug run also says where it stops and what it holds
    (``debug``); it is its starter's, and an admin's."""
    run = db.get(Run, run_id)
    if run is None or not debugger.may_see(run, caller):
        raise HTTPException(status_code=404, detail="Run not found")
    steps = db.scalars(select(RunStep).where(RunStep.run_id == run.id).order_by(RunStep.seq)).all()
    approvals = db.scalars(select(Approval).where(Approval.run_id == run.id).order_by(Approval.asked_epoch)).all()
    return {
        **_run_summary(run),
        "graph": engine.graph_of(db, run),
        "steps": [_step(step) for step in steps],
        "approvals": [_approval(db, approval) for approval in approvals],
        "debug": debugger.out(db, run),
    }


@router.post("/playbooks/{playbook_id}/debug", status_code=status.HTTP_201_CREATED)
def debug_playbook(
    playbook_id: str, body: DebugStartIn, caller: Principal = Depends(debug_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Start a debug run of a playbook (its saved version, its draft, or one of its branches) on an
    object: a run that stops before the nodes named, or before every node. What goes outside is held,
    as in a dry run, unless one node is let through. It counts for no limit and no statistic, and is
    deleted after a week. A branch is debugged as it was last saved, by who may edit playbooks; this
    is the only way a branch runs."""
    row = _get(db, playbook_id)
    shape = None
    branch = None
    if body.branch is not None:
        if body.draft:
            raise HTTPException(status_code=400, detail="Debug the draft or a branch, not both")
        if not caller.has(AUTOMATION_EDIT):
            raise HTTPException(status_code=403, detail="Debugging a branch needs the permission to edit playbooks")
        _playbook, branch = _get_branch(db, row.id, body.branch)
        shape = branch.graph
        problems = graph.validate(shape, catalog.Library(db), row.name)
        if problems:
            raise HTTPException(
                status_code=400,
                detail={"message": "The branch cannot run yet", "problems": [p.as_dict() for p in problems]},
            )
        shape = shipped.with_script_versions(db, shape)
    elif body.draft:
        shape = row.draft
        if not isinstance(shape, dict):
            raise HTTPException(status_code=400, detail="The playbook has no draft: debug its saved version")
        problems = graph.validate(shape, catalog.Library(db), row.name)
        if problems:
            raise HTTPException(
                status_code=400,
                detail={"message": "The draft cannot run yet", "problems": [p.as_dict() for p in problems]},
            )
        shape = shipped.with_script_versions(db, shape)
    elif not row.current_version:
        raise HTTPException(status_code=400, detail="The playbook has no saved version: debug its draft")
    if not state.enabled(db):
        raise HTTPException(status_code=409, detail="Automation is stopped: an admin can start it again in Settings")
    found = triggers.manual_object(db, body.objectKind, body.objectId, caller.actor)
    if found is None:
        raise HTTPException(status_code=404, detail="The object to run the playbook on does not exist")
    data, classes, _what, incident_id = found
    used = shape if shape is not None else db.get(PlaybookVersion, (row.id, row.current_version)).graph
    run = engine.start_run(
        db,
        row,
        kind="debug",
        payload=data,
        classes=classes,
        object_kind=body.objectKind,
        object_id=body.objectId,
        incident_id=incident_id or None,
        artifact_id=body.objectId if body.objectKind == "artifact" else None,
        dry_run=True,
        started_by=caller.actor,
        inputs=body.inputs,
        debug={"breakpoints": debugger.clean_breakpoints(used, body.breakpoints), "step": body.stepMode},
        shape=shape,
        branch={"id": branch.id, "name": branch.name} if branch is not None else None,
        now=time.time(),
    )
    what = f'the branch "{branch.name}" of the playbook' if branch is not None else "the playbook"
    audit.record(db, caller.actor, "playbook.debug", f'Started a debug run of {what} "{row.name}"', target=row.name)
    db.commit()
    return _run_summary(run)


@router.post("/runs/{run_id}/debug")
def debug_run(
    run_id: str, body: DebugIn, caller: Principal = Depends(debug_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Tell a debug run what to do: ``step`` (go one node on), ``continue`` (to the next breakpoint),
    ``skip`` the node it is stopped at, ``rerun`` a node that is over, ``stop``, or ``set`` (only move the
    breakpoints or change the context: the run stays where it is). ``overrides`` gives the
    node other arguments; ``sendForReal`` lets this one node really send, which needs the permission to run
    playbooks and the approval the node normally asks; ``contextPatch`` changes what later nodes read."""
    run = db.get(Run, run_id)
    if run is None or not run.debug or not debugger.may_see(run, caller):
        raise HTTPException(status_code=404, detail="Run not found")
    if body.sendForReal and not caller.has(AUTOMATION_RUN):
        raise HTTPException(status_code=403, detail="Sending for real needs the permission to run playbooks")
    try:
        debugger.act(
            db,
            run,
            body.action,
            by=caller.actor,
            now=time.time(),
            step_id=body.stepId,
            overrides=body.overrides,
            send_for_real=body.sendForReal,
            context_patch=body.contextPatch,
            breakpoints=body.breakpoints,
        )
    except debugger.DebugError as error:
        db.rollback()
        raise HTTPException(status_code=error.status, detail=error.message) from None
    if body.sendForReal:
        name = (run.trigger or {}).get("playbook", "")
        audit.record(
            db, caller.actor, "playbook.debug.real", f'Let a node of a debug run of "{name}" send for real', target=name
        )
    db.commit()
    db.refresh(run)
    return {**_run_summary(run), "debug": debugger.out(db, run)}


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


class AnswerIn(BaseModel):
    answer: Literal["approved", "refused"]
    comment: str = Field(default="", max_length=1000)


@router.get("/approvals")
def list_approvals(
    approval_status: str = Query("waiting", alias="status", pattern="^(waiting|approved|refused|expired|all)$"),
    incident: str | None = Query(None, max_length=200),
    limit: int = Query(100, ge=1, le=200),
    _caller: Principal = Depends(runner_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """The approvals: those waiting for an answer (oldest first) unless ``status``
    says otherwise. ``waiting`` is how many wait in all, for the count on the rail."""
    query = select(Approval)
    if approval_status != "all":
        query = query.where(Approval.status == approval_status)
    if incident:
        query = query.join(Run, Run.id == Approval.run_id).where(Run.incident_id == incident)
    order = Approval.asked_epoch if approval_status == "waiting" else Approval.asked_epoch.desc()
    rows = db.scalars(query.order_by(order).limit(limit)).all()
    waiting = db.scalar(select(func.count()).select_from(Approval).where(Approval.status == "waiting")) or 0
    return {"approvals": [_approval(db, row) for row in rows], "waiting": waiting}


@router.post("/approvals/{approval_id}")
def answer_approval(
    approval_id: str, body: AnswerIn, caller: Principal = Depends(runner_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Answer an approval: the run goes on by the answer. ``409`` when someone
    answered first (or the wait ended). Who answered is in the audit log and on the run."""
    approval = db.get(Approval, approval_id)
    if approval is None:
        raise HTTPException(status_code=404, detail="Approval not found")
    if not engine.answer(db, approval, body.answer, caller.actor, body.comment.strip(), time.time()):
        db.rollback()
        raise HTTPException(status_code=409, detail="This approval has been answered already")
    run = db.get(Run, approval.run_id)
    name = (run.trigger or {}).get("playbook", "") if run else ""
    word = "Approved" if body.answer == "approved" else "Refused"
    audit.record(
        db,
        caller.actor,
        "playbook.approve" if body.answer == "approved" else "playbook.refuse",
        f'{word} "{approval.question}" in a run of the playbook "{name}"',
        db.get(Incident, run.incident_id) if run and run.incident_id else None,
        target=name,
    )
    db.commit()
    return _approval(db, approval)


@incident_router.get("/{incident_id}/runs")
def incident_runs(
    incident_id: str,
    limit: int = Query(50, ge=1, le=200),
    _caller: Principal = Depends(runner_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """The runs that worked on an incident, newest first, and the approvals of theirs that wait."""
    if db.get(Incident, incident_id) is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    rows = db.scalars(
        select(Run)
        .where(Run.incident_id == incident_id, Run.debug.is_(False))
        .order_by(Run.started_at.desc())
        .limit(limit)
    ).all()
    waiting = db.scalars(
        select(Approval)
        .join(Run, Run.id == Approval.run_id)
        .where(Run.incident_id == incident_id, Approval.status == "waiting")
        .order_by(Approval.asked_epoch)
    ).all()
    return {"runs": [_run_summary(run) for run in rows], "approvals": [_approval(db, row) for row in waiting]}


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


# --------------------------------------------------------------------------- #
# What a playbook may reach and send (admins, behind a double check)          #
# --------------------------------------------------------------------------- #
class EgressIn(BaseModel):
    """``mode``: ``listed`` (the hosts below, and those listed for every playbook) or ``any``.
    Switching to ``any`` needs the double check: ``acknowledged`` and the playbook's name."""

    mode: Literal["listed", "any"]
    hosts: list[str] = Field(default_factory=list, max_length=200)
    acknowledged: bool = False
    confirmName: str = Field(default="", max_length=120)


class DataAllowIn(BaseModel):
    """Open (``allow: true``) or close a class of data for the playbook. Opening needs the double check."""

    dataClass: str = Field(alias="class", max_length=40)
    allow: bool = True
    acknowledged: bool = False
    confirmName: str = Field(default="", max_length=120)
    model_config = ConfigDict(populate_by_name=True)


class SmtpIn(BaseModel):
    host: str = Field(default="", max_length=253)
    port: int = Field(default=587, ge=1, le=65535)
    security: Literal["starttls", "tls", "none"] = "starttls"
    username: str = Field(default="", max_length=320)
    # Write-only: left out, the stored one is kept; empty, it is removed.
    password: str | None = Field(default=None, max_length=1000)
    sender: str = Field(default="", max_length=320)
    caPem: str = Field(default="", max_length=20_000)


class SettingsIn(BaseModel):
    hosts: list[str] | None = Field(default=None, max_length=500)
    smtp: SmtpIn | None = None


def _double_check(row: Playbook, acknowledged: bool, confirm: str) -> None:
    if not acknowledged or confirm != row.name:
        raise HTTPException(
            status_code=400,
            detail="Confirm by ticking the box and typing the name of the playbook exactly as it is written",
        )


def _hosts(values: list[str]) -> list[str]:
    cleaned = []
    for value in values:
        host = egress.clean_host(value)
        if host is None:
            raise HTTPException(status_code=400, detail="A host is a name or an address, with a port if needed")
        cleaned.append(host)
    return sorted(set(cleaned))


@router.get("/data-classes")
def data_classes(_caller: Principal = Depends(runner_principal)) -> dict:
    """The classes of data the guard knows: those that always leave, and those an admin can open."""
    return {
        "always": sorted(guard.ALWAYS),
        "classes": [{"id": name, **meta} for name, meta in guard.CLASSES.items()],
    }


@router.put("/playbooks/{playbook_id}/egress")
def set_egress(
    playbook_id: str, body: EgressIn, caller: Principal = Depends(admin_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Where the playbook may send. Listing hosts is the admin's; letting it reach
    **any** host also needs the double check. Both are in the audit log."""
    row = _get(db, playbook_id)
    hosts = _hosts(body.hosts)
    if body.mode == "any" and row.egress_mode != "any":
        _double_check(row, body.acknowledged, body.confirmName)
    changes = []
    if body.mode != row.egress_mode:
        changes.append(f"may reach {'any host' if body.mode == 'any' else 'listed hosts only'}")
        action = "automation.egress.open" if body.mode == "any" else "automation.egress.close"
    else:
        action = "automation.egress.hosts"
    if hosts != sorted(row.egress_hosts or []):
        changes.append("hosts: " + (", ".join(hosts) or "none"))
    if changes:
        row.egress_mode = body.mode
        row.egress_hosts = hosts
        row.updated_at = now_iso()
        row.updated_by = caller.actor
        audit.record(db, caller.actor, action, f'Playbook "{row.name}": {"; ".join(changes)}', target=row.name)
        db.commit()
    return _detail(db, row)


@router.put("/playbooks/{playbook_id}/data-allow")
def set_data_allow(
    playbook_id: str, body: DataAllowIn, caller: Principal = Depends(admin_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Open or close a class of data for the playbook. Opening needs the double
    check; the audit entry names the hosts that will be able to receive it."""
    row = _get(db, playbook_id)
    if body.dataClass not in guard.CLASSES:
        raise HTTPException(status_code=400, detail="Unknown class of data")
    opened = set(row.data_allow or [])
    label = guard.CLASSES[body.dataClass]["label"]
    if body.allow and body.dataClass not in opened:
        _double_check(row, body.acknowledged, body.confirmName)
        opened.add(body.dataClass)
        policy = outbound.policy_for(db, row)
        where = "any host" if policy.mode == "any" else (", ".join(sorted(policy.hosts)) or "no host yet")
        audit.record(
            db,
            caller.actor,
            "automation.data.open",
            f'Playbook "{row.name}" may send {label.lower()} to: {where}',
            target=row.name,
        )
    elif not body.allow and body.dataClass in opened:
        opened.discard(body.dataClass)
        audit.record(
            db,
            caller.actor,
            "automation.data.close",
            f'Playbook "{row.name}" may no longer send {label.lower()}',
            target=row.name,
        )
    else:
        return _detail(db, row)
    row.data_allow = [name for name in guard.CLASSES if name in opened]
    row.updated_at = now_iso()
    row.updated_by = caller.actor
    db.commit()
    return _detail(db, row)


def _settings_out(db: OrmSession) -> dict:
    current = state.read(db)
    smtp = dict(current.get("smtp") or {})
    return {
        "enabled": bool(current["enabled"]),
        "workerAlive": state.worker_alive(db),
        "hosts": current.get("hosts") or [],
        "smtp": {
            "host": smtp.get("host", ""),
            "port": smtp.get("port", 587),
            "security": smtp.get("security", "starttls"),
            "username": smtp.get("username", ""),
            "sender": smtp.get("sender", ""),
            "caPem": smtp.get("ca_pem", ""),
            "hasPassword": bool(smtp.get("password")),  # never the password itself
        },
    }


@router.get("/settings")
def get_settings(_caller: Principal = Depends(admin_principal), db: OrmSession = Depends(get_db)) -> dict:
    """The hosts every "listed" playbook may reach, and the SMTP server of the e-mail node."""
    return _settings_out(db)


@router.put("/settings")
def put_settings(
    body: SettingsIn, caller: Principal = Depends(admin_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Change the hosts listed for every playbook, or the SMTP server. The password is
    stored encrypted and never returned."""
    current = state.read(db)
    changes = []
    if body.hosts is not None:
        hosts = _hosts(body.hosts)
        if hosts != sorted(current.get("hosts") or []):
            state.write(db, hosts=hosts)
            changes.append("hosts for every playbook: " + (", ".join(hosts) or "none"))
    if body.smtp is not None:
        stored = dict(current.get("smtp") or {})
        host = egress.clean_host(body.smtp.host) if body.smtp.host.strip() else ""
        if host is None:
            raise HTTPException(status_code=400, detail="The SMTP server is a host name or an address")
        fresh = {
            "host": host,
            "port": body.smtp.port,
            "security": body.smtp.security,
            "username": body.smtp.username.strip(),
            "sender": body.smtp.sender.strip(),
            "ca_pem": body.smtp.caPem.strip(),
            "password": stored.get("password", ""),
        }
        if body.smtp.password is not None:
            fresh["password"] = vault.encrypt(body.smtp.password) if body.smtp.password else ""
        if fresh != stored:
            state.write(db, smtp=fresh)
            changes.append(f"SMTP server: {host or 'none'}")
    if changes:
        audit.record(db, caller.actor, "automation.settings", "Changed the automation settings: " + "; ".join(changes))
        db.commit()
    return _settings_out(db)


# --------------------------------------------------------------------------- #
# Scripts                                                                     #
# --------------------------------------------------------------------------- #
STARTER = {
    "code": "def main(args):\n    # args holds the arguments declared below; return something JSON can hold.\n"
    '    return {"greeting": "hello " + str(args.get("name", ""))}\n',
    "arguments": [{"name": "name", "type": "text", "required": False, "description": "Who to greet"}],
    "outputs": [{"name": "greeting", "type": "text", "description": "The greeting"}],
    "test": {"args": {"name": "Nik"}, "expect": {"greeting": "hello Nik"}},
}


class ScriptIn(BaseModel):
    name: str = Field(min_length=3, max_length=49)
    description: str = Field(default="", max_length=2000)


class ScriptPatch(BaseModel):
    description: str | None = Field(default=None, max_length=2000)
    draft: dict[str, Any] | None = None


class ScriptTestIn(BaseModel):
    """Test ``draft`` when given, the stored draft otherwise (the current version when there is none)."""

    draft: dict[str, Any] | None = None


class ScriptImportIn(BaseModel):
    script: dict[str, Any]


def _script(db: OrmSession, script_id: str) -> Script:
    row = db.get(Script, script_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Script not found")
    return row


def _version_out(row: ScriptVersion | None) -> dict[str, Any] | None:
    if row is None:
        return None
    return {
        "version": row.version,
        "code": row.code,
        "arguments": row.arguments or [],
        "outputs": row.outputs or [],
        "test": row.test or {},
        "testResult": row.test_result or {},
        "createdAt": row.created_at,
        "createdBy": row.created_by,
    }


def _users_of(db: OrmSession, name: str) -> list[str]:
    """The playbooks whose current version or draft has a node of this script."""
    found = []
    for playbook in db.scalars(select(Playbook).order_by(Playbook.name)):
        version = db.get(PlaybookVersion, (playbook.id, playbook.current_version)) if playbook.current_version else None
        shapes = [shape for shape in (version.graph if version else None, playbook.draft) if shape]
        if any(
            node.get("kind") == "script" and (node.get("config") or {}).get("script") == name
            for shape in shapes
            for node in graph.nodes_of(shape).values()
        ):
            found.append(playbook.name)
    return found


def _script_summary(db: OrmSession, row: Script) -> dict[str, Any]:
    return {
        "id": row.id,
        "name": row.name,
        "description": row.description,
        "builtin": bool(row.builtin),
        "version": row.current_version,
        "hasDraft": row.draft is not None,
        "inLibrary": row.current_version is not None,
        "updatedAt": row.updated_at,
        "updatedBy": row.updated_by,
    }


def _script_detail(db: OrmSession, row: Script) -> dict[str, Any]:
    versions = db.scalars(
        select(ScriptVersion).where(ScriptVersion.script_id == row.id).order_by(ScriptVersion.version.desc())
    ).all()
    return {
        **_script_summary(db, row),
        "current": _version_out(scripts.current(db, row)),
        "draft": row.draft,
        "versions": [{"version": v.version, "createdAt": v.created_at, "createdBy": v.created_by} for v in versions],
        "usedBy": _users_of(db, row.name),
    }


def _cleaned(source: dict[str, Any]) -> dict[str, Any]:
    try:
        return scripts.clean(source)
    except scripts.ScriptError as error:
        raise HTTPException(status_code=400, detail=str(error)) from None


@router.get("/scripts")
def list_scripts(_caller: Principal = Depends(editor_principal), db: OrmSession = Depends(get_db)) -> dict:
    """Every script: those in the library (with a saved version) and those still a draft."""
    rows = db.scalars(select(Script).order_by(func.lower(Script.name))).all()
    return {"scripts": [_script_summary(db, row) for row in rows], "sandbox": bool(app_settings.SANDBOX_URL)}


@router.post("/scripts", status_code=status.HTTP_201_CREATED)
def create_script(
    body: ScriptIn, caller: Principal = Depends(editor_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Create a script as a draft. Its name is how nodes and the command line call it:
    a capital letter, then letters and digits (``GroupByField``)."""
    name = body.name.strip()
    if not scripts.NAME_RE.match(name):
        raise HTTPException(
            status_code=400, detail="A script's name starts with a capital letter and holds letters and digits only"
        )
    if db.scalars(select(Script).where(func.lower(Script.name) == name.lower())).first() is not None:
        raise HTTPException(status_code=400, detail="A script with this name exists already")
    now = now_iso()
    row = Script(
        id=engine.new_id(),
        name=name,
        description=body.description.strip(),
        draft=dict(STARTER),
        created_at=now,
        created_by=caller.actor,
        updated_at=now,
        updated_by=caller.actor,
    )
    db.add(row)
    audit.record(db, caller.actor, "script.create", f'Created the script "{name}"', target=name)
    db.commit()
    return _script_detail(db, row)


@router.get("/scripts/{script_id}")
def get_script(
    script_id: str, _caller: Principal = Depends(editor_principal), db: OrmSession = Depends(get_db)
) -> dict:
    return _script_detail(db, _script(db, script_id))


@router.get("/scripts/{script_id}/versions/{number}")
def get_script_version(
    script_id: str, number: int, _caller: Principal = Depends(editor_principal), db: OrmSession = Depends(get_db)
) -> dict:
    found = db.get(ScriptVersion, (_script(db, script_id).id, number))
    if found is None:
        raise HTTPException(status_code=404, detail="Version not found")
    return _version_out(found)


@router.put("/scripts/{script_id}")
def update_script(
    script_id: str, body: ScriptPatch, caller: Principal = Depends(editor_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Save the draft (it need not run yet) and the description. Nothing a playbook
    uses changes until a version is saved."""
    row = _script(db, script_id)
    if body.description is not None:
        row.description = body.description.strip()
    if body.draft is not None:
        if len(str(body.draft)) > scripts.MAX_CODE * 2:
            raise HTTPException(status_code=413, detail="The script is too large")
        row.draft = body.draft
        flag_modified(row, "draft")
    row.updated_at = now_iso()
    row.updated_by = caller.actor
    db.commit()
    return _script_detail(db, row)


@router.delete("/scripts/{script_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_script(
    script_id: str, caller: Principal = Depends(editor_principal), db: OrmSession = Depends(get_db)
) -> Response:
    """Delete a script with its versions. A built-in one, or one a playbook uses, is refused."""
    row = _script(db, script_id)
    if row.builtin:
        raise HTTPException(status_code=400, detail="A built-in script cannot be deleted")
    users = _users_of(db, row.name)
    if users:
        raise HTTPException(status_code=409, detail="Used by: " + ", ".join(users[:10]))
    audit.record(db, caller.actor, "script.delete", f'Deleted the script "{row.name}"', target=row.name)
    db.delete(row)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/scripts/{script_id}/test")
def test_script(
    script_id: str, body: ScriptTestIn, _caller: Principal = Depends(editor_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Run the stored test in the sandbox: ``{passed, result | error, stdout, durationMs}``."""
    row = _script(db, script_id)
    latest = scripts.current(db, row)
    source = body.draft or row.draft or (_version_out(latest) if latest else None)
    if source is None:
        raise HTTPException(status_code=400, detail="There is nothing to test")
    return scripts.run_test(_cleaned(source))


@router.post("/scripts/{script_id}/versions", status_code=status.HTTP_201_CREATED, response_model=None)
def save_script_version(
    script_id: str, body: ScriptTestIn, caller: Principal = Depends(editor_principal), db: OrmSession = Depends(get_db)
) -> dict | JSONResponse:
    """Save the draft as the next version, **when its test passes** in the sandbox
    (``422`` with the test's result otherwise). From then on the script is in the
    library; playbooks stay on the version they were saved with."""
    row = _script(db, script_id)
    source = body.draft or row.draft
    if source is None:
        raise HTTPException(status_code=400, detail="There is no draft to save")
    draft = _cleaned(source)
    result = scripts.run_test(draft)
    if not result["passed"]:
        return JSONResponse(
            status_code=422,
            content={
                "detail": "The test does not pass: " + str(result.get("error") or "see the result"),
                "test": result,
            },
        )
    before = scripts.current(db, row)
    version = scripts.add_version(db, row, draft, result, caller.actor)
    diff = scripts.code_diff(before.code if before else "", draft["code"])
    audit.record(
        db,
        caller.actor,
        "script.version",
        f'Saved version {version.version} of the script "{row.name}"\n{diff}',
        target=row.name,
    )
    db.commit()
    return _script_detail(db, row)


@router.get("/scripts/{script_id}/export")
def export_script(
    script_id: str, _caller: Principal = Depends(editor_principal), db: OrmSession = Depends(get_db)
) -> dict:
    row = _script(db, script_id)
    latest = scripts.current(db, row)
    source = _version_out(latest) if latest else (row.draft or {})
    return {
        "app": "Nik",
        "type": "script",
        "version": 1,
        "script": {
            "name": row.name,
            "description": row.description,
            "code": source.get("code", ""),
            "arguments": source.get("arguments", []),
            "outputs": source.get("outputs", []),
            "test": source.get("test", {}),
        },
    }


@router.post("/scripts/import", status_code=status.HTTP_201_CREATED)
def import_script(
    body: ScriptImportIn, caller: Principal = Depends(editor_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Bring a script in from a file, as a draft: it enters the library when its test passes here."""
    source = body.script
    name = str(source.get("name") or "").strip()
    if not scripts.NAME_RE.match(name):
        raise HTTPException(status_code=400, detail="Not a script file")
    draft = _cleaned(source)
    base, counter = name, 2
    while db.scalars(select(Script).where(func.lower(Script.name) == name.lower())).first() is not None:
        name = f"{base[:46]}{counter}"
        counter += 1
    now = now_iso()
    row = Script(
        id=engine.new_id(),
        name=name,
        description=str(source.get("description") or "")[:2000],
        draft=draft,
        created_at=now,
        created_by=caller.actor,
        updated_at=now,
        updated_by=caller.actor,
    )
    db.add(row)
    audit.record(db, caller.actor, "script.import", f'Imported the script "{name}"', target=name)
    db.commit()
    return _script_detail(db, row)

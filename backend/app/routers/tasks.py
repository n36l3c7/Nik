"""Tasks: what people do for an incident, and the questions playbooks ask them.

Reading is for whoever reads incidents. Adding a task to an incident and
giving it to someone else is for whoever writes them. Completing or skipping
one is for whom the task is for (``tasks.may_complete``): the user it names,
whoever holds its role, the owner of its incident, an admin.
"""

from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session as OrmSession

from .. import archive, tasks, timers, war_room, work_plan
from ..core import audit
from ..core.db import get_db
from ..core.models import Incident, Notification, Task, WarRoomEntry
from ..core.security import Principal, reader_principal, writer_principal

router = APIRouter(tags=["tasks"])


class AssigneeIn(BaseModel):
    user: str = Field("", max_length=200)
    role: str = Field("", max_length=40)
    owner: bool = False


class TaskIn(BaseModel):
    title: str = Field(min_length=1, max_length=300)
    instructions: str = Field("", max_length=20_000)
    assignee: AssigneeIn = Field(default_factory=AssigneeIn)
    # In so long (7200, "30m", "2h", "3d") or at a date; nothing for no due time.
    due: Any = None
    fields: list[str] = Field(default_factory=list, max_length=tasks.FIELDS_MAX)


class AnswerIn(BaseModel):
    choice: str = Field("", max_length=200)
    fields: dict[str, Any] = Field(default_factory=dict)
    values: dict[str, Any] = Field(default_factory=dict)
    comment: str = Field("", max_length=2000)


class SkipIn(BaseModel):
    why: str = Field("", max_length=500)


def _task(db: OrmSession, task_id: str, *, lock: bool = False) -> Task:
    stmt = select(Task).where(Task.id == task_id)
    row = db.scalars(stmt.with_for_update() if lock else stmt).one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="Task not found")
    if lock:  # a task of an archived incident is read-only with it
        archive.guard_id(db, row.incident_id)
    return row


def _refuse(error: tasks.TaskError) -> HTTPException:
    return HTTPException(status_code=error.status, detail=error.message)


@router.get("/tasks")
def list_tasks(
    which: str = Query("mine", pattern="^(mine|all)$"),
    task_status: str = Query("open", alias="status", pattern="^(open|closed|all)$"),
    incident: str = Query("", max_length=80),
    limit: int = Query(200, ge=1, le=500),
    caller: Principal = Depends(reader_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Tasks, the most pressing first. ``which=mine`` (the default) gives the open tasks the
    caller may complete; ``which=all`` every task, of one incident when ``incident`` is given."""
    if which == "mine" and not incident:
        rows = tasks.mine(db, caller)[:limit]
    else:
        stmt = select(Task)
        if incident:
            stmt = stmt.where(Task.incident_id == incident)
        if task_status == "open":
            stmt = stmt.where(Task.status.in_(tasks.OPEN))
        elif task_status == "closed":
            stmt = stmt.where(Task.status.notin_(tasks.OPEN))
        rows = db.scalars(stmt.order_by(Task.created_at).limit(limit)).all()
    return {"tasks": [tasks.out(db, row, caller) for row in rows]}


@router.get("/tasks/count")
def count_tasks(caller: Principal = Depends(reader_principal), db: OrmSession = Depends(get_db)) -> dict:
    """How many open tasks wait for the caller, and how many of them are overdue."""
    rows = tasks.mine(db, caller)
    return {"mine": len(rows), "overdue": sum(1 for row in rows if row.status == "overdue")}


@router.get("/tasks/{task_id}")
def get_task(task_id: str, caller: Principal = Depends(reader_principal), db: OrmSession = Depends(get_db)) -> dict:
    """A task with what the War Room of its incident says of it."""
    row = _task(db, task_id)
    said = []
    if row.incident_id:
        entries = db.scalars(
            select(WarRoomEntry)
            .where(WarRoomEntry.incident_id == row.incident_id, WarRoomEntry.kind == "task")
            .order_by(WarRoomEntry.at)
        )
        said = [war_room.out(entry) for entry in entries if (entry.body or {}).get("task") == row.id]
    return {**tasks.out(db, row, caller), "entries": said}


@router.get("/incidents/{incident_id}/work-plan")
def get_work_plan(
    incident_id: str, caller: Principal = Depends(reader_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """The work plan of an incident: for each playbook that runs or ran on it, its nodes in order,
    grouped by phase, with what happened to each and the task behind it; the graph, for a
    read-only canvas; and the tasks added by hand. A node is shown by its name, never by its settings."""
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return work_plan.of(db, incident, caller)


@router.post("/incidents/{incident_id}/tasks", status_code=status.HTTP_201_CREATED)
def add_task(
    incident_id: str,
    body: TaskIn,
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Add a task to an incident by hand. With nobody named it is for the owner of the incident."""
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    archive.guard(incident)
    who = body.assignee
    if sum(1 for given in (who.user, who.role, who.owner) if given) > 1:
        raise HTTPException(status_code=400, detail="A task is for one user, for one role, or for the owner")
    now = time.time()
    try:
        row = tasks.create(
            db,
            kind="task",
            title=body.title,
            instructions=body.instructions,
            incident_id=incident.id,
            assignee_user=who.user.strip().lstrip("@"),
            assignee_role=who.role,
            assignee_owner=who.owner or not (who.user.strip() or who.role),
            form=tasks.clean_form(db, None, body.fields),
            due_at=tasks.due_at(body.due, now) if body.due not in (None, "") else None,
            actor=caller.actor,
            now=now,
        )
    except tasks.TaskError as error:
        raise _refuse(error) from None
    audit.record(db, caller.actor, "task.added", f'Added the task "{row.title}" for {tasks.for_whom(row)}', incident)
    db.commit()
    return tasks.out(db, row, caller)


@router.post("/tasks/{task_id}/complete")
def complete_task(
    task_id: str,
    body: AnswerIn,
    caller: Principal = Depends(reader_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Complete a task, or answer a question: a choice, the fields it asks for, a comment.
    ``403`` when the task is for someone else, ``409`` when it is not open any more."""
    row = _task(db, task_id, lock=True)
    try:
        tasks.complete(db, row, caller, body.model_dump(), time.time())
    except tasks.TaskError as error:
        db.rollback()
        raise _refuse(error) from None
    db.commit()
    return tasks.out(db, row, caller)


@router.post("/tasks/{task_id}/skip")
def skip_task(
    task_id: str,
    body: SkipIn,
    caller: Principal = Depends(reader_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Give a task up: a playbook that waits for it goes on as if it were done
    (a question, as if nobody had answered)."""
    row = _task(db, task_id, lock=True)
    if row.status not in tasks.OPEN:
        raise HTTPException(status_code=409, detail="This task is not open any more")
    if not tasks.may_complete(db, row, caller):
        raise HTTPException(status_code=403, detail="This task is for " + tasks.for_whom(row))
    tasks.skip(db, row, caller.actor, body.why or "Skipped", time.time())
    audit.record(
        db,
        caller.actor,
        "task.skipped",
        f'Skipped the task "{row.title}"',
        db.get(Incident, row.incident_id) if row.incident_id else None,
    )
    db.commit()
    return tasks.out(db, row, caller)


@router.put("/tasks/{task_id}/assignee")
def give_task(
    task_id: str,
    body: AssigneeIn,
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Give an open task to someone else: a user, a role, or the owner of the incident."""
    row = _task(db, task_id, lock=True)
    if row.status not in tasks.OPEN:
        raise HTTPException(status_code=409, detail="This task is not open any more")
    try:
        tasks.give(db, row, body.user.strip().lstrip("@"), body.role, body.owner, caller.actor)
    except tasks.TaskError as error:
        raise _refuse(error) from None
    db.commit()
    return tasks.out(db, row, caller)


def open_count(db: OrmSession, incident_id: str) -> int:
    return (
        db.scalar(
            select(func.count()).select_from(Task).where(Task.incident_id == incident_id, Task.status.in_(tasks.OPEN))
        )
        or 0
    )


# --------------------------------------------------------------------------- #
# SLA timers                                                                  #
# --------------------------------------------------------------------------- #
class TimerIn(BaseModel):
    # For "start": the time allowed in minutes (empty keeps what the timer has).
    minutes: int | None = Field(default=None, ge=1, le=timers.MINUTES_MAX)
    businessHours: bool | None = None
    restart: bool = False


@router.get("/incidents/{incident_id}/timers")
def list_timers(
    incident_id: str, _caller: Principal = Depends(reader_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """The SLA timers of the incident that were started: state, what each counted, what is left."""
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return {"timers": timers.of(db, incident, time.time()), "businessHours": timers.business_hours(db, incident)}


@router.post("/incidents/{incident_id}/timers/{field}/{what}")
def move_timer(
    incident_id: str,
    field: str,
    what: str,
    body: TimerIn,
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Start, pause or stop a timer of the incident by hand (``what``: start | pause | stop)."""
    from ..core.locking import lock_incident

    if what not in ("start", "pause", "stop"):
        raise HTTPException(status_code=404, detail="A timer is started, paused or stopped")
    incident = lock_incident(db, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    archive.guard(incident)
    now = time.time()
    try:
        if what == "start":
            timers.start(
                db,
                incident,
                field,
                now,
                due_s=body.minutes * 60 if body.minutes else None,
                business=body.businessHours,
                restart=body.restart,
            )
        else:
            timers.halt(db, incident, field, now, state="paused" if what == "pause" else "stopped")
    except timers.TimerError as error:
        raise HTTPException(status_code=400, detail=error.message) from None
    audit.record(db, caller.actor, f"timer.{what}", f"Timer {field}: {what}", incident)
    db.commit()
    return {"timers": timers.of(db, incident, now)}


# --------------------------------------------------------------------------- #
# What an account is told                                                     #
# --------------------------------------------------------------------------- #
class ReadIn(BaseModel):
    # The notifications that were read; none given means all of them.
    ids: list[str] = Field(default_factory=list, max_length=500)


def _told(row: Notification) -> dict:
    return {"id": row.id, "kind": row.kind, "text": row.text, "link": row.link, "at": row.at, "read": bool(row.read_at)}


@router.get("/notifications")
def list_notifications(
    limit: int = Query(50, ge=1, le=200),
    caller: Principal = Depends(reader_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """What the caller was told, the newest first, and how many are not read yet."""
    mine = Notification.username == caller.actor
    rows = db.scalars(select(Notification).where(mine).order_by(Notification.at.desc()).limit(limit)).all()
    unread = db.scalar(select(func.count()).select_from(Notification).where(mine, Notification.read_at.is_(None)))
    return {"notifications": [_told(row) for row in rows], "unread": unread or 0}


@router.post("/notifications/read")
def read_notifications(
    body: ReadIn, caller: Principal = Depends(reader_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Mark notifications of the caller as read: those named, or all of them."""
    from ..core.security import now_iso

    stmt = select(Notification).where(Notification.username == caller.actor, Notification.read_at.is_(None))
    if body.ids:
        stmt = stmt.where(Notification.id.in_(body.ids))
    stamp = now_iso()
    for row in db.scalars(stmt):
        row.read_at = stamp
    db.commit()
    return list_notifications(50, caller, db)

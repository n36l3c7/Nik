"""Tasks: what a person does for an incident, and questions a playbook asks.

A ``task`` or an ``ask`` node of a playbook makes a row of ``tasks`` and its
step waits; completing the task lets the run go on by the port the answer
names. A task can also be added to an incident by hand, with no run behind it.

Who may complete one: the user it is for; whoever holds the role it is for;
the owner of the incident when it is for "the owner", whoever that is at that
moment; and an admin. A task with no assignee is for anyone who writes
incidents.

The worker looks at open tasks every minute (``tick``): a task past its due
time becomes *overdue* and stays open, and the run also leaves the node by its
``overdue`` port; a question nobody answered in its time is given up and the
run leaves by ``timeout``; reminders are sent at their interval.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session as OrmSession

from . import fields as registry
from . import war_room
from .automation import graph
from .core import audit
from .core.models import Incident, Notification, Run, RunStep, Task, User
from .core.permissions import ADMIN, ROLE_PERMISSIONS, SYSTEM_ROLE, WRITE, clean_roles
from .core.security import Principal, now_iso

OPEN = ("open", "overdue")
CHOICES_MAX, FIELDS_MAX, INPUTS_MAX = graph.CHOICES_MAX, graph.FORM_FIELDS_MAX, graph.FORM_INPUTS_MAX
DUE_MIN, DUE_MAX = graph.WAIT_MIN, graph.DUE_MAX
REMINDER_MIN = graph.REMINDER_MIN
slug = graph.slug


class TaskError(ValueError):
    """What is wrong with a task or with its answer, as a sentence."""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.message = message
        self.status = status


def new_id() -> str:
    return uuid.uuid4().hex


def due_at(value: Any, now: float) -> float:
    """When a task is due: in so many seconds (``7200``, ``2h``, ``3d``), or at a date."""
    seconds = graph.seconds_of(value)
    if seconds is None:
        try:
            moment = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
        except ValueError:
            raise TaskError("Due in a time (7200, 30m, 2h, 3d) or at a date") from None
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        seconds = int(moment.timestamp() - now)
    if not DUE_MIN <= seconds <= DUE_MAX:
        raise TaskError("A task is due in 1 minute to 90 days")
    return now + seconds


def fillable(db: OrmSession) -> set[str]:
    """The fields of incidents a person can be asked to fill."""
    return {
        name
        for name, field in registry.registry(db).items()
        if field.applies_to == "incident"
        and (name not in registry.SYSTEM_FIELDS or registry.SYSTEM_FIELDS[name].writable)
    }


def notify(db: OrmSession, username: str, kind: str, text: str, link: str = "") -> None:
    """Tell an account something inside Nik (the caller commits)."""
    if not username:
        return
    db.add(Notification(id=new_id(), username=username, kind=kind, text=text[:500], link=link[:500], at=now_iso()))


def notify_approval(db: OrmSession, run: Run, question: str) -> None:
    """An approval waits: whoever may answer it is told (the caller commits)."""
    from .core.permissions import AUTOMATION_RUN, permissions_of

    link_to = f"/incident/{run.incident_id}" if run.incident_id else "/automation/approvals"
    for user in db.scalars(select(User).where(User.disabled.is_(False))):
        if AUTOMATION_RUN in permissions_of(clean_roles(user.roles)) and SYSTEM_ROLE not in clean_roles(user.roles):
            notify(db, user.username, "approval", f"An approval waits: {question}", link_to)


MENTION = re.compile(r"(?<![\w@])@([A-Za-z0-9][A-Za-z0-9._-]{0,63})")


def notify_mentions(db: OrmSession, incident: Incident, text: str, author: str) -> list[str]:
    """``@name`` in a note of the War Room tells that account (the caller commits). Returns who was told."""
    wanted = {name.lower().rstrip(".") for name in MENTION.findall(text or "")}
    if not wanted:
        return []
    told = []
    for user in db.scalars(select(User).where(User.disabled.is_(False))):
        if user.username.lower() in wanted and user.username.lower() != author.lower():
            notify(
                db, user.username, "mention", f"{author} mentioned you in {incident.name}", f"/incident/{incident.id}"
            )
            told.append(user.username)
    return told


def users_with_role(db: OrmSession, role: str) -> list[str]:
    return [
        user.username
        for user in db.scalars(select(User).where(User.disabled.is_(False)))
        if role in clean_roles(user.roles) or (role == "analyst" and "admin" in clean_roles(user.roles))
    ]


def assignees(db: OrmSession, task: Task) -> list[str]:
    """The accounts a task is for, by name, as things stand now."""
    if task.assignee_user:
        return [task.assignee_user]
    if task.assignee_role:
        return users_with_role(db, task.assignee_role)
    if task.assignee_owner and task.incident_id:
        incident = db.get(Incident, task.incident_id)
        return [incident.assignee] if incident is not None and incident.assignee else []
    return []


def may_complete(db: OrmSession, task: Task, caller: Principal) -> bool:
    if caller.has(ADMIN):
        return True
    if task.assignee_user:
        return caller.actor.lower() == task.assignee_user.lower()
    if task.assignee_role:
        return task.assignee_role in caller.roles
    if task.assignee_owner and task.incident_id:
        incident = db.get(Incident, task.incident_id)
        owner = (incident.assignee if incident is not None else "") or ""
        # Nobody has the incident: whoever works incidents may take its tasks.
        return caller.actor.lower() == owner.lower() if owner else caller.has(WRITE)
    return caller.has(WRITE)


def clean_form(db: OrmSession, choices: Any, field_names: Any, inputs: Any = None) -> dict[str, Any]:
    """What is filled on completion: the choices of a question, the fields of
    the registry to give, and what is asked for the playbook alone."""
    form: dict[str, Any] = {}
    if choices:
        if not isinstance(choices, list) or len(choices) > CHOICES_MAX:
            raise TaskError(f"A question has {CHOICES_MAX} choices at most")
        labels = [str(choice).strip() for choice in choices if str(choice).strip()]
        ports = [slug(label) for label in labels]
        if len(set(ports)) != len(ports) or not labels:
            raise TaskError("The choices of a question are different from one another")
        form["choices"] = [{"label": label, "port": port} for label, port in zip(labels, ports, strict=True)]
    if field_names:
        if not isinstance(field_names, list) or len(field_names) > FIELDS_MAX:
            raise TaskError(f"A task asks for {FIELDS_MAX} fields at most")
        known = fillable(db)
        names = []
        for name in field_names:
            if str(name) not in known:
                raise TaskError(f'"{name}" is not a field of incidents that can be filled')
            if str(name) not in names:
                names.append(str(name))
        form["fields"] = names
    if inputs:
        if not isinstance(inputs, list) or len(inputs) > INPUTS_MAX:
            raise TaskError(f"A question asks for {INPUTS_MAX} things at most")
        asked = []
        for item in inputs:
            name = str(item.get("name") or "") if isinstance(item, dict) else ""
            kind = item.get("type", "text") if isinstance(item, dict) else ""
            if not graph.INPUT_RE.match(name) or kind not in graph.INPUT_TYPES or name in [a["name"] for a in asked]:
                raise TaskError("What is asked for needs a name of its own, and is text, a number or yes/no")
            asked.append(
                {
                    "name": name,
                    "label": str(item.get("label") or name)[:80],
                    "type": kind,
                    "required": bool(item.get("required")),
                }
            )
        form["inputs"] = asked
    return form


def _input_value(item: dict[str, Any], value: Any) -> Any:
    """A value typed for something a question asks for, as its type says."""
    label = item["label"]
    if value in (None, ""):
        if item["required"]:
            raise TaskError(f"Needed: {label}")
        return None
    if item["type"] == "bool":
        if isinstance(value, bool):
            return value
        if str(value).strip().lower() in ("true", "yes", "1", "false", "no", "0"):
            return str(value).strip().lower() in ("true", "yes", "1")
        raise TaskError(f"{label} is yes or no")
    if item["type"] == "number":
        try:
            if isinstance(value, bool):
                raise ValueError
            number = float(value)
        except (TypeError, ValueError):
            raise TaskError(f"{label} is a number") from None
        if number != number or number in (float("inf"), float("-inf")):
            raise TaskError(f"{label} is a number")
        return int(number) if number == int(number) else number
    return str(value)[:5000]


def create(
    db: OrmSession,
    *,
    kind: str,
    title: str,
    instructions: str = "",
    incident_id: str | None = None,
    assignee_user: str = "",
    assignee_role: str = "",
    assignee_owner: bool = False,
    form: dict[str, Any] | None = None,
    due_at: float | None = None,
    reminder_s: int | None = None,
    timeout_at: float | None = None,
    run: Run | None = None,
    step: RunStep | None = None,
    actor: str = "",
    now: float,
) -> Task:
    """Make a task and tell who it is for (the caller commits)."""
    assignee_user = _account(db, assignee_user)
    _role(assignee_role)
    task = Task(
        id=new_id(),
        incident_id=incident_id,
        run_id=run.id if run is not None else None,
        step_id=step.id if step is not None else None,
        kind=kind,
        title=title.strip()[:300],
        instructions=instructions[:20_000],
        assignee_user=assignee_user,
        assignee_role=assignee_role,
        assignee_owner=bool(assignee_owner),
        status="open",
        form=form or {},
        due_at=due_at,
        reminder_s=reminder_s,
        next_reminder_at=(now + reminder_s) if reminder_s else None,
        timeout_at=timeout_at,
        created_at=now_iso(),
        created_by=actor,
    )
    db.add(task)
    db.flush()
    for name in assignees(db, task):
        notify(db, name, "task", f"A task for you: {task.title}", link(task))
    if incident_id:
        war_room.add(
            db,
            incident_id,
            "task",
            {"title": task.title, "task": task.id, "state": "asked", "for": for_whom(task)},
            actor or "nik-automation",
            run_id=task.run_id,
            step_id=task.step_id,
        )
    return task


def _account(db: OrmSession, name: str) -> str:
    """The name of the account a task is given to, as it is written."""
    if not name:
        return ""
    user = db.scalars(select(User).where(func.lower(User.username) == name.lower(), User.disabled.is_(False))).first()
    if user is None:
        raise TaskError(f"There is no account called {name} to give the task to")
    return user.username


def _role(role: str) -> None:
    if role and (role not in ROLE_PERMISSIONS or role == SYSTEM_ROLE):
        raise TaskError("A task is for a role that exists")


def give(db: OrmSession, task: Task, user: str, role: str, owner: bool, actor: str) -> None:
    """Give an open task to someone else (the caller commits)."""
    if sum(1 for given in (user, role, owner) if given) != 1:
        raise TaskError("A task is for one user, for one role, or for the owner of the incident")
    user = _account(db, user)
    _role(role)
    task.assignee_user, task.assignee_role, task.assignee_owner = user, role, bool(owner)
    for name in assignees(db, task):
        notify(db, name, "task", f"A task for you: {task.title}", link(task))
    if task.incident_id:
        war_room.add(
            db,
            task.incident_id,
            "task",
            {"title": task.title, "task": task.id, "state": "given", "for": for_whom(task)},
            actor,
            run_id=task.run_id,
            step_id=task.step_id,
        )


def from_line(text: str) -> tuple[str, str, str]:
    """``Call the user @anna due=2h`` as (title, user, due)."""
    user = due = ""
    words = []
    for word in str(text).split():
        if word.startswith("@") and len(word) > 1 and not user:
            user = word[1:]
        elif word.lower().startswith("due=") and len(word) > 4 and not due:
            due = word[4:]
        else:
            words.append(word)
    title = " ".join(words).strip()
    if not title:
        raise TaskError("/task is followed by what to do: /task Call the user @anna due=2h")
    return title, user, due


def link(task: Task) -> str:
    return f"/tasks/{task.id}"


def for_whom(task: Task) -> str:
    if task.assignee_user:
        return task.assignee_user
    if task.assignee_role:
        return f"the role {task.assignee_role}"
    return "the owner of the incident" if task.assignee_owner else "anyone"


def out(db: OrmSession, task: Task, caller: Principal | None = None) -> dict[str, Any]:
    incident = db.get(Incident, task.incident_id) if task.incident_id else None
    known = registry.registry(db) if (task.form or {}).get("fields") else {}
    return {
        "id": task.id,
        "kind": task.kind,
        "title": task.title,
        "instructions": task.instructions,
        "status": task.status,
        "incidentId": task.incident_id,
        "incidentName": incident.name if incident is not None else "",
        "incidentNumber": incident.number if incident is not None else None,
        "runId": task.run_id,
        "assignee": {"user": task.assignee_user, "role": task.assignee_role, "owner": bool(task.assignee_owner)},
        "for": for_whom(task),
        "choices": (task.form or {}).get("choices") or [],
        "inputs": (task.form or {}).get("inputs") or [],
        "fields": [
            {
                "name": name,
                "label": known[name].label or name,
                "type": known[name].type,
                "options": known[name].options or {},
                "description": known[name].description,
            }
            for name in (task.form or {}).get("fields") or []
            if name in known
        ],
        "answer": task.answer,
        "dueAt": task.due_at,
        "createdAt": task.created_at,
        "createdBy": task.created_by,
        "completedAt": task.completed_at,
        "completedBy": task.completed_by,
        "mine": may_complete(db, task, caller) if caller is not None else False,
    }


def mine(db: OrmSession, caller: Principal) -> list[Task]:
    """The open tasks the caller may complete, the most pressing first."""
    conditions = [func.lower(Task.assignee_user) == caller.actor.lower()]
    if caller.roles:
        conditions.append(Task.assignee_role.in_(caller.roles))
    conditions.append(Task.assignee_owner.is_(True))
    if caller.has(WRITE):
        # What is asked of anyone is asked of whoever works incidents.
        conditions.append(and_(Task.assignee_user == "", Task.assignee_role == "", Task.assignee_owner.is_(False)))
    rows = db.scalars(select(Task).where(Task.status.in_(OPEN), or_(*conditions))).all()
    found = [task for task in rows if not task.assignee_owner or task.assignee_user or _owned(db, task, caller)]
    return sorted(found, key=lambda task: (task.due_at is None, task.due_at or 0, task.created_at))


def _owned(db: OrmSession, task: Task, caller: Principal) -> bool:
    incident = db.get(Incident, task.incident_id) if task.incident_id else None
    return incident is not None and (incident.assignee or "").lower() == caller.actor.lower()


def complete(db: OrmSession, task: Task, caller: Principal, body: dict[str, Any], now: float) -> Task:
    """Complete a task with its answer: a choice, the fields it asks for, a comment (the caller commits).

    The fields are written to the incident through the registry, which checks
    them; a wrong value refuses the completion. The run behind the task, if
    any, goes on by the port of the answer.
    """
    from .automation import engine

    if task.status not in OPEN:
        raise TaskError("This task is not open any more", 409)
    if not may_complete(db, task, caller):
        raise TaskError("This task is for " + for_whom(task), 403)
    form = task.form or {}
    answer: dict[str, Any] = {"by": caller.actor, "at": now_iso(), "comment": str(body.get("comment") or "")[:2000]}
    port = "done" if task.kind == "task" else "answered"
    choices = form.get("choices") or []
    if choices:
        chosen = next((item for item in choices if body.get("choice") in (item["port"], item["label"])), None)
        if chosen is None:
            raise TaskError("Choose one of: " + ", ".join(item["label"] for item in choices))
        answer["choice"], port = chosen["label"], chosen["port"]
    names = form.get("fields") or []
    if names:
        given = body.get("fields") if isinstance(body.get("fields"), dict) else {}
        values = {name: given.get(name) for name in names}
        missing = [name for name, value in values.items() if value in (None, "", [])]
        if missing:
            known = registry.registry(db)
            raise TaskError("Needed: " + ", ".join(known[name].label or name for name in missing if name in known))
        incident = db.get(Incident, task.incident_id) if task.incident_id else None
        if incident is not None:
            try:
                registry.update(db, incident, values, caller.actor, f"user:{caller.actor}")
            except registry.FieldError as error:
                raise TaskError(error.message) from None
            answer["fields"] = {name: registry.read(db, incident).get(name) for name in names}
        else:
            answer["fields"] = values
    asked = form.get("inputs") or []
    if asked:
        typed = body.get("values") if isinstance(body.get("values"), dict) else {}
        answer["values"] = {item["name"]: _input_value(item, typed.get(item["name"])) for item in asked}
    task.status, task.answer = "done", answer
    task.completed_at, task.completed_by = now_iso(), caller.actor
    task.next_reminder_at = None
    if task.incident_id:
        incident = db.get(Incident, task.incident_id)
        war_room.add(
            db,
            task.incident_id,
            "task",
            {
                "title": task.title,
                "task": task.id,
                "state": "done",
                "answer": answer.get("choice") or "",
                "comment": answer["comment"],
            },
            caller.actor,
            run_id=task.run_id,
            step_id=task.step_id,
        )
        audit.record(db, caller.actor, "task.done", f'Completed the task "{task.title}"', incident)
    if task.step_id:
        engine.resume(db, task.step_id, port, {**answer, "task": task.id}, now)
    return task


def skip(db: OrmSession, task: Task, actor: str, why: str, now: float, *, port: str | None = None) -> None:
    """Give a task up (the caller commits): the run behind it, if any, leaves by ``port`` or is told it was skipped."""
    from .automation import engine

    if task.status not in OPEN:
        return
    task.status, task.completed_at, task.completed_by = "skipped", now_iso(), actor
    task.answer = {"by": actor, "at": now_iso(), "skipped": why[:500]}
    task.next_reminder_at = None
    if task.incident_id:
        war_room.add(
            db,
            task.incident_id,
            "task",
            {"title": task.title, "task": task.id, "state": "skipped", "comment": why[:500]},
            actor,
            run_id=task.run_id,
            step_id=task.step_id,
        )
    if task.step_id:
        leave = port or ("done" if task.kind == "task" else "timeout")
        engine.resume(db, task.step_id, leave, {**task.answer, "task": task.id}, now)


def tick(db: OrmSession, now: float) -> int:
    """What time does to open tasks (the worker, every minute; it commits). Returns how many it touched."""
    from .automation import engine

    touched = 0
    for task in db.scalars(select(Task).where(Task.status.in_(OPEN))).all():
        if task.timeout_at is not None and task.timeout_at <= now:
            skip(db, task, "nik", "Nobody answered in time", now, port="timeout")
            touched += 1
        elif task.status == "open" and task.due_at is not None and task.due_at <= now:
            # Overdue, and still to do: the run also leaves by "overdue" when that port is drawn.
            task.status = "overdue"
            for name in assignees(db, task):
                notify(db, name, "task.overdue", f"Overdue: {task.title}", link(task))
            if task.incident_id:
                war_room.system(db, task.incident_id, f'The task "{task.title}" is overdue')
            if task.step_id:
                engine.follow(db, task.step_id, "overdue", now)
            touched += 1
        elif task.next_reminder_at is not None and task.next_reminder_at <= now:
            task.next_reminder_at = now + (task.reminder_s or REMINDER_MIN)
            for name in assignees(db, task):
                notify(db, name, "task.reminder", f"Still waiting: {task.title}", link(task))
            touched += 1
        db.commit()
    return touched

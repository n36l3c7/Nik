"""The engine: a run advances one step at a time, and survives a restart.

A run is a row (``runs``) and its steps are rows (``run_steps``); nothing of a
run lives in memory. The worker claims the steps that are due and calls
``execute`` for each; a step reads what it needs, does its work, then applies
its result **in one transaction with the run locked**: its output goes into
the run's context, the edges it leaves by are marked, the next steps are
inserted. A crash leaves a step either not done (it is claimed again) or
fully applied.

How a graph is walked:

- A node that finishes takes one of its ports. The edges of that port are
  *taken*, those of its other ports are *dead*.
- A node runs when every edge that leads to it is settled and at least one is
  taken. When all are dead the node is dead too, and so are its edges: a
  branch not taken does not hold back the node where branches meet.
- A "for each" starts its body once per item (five at a time), each with its
  own results and edges, then leaves by ``done`` with what the items gave.
- An ``end`` node, a failure nobody handles, a stop or the deadline finish
  the run; whatever was still to do is skipped.

Failure of a step: tried again with growing waits while it has tries left,
then the ``error`` port when one is drawn, else the run fails. An action
that changes something outside and timed out with no answer is not tried
again unless it says it is idempotent: its outcome is unknown.

**Across a restart** (the worker stopped, was killed, or the server moved to
another host: all that is left is the database):

- A step is *started* and *done* in separate commits. The claim of the worker
  (``running``, by whom) is committed before the step does anything. A step
  about to make a call that changes something outside Nik (it isolates a host,
  sends a mail, opens a ticket) first writes and commits ``calling_at``. Its
  result is applied in one commit, which empties the mark.
- What a step does inside Nik (an incident it creates, a task, a note, the
  next steps, the event that starts other playbooks) is in that same last
  commit: it happened whole or not at all, so a step found ``running`` with
  no mark did nothing that lasts and is simply **tried again**.
- A step found ``running`` *with* the mark may have made its call. It is
  **tried again** only when the action says a second call does no harm
  (``idempotent``, or a command that sends the vendor an idempotency key).
  Otherwise nobody knows whether the host was isolated or the mail sent, and
  Nik does not guess: the step becomes ``interrupted`` and the run waits for a
  person, who says on the run's page *it happened, go on*, *it did not, do it
  again* or *stop the run* (``resolve``). That is what at-most-once means for
  something outside that cannot be asked.
- A step that was interrupted ``MAX_RESTARTS`` times while it ran is not
  started again: it fails, as a step that takes its worker down every time.
  A worker that was asked to stop and left a step unfinished did not fall
  because of the step: that interruption is noted and not counted.
- Waits (a time, a person, another run, a job of the API process) hold no
  worker and are rows: they go on where they were.
- The database going away under a step (it is restarted, or killed) is the
  same case seen from the other side: the worker lives and cannot write. The
  step is not failed for it; it stays claimed and is taken back by the rules
  above once the database answers.
"""

from __future__ import annotations

import contextlib
import logging
import random
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import regex
from sqlalchemy import func, select
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm.attributes import flag_modified

from ..core.models import Approval, Incident, Playbook, PlaybookVersion, Run, RunStep, Task
from ..core.permissions import SYSTEM_USER
from . import actions, graph
from . import expressions as ex

logger = logging.getLogger("nik.automation")

MAX_OUTPUT = 1_000_000  # characters of a step's output as JSON
MAX_CONTEXT = 8_000_000
EACH_PARALLEL = 5
POLL_EVERY = 30
BACKOFF_CAP = 900
RECLAIM_GRACE = 30
MATCH_TIMEOUT = 0.5
MAX_RESTARTS = 3
RESTARTS_KEPT = 20
# A step whose worker was away (the sandbox restarts) is taken again after this long, then twice
# and three times this long: about a minute in all before it fails as it always did.
AWAY_WAIT = 10
ACTIVE = ("pending", "running", "waiting", "interrupted")
ANSWERS = ("happened", "again", "stop")
FINISHED = ("done", "failed", "stopped")
TIMEOUTS = {"action": 60, "script": 10, "playbook": 30}

# A run is locked while a step of it does its work and applies its result
# (SELECT … FOR UPDATE): the steps of one run go one at a time, runs go side
# by side. SQLite has no row locks, so there the whole process takes turns.
_apply_lock = threading.RLock()


def serial(db: OrmSession):
    return _apply_lock if db.get_bind().dialect.name == "sqlite" else contextlib.nullcontext()


def iso(now: float) -> str:
    return datetime.fromtimestamp(now, tz=timezone.utc).isoformat()


def new_id() -> str:
    return uuid.uuid4().hex


class StepFailed(Exception):
    """A step that did not do its work: a sentence safe to show, and whether trying again can help."""

    def __init__(
        self,
        message: str,
        *,
        retry: bool = True,
        request: dict | None = None,
        log: str | None = None,
        away: bool = False,
    ):
        super().__init__(message)
        self.message = message
        self.retry = retry
        self.request = request
        self.log = log
        # The worker that does the step's work was not there (the sandbox was restarting): nothing
        # of the step ran, and it is taken again by itself a few times.
        self.away = away


@dataclass
class Outcome:
    """What performing a step gave: a port to leave by, or something to wait for."""

    port: str | None = None
    output: Any = None
    classes: dict | None = None
    request: dict | None = None
    log: str | None = None
    input: dict | None = None
    wait: dict | None = None  # stay `waiting`: {"kind": …}
    next_at: float | None = None
    end: dict | None = None  # {"status", "message"}: the run finishes here
    skipped: bool = False


# Set by scripts.py and by the tests: how a script node runs its code.
script_runner = None


# --------------------------------------------------------------------------- #
# Reading a run                                                               #
# --------------------------------------------------------------------------- #
def locked_run(db: OrmSession, run_id: str, *, wait: bool = True) -> Run | None:
    """The run, locked. With ``wait`` off, None as well when another session holds it now."""
    return db.scalars(
        select(Run)
        .where(Run.id == run_id)
        .with_for_update(skip_locked=not wait)
        .execution_options(populate_existing=True)
    ).one_or_none()


def graph_of(db: OrmSession, run: Run) -> dict:
    held = (run.state or {}).get("graph")
    if isinstance(held, dict):
        return held  # a debug run of a draft or of a branch carries the graph it was started with
    row = db.get(PlaybookVersion, (run.playbook_id, run.version))
    return row.graph if row else {"nodes": [], "edges": []}


def _loop_of(shape: dict, node_id: str) -> str | None:
    for loop, body in graph.loop_bodies(shape).items():
        if node_id in body:
            return loop
    return None


def _edges(run: Run, loop: str | None, index: int | None) -> dict:
    state = run.state
    if loop is None:
        return state.setdefault("edges", {})
    return state["each"][loop]["edges"].setdefault(str(index), {})


def _outputs(run: Run, loop: str | None, index: int | None) -> dict:
    if loop is None:
        return run.context
    return run.context.setdefault("__each", {}).setdefault(loop, {}).setdefault(str(index), {})


def _in_list(db: OrmSession | None):
    """What answers ``| in_list('name')``: None where there is no database to read the lists from."""
    if db is None:
        return None
    from .. import lists

    def held(name: str, value: Any) -> bool:
        if isinstance(value, (list, tuple)):
            return any(lists.contains(db, name, item) for item in value)
        return lists.contains(db, name, value)

    return held


def scope_of(run: Run, shape: dict, node_id: str, index: int | None, db: OrmSession | None = None) -> ex.Scope:
    """What the expressions of a node can read."""
    trigger = graph.trigger_of(shape)
    values = {key: value for key, value in run.context.items() if not key.startswith("__")}
    classes = {key: value for key, value in (run.context_classes or {}).items() if not key.startswith("__")}
    # The incident the run works on, as it is now: its fields by the names of the registry, and
    # its context. Read at each step, so a step sees what the one before it wrote.
    values["incident"], values["context"] = {}, {}
    if db is not None and run.incident_id:
        from .. import context as incident_context
        from .. import fields as field_registry
        from .. import incident_tags
        from . import payloads

        incident = db.get(Incident, run.incident_id)
        if incident is not None:
            # ``incident.tags`` is the field ``labels`` by the name a person knows it by.
            values["incident"] = incident_tags.named(db, field_registry.read(db, incident))
            classes["incident"] = payloads.registry_classes()
            values["context"] = incident_context.read(db, incident.id)
            classes["context"] = incident_context.classes()
    if trigger is not None:
        values[trigger["id"]] = values.get("trigger")
        classes[trigger["id"]] = classes.get("trigger") or {}
    values["run"] = {
        "id": run.id,
        "url": f"/automation/runs/{run.id}",
        "playbook": run.trigger.get("playbook", ""),
        "started_at": run.started_at,
        "dry_run": bool(run.dry_run),
    }
    values.setdefault("inputs", {})
    loop = _loop_of(shape, node_id)
    if loop is not None and index is not None:
        each = run.state["each"][loop]
        values.update(_outputs(run, loop, index))
        classes.update(((run.context_classes or {}).get("__each") or {}).get(loop, {}).get(str(index), {}))
        values["item"] = each["items"][index]
        values["index"] = index
        classes["item"] = {"": each.get("classes") or []}
    return ex.Scope(values=values, classes=classes, in_list=_in_list(db))


# --------------------------------------------------------------------------- #
# Starting                                                                    #
# --------------------------------------------------------------------------- #
def start_run(
    db: OrmSession,
    playbook: Playbook,
    *,
    kind: str,
    payload: dict | None = None,
    classes: dict | None = None,
    object_kind: str = "",
    object_id: str = "",
    incident_id: str | None = None,
    artifact_id: str | None = None,
    dry_run: bool = False,
    started_by: str = "",
    inputs: dict | None = None,
    event_id: str | None = None,
    caused_by_run: str | None = None,
    depth: int = 0,
    parent: tuple[Run, RunStep] | None = None,
    version: int | None = None,
    debug: dict | None = None,
    shape: dict | None = None,
    branch: dict | None = None,
    event_key: str | None = None,
    now: float,
) -> Run:
    """Create a run of the playbook's current version and its first steps (the caller commits).
    ``debug`` (``{"breakpoints": [...], "step": bool}``) makes it a debug run, which stops before
    nodes (debugger.py); ``shape`` runs a graph that is no saved version: a draft being debugged,
    or a branch, which ``branch`` (``{"id", "name"}``) then names. Only a debug run is given a
    graph: everything else that starts a run uses a saved version, so a branch never runs for real."""
    if debug is None and (shape is not None or branch is not None):
        raise ValueError("Only a debug run uses a graph that is not a saved version")
    number = version or playbook.current_version or 0
    carried = shape is not None
    if shape is None:
        shape = db.get(PlaybookVersion, (playbook.id, number)).graph
    run = Run(
        id=new_id(),
        playbook_id=playbook.id,
        version=number,
        status="running",
        trigger={
            "kind": kind,
            "event_id": event_id,
            "actor": started_by,
            "playbook": playbook.name,
            "caused_by_run": caused_by_run,
            "depth": depth,
            **(
                {"branch": {"id": str(branch.get("id") or ""), "name": str(branch.get("name") or "")}} if branch else {}
            ),
        },
        object_kind=object_kind,
        object_id=object_id,
        incident_id=incident_id,
        artifact_id=artifact_id,
        dry_run=dry_run,
        context={"trigger": payload or {}, "inputs": inputs or {}},
        context_classes={"trigger": classes or {}},
        state={
            "edges": {},
            "each": {},
            "seq": 0,
            **({"debug": debug} if debug is not None else {}),
            **({"graph": shape} if carried else {}),
        },
        debug=debug is not None,
        started_at=iso(now),
        deadline=now + (playbook.max_seconds or 86400),
        started_by=started_by,
        parent_run_id=parent[0].id if parent else None,
        parent_step_id=parent[1].id if parent else None,
        depth=(parent[0].depth + 1) if parent else 0,
        event_key=event_key,
    )
    db.add(run)
    db.flush()
    trigger = graph.trigger_of(shape)
    step = _new_step(db, run, trigger, None, now)
    step.status = "done"
    step.port = "out"
    step.output = _cut(payload or {})
    step.started_at = step.finished_at = iso(now)
    _resolve(db, run, shape, None, None, trigger["id"], "out", now)
    _settle(db, run, shape, now)
    _touch(run)
    return run


def _new_step(db: OrmSession, run: Run, node: dict, index: int | None, now: float) -> RunStep:
    config = node.get("config") or {}
    on_error = config.get("on_error") or {}
    tries = 1 + (int(on_error.get("times") or 0) if on_error.get("mode") == "retry" else 0)
    timeout = TIMEOUTS.get(node["kind"], 30)
    if node["kind"] == "action":
        spec = actions.lookup(db, str(config.get("action") or ""))
        timeout = spec.timeout if spec else timeout
    run.state["seq"] = int(run.state.get("seq", 0)) + 1
    step = RunStep(
        id=new_id(),
        run_id=run.id,
        node_id=node["id"],
        seq=run.state["seq"],
        kind=node["kind"],
        status="pending",
        attempt=0,
        max_attempts=tries,
        next_at=now,
        timeout_s=timeout,
        item_index=index,
    )
    db.add(step)
    return step


def _touch(run: Run) -> None:
    for name in ("context", "context_classes", "state"):
        flag_modified(run, name)


# --------------------------------------------------------------------------- #
# Walking the graph                                                           #
# --------------------------------------------------------------------------- #
def _resolve(
    db: OrmSession,
    run: Run,
    shape: dict,
    loop: str | None,
    index: int | None,
    node_id: str,
    port: str | None,
    now: float,
) -> None:
    """A node is over (by ``port``, or dead when None): settle its edges and what they lead to."""
    nodes = graph.nodes_of(shape)
    edges = _edges(run, loop, index)
    body = graph.loop_bodies(shape).get(loop, set()) if loop else None
    for found, target in graph.edges_from(shape).get(node_id, []):
        if target not in nodes:
            continue
        # The body of a "for each" is started per item, not by the loop node's own edges.
        if nodes[node_id]["kind"] == "for_each" and found == "each" and loop is None:
            continue
        if body is not None and target not in body:
            continue
        key = f"{node_id}|{found}|{target}"
        if edges.get(key) == "t":
            continue  # followed already: the "overdue" of a task that was still to do
        edges[key] = "t" if found == port else "d"
        _consider(db, run, shape, loop, index, target, now)


def _consider(
    db: OrmSession, run: Run, shape: dict, loop: str | None, index: int | None, node_id: str, now: float
) -> None:
    edges = _edges(run, loop, index)
    if f"#{node_id}" in edges:
        return  # started or dead already
    nodes = graph.nodes_of(shape)
    states = []
    for source, port in graph.edges_to(shape).get(node_id, []):
        if loop is not None and source == loop and port == "each":
            states.append("t")  # the item itself
        else:
            states.append(edges.get(f"{source}|{port}|{node_id}"))
    if any(state is None for state in states):
        return  # a branch that can still reach it is not over
    if any(state == "t" for state in states):
        edges[f"#{node_id}"] = "s"
        _new_step(db, run, nodes[node_id], index, now)
    else:
        edges[f"#{node_id}"] = "x"
        _resolve(db, run, shape, loop, index, node_id, None, now)


def _active_steps(db: OrmSession, run: Run, *, body: set | None = None, index: int | None = None) -> int:
    db.flush()
    stmt = select(func.count()).select_from(RunStep).where(RunStep.run_id == run.id, RunStep.status.in_(ACTIVE))
    if body is not None:
        stmt = stmt.where(RunStep.node_id.in_(body), RunStep.item_index == index)
    return db.scalar(stmt) or 0


def _settle(db: OrmSession, run: Run, shape: dict, now: float) -> None:
    """Nothing left to do: the run is over."""
    if run.status in FINISHED:
        return
    if _active_steps(db, run) == 0:
        _finish(db, run, "done", None, now, shape=shape)


def _finish(db: OrmSession, run: Run, status: str, error: str | None, now: float, shape: dict | None = None) -> None:
    """End the run: what was still to do is skipped, whoever waits for it is told."""
    if run.status in FINISHED:
        return
    run.status = status
    run.error = error
    run.finished_at = iso(now)
    db.flush()
    for step in db.scalars(select(RunStep).where(RunStep.run_id == run.id, RunStep.status.in_(ACTIVE))):
        step.status = "skipped"
        step.finished_at = iso(now)
        step.next_at = None
    for approval in db.scalars(select(Approval).where(Approval.run_id == run.id, Approval.status == "waiting")):
        approval.status = "expired"
        approval.answered_at = iso(now)
    # What a person was still to do for this run is not asked any more.
    for task in db.scalars(select(Task).where(Task.run_id == run.id, Task.status.in_(("open", "overdue")))):
        task.status = "skipped"
        task.completed_at = iso(now)
        task.completed_by = "nik"
        task.next_reminder_at = None
        task.answer = {"by": "nik", "at": iso(now), "skipped": f"The run ended ({status})"}
    # Child runs stop with their parent.
    for child in db.scalars(select(Run).where(Run.parent_run_id == run.id, Run.status.notin_(FINISHED))):
        _finish(db, child, "stopped", "The playbook that started it ended", now)
    if shape is not None and status == "done":
        run.context["__outputs"] = _run_outputs(run, shape)
    _touch(run)
    if run.parent_run_id and run.parent_step_id:
        _child_finished(db, run, now)


def _run_outputs(run: Run, shape: dict) -> dict:
    """The declared outputs of a playbook, for the one that ran it."""
    out = {}
    trigger = graph.trigger_of(shape)
    values = {key: value for key, value in run.context.items() if not key.startswith("__")}
    if trigger:
        values[trigger["id"]] = values.get("trigger")
    scope = ex.Scope(values=values)
    for item in shape.get("outputs") or []:
        try:
            out[str(item.get("name"))] = ex.render(item.get("from"), scope).data
        except ex.ExpressionError:
            out[str(item.get("name"))] = None
    return out


def _child_finished(db: OrmSession, child: Run, now: float) -> None:
    step = db.get(RunStep, child.parent_step_id)
    if step is None or step.status != "waiting":
        return
    parent = locked_run(db, child.parent_run_id)
    if parent is None or parent.status in FINISHED:
        return
    shape = graph_of(db, parent)
    if child.status == "done":
        _complete(
            db, parent, shape, step, "out", {"run": child.id, "result": child.context.get("__outputs") or {}}, now
        )
    else:
        _fail(db, parent, shape, step, f"The playbook it ran ended {child.status}", now, retry=False)


# --------------------------------------------------------------------------- #
# Applying what a step gave                                                   #
# --------------------------------------------------------------------------- #
def _cut(value: Any) -> Any:
    """An output larger than the limit is cut and says so."""
    import json

    try:
        text = json.dumps(value, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return {"truncated": True, "note": "The result could not be stored as JSON"}
    if len(text) <= MAX_OUTPUT:
        return json.loads(text)
    return {"truncated": True, "note": f"The result was larger than {MAX_OUTPUT} characters", "start": text[:2000]}


def _context_size(run: Run) -> int:
    import json

    return len(json.dumps(run.context, ensure_ascii=False, default=str))


def _complete(
    db: OrmSession,
    run: Run,
    shape: dict,
    step: RunStep,
    port: str,
    output: Any,
    now: float,
    *,
    classes: dict | None = None,
    skipped: bool = False,
) -> None:
    """The step is done: keep its result, walk on."""
    loop = _loop_of(shape, step.node_id)
    index = step.item_index if loop else None
    stored = _cut(output)
    step.status = "skipped" if skipped else "done"
    step.port = port
    step.output = stored
    step.error = None if not skipped else step.error
    step.finished_at = iso(now)
    step.next_at = None
    step.waiting = None
    step.calling_at = None
    _outputs(run, loop, index)[step.node_id] = stored
    if not skipped:
        # A line in the War Room of the incident the run works on.
        from .. import war_room

        war_room.step_done(db, run, step, graph.nodes_of(shape).get(step.node_id) or {})
    if classes:
        held = run.context_classes
        if loop:
            held = held.setdefault("__each", {}).setdefault(loop, {}).setdefault(str(index), {})
        held[step.node_id] = classes
    if _context_size(run) > MAX_CONTEXT:
        _fail_run(db, run, f"The run holds more than {MAX_CONTEXT // 1_000_000} MB of results", now)
        return
    _resolve(db, run, shape, loop, index, step.node_id, port, now)
    _after(db, run, shape, loop, index, now)
    _touch(run)


def _after(db: OrmSession, run: Run, shape: dict, loop: str | None, index: int | None, now: float) -> None:
    if loop is not None:
        body = graph.loop_bodies(shape)[loop]
        if _active_steps(db, run, body=body, index=index) == 0:
            _item_finished(db, run, shape, loop, index, None, now)
    _settle(db, run, shape, now)


def _fail_run(db: OrmSession, run: Run, message: str, now: float) -> None:
    _finish(db, run, "failed", message, now)


def _fail(
    db: OrmSession,
    run: Run,
    shape: dict,
    step: RunStep,
    message: str,
    now: float,
    *,
    retry: bool = True,
    request: dict | None = None,
    log: str | None = None,
    away: bool = False,
) -> None:
    """The step failed: try again, or leave by the error port, or fail what holds it."""
    step.error = message[:2000]
    step.request = request or step.request
    step.log = log or step.log
    step.calling_at = None
    waited = sum(1 for line in step.restarts or [] if line.get("what") == "away")
    if away and waited < MAX_RESTARTS:
        # Its worker was away: taken again later, without counting against the tries of the node.
        _noted(step, now, "away")
        step.attempt = max(0, (step.attempt or 0) - 1)
        step.status, step.next_at, step.claimed_by = "pending", now + AWAY_WAIT * (waited + 1), None
        return
    if retry and step.attempt < step.max_attempts:
        step.status = "pending"
        step.next_at = now + backoff(step.attempt)
        step.claimed_by = None
        return
    step.status = "failed"
    step.finished_at = iso(now)
    step.next_at = None
    step.waiting = None
    nodes = graph.nodes_of(shape)
    from .. import war_room

    war_room.step_done(db, run, step, nodes.get(step.node_id) or {}, error=step.error)
    loop = _loop_of(shape, step.node_id)
    index = step.item_index if loop else None
    handled = any(port == "error" for port, _target in graph.edges_from(shape).get(step.node_id, []))
    if handled:
        _outputs(run, loop, index)[step.node_id] = {"error": step.error}
        step.port = "error"
        _resolve(db, run, shape, loop, index, step.node_id, "error", now)
        _after(db, run, shape, loop, index, now)
        _touch(run)
        return
    name = nodes.get(step.node_id, {}).get("name") or step.node_id
    if loop is not None:
        _item_finished(db, run, shape, loop, index, f"{name}: {step.error}", now)
        _settle(db, run, shape, now)
        _touch(run)
        return
    _fail_run(db, run, f"{name}: {step.error}", now)


def backoff(attempt: int) -> float:
    """5 s, 15 s, 45 s … capped at 15 minutes, with a little noise."""
    return min(BACKOFF_CAP, 5 * 3 ** max(attempt - 1, 0)) * random.uniform(0.8, 1.2)  # noqa: S311 (jitter)


# --------------------------------------------------------------------------- #
# "For each"                                                                  #
# --------------------------------------------------------------------------- #
def _start_items(db: OrmSession, run: Run, shape: dict, loop: str, now: float) -> None:
    each = run.state["each"][loop]
    nodes = graph.nodes_of(shape)
    entries = [target for port, target in graph.edges_from(shape)[loop] if port == "each" and target in nodes]
    while each["next"] < len(each["items"]) and len(each["active"]) < EACH_PARALLEL:
        index = each["next"]
        each["next"] += 1
        each["active"].append(index)
        for target in entries:
            _consider(db, run, shape, loop, index, target, now)
        # An item whose body had nothing to start is over at once.
        if _active_steps(db, run, body=graph.loop_bodies(shape)[loop], index=index) == 0:
            _item_finished(db, run, shape, loop, index, None, now)


def _item_finished(db: OrmSession, run: Run, shape: dict, loop: str, index: int, error: str | None, now: float) -> None:
    each = run.state["each"][loop]
    if index not in each["active"]:
        return
    each["active"].remove(index)
    outputs = dict(_outputs(run, loop, index))
    each["results"][str(index)] = {"error": error} if error else outputs
    if error:
        each["failed"] += 1
    step = db.scalars(
        select(RunStep).where(RunStep.run_id == run.id, RunStep.node_id == loop, RunStep.status == "waiting")
    ).first()
    if step is None:
        return
    config = graph.nodes_of(shape)[loop].get("config") or {}
    if error and not config.get("continue_on_item_error"):
        # The other items in flight are dropped with the loop.
        body = graph.loop_bodies(shape)[loop]
        for other in db.scalars(
            select(RunStep).where(RunStep.run_id == run.id, RunStep.node_id.in_(body), RunStep.status.in_(ACTIVE))
        ):
            other.status = "skipped"
            other.finished_at = iso(now)
            other.next_at = None
        each["active"] = []
        _fail(db, run, shape, step, f"Item {index + 1}: {error}", now, retry=False)
        return
    _start_items(db, run, shape, loop, now)
    if not each["active"] and each["next"] >= len(each["items"]):
        results = [each["results"].get(str(i)) for i in range(len(each["items"]))]
        _complete(
            db, run, shape, step, "done", {"count": len(results), "failed": each["failed"], "results": results}, now
        )


# --------------------------------------------------------------------------- #
# Performing a step                                                           #
# --------------------------------------------------------------------------- #
def matches(pattern: str, text: str) -> bool:
    """A user-written pattern, matched with a time limit (never the unbounded ``re``)."""
    try:
        return regex.search(pattern, text, timeout=MATCH_TIMEOUT) is not None
    except TimeoutError:
        raise StepFailed("The pattern took too long to match: make it simpler", retry=False) from None
    except regex.error:
        raise StepFailed("The pattern is not a valid regular expression", retry=False) from None


def holds(conditions: dict, scope: ex.Scope) -> bool:
    """Whether a condition (``all`` / ``any`` of comparisons) is true in the scope."""
    key = "all" if "all" in conditions else "any"
    results = []
    for item in conditions.get(key) or []:
        op = item.get("op")
        try:
            left = ex.render(item.get("left"), scope).data
        except ex.ExpressionError:
            if op not in ("exists", "empty"):
                raise
            left = ex.MISSING
        right = ex.render(item.get("right"), scope).data if "right" in item else None
        if op == "matches":
            results.append(matches(str(right), ex._text(None if left is ex.MISSING else left)))
        else:
            results.append(ex.compare(left, op, right))
    return all(results) if key == "all" else any(results)


def _needs_approval(node: dict, spec: actions.Spec, playbook: Playbook, args: dict) -> bool:
    approval = (node.get("config") or {}).get("approval")
    if isinstance(approval, dict) and "ask" in approval:
        return bool(approval["ask"])
    return bool(spec.changes(args) and playbook.approval_default)


def _ask(
    db: OrmSession, run: Run, step: RunStep, question: str, detail: dict, wait_seconds, on_expire: str, now: float
) -> Outcome:
    approval = Approval(
        id=new_id(),
        run_id=run.id,
        step_id=step.id,
        question=question[:500],
        detail=detail,
        status="waiting",
        on_expire=on_expire,
        asked_at=iso(now),
        asked_epoch=now,
        expires_at=(now + int(wait_seconds)) if wait_seconds else None,
    )
    db.add(approval)
    from .. import tasks

    tasks.notify_approval(db, run, question)
    return Outcome(wait={"kind": "approval", "id": approval.id, "inline": step.kind != "approval"})


def _person(db: OrmSession, run: Run, node: dict, step: RunStep, scope: ex.Scope, now: float) -> Outcome:
    """A task or a question: make it, and wait for the person it is for."""
    from .. import tasks

    kind = node["kind"]
    config = node.get("config") or {}

    def text(key: str) -> str:
        return ex._text(ex.render(config.get(key) or "", scope).data).strip()

    title = text("title" if kind == "task" else "question") or str(node.get("name") or node["id"])
    if run.dry_run:
        # A dry run shows the path of a task done, or of the first answer, without asking anyone.
        port = "done" if kind == "task" else graph.answer_ports(config)[0]
        output = {"by": "dry run", "at": iso(now), "comment": ""}
        if kind == "ask" and config.get("choices"):
            output["choice"] = str(config["choices"][0])
        # What would be filled is there, empty, for the steps after to read.
        if config.get("fields"):
            output["fields"] = {str(name): None for name in config["fields"]}
        if kind == "ask" and config.get("inputs"):
            output["values"] = {str(item.get("name")): None for item in config["inputs"] if isinstance(item, dict)}
        return Outcome(port=port, output=output, input={"title": title})
    who = config.get("assignee") if isinstance(config.get("assignee"), dict) else {}
    user = ex._text(ex.render(who.get("user") or "", scope).data).strip().lstrip("@")
    role = str(who.get("role") or "")
    try:
        due = config.get("due")
        due_at = tasks.due_at(ex.render(due, scope).data, now) if due not in (None, "") else None
        task = tasks.create(
            db,
            kind=kind,
            title=title,
            instructions=text("instructions"),
            incident_id=run.incident_id,
            assignee_user=user,
            assignee_role=role,
            # A task with nobody named is for whoever has the incident; a question, for anyone.
            assignee_owner=bool(who.get("owner")) or (kind == "task" and not user and not role),
            form=tasks.clean_form(db, config.get("choices"), config.get("fields"), config.get("inputs")),
            due_at=due_at,
            reminder_s=config.get("reminder_seconds"),
            timeout_at=(now + int(config["timeout_seconds"])) if config.get("timeout_seconds") else None,
            run=run,
            step=step,
            actor="nik-automation",
            now=now,
        )
    except tasks.TaskError as error:
        raise StepFailed(error.message, retry=False) from None
    return Outcome(
        wait={"kind": "task", "id": task.id, "since": now}, input={"title": title, "for": tasks.for_whom(task)}
    )


def _perform(
    db: OrmSession, run: Run, playbook: Playbook, shape: dict, node: dict, step: RunStep, now: float
) -> Outcome:
    kind = node["kind"]
    config = node.get("config") or {}
    scope = scope_of(run, shape, node["id"], step.item_index, db)
    waiting = step.waiting or {}

    if kind == "condition":
        result = holds(config, scope)
        return Outcome(port="yes" if result else "no", output={"result": result})

    if kind == "wait":
        started = waiting.get("since", now)
        if "until" in config:
            poll = config.get("poll")
            if isinstance(poll, dict) and poll.get("action"):
                spec = actions.lookup(db, str(poll["action"]))
                if spec is None:
                    raise StepFailed("The action this wait asks does not exist", retry=False)
                rendered = ex.render(poll.get("args") or {}, scope)
                call = actions.Call(
                    db=db, args=actions.argument_values(spec, rendered), classes=rendered.classes, arg_classes={},
                    dry_run=bool(run.dry_run), run=run, playbook=playbook, step_id=step.id, now=now,
                )  # fmt: skip
                scope.values["poll"] = spec.run(call).output
            if holds(config["until"], scope):
                return Outcome(port="out", output={"waited": int(now - started), "timed_out": False})
            if now - started >= int(config.get("timeout") or 86400):
                return Outcome(port="out", output={"waited": int(now - started), "timed_out": True})
            return Outcome(
                wait={"kind": "wait", "since": started}, next_at=now + int(config.get("every") or POLL_EVERY)
            )
        if waiting.get("kind") == "wait":
            return Outcome(port="out", output={"waited": int(now - started)})
        return Outcome(wait={"kind": "wait", "since": now}, next_at=now + int(config["seconds"]))

    if kind == "approval":
        if run.dry_run:
            # A dry run shows the path of a yes without asking anyone.
            return Outcome(
                port="approved", output={"answer": "approved", "by": "dry run", "at": iso(now), "comment": ""}
            )
        question = ex._text(ex.render(config.get("question") or "", scope).data)
        detail = ex.render(config.get("detail") or {}, scope).data
        detail = detail if isinstance(detail, dict) else {"detail": detail}
        return _ask(db, run, step, question, detail, config.get("wait_seconds"), config.get("on_expire", "skip"), now)

    if kind in ("task", "ask"):
        return _person(db, run, node, step, scope, now)

    if kind == "for_each":
        rendered = ex.render(config.get("items"), scope)
        items = rendered.data
        if isinstance(items, str) or not isinstance(items, (list, tuple)):
            raise StepFailed('"For each" needs a list: this is not one', retry=False)
        ceiling = int(config.get("max") or graph.EACH_MAX)
        if len(items) > ceiling:
            raise StepFailed(f"{len(items)} items, more than the {ceiling} this loop allows", retry=False)
        if not items:
            return Outcome(port="done", output={"count": 0, "failed": 0, "results": []})
        run.state.setdefault("each", {})[node["id"]] = {
            "items": list(items), "classes": sorted(rendered.classes), "next": 0, "active": [],
            "failed": 0, "results": {}, "edges": {},
        }  # fmt: skip
        return Outcome(wait={"kind": "each"}, input={"items": len(items)})

    if kind == "action":
        spec = actions.lookup(db, str(config.get("action") or ""))
        if spec is None:
            raise StepFailed("This action does not exist any more", retry=False)
        rendered = ex.render(config.get("args") or {}, scope)
        args = actions.argument_values(spec, rendered)
        if isinstance(waiting.get("override"), dict):
            args = {**args, **waiting["override"]}  # typed by who debugs the run
        arg_classes = ex.render_classes(config.get("args") or {}, scope)
        shown = {"action": spec.id, "args": _cut(actions.shown_arguments(spec, args))}
        approved_by = waiting.get("approved_by")
        # A debug run holds what goes outside, as a dry run does, unless this one node was let through.
        dry = bool(run.dry_run) and not waiting.get("real")
        if _needs_approval(node, spec, playbook, args) and not approved_by and not dry:
            approval = config.get("approval") if isinstance(config.get("approval"), dict) else {}
            question = f"{node.get('name') or spec.name}: go ahead?"
            outcome = _ask(
                db, run, step, question, shown, approval.get("wait_seconds"), approval.get("on_expire", "skip"), now
            )
            outcome.input = shown
            return outcome
        if not dry and spec.changes(args):
            run = _mark_calling(db, run, step, now)
        call = actions.Call(
            db=db, args=args, classes=rendered.classes, arg_classes=arg_classes, dry_run=dry,
            run=run, playbook=playbook, step_id=step.id, approved_by=approved_by, now=now,
            held="drop" if config.get("held") == "drop" else "fail",
            connection=str(config.get("connection") or ""),
            state=waiting.get("state") if waiting.get("kind") == "again" else None,
        )  # fmt: skip
        try:
            result = spec.run(call)
        except actions.ActionError as error:
            unknown = error.unknown_outcome and spec.changes(args) and not spec.idempotent
            message = f"{error.message} (outcome unknown: it is not tried again)" if unknown else error.message
            raise StepFailed(message, retry=error.retry and not unknown, request=error.request) from None
        if result.again_at is not None:
            # The action is not finished (it waits for the other side): the step is called again then.
            step.calling_at = None
            return Outcome(
                wait={"kind": "again", "state": result.state or {}, "approved_by": approved_by},
                next_at=max(now + 1, float(result.again_at)), request=result.request, log=result.log, input=shown,
            )  # fmt: skip
        wrote = _to_context(db, run, result.context, result.context_source)
        return Outcome(
            port="out", output=result.output, classes=result.classes or _inherit(rendered.classes),
            request=result.request, log=_with(result.log, wrote), input=shown,
        )  # fmt: skip

    if kind == "script":
        if script_runner is None:
            raise StepFailed("Scripts cannot run here: the sandbox is not configured", retry=False)
        rendered = ex.render(config.get("args") or {}, scope)
        args = rendered.data if isinstance(rendered.data, dict) else {}
        if isinstance(waiting.get("override"), dict):
            args = {**args, **waiting["override"]}  # typed by who debugs the run
        output, log = script_runner(db, str(config.get("script")), config.get("script_version"), args, run)
        # The outputs the script declares a context path for go to the context of the incident.
        log = _with(log, _to_context(db, run, script_context(db, config, output), ""))
        # A script cannot launder data: what comes out has the classes of all that went in.
        return Outcome(
            port="out", output=output, classes=_inherit(rendered.classes), log=log, input={"args": _cut(args)}
        )

    if kind == "playbook":
        if waiting.get("kind") == "run":
            return Outcome(wait=waiting)  # the child tells when it ends
        called = db.scalars(select(Playbook).where(Playbook.name == str(config.get("playbook")))).first()
        if called is None or not called.current_version:
            raise StepFailed("The playbook to run does not exist, or has no saved version", retry=False)
        if run.depth + 1 > graph.CALL_DEPTH:
            raise StepFailed(f"Playbooks run each other more than {graph.CALL_DEPTH} deep", retry=False)
        rendered = ex.render(config.get("args") or {}, scope)
        child = start_run(
            db, called, kind="playbook", payload=run.context.get("trigger") or {},
            classes=(run.context_classes or {}).get("trigger") or {}, object_kind=run.object_kind,
            object_id=run.object_id, incident_id=run.incident_id, artifact_id=run.artifact_id,
            dry_run=bool(run.dry_run), started_by=run.started_by,
            inputs=rendered.data if isinstance(rendered.data, dict) else {}, parent=(run, step), now=now,
        )  # fmt: skip
        if not config.get("wait", True):
            child.parent_step_id = None  # nobody waits for it
            return Outcome(port="out", output={"run": child.id})
        if child.status in FINISHED:
            if child.status != "done":
                raise StepFailed(f"The playbook it ran ended {child.status}", retry=False)
            return Outcome(port="out", output={"run": child.id, "result": child.context.get("__outputs") or {}})
        return Outcome(wait={"kind": "run", "id": child.id}, input={"playbook": called.name})

    if kind == "end":
        message = ex._text(ex.render(config.get("message") or "", scope).data)[:500]
        return Outcome(end={"status": config.get("status", "done"), "message": message})

    raise StepFailed("Unknown kind of node", retry=False)


def script_context(db: OrmSession, config: dict, output: Any) -> list[tuple[str, Any]]:
    """(context path, value) for each output of a script node that declares where it goes."""
    from ..core.models import Script, ScriptVersion

    if not isinstance(output, dict):
        return []
    script = db.scalars(select(Script).where(Script.name == str(config.get("script")))).first()
    version = config.get("script_version")
    row = db.get(ScriptVersion, (script.id, version)) if script is not None and isinstance(version, int) else None
    return [
        (item["context_path"], output[item["name"]])
        for item in (row.outputs if row is not None else None) or []
        if item.get("context_path") and output.get(item["name"]) not in (None, "", [], {})
    ]


def _to_context(db: OrmSession, run: Run, writes: list, source: str) -> list[str]:
    """Write what a step declared to the context of the run's incident. Nothing in a dry run, and
    nothing for a run that works on no incident. A write that is refused fails the step."""
    if not writes or run.dry_run or not run.incident_id or (run.trigger or {}).get("no_context"):
        return []
    from .. import context as incident_context

    incident = db.get(Incident, run.incident_id)
    if incident is None:
        return []
    try:
        return incident_context.apply(db, incident, list(writes), source or f"run:{run.id}", SYSTEM_USER)
    except incident_context.ContextError as error:
        raise StepFailed(f"Context: {error.message}", retry=False) from None


def _with(log: str | None, wrote: list[str]) -> str | None:
    if not wrote:
        return log
    line = "[nik] written to the context: " + ", ".join(wrote[:20])
    return f"{log}\n{line}" if log else line


def _inherit(classes: frozenset) -> dict:
    return {"": sorted(classes)} if classes else {}


# --------------------------------------------------------------------------- #
# Executing a claimed step                                                    #
# --------------------------------------------------------------------------- #
def _is_try(step: RunStep) -> bool:
    """A new try of the step's work, not the continuation of a wait."""
    return not (step.waiting or {}).get("kind")


class _Gone(Exception):
    """The run ended, or the step was taken from this worker, while the step was about to call."""


def _mark_calling(db: OrmSession, run: Run, step: RunStep, now: float) -> Run:
    """Write down, and commit, that this try is about to make a call that changes something
    outside Nik: *started*, in a commit of its own, before the call leaves. The commit lets go of
    the run, so it is locked again and looked at again: a run that ended meanwhile makes no call."""
    step.calling_at = now
    db.commit()
    run = locked_run(db, step.run_id)
    db.refresh(step)
    if run is None or run.status in FINISHED or step.status != "running":
        raise _Gone
    return run


def execute(db: OrmSession, step_id: str, now: float, holder: str | None = None) -> None:
    """Do the work of a step the worker claimed, and apply the result. ``holder`` is the worker
    that claimed it: a step that is no longer its own (it was taken back after this worker was
    thought gone) is left alone, so that a worker that comes back late applies nothing twice."""
    step = db.get(RunStep, step_id)
    if step is None or step.status != "running" or (holder is not None and step.claimed_by != holder):
        return
    run = db.get(Run, step.run_id)
    if run is None:
        return
    if run.status in FINISHED:
        step.status = "skipped"
        step.finished_at = iso(now)
        db.commit()
        return
    shape = graph_of(db, run)
    node = graph.nodes_of(shape).get(step.node_id)
    playbook = db.get(Playbook, run.playbook_id)
    if _is_try(step):
        step.attempt = (step.attempt or 0) + 1
        step.started_at = step.started_at or iso(now)
    tried = step.attempt
    outcome: Outcome | None = None
    failure: StepFailed | None = None
    with serial(db):
        try:
            if node is None or playbook is None:
                raise StepFailed("The node is not in this version of the playbook", retry=False)
            run = locked_run(db, step.run_id)
            if run.status in FINISHED:
                step.status = "skipped"
                step.finished_at = iso(now)
                db.commit()
                return
            if run.debug and _is_try(step) and step.attempt <= 1:
                from . import debugger

                if debugger.park(db, run, shape, node, step, now):
                    db.commit()
                    return
            outcome = _perform(db, run, playbook, shape, node, step, now)
        except _Gone:
            db.rollback()
            return
        except StepFailed as error:
            failure = error
        except ex.ExpressionError as error:
            failure = StepFailed(error.message, retry=False)
        except Exception as error:  # noqa: BLE001 - a step must never take the worker down
            from ..core.db import connection_lost

            if connection_lost(error):
                # The database went away under the step. That is not a failure of the step, and
                # nothing can be written now: it stays claimed, and is taken back by the rule of a
                # step whose worker stopped (done again, or a person is asked when it had made a
                # call that may not be repeated).
                raise
            logger.exception("Step %s of run %s failed unexpectedly", step.node_id, step.run_id)
            failure = StepFailed("The step failed for a reason Nik did not expect: see the server's log", retry=True)
        if failure is not None:
            # What the step did to the database before failing is undone; the failure is kept.
            db.rollback()
            step = db.get(RunStep, step_id)
            run = locked_run(db, step.run_id)
            db.refresh(step)
            if step.status != "running" or (holder is not None and step.claimed_by != holder):
                db.rollback()
                return  # taken back meanwhile: what this worker found is not written over it
            if _is_try(step):
                # Counted again when the rollback undid it; not when the mark of a call committed it.
                step.attempt = max(step.attempt or 0, tried or 0)
                step.started_at = step.started_at or iso(now)
            if run.status not in FINISHED:
                _fail(
                    db,
                    run,
                    shape,
                    step,
                    failure.message,
                    now,
                    retry=failure.retry,
                    request=failure.request,
                    log=failure.log,
                    away=failure.away,
                )
            db.commit()
            return
        if holder is not None and not _still_ours(db, step_id, holder):
            db.rollback()
            return
        _apply(db, run, shape, step, outcome, now)
        db.commit()


def _still_ours(db: OrmSession, step_id: str, holder: str) -> bool:
    """Whether the step is still claimed by this worker, read from the database under its lock:
    the last look before its result is applied."""
    found = db.execute(
        select(RunStep.status, RunStep.claimed_by).where(RunStep.id == step_id).with_for_update()
    ).first()
    return found is not None and found[0] == "running" and found[1] == holder


def _apply(db: OrmSession, run: Run, shape: dict, step: RunStep, outcome: Outcome, now: float) -> None:
    if outcome.input is not None:
        step.input = outcome.input
    if outcome.request is not None:
        step.request = outcome.request
    if outcome.log is not None:
        step.log = outcome.log[:20_000]
    if outcome.end is not None:
        step.status = "done"
        step.output = outcome.end
        step.finished_at = iso(now)
        step.next_at = None
        failed = outcome.end["status"] == "failed"
        _finish(db, run, "failed" if failed else "done", outcome.end["message"] or None, now, shape=shape)
        return
    if outcome.wait is not None:
        step.status = "waiting"
        step.calling_at = None
        # What who debugs the run said of this step stays with it while it waits.
        kept = {key: value for key, value in (step.waiting or {}).items() if key in ("released", "override", "real")}
        step.waiting = {**kept, **outcome.wait}
        step.next_at = outcome.next_at
        step.claimed_by = None
        if outcome.wait.get("kind") == "each":
            _start_items(db, run, shape, step.node_id, now)
        if run.status == "running" and outcome.wait.get("kind") in ("approval", "task"):
            run.status = "waiting"
        _touch(run)
        return
    _complete(db, run, shape, step, outcome.port, outcome.output, now, classes=outcome.classes, skipped=outcome.skipped)


# --------------------------------------------------------------------------- #
# Approvals, stop                                                             #
# --------------------------------------------------------------------------- #
def answer(db: OrmSession, approval: Approval, verdict: str, by: str, comment: str, now: float) -> bool:
    """Record the answer to an approval and let the run go on (the caller commits).
    ``verdict``: approved | refused | expired. False when it was answered already."""
    with serial(db):
        run = locked_run(db, approval.run_id)
        db.refresh(approval)
        if approval.status != "waiting" or run is None:
            return False
        approval.status = verdict
        approval.answered_at = iso(now)
        approval.answered_by = by
        approval.comment = comment[:1000]
        from .. import war_room

        war_room.approval_answered(db, run, approval.question, verdict, by, approval.comment)
        step = db.get(RunStep, approval.step_id)
        if run.status in FINISHED or step is None or step.status != "waiting":
            return True
        # Time spent waiting for a person does not count against the longest run.
        waited = max(0.0, now - (approval.asked_epoch or now))
        run.waited_seconds = (run.waited_seconds or 0) + waited
        run.deadline = (run.deadline or now) + waited
        shape = graph_of(db, run)
        result = {"answer": verdict, "by": by, "at": iso(now), "comment": approval.comment}
        if step.kind == "approval":
            if verdict == "expired" and approval.on_expire == "stop":
                _finish(db, run, "stopped", "An approval was not answered in time", now)
            else:
                # An approval nobody answered is never an approval.
                _complete(db, run, shape, step, "approved" if verdict == "approved" else "refused", result, now)
        elif verdict == "approved":
            # What who debugs the run said of this step stays with it through the approval.
            kept = {
                key: value for key, value in (step.waiting or {}).items() if key in ("released", "override", "real")
            }
            step.waiting = {**kept, "approved_by": by}
            step.status = "pending"
            step.next_at = now
        elif verdict == "expired" and approval.on_expire == "stop":
            _finish(db, run, "stopped", "An approval was not answered in time", now)
        elif verdict == "expired" and approval.on_expire == "skip":
            step.error = "Skipped: the approval was not answered in time"
            _complete(db, run, shape, step, "out", {"skipped": True, "approval": result}, now, skipped=True)
        else:
            step.waiting = None
            _fail(
                db,
                run,
                shape,
                step,
                f"Refused by {by}" if verdict == "refused" else "Not approved in time",
                now,
                retry=False,
            )
            if run.status == "failed" and not any(
                port == "error" for port, _t in graph.edges_from(shape).get(step.node_id, [])
            ):
                # A person saying no is not a malfunction: the run stops, it has not failed.
                run.status = "stopped"
        if run.status == "waiting" and not _waiting_people(db, run):
            run.status = "running"
        _touch(run)
        return True


def _waiting_people(db: OrmSession, run: Run) -> int:
    """How many answers of people the run waits for: approvals, tasks, questions."""
    db.flush()
    approvals = db.scalar(
        select(func.count()).select_from(Approval).where(Approval.run_id == run.id, Approval.status == "waiting")
    )
    tasks = db.scalar(
        select(func.count()).select_from(Task).where(Task.run_id == run.id, Task.status.in_(("open", "overdue")))
    )
    asked = db.scalar(
        select(func.count()).select_from(RunStep).where(RunStep.run_id == run.id, RunStep.status == "interrupted")
    )
    return (approvals or 0) + (tasks or 0) + (asked or 0)


# --------------------------------------------------------------------------- #
# A step cut by a restart                                                     #
# --------------------------------------------------------------------------- #
def _noted(step: RunStep, now: float, what: str, **more: Any) -> None:
    """Add a line to what restarts did to the step (the last ``RESTARTS_KEPT`` are kept)."""
    step.restarts = [*(step.restarts or []), {"at": iso(now), "what": what, **more}][-RESTARTS_KEPT:]
    flag_modified(step, "restarts")


def safe_to_repeat(spec: Any) -> bool:
    """Whether making the call of this action a second time does no harm: it changes nothing
    outside, or says it is idempotent (by its nature, or by the key it sends the vendor)."""
    return spec is None or not spec.changes_outside or bool(spec.idempotent)


def take_back(db: OrmSession, step: RunStep, now: float, *, counted: bool = True) -> str:
    """A step that was ``running`` when its worker stopped (the caller found it and commits).
    Returns what was done with it: ``again`` | ``interrupted`` | ``failed`` | ``skipped``, or
    ``busy`` when the run is locked: the session that does the step is still connected, so the
    worker is not gone (it finishes, or its connection drops and the next pass finds the step).
    ``counted`` is off for a step whose worker was asked to stop: the step is not what stopped it."""
    with serial(db):
        run = locked_run(db, step.run_id, wait=False)
        if run is None and db.get(Run, step.run_id) is not None:
            return "busy"
        db.refresh(step)
        if step.status != "running":
            return "skipped"
        if run is None or run.status in FINISHED:
            step.status, step.finished_at, step.calling_at = "skipped", iso(now), None
            return "skipped"
        shape = graph_of(db, run)
        node = graph.nodes_of(shape).get(step.node_id) or {}
        spec = (
            actions.lookup(db, str((node.get("config") or {}).get("action") or "")) if step.kind == "action" else None
        )
        _noted(step, now, "interrupted", **({} if counted else {"asked": True}))
        if step.calling_at is not None and not safe_to_repeat(spec):
            _interrupt(db, run, node, step, now)
            return "interrupted"
        cut = sum(1 for line in step.restarts or [] if line.get("what") == "interrupted" and not line.get("asked"))
        if cut >= MAX_RESTARTS:
            _fail(
                db, run, shape, step,
                f"Interrupted by a restart {cut} times while it ran: it is not started again. "
                "It may be what stops the worker",
                now, retry=False,
            )  # fmt: skip
            _touch(run)
            return "failed"
        # Nothing of this try lasted (or doing it twice does no harm): it is done again, and the
        # try that was cut does not count against the tries the node allows (it was counted in
        # the commit of the mark, when there is one).
        if step.calling_at is not None and _is_try(step):
            step.attempt = max(0, (step.attempt or 0) - 1)
        step.status, step.next_at, step.claimed_by, step.calling_at = "pending", now, None, None
        _noted(step, now, "again")
        return "again"


def _interrupt(db: OrmSession, run: Run, node: dict, step: RunStep, now: float) -> None:
    """The step may have made its call and nobody can tell: the run waits for a person to say."""
    name = str(node.get("name") or step.node_id)
    step.status, step.next_at, step.claimed_by = "interrupted", None, None
    step.error = "Interrupted by a restart: it is not known whether this happened"
    _noted(step, now, "waiting")
    if run.status == "running":
        run.status = "waiting"
    _touch(run)
    from .. import tasks, war_room

    tasks.notify_interrupted(db, run, name)
    war_room.step_done(db, run, step, node, error=f"{step.error}. Say what happened on the page of the run")


def resolve(db: OrmSession, step_id: str, answer: str, by: str, now: float) -> bool:
    """A person says what happened to a step a restart interrupted (the caller commits):

    - ``happened``: the call was made. The step is done with no result of its own (what it would
      have given is not known) and the run goes on by its ``out`` port;
    - ``again``: it was not. The step is tried again from the beginning;
    - ``stop``: the run stops here.

    False when the step waits for no such answer any more."""
    if answer not in ANSWERS:
        raise ValueError("The answer is happened, again or stop")
    step = db.get(RunStep, step_id)
    if step is None:
        return False
    with serial(db):
        run = locked_run(db, step.run_id)
        db.refresh(step)
        if run is None or run.status in FINISHED or step.status != "interrupted":
            return False
        cut = next((line for line in reversed(step.restarts or []) if line.get("what") == "waiting"), None)
        # Time spent waiting for a person does not count against the longest run.
        waited = max(0.0, now - datetime.fromisoformat(cut["at"]).timestamp()) if cut else 0.0
        run.waited_seconds = (run.waited_seconds or 0) + waited
        run.deadline = (run.deadline or now) + waited
        _noted(step, now, {"happened": "happened", "again": "again", "stop": "stopped"}[answer], by=by)
        step.calling_at = None
        if answer == "stop":
            _finish(db, run, "stopped", f"Stopped by {by} at a step a restart interrupted", now)
            return True
        shape = graph_of(db, run)
        if answer == "again":
            step.status, step.next_at, step.error = "pending", now, None
            step.attempt = max(0, (step.attempt or 0) - 1)
        else:
            step.error = None
            output = {"interrupted": True, "resolved": "happened", "by": by, "at": iso(now)}
            _complete(db, run, shape, step, "out", output, now)
        if run.status == "waiting" and not _waiting_people(db, run):
            run.status = "running"
        _touch(run)
        return True


def resume(db: OrmSession, step_id: str, port: str, output: Any, now: float) -> bool:
    """A person did what a step waited for: the run goes on by ``port`` (the caller commits).
    False when the step waits no more."""
    step = db.get(RunStep, step_id)
    if step is None:
        return False
    with serial(db):
        run = locked_run(db, step.run_id)
        if run is None or run.status in FINISHED or step.status != "waiting":
            return False
        # Time spent waiting for a person does not count against the longest run.
        waited = max(0.0, now - float((step.waiting or {}).get("since") or now))
        run.waited_seconds = (run.waited_seconds or 0) + waited
        run.deadline = (run.deadline or now) + waited
        _complete(db, run, graph_of(db, run), step, port, output, now)
        if run.status == "waiting" and not _waiting_people(db, run):
            run.status = "running"
        _touch(run)
        return True


def follow(db: OrmSession, step_id: str, port: str, now: float) -> bool:
    """Leave a waiting step by one more port while it goes on waiting: the
    ``overdue`` of a task that is still to do (the caller commits). False when
    nothing is drawn from that port, or it was followed already."""
    step = db.get(RunStep, step_id)
    if step is None:
        return False
    with serial(db):
        run = locked_run(db, step.run_id)
        waiting = dict(step.waiting or {})
        if run is None or run.status in FINISHED or step.status != "waiting" or port in waiting.get("followed", []):
            return False
        shape = graph_of(db, run)
        nodes = graph.nodes_of(shape)
        targets = [
            target
            for found, target in graph.edges_from(shape).get(step.node_id, [])
            if found == port and target in nodes
        ]
        waiting["followed"] = [*waiting.get("followed", []), port]
        step.waiting = waiting
        if not targets:
            return False
        # What comes after reads the node before its answer is there.
        _outputs(run, None, None).setdefault(step.node_id, {port: True, "task": waiting.get("id")})
        edges = _edges(run, None, None)
        for target in targets:
            edges[f"{step.node_id}|{port}|{target}"] = "t"
            _consider(db, run, shape, None, None, target, now)
        _touch(run)
        return True


def stop(db: OrmSession, run_id: str, by: str, now: float) -> bool:
    """Stop a run (the caller commits). A step in flight finishes and is discarded."""
    with serial(db):
        run = locked_run(db, run_id)
        if run is None or run.status in FINISHED:
            return False
        _finish(db, run, "stopped", f"Stopped by {by}", now)
        return True

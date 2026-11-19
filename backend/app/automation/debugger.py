"""The debugger: a run that stops before its nodes, for whoever builds the playbook.

A debug run is a run like any other, with two differences the engine knows
(engine.py): before a node it asks ``park`` here whether to stop, and what
goes outside is held as in a dry run unless one node was let through.
``run.state["debug"]`` holds where it stops::

    {"breakpoints": ["block", "notify"], "step": true}

A node it stopped at is a step ``waiting`` with ``{"kind": "debug"}``: its
``input`` shows what the node would be given. From there the run is told
what to do (``act``): go one node on, go on to the next breakpoint, skip the
node, run it with other arguments, send for real this once, or stop. A
finished node can be run again while the run is not over, and ``set`` moves
the breakpoints or changes the context without moving the run.

Debug runs count for no limit and no statistic, are shown to who started
them (and to an admin), and are deleted after a week.

A debug run is also the only run a branch of a playbook ever has: it is given
the graph of the branch as it was saved, the way it is given a draft, and
``run.trigger["branch"]`` keeps which branch that was.
"""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.orm import Session as OrmSession

from ..core.models import Approval, Run, RunStep, Task
from . import actions, engine, graph
from . import expressions as ex

KEEP_SECONDS = 7 * 86400
BREAKPOINTS_MAX = 200
PATCH_MAX = 200_000  # characters of what is written to the context of a run, as JSON
ACTIONS = ("step", "continue", "skip", "stop", "rerun", "set")


class DebugError(ValueError):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.message = message
        self.status = status


def clean_breakpoints(shape: dict, raw: Any) -> list[str]:
    """The nodes to stop before: ids of nodes of the graph, once each."""
    nodes = graph.nodes_of(shape)
    wanted = [str(item) for item in (raw if isinstance(raw, list) else [])][:BREAKPOINTS_MAX]
    return [node_id for node_id in dict.fromkeys(wanted) if node_id in nodes and nodes[node_id]["kind"] != "trigger"]


def settings_of(run: Run) -> dict[str, Any]:
    held = (run.state or {}).get("debug")
    return held if isinstance(held, dict) else {"breakpoints": [], "step": False}


def branch_of(run: Run) -> dict[str, str] | None:
    """The branch a debug run was started on (``{"id", "name"}``, as it was called then), if any."""
    held = (run.trigger or {}).get("branch")
    if not isinstance(held, dict):
        return None
    return {"id": str(held.get("id") or ""), "name": str(held.get("name") or "")}


def _preview(db: OrmSession, run: Run, shape: dict, node: dict, step: RunStep) -> dict[str, Any]:
    """What the node would be given, worked out without doing anything."""
    config = node.get("config") or {}
    try:
        scope = engine.scope_of(run, shape, node["id"], step.item_index, db)
        if node["kind"] == "condition":
            return {"result": engine.holds(config, scope)}
        if node["kind"] == "action":
            spec = actions.lookup(db, str(config.get("action") or ""))
            rendered = ex.render(config.get("args") or {}, scope)
            args = actions.argument_values(spec, rendered) if spec is not None else rendered.data
            return {"action": str(config.get("action") or ""), "args": engine._cut(args)}
        if node["kind"] in ("script", "playbook"):
            rendered = ex.render(config.get("args") or {}, scope)
            return {"args": engine._cut(rendered.data if isinstance(rendered.data, dict) else {})}
        if node["kind"] == "for_each":
            items = ex.render(config.get("items"), scope).data
            return {"items": len(items) if isinstance(items, (list, tuple)) else 0}
    except ex.ExpressionError as error:
        return {"problem": error.message}
    return {}


def park(db: OrmSession, run: Run, shape: dict, node: dict, step: RunStep, now: float) -> bool:
    """Stop the run before this node when it is a breakpoint or the run goes step by step. True when it
    stopped (the caller commits and does not perform the node)."""
    waiting = step.waiting or {}
    if waiting.get("released"):
        return False
    held = settings_of(run)
    if not held.get("step") and node["id"] not in (held.get("breakpoints") or []):
        return False
    step.status = "waiting"
    step.waiting = {"kind": "debug", "since": now}
    step.input = _preview(db, run, shape, node, step)
    step.next_at = None
    step.claimed_by = None
    step.attempt = 0
    if run.status == "running":
        run.status = "waiting"
    engine._touch(run)
    return True


def parked(db: OrmSession, run: Run) -> list[RunStep]:
    db.flush()
    steps = db.scalars(select(RunStep).where(RunStep.run_id == run.id, RunStep.status == "waiting")).all()
    return sorted((step for step in steps if (step.waiting or {}).get("kind") == "debug"), key=lambda step: step.seq)


def _release(run: Run, step: RunStep, now: float, *, override: dict | None = None, real: bool = False) -> None:
    since = float((step.waiting or {}).get("since") or now)
    # Time spent stopped does not count against the longest run.
    run.waited_seconds = (run.waited_seconds or 0) + max(0.0, now - since)
    run.deadline = (run.deadline or now) + max(0.0, now - since)
    step.waiting = {
        "released": True,
        **({"override": override} if override else {}),
        **({"real": True} if real else {}),
    }
    step.status = "pending"
    step.next_at = now


def _people_wait(db: OrmSession, run: Run) -> bool:
    db.flush()
    asked = db.scalar(select(Approval.id).where(Approval.run_id == run.id, Approval.status == "waiting").limit(1))
    tasks = db.scalar(select(Task.id).where(Task.run_id == run.id, Task.status.in_(("open", "overdue"))).limit(1))
    return bool(asked or tasks)


def _patch_context(run: Run, patch: Any) -> None:
    """Change what the nodes after this one read: the output of a node, or an input of the run."""
    if not isinstance(patch, dict) or not patch:
        return
    if len(json.dumps(patch, default=str)) > PATCH_MAX:
        raise DebugError("What is written to the context of the run is too large")
    context = dict(run.context or {})
    for key, value in patch.items():
        name = str(key)
        if name.startswith("__") or name == "trigger":
            raise DebugError(f'"{name}" of a run is not changed: change the output of a node, or "inputs"')
        if name != "inputs" and name not in context:
            raise DebugError(f'"{name}" is not something this run holds yet')
        context[name] = value
    run.context = context


def act(
    db: OrmSession,
    run: Run,
    action: str,
    *,
    by: str,
    now: float,
    step_id: str | None = None,
    overrides: dict | None = None,
    send_for_real: bool = False,
    context_patch: dict | None = None,
    breakpoints: list | None = None,
) -> Run:
    """Tell a debug run what to do next (the caller commits)."""
    if action not in ACTIONS:
        raise DebugError("A debug run is told: " + ", ".join(ACTIONS))
    with engine.serial(db):
        run = engine.locked_run(db, run.id)
        if run is None or not run.debug:
            raise DebugError("This is not a debug run", 404)
        if action == "stop":
            engine.stop(db, run.id, by, now)
            return run
        if run.status in engine.FINISHED:
            raise DebugError("The run is over", 409)
        shape = engine.graph_of(db, run)
        nodes = graph.nodes_of(shape)
        held = dict(settings_of(run))
        if breakpoints is not None:
            held["breakpoints"] = clean_breakpoints(shape, breakpoints)
        _patch_context(run, context_patch)
        if overrides is not None and not isinstance(overrides, dict):
            raise DebugError("The arguments of a node are an object: {name: value}")

        if action == "rerun":
            done = db.get(RunStep, str(step_id or ""))
            if done is None or done.run_id != run.id or done.status not in ("done", "failed", "skipped"):
                raise DebugError("Choose a node of this run that is over to run it again", 409)
            node = nodes.get(done.node_id)
            if node is None or node["kind"] in ("trigger", "for_each", "end"):
                raise DebugError("This node cannot be run again")
            again = engine._new_step(db, run, node, done.item_index, now)
            again.waiting = {
                "released": True,
                **({"override": overrides} if overrides else {}),
                **({"real": True} if send_for_real else {}),
            }
            held["step"] = True  # it stops again before what comes next
        elif action != "set":  # "set" only moves breakpoints and changes the context: the run stays where it is
            waiting = parked(db, run)
            chosen = [step for step in waiting if step.id == step_id] if step_id else waiting
            if not chosen:
                raise DebugError("The run is not stopped at a node", 409)
            if (overrides or send_for_real) and len(chosen) != 1:
                raise DebugError("Arguments and sending for real are for one node: say which", 409)
            if action != "skip":  # skipping a node does not change how the run goes on
                held["step"] = action == "step"
            for step in chosen:
                if action == "skip":
                    since = float((step.waiting or {}).get("since") or now)
                    run.deadline = (run.deadline or now) + max(0.0, now - since)
                    step.error = "Skipped by who debugs the run"
                    step.waiting = None
                    engine._complete(db, run, shape, step, "out", {"skipped": True}, now, skipped=True)
                else:
                    _release(run, step, now, override=overrides, real=send_for_real)
            if action == "continue":
                # Whatever else was stopped goes on too: only breakpoints stop the run from here.
                for step in parked(db, run):
                    _release(run, step, now)
        state = dict(run.state or {})
        state["debug"] = held
        run.state = state
        if run.status == "waiting" and not parked(db, run) and not _people_wait(db, run):
            run.status = "running"
        engine._touch(run)
        return run


def out(db: OrmSession, run: Run) -> dict[str, Any] | None:
    """What the debugger shows of a run: where it stops, where it is stopped, what it holds."""
    if not run.debug:
        return None
    held = settings_of(run)
    context = {key: value for key, value in (run.context or {}).items() if not str(key).startswith("__")}
    branch = branch_of(run)
    return {
        "breakpoints": list(held.get("breakpoints") or []),
        "stepMode": bool(held.get("step")),
        "at": [{"step": step.id, "node": step.node_id, "itemIndex": step.item_index} for step in parked(db, run)],
        "draft": branch is None and isinstance((run.state or {}).get("graph"), dict),
        "branch": branch["name"] if branch else None,
        "context": engine._cut(context),
    }


def may_see(run: Run, principal: Any) -> bool:
    """A debug run is its starter's, and an admin's."""
    return not run.debug or run.started_by == principal.actor or principal.has("admin")


def prune(db: OrmSession, now: float) -> int:
    """Delete the debug runs older than a week, whatever state they are in (the caller commits)."""
    old = db.scalars(select(Run.id).where(Run.debug.is_(True), Run.started_at < engine.iso(now - KEEP_SECONDS))).all()
    if not old:
        return 0
    db.execute(delete(RunStep).where(RunStep.run_id.in_(old)))
    db.execute(delete(Approval).where(Approval.run_id.in_(old)))
    db.execute(delete(Task).where(Task.run_id.in_(old)))
    db.execute(delete(Run).where(Run.id.in_(old)))
    return len(old)

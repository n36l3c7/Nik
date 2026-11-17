"""The work plan of an incident: what its playbooks do and did, step by step, and its tasks.

For each run that works on the incident (dry runs and the commands typed in
the War Room left out) the nodes of its playbook in an order where each comes
after what leads to it, grouped by the ``phase`` a node names, each with what
happened to it; and the graph itself, for the read-only canvas. Tasks added by
hand have no run: they are listed apart.

Whoever reads the incident reads its plan, so a node is shown by its name,
its kind and its phase, and never by its settings: what an action is given
belongs to the run's own page, for those who may open it.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from . import tasks
from .automation import engine, graph
from .core.models import Incident, Run, RunStep, Task
from .core.security import Principal

RUNS_MAX = 20
NO_PHASE = ""
# What a reader of the incident may see of a node's settings.
SHOWN_CONFIG = ("phase", "title", "question", "choices", "assignee")


def _phase(node: dict) -> str:
    config = node.get("config") if isinstance(node.get("config"), dict) else {}
    return str(config.get("phase") or NO_PHASE).strip()


def _summary(node: dict) -> str:
    """A few words under the name of a node: for whom a task or a question is."""
    config = node.get("config") if isinstance(node.get("config"), dict) else {}
    if node.get("kind") not in ("task", "ask"):
        return ""
    who = config.get("assignee") if isinstance(config.get("assignee"), dict) else {}
    if who.get("user"):
        return f"for {who['user']}"
    if who.get("role"):
        return f"for the role {who['role']}"
    return "for the owner" if who.get("owner") or node.get("kind") == "task" else "for anyone"


def _order(shape: dict) -> list[str]:
    """The nodes after the trigger, each after what leads to it; the body of a loop right after its loop."""
    order = graph.topological(shape) or list(graph.nodes_of(shape))
    nodes = graph.nodes_of(shape)
    return [node_id for node_id in order if nodes[node_id].get("kind") != "trigger"]


def _status(found: list[RunStep]) -> str:
    """What happened to a node: the state of its step, or of its steps when it ran once per item."""
    if not found:
        return "none"
    states = {step.status for step in found}
    for state in ("failed", "waiting", "running", "pending"):
        if state in states:
            return state
    return "done" if "done" in states else "skipped"


def _plan(db: OrmSession, run: Run, by_step: dict[str, Task], caller: Principal) -> dict[str, Any]:
    shape = engine.graph_of(db, run)
    nodes = graph.nodes_of(shape)
    steps: dict[str, list[RunStep]] = {}
    for step in db.scalars(select(RunStep).where(RunStep.run_id == run.id).order_by(RunStep.seq)):
        steps.setdefault(step.node_id, []).append(step)
    phases: list[dict[str, Any]] = []
    for node_id in _order(shape):
        node = nodes[node_id]
        found = steps.get(node_id, [])
        task = next((by_step[step.id] for step in found if step.id in by_step), None)
        row = {
            "node": node_id,
            "name": str(node.get("name") or node_id),
            "kind": node.get("kind"),
            "summary": _summary(node),
            "status": _status(found),
            "port": found[-1].port if found else None,
            "error": found[-1].error if found else None,
            "finishedAt": found[-1].finished_at if found else None,
            "task": tasks.out(db, task, caller) if task is not None else None,
        }
        # Phases keep the order in which the plan first reaches them.
        phase = next((item for item in phases if item["name"] == _phase(node)), None)
        if phase is None:
            phase = {"name": _phase(node), "steps": []}
            phases.append(phase)
        phase["steps"].append(row)
    return {
        "runId": run.id,
        "playbookId": run.playbook_id,
        "playbook": (run.trigger or {}).get("playbook", ""),
        "status": run.status,
        "startedAt": run.started_at,
        "finishedAt": run.finished_at,
        "phases": phases,
        "graph": {
            "nodes": [
                {
                    "id": node["id"],
                    "kind": node.get("kind"),
                    "name": node.get("name") or node["id"],
                    "position": node.get("position") or {"x": 0, "y": 0},
                    "summary": _summary(node),
                    "config": {key: value for key, value in (node.get("config") or {}).items() if key in SHOWN_CONFIG},
                }
                for node in nodes.values()
            ],
            "edges": [edge for edge in shape.get("edges") or [] if isinstance(edge, dict)],
        },
        "statuses": {node_id: _status(found) for node_id, found in steps.items()},
    }


def of(db: OrmSession, incident: Incident, caller: Principal) -> dict[str, Any]:
    """The plans of the incident, the newest run first, and the tasks nobody's playbook asked for."""
    rows = db.scalars(select(Task).where(Task.incident_id == incident.id).order_by(Task.created_at)).all()
    by_step = {task.step_id: task for task in rows if task.step_id}
    runs = db.scalars(
        select(Run)
        .where(Run.incident_id == incident.id, Run.dry_run.is_(False), Run.parent_run_id.is_(None))
        .order_by(Run.started_at.desc())
        .limit(RUNS_MAX * 3)
    ).all()
    plans = [
        _plan(db, run, by_step, caller)
        for run in [run for run in runs if (run.trigger or {}).get("kind") != "adhoc"][:RUNS_MAX]
    ]
    done = sum(1 for task in rows if task.status not in tasks.OPEN)
    return {
        "plans": plans,
        "tasks": [tasks.out(db, task, caller) for task in rows if not task.step_id],
        "counts": {"tasks": len(rows), "open": len(rows) - done, "done": done},
    }

"""The Playground: commands that belong to no incident (5.3).

The command line of the War Room, without an incident: to try a connector, to
look something up. A line that starts with ``!`` runs as a run of one node,
exactly as in the War Room (``commands.start``), and what it gives is written
under it. The history is each person's own, and is kept until they clear it.

Nothing here touches an incident: a command that needs one (a note, a field,
the context) fails and says so, and a reputation command adds no indicator.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.orm import Session as OrmSession

from .core.models import PlaygroundEntry, Run, RunStep
from .core.security import now_iso

KINDS = ("command", "result", "error")
MAX_SHOWN = 500


def add(
    db: OrmSession,
    owner: str,
    kind: str,
    body: dict[str, Any],
    *,
    run_id: str | None = None,
    step_id: str | None = None,
    parent_id: str | None = None,
) -> PlaygroundEntry:
    """Add an entry to somebody's Playground (the caller commits)."""
    row = PlaygroundEntry(
        id=uuid.uuid4().hex,
        owner=owner[:200],
        at=now_iso(),
        kind=kind if kind in KINDS else "result",
        body=body,
        run_id=run_id,
        step_id=step_id,
        parent_id=parent_id,
    )
    db.add(row)
    return row


def out(row: PlaygroundEntry) -> dict[str, Any]:
    return {
        "id": row.id,
        "at": row.at,
        "kind": row.kind,
        "body": row.body or {},
        "runId": row.run_id,
        "stepId": row.step_id,
        "parentId": row.parent_id,
    }


def entries(db: OrmSession, owner: str, limit: int = 200) -> list[dict[str, Any]]:
    """The last entries of a person's Playground, oldest first."""
    limit = max(1, min(limit, MAX_SHOWN))
    rows = db.scalars(
        select(PlaygroundEntry)
        .where(PlaygroundEntry.owner == owner)
        .order_by(PlaygroundEntry.at.desc(), PlaygroundEntry.id.desc())
        .limit(limit)
    ).all()
    return [out(row) for row in reversed(rows)]


def clear(db: OrmSession, owner: str) -> int:
    """Forget a person's history (the caller commits). The runs behind it stay, as runs do."""
    found = db.execute(delete(PlaygroundEntry).where(PlaygroundEntry.owner == owner))
    return int(found.rowcount or 0)


def step_detail(db: OrmSession, row: PlaygroundEntry) -> dict[str, Any] | None:
    """What the step behind an entry got, gave and sent (None when it has none, or it is gone)."""
    step = db.get(RunStep, row.step_id) if row.step_id else None
    if step is None:
        return None
    return {
        "status": step.status,
        "input": step.input,
        "output": step.output,
        "request": step.request,
        "error": step.error,
        "log": step.log,
        "startedAt": step.started_at,
        "finishedAt": step.finished_at,
    }


def step_done(db: OrmSession, run: Run, step: RunStep, node: dict, *, error: str | None = None) -> bool:
    """A step of a run started from the Playground ended: one line under the command that asked for
    it. True when the run is one of the Playground's (the War Room has nothing to write then)."""
    owner = (run.trigger or {}).get("playground")
    if not owner:
        return False
    if step.kind not in ("action", "script"):
        return True
    config = node.get("config") or {}
    what = str(config.get("action") or config.get("script") or "")
    add(
        db,
        str(owner),
        "error" if error else "result",
        {
            "title": str(node.get("name") or what or step.node_id)[:200],
            "what": what,
            **({"error": error[:2000]} if error else {}),
        },
        run_id=run.id,
        step_id=step.id,
        parent_id=(run.trigger or {}).get("entry_id"),
    )
    return True

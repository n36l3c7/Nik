"""The War Room of an incident: one chronological log of what was said and done.

Entries (``war_room_entries``): notes people write, the steps playbooks run on
the incident, approvals answered, commands typed in the War Room and their
results. The Timeline is not this: it is the forensic timeline of the
evidence, and stays what it is.

**Notes are not moved.** The notes an incident always had live in its document
(``doc.notes``), which older clients and the report read; the War Room lists
them through a read adapter, and a note written here is written to the
document too, with an entry that points at it so that it is shown once.

An entry made by the engine for a step keeps a few words and the ids of the
run and the step: what went in, what came out and what was sent are read from
the step when the entry is opened, not copied here.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from .core.ids import new_id
from .core.models import Incident, Run, RunStep, WarRoomEntry
from .core.security import now_iso

KINDS = ("note", "command", "result", "error", "task", "approval", "mirror", "file", "system")
EVIDENCE = "evidence"
TAG_MAX, TAGS_MAX, TEXT_MAX = 40, 12, 20_000
# The filters of the stream: what each chip shows.
FILTERS = {
    "all": None,
    # A comment of the other side of a mirror is a note too: someone wrote it, there.
    "notes": ("note", "mirror"),
    "commands": ("command",),
    "automation": ("result", "error", "approval", "task", "system"),
}


def clean_tags(tags: Any) -> list[str]:
    cleaned = []
    for tag in tags if isinstance(tags, (list, tuple)) else []:
        text = str(tag).strip().lower()[:TAG_MAX]
        if text and text not in cleaned:
            cleaned.append(text)
    return cleaned[:TAGS_MAX]


def add(
    db: OrmSession,
    incident_id: str,
    kind: str,
    body: dict[str, Any],
    author: str,
    *,
    run_id: str | None = None,
    step_id: str | None = None,
    tags: list[str] | None = None,
    parent_id: str | None = None,
    at: str | None = None,
) -> WarRoomEntry:
    """Add an entry (the caller commits)."""
    row = WarRoomEntry(
        id=new_id(),
        incident_id=incident_id,
        at=at or now_iso(),
        author=author[:200],
        kind=kind if kind in KINDS else "system",
        body=body,
        run_id=run_id,
        step_id=step_id,
        tags=clean_tags(tags),
        parent_id=parent_id,
    )
    db.add(row)
    return row


def system(db: OrmSession, incident_id: str, text: str) -> WarRoomEntry:
    return add(db, incident_id, "system", {"text": text[:2000]}, "nik")


def out(row: WarRoomEntry) -> dict[str, Any]:
    return {
        "id": row.id,
        "at": row.at,
        "author": row.author,
        "kind": row.kind,
        "body": row.body or {},
        "runId": row.run_id,
        "stepId": row.step_id,
        "tags": list(row.tags or []),
        "parentId": row.parent_id,
    }


def _note_entry(note: dict, tags: list[str] | None = None, entry_id: str | None = None) -> dict[str, Any]:
    """A note of the incident's document, as an entry."""
    note_id = str(note.get("id") or "")
    return {
        "id": entry_id or f"note-{note_id}",
        "at": str(note.get("createdAt") or note.get("updatedAt") or ""),
        "author": str(note.get("author") or ""),
        "kind": "note",
        "body": {
            "text": str(note.get("text") or ""),
            "noteId": note_id,
            "automation": bool(note.get("automation")),
            "edited": bool(note.get("updatedAt") and note.get("updatedAt") != note.get("createdAt")),
        },
        "runId": (note.get("automation") or {}).get("run") if isinstance(note.get("automation"), dict) else None,
        "stepId": None,
        "tags": tags or [],
        "parentId": None,
    }


def entries(
    db: OrmSession,
    incident: Incident,
    *,
    which: str = "all",
    tag: str = "",
    author: str = "",
    limit: int = 200,
    before: str = "",
) -> list[dict[str, Any]]:
    """The entries of an incident, oldest first: those stored, and the notes of its document.

    A note written here has an entry that points at it (``body.noteId``): the
    text shown is the one in the document, so an edit made anywhere is seen.
    """
    stored = db.scalars(select(WarRoomEntry).where(WarRoomEntry.incident_id == incident.id)).all()
    notes = {str(note.get("id")): note for note in (incident.doc or {}).get("notes") or [] if isinstance(note, dict)}
    found: list[dict[str, Any]] = []
    pointed: set[str] = set()
    for row in stored:
        note_id = (row.body or {}).get("noteId") if row.kind == "note" else None
        if note_id:
            pointed.add(str(note_id))
            note = notes.get(str(note_id))
            if note is None:
                continue  # the note was deleted from the incident: so is its line here
            found.append({**_note_entry(note, list(row.tags or []), row.id), "at": row.at})
        else:
            found.append(out(row))
    found += [_note_entry(note) for note_id, note in notes.items() if note_id not in pointed]
    kinds = FILTERS.get(which)
    if which == EVIDENCE:
        found = [item for item in found if EVIDENCE in item["tags"]]
    elif kinds is not None:
        found = [item for item in found if item["kind"] in kinds]
    if tag:
        found = [item for item in found if tag.lower() in item["tags"]]
    if author:
        found = [item for item in found if item["author"].lower() == author.lower()]
    if before:
        found = [item for item in found if item["at"] < before]
    found.sort(key=lambda item: (item["at"], item["id"]))
    return found[-limit:]


def step_detail(db: OrmSession, row: WarRoomEntry) -> dict[str, Any] | None:
    """What the step behind an entry got, gave and sent (None when it has none, or it is gone)."""
    step = db.get(RunStep, row.step_id) if row.step_id else None
    if step is None:
        return None
    run = db.get(Run, step.run_id)
    return {
        "status": step.status,
        "input": step.input,
        "output": step.output,
        "request": step.request,
        "error": step.error,
        "log": step.log,
        "startedAt": step.started_at,
        "finishedAt": step.finished_at,
        "playbook": (run.trigger or {}).get("playbook", "") if run is not None else "",
        "dryRun": bool(run.dry_run) if run is not None else False,
    }


# --------------------------------------------------------------------------- #
# What the engine tells                                                       #
# --------------------------------------------------------------------------- #
def step_done(db: OrmSession, run: Run, step: RunStep, node: dict, *, error: str | None = None) -> None:
    """A step of a run that works on an incident ended: one line in its War Room.

    Only the steps that do something (an action, a script); never for a dry
    run, which changes nothing and is read on its own page.
    """
    if (run.trigger or {}).get("playground"):
        from . import playground

        # A command typed outside any incident: its result goes to who typed it.
        playground.step_done(db, run, step, node, error=error)
        return
    if not run.incident_id or run.dry_run or step.kind not in ("action", "script"):
        return
    config = node.get("config") or {}
    what = str(config.get("action") or config.get("script") or "")
    # A command of a connector is signed by the connector; everything else by the engine.
    connector = ""
    if step.kind == "action":
        from .automation import actions

        spec = actions.lookup(db, what)
        connector = str((spec.extra or {}).get("connector") or "") if spec is not None else ""
    add(
        db,
        run.incident_id,
        "error" if error else "result",
        {
            "title": str(node.get("name") or what or step.node_id)[:200],
            "what": what,
            "playbook": (run.trigger or {}).get("playbook", ""),
            **({"error": error[:2000]} if error else {}),
            # A command typed in the War Room: its result belongs under the line that asked for it.
            **({"adhoc": True} if (run.trigger or {}).get("kind") == "adhoc" else {}),
        },
        f"connector:{connector}" if connector else "nik-automation",
        run_id=run.id,
        step_id=step.id,
        parent_id=(run.trigger or {}).get("entry_id"),
    )


def approval_answered(db: OrmSession, run: Run, question: str, verdict: str, by: str, comment: str) -> None:
    if not run.incident_id or run.dry_run:
        return
    add(
        db,
        run.incident_id,
        "approval",
        {
            "question": question[:500],
            "answer": verdict,
            "comment": comment[:1000],
            "playbook": (run.trigger or {}).get("playbook", ""),
        },
        by or "nik",
        run_id=run.id,
    )

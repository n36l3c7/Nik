"""The War Room of an incident: its log, notes written in it, entries marked as evidence.

Reading is for whoever reads incidents; writing a note and tagging an entry
for whoever writes them. Typing a command is in ``commands`` (it runs on the
automation engine and needs ``automation.run``).
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as OrmSession

from .. import war_room
from ..core import audit
from ..core.db import get_db
from ..core.locking import lock_incident
from ..core.models import Incident, WarRoomEntry
from ..core.security import Principal, now_iso, reader_principal, writer_principal
from ..events import emit

router = APIRouter(prefix="/incidents", tags=["war room"])


class NoteIn(BaseModel):
    text: str = Field(min_length=1, max_length=war_room.TEXT_MAX)
    tags: list[str] = Field(default_factory=list, max_length=war_room.TAGS_MAX)


class TagsIn(BaseModel):
    tags: list[str] = Field(max_length=war_room.TAGS_MAX)


def _incident(db: OrmSession, incident_id: str, *, lock: bool = False) -> Incident:
    row = lock_incident(db, incident_id) if lock else db.get(Incident, incident_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return row


@router.get("/{incident_id}/war-room")
def list_entries(
    incident_id: str,
    show: str = Query("all", pattern="^(all|notes|commands|automation|evidence)$"),
    tag: str = Query("", max_length=war_room.TAG_MAX),
    author: str = Query("", max_length=200),
    limit: int = Query(200, ge=1, le=1000),
    before: str = Query("", max_length=40, description="Only entries older than this moment (to page back)."),
    _caller: Principal = Depends(reader_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """The entries of the incident, oldest first: notes, what playbooks did, commands and their results."""
    found = war_room.entries(
        db, _incident(db, incident_id), which=show, tag=tag, author=author, limit=limit, before=before
    )
    return {"entries": found}


@router.get("/{incident_id}/war-room/{entry_id}")
def get_entry(
    incident_id: str, entry_id: str, _caller: Principal = Depends(reader_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """One entry, with what its step got, gave and sent when a playbook or a command made it."""
    incident = _incident(db, incident_id)
    row = db.get(WarRoomEntry, entry_id)
    if row is None or row.incident_id != incident.id:
        # A note of the document that has no entry of its own.
        found = next((item for item in war_room.entries(db, incident, limit=1000) if item["id"] == entry_id), None)
        if found is None:
            raise HTTPException(status_code=404, detail="Entry not found")
        return {**found, "step": None}
    shown = next(
        (item for item in war_room.entries(db, incident, limit=1000) if item["id"] == row.id), war_room.out(row)
    )
    return {**shown, "step": war_room.step_detail(db, row)}


@router.post("/{incident_id}/war-room", status_code=status.HTTP_201_CREATED)
def add_note(
    incident_id: str,
    body: NoteIn,
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
    background_tasks: BackgroundTasks = None,
) -> dict:
    """Write a note. It is a note of the incident like any other (its Summary and its report
    show it), with a line here."""
    from .incidents import _notes, _save_doc

    text = body.text.strip()
    if not text:
        raise HTTPException(status_code=400, detail="Note text is required")
    incident = _incident(db, incident_id, lock=True)
    doc = dict(incident.doc or {})
    now = now_iso()
    note = {"id": str(uuid.uuid4()), "text": text, "createdAt": now, "updatedAt": now, "author": caller.actor}
    doc["notes"] = [*_notes(doc), note]
    _save_doc(db, incident, doc)
    row = war_room.add(db, incident.id, "note", {"noteId": note["id"]}, caller.actor, tags=body.tags, at=now)
    audit.record(db, caller.actor, "note.add", "Added a note", incident)
    db.commit()
    emit(db, background_tasks, "note.added", {"incidentId": incident_id, "noteId": note["id"]})
    return next(item for item in war_room.entries(db, incident, limit=1000) if item["id"] == row.id)


@router.put("/{incident_id}/war-room/{entry_id}/tags")
def set_tags(
    incident_id: str,
    entry_id: str,
    body: TagsIn,
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    """Tag an entry. ``evidence`` puts it among the evidence of the incident."""
    incident = _incident(db, incident_id, lock=True)
    tags = war_room.clean_tags(body.tags)
    row = db.get(WarRoomEntry, entry_id)
    if row is None or row.incident_id != incident.id:
        # A note of the document with no entry yet: tagging it gives it one.
        note_id = entry_id[5:] if entry_id.startswith("note-") else ""
        notes = {
            str(note.get("id")): note for note in (incident.doc or {}).get("notes") or [] if isinstance(note, dict)
        }
        if note_id not in notes:
            raise HTTPException(status_code=404, detail="Entry not found")
        note = notes[note_id]
        row = war_room.add(
            db,
            incident.id,
            "note",
            {"noteId": note_id},
            str(note.get("author") or ""),
            tags=tags,
            at=str(note.get("createdAt") or now_iso()),
        )
    else:
        was_evidence = war_room.EVIDENCE in (row.tags or [])
        row.tags = tags
        if (war_room.EVIDENCE in tags) != was_evidence:
            what = (
                "Marked an entry of the War Room as evidence"
                if not was_evidence
                else "Took an entry out of the evidence"
            )
            audit.record(db, caller.actor, "warroom.evidence", what, incident)
    db.commit()
    return next(item for item in war_room.entries(db, incident, limit=1000) if item["id"] == row.id)


class LineIn(BaseModel):
    line: str = Field(min_length=1, max_length=8000)
    # A command that changes something outside is started only when this says so.
    confirm: bool = False


@router.post("/{incident_id}/war-room/command", status_code=status.HTTP_201_CREATED, response_model=None)
def run_line(
    incident_id: str,
    body: LineIn,
    caller: Principal = Depends(reader_principal),
    db: OrmSession = Depends(get_db),
    background_tasks: BackgroundTasks = None,
):
    """What is typed in the War Room. Plain text and ``/note`` write a note; ``/assign @user``
    gives the incident to someone; ``/close`` answers ``{action: "close"}`` for the form of
    closing; ``!name arg=value`` runs a command as a run of one node (``automation.run``).

    ``409`` with ``needsConfirm`` for a command that changes something outside until
    ``confirm`` is sent; ``400`` with what is wrong in the line.
    """
    from fastapi.responses import JSONResponse

    from .. import commands
    from .. import fields as registry
    from ..automation import state as automation_state
    from ..core.permissions import AUTOMATION_RUN, WRITE

    try:
        parsed = commands.parse(body.line)
    except commands.CommandError as error:
        raise HTTPException(status_code=400, detail=error.message) from None

    def needs(permission: str, what: str) -> None:
        if not caller.has(permission):
            raise HTTPException(status_code=403, detail=f"Your roles do not include {what}")

    if parsed.kind == "note" or (parsed.kind == "slash" and parsed.name == "note"):
        needs(WRITE, "writing in an incident")
        if not parsed.text:
            raise HTTPException(status_code=400, detail="/note is followed by the note")
        return add_note(incident_id, NoteIn(text=parsed.text), caller, db, background_tasks)
    incident = _incident(db, incident_id, lock=True)
    if parsed.kind == "slash":
        needs(WRITE, "changing an incident")
        if parsed.name == "close":
            return JSONResponse(status_code=200, content={"action": "close"})
        if parsed.name == "task":
            import time

            from .. import tasks

            now = time.time()
            try:
                title, user, due = tasks.from_line(parsed.text)
                task = tasks.create(
                    db,
                    kind="task",
                    title=title,
                    incident_id=incident.id,
                    assignee_user=user,
                    assignee_owner=not user,
                    due_at=tasks.due_at(due, now) if due else None,
                    actor=caller.actor,
                    now=now,
                )
            except tasks.TaskError as error:
                raise HTTPException(status_code=400, detail=error.message) from None
            audit.record(db, caller.actor, "task.added", f'Added the task "{task.title}"', incident)
            db.commit()
            return JSONResponse(status_code=201, content={"action": "task", "task": task.id})
        who = parsed.text.lstrip("@").strip()
        try:
            registry.update(db, incident, {"owner": who or None}, caller.actor, f"user:{caller.actor}")
        except registry.FieldError as error:
            raise HTTPException(status_code=400, detail=error.message) from None
        row = war_room.system(
            db,
            incident.id,
            f"{caller.actor} assigned the incident to {who}" if who else f"{caller.actor} removed the assignee",
        )
        db.commit()
        emit(db, background_tasks, "incident.updated", {"id": incident.id, "name": incident.name})
        return JSONResponse(status_code=201, content={**war_room.out(row), "action": "assigned"})
    needs(AUTOMATION_RUN, "running commands")
    if not automation_state.enabled(db):
        raise HTTPException(status_code=409, detail="Automation is stopped: an admin can start it again in Settings")
    try:
        target = commands.resolve(db, parsed)
    except commands.CommandError as error:
        raise HTTPException(status_code=400, detail=error.message) from None
    if target.changes and not body.confirm:
        return JSONResponse(
            status_code=409,
            content={
                "detail": f"{target.title} changes something outside Nik: confirm to run it",
                "needsConfirm": True,
                "command": target.title,
            },
        )
    entry, run = commands.start(db, incident, body.line.strip(), target, parsed, caller.actor)
    audit.record(
        db, caller.actor, "warroom.command", f"Ran {target.title} in the War Room", incident, target=target.title
    )
    db.commit()
    return JSONResponse(status_code=201, content={**war_room.out(entry), "runId": run.id})

"""The Playground: commands outside any incident, for who may run automations (5.3)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as OrmSession

from .. import commands, playground
from ..automation import state as automation_state
from ..core import audit
from ..core.db import get_db
from ..core.models import PlaygroundEntry
from ..core.security import Principal, runner_principal

router = APIRouter(prefix="/playground", tags=["playground"])


class LineIn(BaseModel):
    line: str = Field(min_length=1, max_length=commands.LINE_MAX)
    # A command that changes something outside runs only once this is sent.
    confirm: bool = False


@router.get("")
def list_entries(
    limit: int = Query(200, ge=1, le=playground.MAX_SHOWN),
    show: str = Query("all"),
    caller: Principal = Depends(runner_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """What the caller typed in the Playground and what it gave, oldest first. Nobody else's.
    ``show`` keeps the ``notes`` or the ``commands``."""
    if show not in playground.SHOWS:
        raise HTTPException(status_code=400, detail="show is one of: " + ", ".join(playground.SHOWS))
    return {"entries": playground.entries(db, caller.actor, limit, show)}


@router.post("/command", status_code=status.HTTP_201_CREATED, response_model=None)
def run_line(body: LineIn, caller: Principal = Depends(runner_principal), db: OrmSession = Depends(get_db)):
    """Run ``!name arg=value`` with no incident, as a run of one node; plain text, or
    ``/note``, is a note to oneself. ``409`` with ``needsConfirm`` for a command that changes
    something outside until ``confirm`` is sent; ``400`` with what is wrong in the line, and for
    ``/assign`` and ``/close``, which are about an incident."""
    try:
        parsed = commands.parse(body.line)
    except commands.CommandError as error:
        raise HTTPException(status_code=400, detail=error.message) from None
    if parsed.kind == "note" or (parsed.kind == "slash" and parsed.name == "note"):
        if not parsed.text:
            raise HTTPException(status_code=400, detail="A note needs its text")
        entry = playground.add(db, caller.actor, "note", {"text": parsed.text})
        db.commit()
        return JSONResponse(status_code=201, content=playground.out(entry))
    if parsed.kind != "command":
        raise HTTPException(
            status_code=400,
            detail=f"/{parsed.name} is about an incident: the Playground has none. Use it in a War Room",
        )
    if not automation_state.enabled(db):
        raise HTTPException(status_code=409, detail="Automation is stopped: an admin can start it again in Settings")
    try:
        target = commands.resolve(db, parsed)
    except commands.CommandError as error:
        raise HTTPException(status_code=400, detail=error.message) from None
    if target.changes and not body.confirm:
        return JSONResponse(status_code=409, content=commands.confirm_answer(target))
    entry, run = commands.start(db, None, body.line.strip(), target, parsed, caller.actor)
    audit.record(db, caller.actor, "playground.command", f"Ran {target.title} in the Playground", target=target.title)
    db.commit()
    return JSONResponse(status_code=201, content={**playground.out(entry), "runId": run.id})


@router.get("/{entry_id}")
def get_entry(entry_id: str, caller: Principal = Depends(runner_principal), db: OrmSession = Depends(get_db)) -> dict:
    """One entry of the caller's Playground, with what its step got, gave and sent."""
    row = db.get(PlaygroundEntry, entry_id)
    if row is None or row.owner != caller.actor:
        raise HTTPException(status_code=404, detail="Entry not found")
    return {**playground.out(row), "step": playground.step_detail(db, row)}


@router.delete("", status_code=status.HTTP_204_NO_CONTENT)
def clear(caller: Principal = Depends(runner_principal), db: OrmSession = Depends(get_db)) -> Response:
    """Forget the caller's history. The runs behind it stay in the list of runs."""
    playground.clear(db, caller.actor)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)

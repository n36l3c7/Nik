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
from ..core.permissions import AUTOMATION_RUN
from ..core.security import Principal, require

router = APIRouter(prefix="/playground", tags=["playground"])

runner_principal = require(AUTOMATION_RUN)


class LineIn(BaseModel):
    line: str = Field(min_length=1, max_length=commands.LINE_MAX)
    # A command that changes something outside runs only once this is sent.
    confirm: bool = False


@router.get("")
def list_entries(
    limit: int = Query(200, ge=1, le=playground.MAX_SHOWN),
    caller: Principal = Depends(runner_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """What the caller typed in the Playground and what it gave, oldest first. Nobody else's."""
    return {"entries": playground.entries(db, caller.actor, limit)}


@router.post("/command", status_code=status.HTTP_201_CREATED, response_model=None)
def run_line(body: LineIn, caller: Principal = Depends(runner_principal), db: OrmSession = Depends(get_db)):
    """Run ``!name arg=value`` with no incident, as a run of one node. ``409`` with
    ``needsConfirm`` for a command that changes something outside until ``confirm`` is sent;
    ``400`` with what is wrong in the line, or when it is not a command."""
    try:
        parsed = commands.parse(body.line)
    except commands.CommandError as error:
        raise HTTPException(status_code=400, detail=error.message) from None
    if parsed.kind != "command":
        raise HTTPException(
            status_code=400,
            detail="The Playground runs commands: start the line with !. Notes and /commands belong to an incident",
        )
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

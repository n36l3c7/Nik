"""What the widgets of an incident page ask: script buttons, linked incidents, a narrowed chart.

Pressing a button is running a script: ``automation.run``, as for a command of
the War Room, and reading the incident it runs on. The two other widgets only
read, as whoever reads incidents.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as OrmSession

from .. import archive, buttons, page_widgets
from ..automation import state as automation_state
from ..core.config import settings as app_settings
from ..core.db import get_db
from ..core.locking import lock_incident
from ..core.models import Incident
from ..core.permissions import AUTOMATION_RUN, INCIDENTS_CONFIGURE, READ
from ..core.security import Principal, reader_principal, require, runner_principal
from ..iocs import Allowlist
from .settings import read_settings

router = APIRouter(tags=["incident page"])
# Who arranges the pages of a type chooses the script of a button; who runs scripts sees what one takes.
script_chooser_principal = require(INCIDENTS_CONFIGURE, AUTOMATION_RUN)


class PressIn(BaseModel):
    """A button as the page holds it, and what was typed for the arguments it asks."""

    script: str = Field(min_length=1, max_length=49)
    label: str = Field(default="", max_length=200)
    # name → template, as the type keeps them; rendered here, on the incident as it is now.
    args: dict[str, str] = Field(default_factory=dict)
    # name → what the person typed, for the arguments that were asked.
    values: dict[str, Any] = Field(default_factory=dict)


class RunIn(PressIn):
    # The number of runs the dialog showed: a press that would make another number is refused.
    expect: int | None = Field(default=None, ge=1)
    # Only the runs at these places (0 is the first): the failed ones, to run again.
    only: list[int] | None = Field(default=None, max_length=10_000)


class StatusIn(BaseModel):
    runs: list[str] = Field(max_length=buttons.STATUS_MAX)


def _incident(db: OrmSession, incident_id: str, *, lock: bool = False) -> Incident:
    row = lock_incident(db, incident_id) if lock else db.get(Incident, incident_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    if lock:  # a lock is taken to write: an archived incident is read-only
        archive.guard(row)
    return row


def _reads(caller: Principal) -> None:
    if not caller.has(READ):
        raise HTTPException(status_code=403, detail="Your roles do not include reading incidents")


def _planned(db: OrmSession, incident: Incident, body: PressIn) -> buttons.Plan:
    try:
        return buttons.plan(db, incident, body.script, body.args, body.values)
    except buttons.ButtonError as error:
        raise HTTPException(status_code=error.status, detail=error.message) from None


@router.get("/script-buttons/scripts")
def button_scripts(_caller: Principal = Depends(script_chooser_principal), db: OrmSession = Depends(get_db)) -> dict:
    """The scripts a button can run: those with a saved version, each with its arguments.
    ``sandbox`` says whether there is a sandbox to run them in."""
    return {"scripts": buttons.library(db), "sandbox": bool(app_settings.SANDBOX_URL)}


@router.post("/incidents/{incident_id}/script-buttons/plan")
def plan_press(
    incident_id: str, body: PressIn, caller: Principal = Depends(runner_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """What pressing a button would run, without running anything: each argument ``filled`` from
    the incident (with its ``value`` and the field it comes from) or to ``ask``, and how many
    ``runs`` it makes: one for each value of the argument named by ``each``."""
    _reads(caller)
    return _planned(db, _incident(db, incident_id), body).out()


@router.post("/incidents/{incident_id}/script-buttons/run", status_code=status.HTTP_201_CREATED)
def run_press(
    incident_id: str, body: RunIn, caller: Principal = Depends(runner_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Press a button: the script runs in the sandbox, once, or once for each value of the
    argument that holds several. Each run is a command in the War Room of the incident
    (``entryId``) and a line of the audit log; ``runs`` gives the id of each, to follow with
    ``…/script-buttons/status``. ``409`` when the incident changed since the dialog was shown
    (``expect``), or when automation is stopped."""
    _reads(caller)
    if not automation_state.enabled(db):
        raise HTTPException(status_code=409, detail="Automation is stopped: an admin can start it again in Settings")
    incident = _incident(db, incident_id, lock=True)
    planned = _planned(db, incident, body)
    if body.expect is not None and body.expect != len(planned.runs):
        raise HTTPException(
            status_code=409,
            detail=f"The incident changed: this would now make {len(planned.runs)} runs, not {body.expect}. "
            "Open the button again",
        )
    try:
        started = buttons.start(db, incident, body.label, planned, caller.actor, body.only)
    except buttons.ButtonError as error:
        raise HTTPException(status_code=error.status, detail=error.message) from None
    db.commit()
    return {"script": planned.script.name, "total": len(planned.runs), "runs": started}


@router.post("/incidents/{incident_id}/script-buttons/status")
def press_status(
    incident_id: str, body: StatusIn, caller: Principal = Depends(runner_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Where the runs of a press are: each ``running``, ``done`` with ``durationMs``, or ``failed``
    with ``error``. The output of a run is under its line in the War Room."""
    _reads(caller)
    return {"runs": buttons.status(db, _incident(db, incident_id), body.runs)}


@router.get("/incidents/{incident_id}/linked")
def linked_incidents(
    incident_id: str, _caller: Principal = Depends(reader_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """The incidents linked to this one, ten at most: those its field ``related_incidents`` names
    (or that name it), then those that hold the most indicators it holds too. Each says which:
    ``related``, and ``shared`` with the first ``indicators`` both hold."""
    allowlist = Allowlist(read_settings(db).get("iocAllowlist") or [])
    return page_widgets.linked(db, _incident(db, incident_id), allowlist)


@router.get("/incidents/{incident_id}/chart")
def narrowed_chart(
    incident_id: str,
    dashboard: str = Query(..., max_length=64),
    widget: str = Query(..., max_length=64),
    field: str = Query("", max_length=64),
    caller: Principal = Depends(reader_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """A widget of a dashboard with its query narrowed to what this incident holds for ``field``:
    ``{widget, board, field, value}``, to be asked of ``POST /api/query/aggregate`` like any
    widget. ``empty`` is true, with no widget, when the incident holds nothing for the field."""
    try:
        return page_widgets.chart(db, _incident(db, incident_id), dashboard, widget, field, caller)
    except page_widgets.ChartError as error:
        raise HTTPException(status_code=error.status, detail=error.message) from None

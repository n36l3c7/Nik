"""Mirroring: an incident kept in step with one object of another product.

Whoever reads an incident sees whether it is mirrored and how it goes;
whoever writes it starts, stops and reads the other side now. Starting a
mirror that sends (``out``, ``both``) is a standing permission to send what
changes: it needs the permission to run playbooks, opening a class of data
for it needs the one that opens classes for playbooks, and both are recorded.
What waits to be sent, or could not be, is listed for whoever manages connectors.
"""

from __future__ import annotations

import time

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as OrmSession

from .. import mirror
from ..automation import expressions as ex
from ..automation.connector_runtime import CommandError
from ..core import audit
from ..core.db import get_db
from ..core.locking import lock_incident
from ..core.models import Connection, Incident, MirrorJob
from ..core.permissions import AUTOMATION_OPEN, AUTOMATION_RUN
from ..core.security import Principal, manager_principal, reader_principal, writer_principal

router = APIRouter(tags=["mirroring"])


class DirectionIn(BaseModel):
    direction: str = Field(pattern="^(in|out|both)$")
    # Left out, the classes the mirror may send stay as they are.
    dataAllow: list[str] | None = Field(default=None, max_length=40)


class StartIn(BaseModel):
    instanceId: str = Field(max_length=32)
    # The id of the object on the other side: a ticket's sys_id, an issue's key.
    mirrorId: str = Field(min_length=1, max_length=300)
    direction: str = Field(pattern="^(in|out|both)$")
    # Classes of data this mirror may send besides those that always may (the data guard).
    dataAllow: list[str] = Field(default_factory=list, max_length=40)


def _incident(db: OrmSession, incident_id: str, *, lock: bool = False) -> Incident:
    row = lock_incident(db, incident_id) if lock else db.get(Incident, incident_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return row


@router.get("/incidents/{incident_id}/mirror")
def get_mirror(
    incident_id: str, _caller: Principal = Depends(reader_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Whether the incident is mirrored, with what, in which direction and how it goes; and the
    connections it can be mirrored with."""
    incident = _incident(db, incident_id)
    return {**mirror.out(db, incident), "instances": mirror.mirroring_connections(db)}


@router.post("/incidents/{incident_id}/mirror", status_code=status.HTTP_201_CREATED)
def start_mirror(
    incident_id: str, body: StartIn, caller: Principal = Depends(writer_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Mirror the incident with an object of a connection. ``out`` and ``both`` send what changes in
    Nik to the other side from now on: they need the permission to run playbooks."""
    incident = _incident(db, incident_id, lock=True)
    connection = db.get(Connection, body.instanceId)
    if connection is None:
        raise HTTPException(status_code=404, detail="Instance not found")
    if body.direction != "in" and not caller.has(AUTOMATION_RUN):
        raise HTTPException(status_code=403, detail="Sending to another system needs the permission to run playbooks")
    if body.dataAllow and not caller.has(AUTOMATION_OPEN):
        raise HTTPException(status_code=403, detail="Opening a class of data needs the permission that opens them")
    try:
        mirror.start(db, incident, connection, body.mirrorId, body.direction, caller.actor, time.time(), body.dataAllow)
    except mirror.MirrorError as error:
        raise HTTPException(status_code=error.status, detail=error.message) from None
    db.commit()
    return {**mirror.out(db, incident), "instances": mirror.mirroring_connections(db)}


@router.patch("/incidents/{incident_id}/mirror")
def change_mirror(
    incident_id: str, body: DirectionIn, caller: Principal = Depends(writer_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Change the direction of the mirror of this incident, whatever started it: from then on it is
    "set here", and what its instance says is for the incidents fetched later. The same permissions
    as starting one."""
    incident = _incident(db, incident_id, lock=True)
    state = mirror.state_of(incident)
    if state is None:
        raise HTTPException(status_code=409, detail="This incident is not mirrored")
    if body.direction != "in" and not caller.has(AUTOMATION_RUN):
        raise HTTPException(status_code=403, detail="Sending to another system needs the permission to run playbooks")
    opened = set(body.dataAllow or []) - set(state.get("allow") or [])
    if opened and not caller.has(AUTOMATION_OPEN):
        raise HTTPException(status_code=403, detail="Opening a class of data needs the permission that opens them")
    try:
        mirror.redirect(db, incident, body.direction, caller.actor, time.time(), body.dataAllow)
    except mirror.MirrorError as error:
        raise HTTPException(status_code=error.status, detail=error.message) from None
    db.commit()
    return {**mirror.out(db, incident), "instances": mirror.mirroring_connections(db)}


@router.delete("/incidents/{incident_id}/mirror", status_code=status.HTTP_204_NO_CONTENT)
def stop_mirror(
    incident_id: str, caller: Principal = Depends(writer_principal), db: OrmSession = Depends(get_db)
) -> Response:
    """Stop mirroring: nothing is read or sent any more, and what waited to be sent is dropped."""
    incident = _incident(db, incident_id, lock=True)
    mirror.stop(db, incident, caller.actor)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/incidents/{incident_id}/mirror/sync")
def sync_mirror(
    incident_id: str, caller: Principal = Depends(writer_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Read the other side now: ``{changed, kept, comments, problems}``, where ``kept`` are the
    fields a person set in Nik that were left as they are. ``gone`` is there, and true, when the
    object is not on the other side any more."""
    incident = _incident(db, incident_id, lock=True)
    try:
        done = mirror.pull(db, incident, time.time())
    except mirror.MirrorError as error:
        raise HTTPException(status_code=error.status, detail=error.message) from None
    except (CommandError, ex.ExpressionError) as error:
        db.rollback()
        raise HTTPException(status_code=502, detail=getattr(error, "message", str(error))) from None
    db.commit()
    return {**done, "mirror": mirror.out(db, incident)}


@router.get("/mirror/queue")
def mirror_queue(_caller: Principal = Depends(manager_principal), db: OrmSession = Depends(get_db)) -> dict:
    """What waits to be sent to the other side of mirrored incidents, and what could not be."""
    return {"jobs": mirror.queue(db)}


@router.post("/mirror/queue/{job_id}/retry")
def retry_job(job_id: str, caller: Principal = Depends(manager_principal), db: OrmSession = Depends(get_db)) -> dict:
    """Try again, at the next turn of the worker, something that could not be sent."""
    job = db.get(MirrorJob, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Nothing waits with this id")
    job.status, job.attempts, job.next_at, job.error = "pending", 0, time.time(), ""
    audit.record(
        db, caller.actor, "mirror.retry", "Sent again what mirroring could not send", db.get(Incident, job.incident_id)
    )
    db.commit()
    return {"jobs": mirror.queue(db)}

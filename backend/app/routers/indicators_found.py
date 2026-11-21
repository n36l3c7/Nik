"""Indicators found by themselves when an incident comes in: the setting, and what an incident was given.

The reading itself is ``app/indicators_found.py``. Here: the setting an
administrator keeps (whether incidents are read, which types, what is left
out, the paths that are never read, how many an incident may be given), the
word of one instance of a connector, and for an incident what was found, with
where, and the two things a person does with it: take one off (which is
remembered) and ask for the incident to be read now.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, BackgroundTasks, Body, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as OrmSession

from .. import indicators_found as found
from ..core import audit
from ..core.db import get_db
from ..core.locking import lock_incident
from ..core.models import Connection, Incident
from ..core.security import Principal, admin_principal, manager_principal, reader_principal, writer_principal
from ..events import emit
from ..iocs import TYPES

router = APIRouter(tags=["indicators found"])


def _settings_out(cfg: dict[str, Any]) -> dict[str, Any]:
    return {
        **cfg,
        "allTypes": list(TYPES),
        "capMax": found.CAP_MAX,
        "skipDefault": list(found.SKIP_DEFAULT),
        "limits": {"strings": found.STRINGS_MAX, "characters": found.BYTES_MAX},
    }


@router.get("/iocs/found/settings")
def get_settings(_caller: Principal = Depends(reader_principal), db: OrmSession = Depends(get_db)) -> dict:
    """How incidents are read for indicators as they come in, and the instances told apart."""
    return _settings_out(found.config(db))


@router.put("/iocs/found/settings")
def put_settings(
    body: dict[str, Any] = Body(...), caller: Principal = Depends(admin_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Change it (an administrator). A key left out keeps what it had: ``enabled``, ``types``,
    ``leaveOutPrivate``, ``leaveOutBenign``, ``cap``, ``skip``, ``lookUps``."""
    current = found.config(db)
    try:
        wanted = found.clean(body, current)
    except found.FoundError as error:
        raise HTTPException(status_code=400, detail=error.message) from None
    changed = sorted(key for key in wanted if wanted[key] != current[key])
    if changed:
        found.save(db, wanted)
        audit.record(db, caller.actor, "settings.update", "Changed how indicators are found: " + ", ".join(changed))
        db.commit()
    return _settings_out(found.config(db))


class InstanceIn(BaseModel):
    # True: the incidents of this instance are read; False: they are not; null: as the setting says.
    enabled: bool | None = None


@router.put("/iocs/found/instances/{connection_id}")
def put_instance(
    connection_id: str,
    body: InstanceIn,
    caller: Principal = Depends(manager_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Tell one instance of a connector apart from the setting: its incidents are read for
    indicators, are not, or follow the setting."""
    connection = db.get(Connection, connection_id)
    if connection is None:
        raise HTTPException(status_code=404, detail="There is no such instance")
    cfg = found.set_instance(db, connection, body.enabled)
    said = {True: "are read for indicators", False: "are not read for indicators", None: "follow the setting"}
    audit.record(
        db,
        caller.actor,
        "connection.update",
        f'The incidents of "{connection.name}" {said[body.enabled]}',
        target=connection.name,
    )
    db.commit()
    return {"id": connection.id, "enabled": cfg["instances"].get(connection.id), "setting": cfg["enabled"]}


@router.get("/iocs/found/instances/{connection_id}")
def get_instance(
    connection_id: str, _caller: Principal = Depends(manager_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """What one instance says: ``enabled`` true, false, or null when it follows the setting."""
    if db.get(Connection, connection_id) is None:
        raise HTTPException(status_code=404, detail="There is no such instance")
    cfg = found.config(db)
    return {"id": connection_id, "enabled": cfg["instances"].get(connection_id), "setting": cfg["enabled"]}


def _incident(db: OrmSession, incident_id: str, *, lock: bool = False) -> Incident:
    row = lock_incident(db, incident_id) if lock else db.get(Incident, incident_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return row


@router.get("/incidents/{incident_id}/iocs/found")
def list_found(
    incident_id: str, _caller: Principal = Depends(reader_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """The indicators the incident was given by itself, each with the path it was read at; the
    ones a person removed; and what the last reading came to."""
    return found.listing(db, _incident(db, incident_id))


@router.post("/incidents/{incident_id}/iocs/found/scan")
def scan_now(
    incident_id: str,
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
    background_tasks: BackgroundTasks = None,
) -> dict:
    """Read the incident for indicators now: its fields and its context as they are. For an
    incident that came in before incidents were read, or after its context grew."""
    incident = _incident(db, incident_id, lock=True)
    summary = found.scan(db, incident, "asked", asked=True)
    audit.record(db, caller.actor, "ioc.found_scan", "Asked for the incident to be read for indicators", incident)
    db.commit()
    if summary and summary.get("new"):
        emit(db, background_tasks, "incident.updated", {"id": incident.id, "name": incident.name})
    return found.listing(db, incident)


class PairIn(BaseModel):
    type: str = Field(max_length=16)
    value: str = Field(max_length=1024)


@router.post("/incidents/{incident_id}/iocs/found/remove")
def remove_found(
    incident_id: str,
    body: PairIn,
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
    background_tasks: BackgroundTasks = None,
) -> dict:
    """Take a found indicator off the incident. It is remembered: the value is not found again
    when the incident is updated or read again."""
    incident = _incident(db, incident_id, lock=True)
    if not found.remove(db, incident, body.type, body.value, caller.actor):
        raise HTTPException(status_code=404, detail="The incident was not given this indicator by itself")
    db.commit()
    emit(db, background_tasks, "incident.updated", {"id": incident.id, "name": incident.name})
    return found.listing(db, incident)


@router.post("/incidents/{incident_id}/iocs/found/restore")
def restore_found(
    incident_id: str,
    body: PairIn,
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
    background_tasks: BackgroundTasks = None,
) -> dict:
    """Give back a found indicator that was removed."""
    incident = _incident(db, incident_id, lock=True)
    if not found.restore(db, incident, body.type, body.value, caller.actor):
        raise HTTPException(status_code=404, detail="This indicator was not removed from the incident")
    db.commit()
    emit(db, background_tasks, "incident.updated", {"id": incident.id, "name": incident.name})
    return found.listing(db, incident)

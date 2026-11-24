"""Archiving an incident, and taking it out of the archive (7.0).

``POST /incidents/{id}/archive`` archives a closed incident, ``DELETE`` takes it out;
both ask for ``incidents.archive`` and answer ``409`` with a sentence when the incident
cannot be (it is not closed, a file of it is being read). The rule that archives the
incidents closed for long (``archive.auto``) has its settings here.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session as OrmSession

from .. import archive
from ..core import audit
from ..core.db import get_db
from ..core.locking import lock_incident
from ..core.permissions import ADMIN, INCIDENTS_ARCHIVE
from ..core.security import Principal, require
from ..evidence import parse
from .incidents import _shown, _source

router = APIRouter(tags=["archive"])

# The administrators, and whoever holds the permission, change the rule.
settings_principal = require(ADMIN, INCIDENTS_ARCHIVE)
archive_principal = require(INCIDENTS_ARCHIVE)


class SettingsIn(BaseModel):
    enabled: bool | None = None
    days: int | None = None


def _locked(db: OrmSession, incident_id: str):
    row = lock_incident(db, incident_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return row


@router.post("/incidents/{incident_id}/archive")
def archive_incident(
    incident_id: str, caller: Principal = Depends(archive_principal), db: OrmSession = Depends(get_db)
) -> dict[str, Any]:
    """Archive a closed incident: read-only, out of the lists, its host evidence out of the database
    (the originals, the reports and the flags and notes stay)."""
    row = _locked(db, incident_id)
    try:
        done = archive.put(db, row, caller.actor)
    except ValueError as error:
        raise HTTPException(status_code=409, detail=str(error)) from None
    db.commit()
    return {**_shown(row, _source(db, row.source_connection_id)), "done": done}


@router.delete("/incidents/{incident_id}/archive")
def take_out_of_archive(
    incident_id: str, caller: Principal = Depends(archive_principal), db: OrmSession = Depends(get_db)
) -> dict[str, Any]:
    """Take an incident out of the archive: it is writable again, and its files are read again."""
    row = _locked(db, incident_id)
    try:
        reading = archive.take_out(db, row, caller.actor)
    except ValueError as error:
        raise HTTPException(status_code=409, detail=str(error)) from None
    db.commit()
    for source_id in reading:
        parse.start(source_id)
    return {**_shown(row, _source(db, row.source_connection_id)), "done": {"reading": len(reading)}}


@router.get("/settings/archive")
def get_settings(_caller: Principal = Depends(settings_principal), db: OrmSession = Depends(get_db)) -> dict:
    """The rule: archive the incidents closed for more than ``days`` days, when ``enabled``."""
    return {**archive.config(db), "defaults": dict(archive.DEFAULTS)}


@router.put("/settings/archive")
def put_settings(
    body: SettingsIn, caller: Principal = Depends(settings_principal), db: OrmSession = Depends(get_db)
) -> dict:
    try:
        doc = archive.save(db, body.model_dump())
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from None
    said = "on, after " + f"{doc['days']} days" if doc["enabled"] else "off"
    audit.record(db, caller.actor, "archive.settings", f"Set the archiving of closed incidents: {said}")
    db.commit()
    return {**doc, "defaults": dict(archive.DEFAULTS)}

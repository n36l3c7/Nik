"""The context of an incident, for the accounts that run playbooks.

Read only: the context is written by Nik's own analysis and by what commands
and scripts declare (``context.py``), never by hand through this API.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session as OrmSession

from .. import context as incident_context
from .. import fields as registry
from ..core.db import get_db
from ..core.models import Incident, IncidentContext
from ..core.permissions import AUTOMATION_RUN
from ..core.security import Principal, require

router = APIRouter(prefix="/incidents", tags=["context"])
runner_principal = require(AUTOMATION_RUN)


@router.get("/{incident_id}/context")
def get_context(
    incident_id: str, _caller: Principal = Depends(runner_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """What a playbook reads of the incident: ``incident`` (its fields, by the names of the
    registry) and ``context`` (the entities of the common schema, and ``ext``), with who last
    set each item of the context and the schema itself."""
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    row = db.get(IncidentContext, incident_id)
    return {
        "incident": registry.read(db, incident),
        "context": dict(row.data or {}) if row is not None else {},
        "version": row.version if row is not None else 0,
        "updatedAt": row.updated_at if row is not None else None,
        "provenance": incident_context.provenance(db, incident_id),
        "schema": {
            entity: {"keys": list(keys), "key": list(key)} for entity, (keys, key) in incident_context.SCHEMA.items()
        },
    }

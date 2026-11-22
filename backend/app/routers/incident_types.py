"""Incident types: read by whoever reads incidents, changed by who configures them."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import update
from sqlalchemy.orm import Session as OrmSession

from .. import fields as registry
from .. import incident_types as types
from ..core import audit
from ..core.db import get_db
from ..core.models import Incident, IncidentType
from ..core.permissions import ADMIN, INCIDENTS_CONFIGURE
from ..core.security import Principal, configure_principal, now_iso, reader_principal

router = APIRouter(prefix="/incident-types", tags=["incident types"])


class TypeIn(BaseModel):
    """A type as it is saved. On ``PUT`` a key left out keeps what the type has."""

    name: str | None = Field(default=None, max_length=80)
    description: str | None = Field(default=None, max_length=1000)
    colour: str | None = Field(default=None, max_length=16)
    icon: str | None = Field(default=None, max_length=32)
    fields: list[dict[str, Any]] | None = None
    layout: dict[str, Any] | None = None
    closeReasons: list[str] | None = None
    # For each timer: {field, minutes, bySeverity: {high: 60, …}, businessHours}.
    sla: list[dict[str, Any]] | None = None
    defaultPlaybookId: str | None = Field(default=None, max_length=32)
    autoRun: bool | None = None
    visibleToRoles: list[str] | None = None


def _get(db: OrmSession, type_id: str) -> IncidentType:
    types.every(db)  # the shipped ones, when this is the first time they are asked for
    row = db.get(IncidentType, type_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Incident type not found")
    return row


def _sees(caller: Principal, row: IncidentType) -> bool:
    """A type limited to some roles is for the accounts that hold one of them (and for who configures)."""
    if not row.visible_to_roles or caller.has(INCIDENTS_CONFIGURE) or caller.has(ADMIN):
        return True
    return bool(set(row.visible_to_roles) & set(caller.roles))


def _apply(row: IncidentType, cleaned: dict[str, Any], actor: str) -> None:
    for key, value in cleaned.items():
        setattr(row, key, value)
    row.updated_at, row.updated_by = now_iso(), actor


@router.get("")
def list_types(caller: Principal = Depends(reader_principal), db: OrmSession = Depends(get_db)) -> dict:
    """The types, each with its fields, its layout (saved, or generated from its fields) and its close reasons."""
    rows = types.every(db)
    known = registry.registry(db)
    db.commit()  # what was seeded, when this is the first time
    return {
        "types": [types.out(db, row, known) for row in rows if _sees(caller, row)],
        "tabs": list(types.TABS),
        "colours": list(types.COLOURS),
    }


@router.post("", status_code=status.HTTP_201_CREATED)
def create_type(
    body: TypeIn, caller: Principal = Depends(configure_principal), db: OrmSession = Depends(get_db)
) -> dict:
    types.every(db)
    try:
        cleaned = types.clean(db, body.model_dump(exclude_unset=True))
    except types.TypeError_ as error:
        raise HTTPException(status_code=400, detail=error.message) from None
    stamp = now_iso()
    row = IncidentType(id=types.new_id(db, cleaned["name"]), created_at=stamp, updated_at=stamp, fields=[], sla=[])
    row.close_reasons = list(types.CLOSE_REASONS)
    _apply(row, cleaned, caller.actor)
    db.add(row)
    audit.record(db, caller.actor, "type.create", f'Created the incident type "{row.name}"', target=row.name)
    db.commit()
    return types.out(db, row)


@router.get("/{type_id}")
def get_type(type_id: str, caller: Principal = Depends(reader_principal), db: OrmSession = Depends(get_db)) -> dict:
    row = _get(db, type_id)
    if not _sees(caller, row):
        raise HTTPException(status_code=404, detail="Incident type not found")
    answer = types.out(db, row)
    db.commit()
    return answer


@router.put("/{type_id}")
def update_type(
    type_id: str, body: TypeIn, caller: Principal = Depends(configure_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Change a type. Sending ``layout: null`` goes back to the generated one."""
    row = _get(db, type_id)
    try:
        cleaned = types.clean(db, body.model_dump(exclude_unset=True), row)
    except types.TypeError_ as error:
        raise HTTPException(status_code=400, detail=error.message) from None
    _apply(row, cleaned, caller.actor)
    audit.record(db, caller.actor, "type.update", f'Changed the incident type "{row.name}"', target=row.name)
    if "sla" in cleaned:
        # The open incidents of the type follow its new SLA at once.
        import time

        from sqlalchemy import select

        from .. import timers
        from ..core.models import Incident

        db.flush()
        of_type = Incident.type_id == row.id
        if row.id == types.UNCLASSIFIED:
            of_type = of_type | Incident.type_id.is_(None)
        for incident in db.scalars(select(Incident).where(of_type, Incident.status != "closed")):
            timers.sync(db, incident, time.time())
    db.commit()
    return types.out(db, row)


@router.delete("/{type_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_type(
    type_id: str,
    moveTo: str = types.UNCLASSIFIED,
    caller: Principal = Depends(configure_principal),
    db: OrmSession = Depends(get_db),
) -> Response:
    """Delete a type. Its incidents become ``moveTo`` (Unclassified when not said) and keep
    every value they hold: fields the new type does not list are hidden, not removed."""
    row = _get(db, type_id)
    if row.id == types.UNCLASSIFIED:
        raise HTTPException(status_code=409, detail="Unclassified cannot be deleted: it is the type of what has none")
    target = _get(db, moveTo)
    if target.id == row.id:
        raise HTTPException(status_code=400, detail="Its incidents need another type to move to")
    moved = db.execute(
        update(Incident)
        .where(Incident.type_id == row.id)
        .values(type_id=None if target.id == types.UNCLASSIFIED else target.id)
    ).rowcount
    audit.record(
        db,
        caller.actor,
        "type.delete",
        f'Deleted the incident type "{row.name}"' + (f"; {moved} incident(s) became {target.name}" if moved else ""),
        target=row.name,
    )
    db.delete(row)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)

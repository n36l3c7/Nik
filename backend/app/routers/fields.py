"""The field registry and the fields of an incident.

Reading the registry is for whoever reads incidents (the forms are built from
it); changing it needs ``incidents.configure``. The values of an incident are
written by whoever may write incidents, through ``fields.update``: the one
place that checks a value against its field and its type.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as OrmSession

from .. import fields as registry
from ..core import audit
from ..core.db import get_db
from ..core.locking import lock_incident
from ..core.models import Field as FieldRow
from ..core.models import Incident
from ..core.security import Principal, configure_principal, reader_principal, writer_principal
from ..events import emit

router = APIRouter(prefix="/fields", tags=["fields"])
incident_router = APIRouter(prefix="/incidents", tags=["fields"])


class FieldIn(BaseModel):
    name: str = Field(min_length=1, max_length=41)
    label: str = Field(default="", max_length=80)
    description: str = Field(default="", max_length=1000)
    type: str = Field(default="text", max_length=16)
    options: dict[str, Any] = Field(default_factory=dict)
    appliesTo: str = Field(default="incident", max_length=12)
    allTypes: bool = False


class FieldPatch(BaseModel):
    """What can change of a field: never its name, never its type."""

    label: str | None = Field(default=None, min_length=1, max_length=80)
    description: str | None = Field(default=None, max_length=1000)
    options: dict[str, Any] | None = None
    allTypes: bool | None = None


class ValuesIn(BaseModel):
    changes: dict[str, Any]
    ifRev: int | None = None


def _refused(error: registry.FieldError) -> HTTPException:
    return HTTPException(status_code=400, detail=error.message)


def _out(row: FieldRow) -> dict[str, Any]:
    system = registry.SYSTEM_FIELDS.get(row.name) if row.system else None
    return {
        "id": row.id,
        "name": row.name,
        "label": row.label or row.name,
        "description": row.description,
        "type": row.type,
        "options": row.options or {},
        "system": bool(row.system),
        "writable": system.writable if system is not None else True,
        "appliesTo": row.applies_to,
        "allTypes": bool(row.all_types),
        "createdAt": row.created_at,
        "createdBy": row.created_by,
    }


def _get(db: OrmSession, name: str) -> FieldRow:
    row = registry.registry(db).get(name)
    if row is None:
        raise HTTPException(status_code=404, detail="Field not found")
    return row


@router.get("")
def list_fields(_caller: Principal = Depends(reader_principal), db: OrmSession = Depends(get_db)) -> dict:
    """Every field of the registry: the system ones first, in their order, then the custom ones by label."""
    rows = list(registry.registry(db).values())
    db.commit()  # the system fields, when this is the first time they are asked for
    order = {name: index for index, name in enumerate(registry.SYSTEM_FIELDS)}
    rows.sort(
        key=lambda row: (0, order.get(row.name, 0), "") if row.system else (1, 0, (row.label or row.name).lower())
    )
    return {"fields": [_out(row) for row in rows], "types": list(registry.TYPES)}


@router.post("", status_code=status.HTTP_201_CREATED)
def create_field(
    body: FieldIn, caller: Principal = Depends(configure_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Make a field. Its name and its type are for ever: playbooks, mappers and queries refer to them."""
    try:
        row = registry.create(db, body.model_dump(), caller.actor)
    except registry.FieldError as error:
        raise _refused(error) from None
    audit.record(
        db, caller.actor, "field.create", f'Created the field "{row.label}" ({row.name}, {row.type})', target=row.name
    )
    db.commit()
    return _out(row)


@router.get("/{name}")
def get_field(name: str, _caller: Principal = Depends(reader_principal), db: OrmSession = Depends(get_db)) -> dict:
    row = _get(db, name)
    return {**_out(row), "usedBy": registry.used_by(db, row)}


@router.patch("/{name}")
def update_field(
    name: str, body: FieldPatch, caller: Principal = Depends(configure_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Change a field's label, description or choices. A system field keeps its choices and stays on every type."""
    row = _get(db, name)
    if body.label is not None:
        row.label = body.label.strip()
    if body.description is not None:
        row.description = body.description
    if row.system and (body.options is not None or body.allTypes is not None):
        raise HTTPException(status_code=400, detail="Of a system field only the label and the description can change")
    if body.options is not None:
        try:
            row.options = registry.clean_options(row.type, body.options)
        except registry.FieldError as error:
            raise _refused(error) from None
    if body.allTypes is not None:
        row.all_types = body.allTypes
    audit.record(db, caller.actor, "field.update", f'Changed the field "{row.label}" ({row.name})', target=row.name)
    db.commit()
    return _out(row)


@router.delete("/{name}", status_code=status.HTTP_204_NO_CONTENT)
def delete_field(
    name: str, caller: Principal = Depends(configure_principal), db: OrmSession = Depends(get_db)
) -> Response:
    """Delete a custom field nothing uses. One a type lists, or an incident holds a value of, is refused."""
    row = _get(db, name)
    if row.system:
        raise HTTPException(status_code=409, detail="A system field cannot be deleted")
    used = registry.used_by(db, row)
    if used["types"]:
        raise HTTPException(status_code=409, detail="Used by the types: " + ", ".join(used["types"]))
    if used["incidents"]:
        raise HTTPException(status_code=409, detail=f"{used['incidents']} incident(s) hold a value of this field")
    audit.record(db, caller.actor, "field.delete", f'Deleted the field "{row.label}" ({row.name})', target=row.name)
    db.delete(row)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --------------------------------------------------------------------------- #
# The fields of an incident                                                   #
# --------------------------------------------------------------------------- #
def _values(db: OrmSession, row: Incident) -> dict[str, Any]:
    return {"fields": registry.read(db, row), "rev": row.fields_rev or 0, "type": row.type_id or registry.UNCLASSIFIED}


@incident_router.get("/{incident_id}/fields")
def incident_fields(
    incident_id: str, _caller: Principal = Depends(reader_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Every field of the incident that has a value, by name, with the revision to send back when changing them."""
    row = db.get(Incident, incident_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return _values(db, row)


@incident_router.patch("/{incident_id}/fields")
def set_incident_fields(
    incident_id: str,
    body: ValuesIn,
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
    background_tasks: BackgroundTasks = None,
) -> dict:
    """Set fields of an incident: ``{changes: {name: value}, ifRev?}``. ``null`` clears a field.

    Every value is checked against the registry and the incident's type; one
    that is wrong refuses the whole change (``400``, with which and why).
    ``409`` when ``ifRev`` is not the current revision.
    """
    row = lock_incident(db, incident_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    try:
        changed = registry.update(db, row, body.changes, caller.actor, f"user:{caller.actor}", if_rev=body.ifRev)
    except registry.FieldError as error:
        raise HTTPException(status_code=409 if error.field == "ifRev" else 400, detail=error.message) from None
    db.commit()
    if changed:
        emit(db, background_tasks, "incident.updated", {"id": row.id, "name": row.name})
    return {**_values(db, row), "changed": changed}

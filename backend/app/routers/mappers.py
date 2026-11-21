"""Classifiers and mappers (``connectors.manage``).

A classifier says which type of incident a fetched item becomes, for one
connection. A mapper says how the names of a connector's product become Nik's
fields and context (incoming) and back (outgoing), for one type of incident
or for all. ``try`` shows what a mapper or a classifier makes of a sample,
and writes nothing.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as OrmSession

from .. import mapping
from ..core import audit
from ..core.db import get_db
from ..core.models import Connection, Connector, Incident, Mapper
from ..core.security import Principal, manager_principal

router = APIRouter(tags=["mappers"])


class MapperIn(BaseModel):
    connectorId: str = Field(max_length=41)
    direction: str = Field(pattern="^(incoming|outgoing)$")
    # A type of incident, or "*" for every type that has no mapper of its own.
    incidentType: str = Field(default="*", max_length=32)
    rules: list[dict[str, Any]] = Field(default_factory=list, max_length=mapping.RULES_MAX)


class TryMapperIn(BaseModel):
    connectorId: str = Field(max_length=41)
    direction: str = Field(pattern="^(incoming|outgoing)$")
    incidentType: str = Field(default="*", max_length=32)
    # The rules to try; left out, those that are saved for the connector and the type.
    rules: list[dict[str, Any]] | None = Field(default=None, max_length=mapping.RULES_MAX)
    # incoming: an item as the product gives it. outgoing: the id of an incident.
    item: Any = None
    incidentId: str | None = Field(default=None, max_length=200)


class ClassifierIn(BaseModel):
    rules: list[dict[str, Any]] = Field(default_factory=list, max_length=mapping.CLASSIFIER_RULES_MAX)
    defaultType: str | None = Field(default=None, max_length=32)


class TryClassifierIn(ClassifierIn):
    item: Any = None


def _refuse(error: mapping.MappingError) -> HTTPException:
    return HTTPException(status_code=error.status, detail=error.message)


def _connection(db: OrmSession, connection_id: str) -> Connection:
    row = db.get(Connection, connection_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Instance not found")
    return row


@router.get("/mappers")
def list_mappers(
    connector: str = Query("", max_length=41),
    _caller: Principal = Depends(manager_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """The mappers, of one connector when ``connector`` is given."""
    return {"mappers": [mapping.mapper_out(row) for row in mapping.mappers_of(db, connector or None)]}


@router.get("/mappers/targets")
def mapper_targets(
    incident_type: str = Query("*", alias="type", max_length=32),
    _caller: Principal = Depends(manager_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Nik's side of a mapper: the fields it may set for a type of incident (those the type
    needs first) and the entities of the context. The product's side is the ``schema`` of its connector."""
    return mapping.targets(db, incident_type)


@router.put("/mappers")
def save_mapper(
    body: MapperIn, caller: Principal = Depends(manager_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Save the mapper of a connector, a direction and a type of incident (it replaces the one there)."""
    try:
        row = mapping.save_mapper(db, body.model_dump(), caller.actor)
    except mapping.MappingError as error:
        raise _refuse(error) from None
    audit.record(
        db,
        caller.actor,
        "mapper.save",
        f"Saved the {row.direction} mapper of {row.connector_id} for {row.incident_type}",
        target=row.connector_id,
    )
    db.commit()
    return mapping.mapper_out(row)


@router.delete("/mappers/{mapper_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_mapper(
    mapper_id: str, caller: Principal = Depends(manager_principal), db: OrmSession = Depends(get_db)
) -> Response:
    row = db.get(Mapper, mapper_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Mapper not found")
    audit.record(
        db,
        caller.actor,
        "mapper.delete",
        f"Deleted the {row.direction} mapper of {row.connector_id} for {row.incident_type}",
        target=row.connector_id,
    )
    db.delete(row)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/mappers/try")
def try_mapper(
    body: TryMapperIn, _caller: Principal = Depends(manager_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """What a mapper makes of a sample, without writing anything.

    Incoming: ``item`` → ``{fields, context, authoritative, problems, missing}``, where
    ``missing`` are the fields the type needs that nothing gave. Outgoing: ``incidentId`` →
    ``{sent}``, what would go to the other side."""
    if db.get(Connector, body.connectorId) is None:
        raise HTTPException(status_code=404, detail="This connector does not exist")
    incident_type = None if body.incidentType == mapping.ANY_TYPE else body.incidentType
    try:
        if body.rules is not None:
            rules = mapping.clean_rules(db, body.connectorId, body.direction, body.rules)
        else:
            saved = mapping.find_mapper(db, body.connectorId, body.direction, incident_type)
            rules = (saved.rules if saved is not None else None) or []
    except mapping.MappingError as error:
        raise _refuse(error) from None
    if body.direction == "incoming":
        return mapping.apply_incoming(db, rules, body.item, body.connectorId, incident_type).out()
    incident = db.get(Incident, body.incidentId or "")
    if incident is None:
        raise HTTPException(status_code=404, detail="Choose an incident to try the mapper on")
    return {"sent": mapping.apply_outgoing(db, rules, incident, {"id": "(the id on the other side)"})}


@router.get("/classifiers/{connection_id}")
def get_classifier(
    connection_id: str, _caller: Principal = Depends(manager_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """The classifier of a connection: its rules and its default type (empty when it has none)."""
    return mapping.classifier_out(db, _connection(db, connection_id))


@router.put("/classifiers/{connection_id}")
def save_classifier(
    connection_id: str,
    body: ClassifierIn,
    caller: Principal = Depends(manager_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Save the classifier of a connection: ``rules`` (``[{when, type}]``, the first that holds
    wins) and ``defaultType``."""
    connection = _connection(db, connection_id)
    try:
        mapping.save_classifier(db, connection, body.model_dump(), caller.actor)
    except mapping.MappingError as error:
        raise _refuse(error) from None
    audit.record(
        db, caller.actor, "classifier.save", f'Saved the classifier of "{connection.name}"', target=connection.name
    )
    db.commit()
    return mapping.classifier_out(db, connection)


@router.post("/classifiers/try")
def try_classifier(
    body: TryClassifierIn, _caller: Principal = Depends(manager_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """The type an item would become under these rules, without saving them."""
    try:
        rules, default = mapping.clean_classifier(db, body.model_dump())
    except mapping.MappingError as error:
        raise _refuse(error) from None
    return {"type": mapping.classify(rules, default, body.item)}

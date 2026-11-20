"""The query language over the API.

- ``GET /query/schema`` lists the entities a caller may query and their
  fields: what the builder and the autocomplete of the interface are made of.
- ``POST /query`` runs a query on an entity and returns a page of it, in the
  shape the entity's own list endpoint uses.
- ``POST /query/check`` reads a query without running it.
- ``POST /query/aggregate`` counts or measures what a query finds, by group
  and over time: what a widget of a dashboard shows.

The list endpoints of incidents, artifacts, indicators and the audit log take
the same language in their ``q`` parameter.
"""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session as OrmSession

from .. import fields as field_registry
from .. import ioc_library as lib
from .. import query as ql
from ..core.db import get_db
from ..core.models import Artifact, AuditEntry, Incident
from ..core.security import Principal, principal
from ..query import aggregate as agg
from .settings import read_settings

router = APIRouter(prefix="/query", tags=["query"])


class QueryIn(BaseModel):
    entity: str = Field(max_length=40)
    query: str = Field(default="", max_length=ql.parser.MAX_LENGTH)
    limit: int = Field(default=50, ge=1, le=ql.MAX_PAGE)
    offset: int = Field(default=0, ge=0)


class CheckIn(BaseModel):
    entity: str = Field(max_length=40)
    query: str = Field(default="", max_length=ql.parser.MAX_LENGTH)


class AggregateIn(BaseModel):
    entity: str = Field(max_length=40)
    query: str = Field(default="", max_length=ql.parser.MAX_LENGTH - 200)
    groupBy: list[str] = Field(default_factory=list, max_length=agg.MAX_GROUPS)
    measure: str = Field(default="count", max_length=120)
    timeField: str | None = Field(default=None, max_length=60)
    timeRange: str | dict[str, str] | None = None
    compare: Literal["previous"] | None = None
    limit: int = Field(default=50, ge=1, le=agg.MAX_LIMIT)


@router.get("/schema")
def schema(
    entity: str | None = Query(None, max_length=40, description="One entity; all the caller may query when left out."),
    caller: Principal = Depends(principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """The entities and their fields: name, aliases, kind, the values a
    keyword can take and a line of description. The incidents list every
    field of the registry: one made in Settings says ``custom`` and carries
    its ``label``."""
    if entity:
        return {"entities": [ql.schema(entity, caller, db=db)]}
    return {
        "entities": [
            ql.entity_of(item.name, db).schema() for item in ql.ENTITIES.values() if caller.has(item.permission)
        ],
    }


@router.post("/check")
def check(body: CheckIn, caller: Principal = Depends(principal), db: OrmSession = Depends(get_db)) -> dict:
    """Read a query without running it: ``{ok: true, tree}``, or 422 with the
    position and the reason."""
    item = ql.entity_of(body.entity, db)
    if item.model is None:
        ql.rows(item.name, body.query, caller)
    else:
        ql.sql(item.name, body.query, caller, db=db)
    return {"ok": True, "tree": ql.to_json(ql.parse(body.query))}


def _incident_row(row: Incident) -> dict[str, Any]:
    return {
        "id": row.id,
        "name": row.name,
        "host": row.host,
        "username": row.username,
        "os": row.os,
        "ticketId": row.ticket_id,
        "severity": row.severity or None,
        "status": row.status or "open",
        "assignee": row.assignee,
        "hasMail": bool(row.has_mail),
        "createdAt": row.created_at,
        "updatedAt": row.updated_at,
        # What it holds for the fields that are not above: the columns a table of a dashboard can show.
        "fields": field_registry.stored_fields(row),
    }


def _audit_row(row: AuditEntry) -> dict[str, Any]:
    return {
        "id": row.id,
        "at": row.at,
        "actor": row.actor,
        "action": row.action,
        "target": row.target,
        "details": row.details,
        "incidentId": row.incident_id,
        "incidentName": row.incident_name,
    }


def _artifact_row(row: Artifact) -> dict[str, Any]:
    return {
        "id": row.id,
        "kind": row.kind,
        "ref": row.ref,
        "name": row.name or f"{row.ref[:16]}…",
        "verdict": row.verdict,
        "score": row.score,
        "detail": row.detail,
        "size": row.size,
        "tags": row.tags or [],
        "createdAt": row.created_at,
        "createdBy": row.created_by,
    }


_TABLES = {
    "incidents": (Incident, Incident.updated_at.desc(), _incident_row),
    "artifacts": (Artifact, Artifact.created_at.desc(), _artifact_row),
    "audit": (AuditEntry, AuditEntry.at.desc(), _audit_row),
}
# The entities with no list of their own here are given by their fields, newest first.
_NEWEST = {"runs": "started", "approvals": "asked", "tasks": "created"}


def _by_fields(db: OrmSession, item, conditions: list, body: QueryIn) -> list[dict[str, Any]]:
    specs = [spec for spec in item.fields if spec.column is not None]
    order = item.field(_NEWEST[item.name]).column.desc()
    found = db.execute(
        select(*(spec.column.label(f"c{index}") for index, spec in enumerate(specs)))
        .select_from(item.model)
        .where(*conditions)
        .order_by(order)
        .offset(body.offset)
        .limit(body.limit)
    ).all()
    return [{spec.name: value for spec, value in zip(specs, row, strict=True)} for row in found]


@router.post("/aggregate")
def aggregate(body: AggregateIn, caller: Principal = Depends(principal), db: OrmSession = Depends(get_db)) -> dict:
    """Count or measure what a query finds: ``{columns, rows, total, previous?, more, truncated,
    range}``. ``groupBy`` holds two fields at most, a date as ``field@hour|day|week|month|year``;
    ``measure`` is ``count`` or ``sum|avg|min|max|median|p90:<number field>`` or
    ``…:duration(from,to)`` in seconds; ``timeRange`` is a length of time back from now (``7d``)
    or ``{from, to}``, on ``timeField``; ``compare: "previous"`` adds the total of the period
    before. The caller needs the permission of the entity, as for ``POST /query``."""
    return agg.run(
        db,
        body.entity,
        body.query,
        caller,
        group_by=body.groupBy,
        measure=body.measure,
        time_field=body.timeField,
        time_range_=body.timeRange,
        compare=body.compare,
        limit=body.limit,
        source=lambda: lib.library(db, read_settings(db)),
    )


@router.post("")
def run(body: QueryIn, caller: Principal = Depends(principal), db: OrmSession = Depends(get_db)) -> dict:
    """Run a query: ``{entity, total, items}``, newest first (indicators: the
    worst verdict first). The caller needs the permission of the entity
    (``read``; ``audit.read`` for the audit log)."""
    item = ql.entity_of(body.entity, db)
    if item.model is None:
        keep = ql.rows(item.name, body.query, caller)
        kept = lib.select_rows([row for row in lib.library(db, read_settings(db)) if keep(row)], {})
        return {"entity": item.name, "total": len(kept), "items": kept[body.offset : body.offset + body.limit]}
    conditions = ql.sql(item.name, body.query, caller, db=db)
    ql.statement_timeout(db)
    if item.name in _NEWEST:
        total = db.scalar(select(func.count()).select_from(item.model).where(*conditions)) or 0
        return {"entity": item.name, "total": total, "items": _by_fields(db, item, conditions, body)}
    model, order, serialise = _TABLES[item.name]
    total = db.scalar(select(func.count()).select_from(model).where(*conditions)) or 0
    found = db.scalars(select(model).where(*conditions).order_by(order).offset(body.offset).limit(body.limit)).all()
    return {"entity": item.name, "total": total, "items": [serialise(row) for row in found]}

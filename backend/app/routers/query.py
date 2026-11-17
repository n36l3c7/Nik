"""The query language over the API.

- ``GET /query/schema`` lists the entities a caller may query and their
  fields: what the builder and the autocomplete of the interface are made of.
- ``POST /query`` runs a query on an entity and returns a page of it, in the
  shape the entity's own list endpoint uses.
- ``POST /query/check`` reads a query without running it.

The list endpoints of incidents, artifacts, indicators and the audit log take
the same language in their ``q`` parameter.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session as OrmSession

from .. import ioc_library as lib
from .. import query as ql
from ..core.db import get_db
from ..core.models import Artifact, AuditEntry, Incident
from ..core.security import Principal, principal
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


@router.get("/schema")
def schema(
    entity: str | None = Query(None, max_length=40, description="One entity; all the caller may query when left out."),
    caller: Principal = Depends(principal),
) -> dict:
    """The entities and their fields: name, aliases, kind, the values a
    keyword can take and a line of description."""
    if entity:
        return {"entities": [ql.schema(entity, caller)]}
    return {
        "entities": [item.schema() for item in ql.ENTITIES.values() if caller.has(item.permission)],
    }


@router.post("/check")
def check(body: CheckIn, caller: Principal = Depends(principal)) -> dict:
    """Read a query without running it: ``{ok: true, tree}``, or 422 with the
    position and the reason."""
    item = ql.entity_of(body.entity)
    if item.model is None:
        ql.rows(item.name, body.query, caller)
    else:
        ql.sql(item.name, body.query, caller)
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


@router.post("")
def run(body: QueryIn, caller: Principal = Depends(principal), db: OrmSession = Depends(get_db)) -> dict:
    """Run a query: ``{entity, total, items}``, newest first (indicators: the
    worst verdict first). The caller needs the permission of the entity
    (``read``; ``audit.read`` for the audit log)."""
    item = ql.entity_of(body.entity)
    if item.model is None:
        keep = ql.rows(item.name, body.query, caller)
        kept = lib.select_rows([row for row in lib.library(db, read_settings(db)) if keep(row)], {})
        return {"entity": item.name, "total": len(kept), "items": kept[body.offset : body.offset + body.limit]}
    conditions = ql.sql(item.name, body.query, caller)
    model, order, serialise = _TABLES[item.name]
    ql.statement_timeout(db)
    total = db.scalar(select(func.count()).select_from(model).where(*conditions)) or 0
    found = db.scalars(select(model).where(*conditions).order_by(order).offset(body.offset).limit(body.limit)).all()
    return {"entity": item.name, "total": total, "items": [serialise(row) for row in found]}

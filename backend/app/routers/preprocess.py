"""Pre-processing rules (``incidents.configure``): what is done with a fetched item before
it becomes an incident. The rules are tried in their order; ``try`` says which would decide
for a sample, and does nothing."""

from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as OrmSession

from .. import fetch, preprocess
from ..core import audit
from ..core.db import get_db
from ..core.models import Connection, PreprocessRule
from ..core.permissions import INCIDENTS_CONFIGURE
from ..core.security import Principal, require

router = APIRouter(prefix="/preprocess-rules", tags=["pre-processing"])
configure_principal = require(INCIDENTS_CONFIGURE)


class RuleIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    enabled: bool = True
    # {all | any: [{left, op, right}]} over ``incident`` and ``item``; nothing for "always".
    when: dict[str, Any] | None = None
    action: str = Field(max_length=20)
    # link_to_existing, close_duplicate: {same: ["host", …], within_hours}; run_script: {script}.
    params: dict[str, Any] = Field(default_factory=dict)


class OrderIn(BaseModel):
    ids: list[str] = Field(max_length=preprocess.RULES_MAX)


class TryIn(BaseModel):
    instanceId: str = Field(max_length=32)
    item: Any = None


def _rule(db: OrmSession, rule_id: str) -> PreprocessRule:
    row = db.get(PreprocessRule, rule_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    return row


def _listed(db: OrmSession) -> dict:
    return {
        "rules": [preprocess.out(row) for row in preprocess.every(db)],
        "actions": list(preprocess.ACTIONS),
        "same": list(preprocess.SAME),
    }


@router.get("")
def list_rules(_caller: Principal = Depends(configure_principal), db: OrmSession = Depends(get_db)) -> dict:
    """The rules in the order they are tried, with what a rule can do and the fields
    "the same incident" can be told by."""
    return _listed(db)


@router.post("", status_code=status.HTTP_201_CREATED)
def create_rule(
    body: RuleIn, caller: Principal = Depends(configure_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Add a rule after those there are."""
    try:
        row = preprocess.save(db, body.model_dump(), caller.actor)
    except preprocess.RuleError as error:
        raise HTTPException(status_code=error.status, detail=error.message) from None
    audit.record(db, caller.actor, "preprocess.create", f'Added the pre-processing rule "{row.name}"', target=row.name)
    db.commit()
    return preprocess.out(row)


@router.put("/order")
def order_rules(
    body: OrderIn, caller: Principal = Depends(configure_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Put the rules in the order of ``ids``."""
    preprocess.reorder(db, body.ids)
    audit.record(db, caller.actor, "preprocess.order", "Changed the order of the pre-processing rules")
    db.commit()
    return _listed(db)


@router.post("/try")
def try_rules(body: TryIn, _caller: Principal = Depends(configure_principal), db: OrmSession = Depends(get_db)) -> dict:
    """What would become of an item a connection fetched: the type and the fields it would have,
    and which rule would decide, without doing anything."""
    connection = db.get(Connection, body.instanceId)
    connector = fetch.connector_of(db, connection) if connection is not None else None
    if connection is None or connector is None:
        raise HTTPException(status_code=404, detail="Instance not found")
    made = fetch.candidate(db, connection, connector, body.item)
    return {
        "incident": preprocess.as_incident(made),
        "decision": preprocess.try_rules(db, body.item, made, time.time()),
    }


@router.put("/{rule_id}")
def update_rule(
    rule_id: str, body: RuleIn, caller: Principal = Depends(configure_principal), db: OrmSession = Depends(get_db)
) -> dict:
    row = _rule(db, rule_id)
    try:
        preprocess.save(db, body.model_dump(), caller.actor, row)
    except preprocess.RuleError as error:
        raise HTTPException(status_code=error.status, detail=error.message) from None
    audit.record(
        db, caller.actor, "preprocess.update", f'Changed the pre-processing rule "{row.name}"', target=row.name
    )
    db.commit()
    return preprocess.out(row)


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_rule(
    rule_id: str, caller: Principal = Depends(configure_principal), db: OrmSession = Depends(get_db)
) -> Response:
    row = _rule(db, rule_id)
    audit.record(
        db, caller.actor, "preprocess.delete", f'Deleted the pre-processing rule "{row.name}"', target=row.name
    )
    db.delete(row)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)

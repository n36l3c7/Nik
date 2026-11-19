"""Fetching (``connectors.manage``): which connections bring alerts in, and how it goes.

``GET /api/fetch`` is the status of every connection whose connector can
fetch; a connection is told to fetch or not, made to fetch now, and let go on
after it was paused. The items it fetched are listed with what became of
each, and the last one is kept as a sample for the mapper editor.
"""

from __future__ import annotations

import time

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from .. import fetch
from ..core import audit
from ..core.db import get_db
from ..core.models import Connection
from ..core.permissions import CONNECTORS_MANAGE
from ..core.security import Principal, require

router = APIRouter(prefix="/fetch", tags=["fetch"])
manager_principal = require(CONNECTORS_MANAGE)


class EnabledIn(BaseModel):
    enabled: bool


def _connection(db: OrmSession, connection_id: str) -> Connection:
    row = db.get(Connection, connection_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Instance not found")
    return row


@router.get("")
def fetch_status(_caller: Principal = Depends(manager_principal), db: OrmSession = Depends(get_db)) -> dict:
    """Every connection whose connector can fetch: whether it does, its state (``off``, ``ok``,
    ``failing``, ``paused``), when it last fetched and will next, what the last cycle found."""
    rows = [fetch.out(db, row) for row in db.scalars(select(Connection).order_by(Connection.name))]
    return {"instances": [row for row in rows if row["canFetch"]]}


@router.put("/{connection_id}")
def set_fetching(
    connection_id: str,
    body: EnabledIn,
    caller: Principal = Depends(manager_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Tell a connection to fetch, or not to. Its first cycle looks back as far as its connector says."""
    connection = _connection(db, connection_id)
    try:
        fetch.enable(db, connection, body.enabled, time.time())
    except fetch.FetchError as error:
        raise HTTPException(status_code=error.status, detail=error.message) from None
    audit.record(
        db,
        caller.actor,
        "fetch.enable" if body.enabled else "fetch.disable",
        f'"{connection.name}" {"fetches" if body.enabled else "does not fetch any more"}',
        target=connection.name,
    )
    db.commit()
    return fetch.out(db, connection)


@router.post("/{connection_id}/run")
def fetch_now(
    connection_id: str, caller: Principal = Depends(manager_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Fetch once now, whatever its interval: ``{result: {state, fetched, new, created, …}, status}``.
    The connection must be one that fetches."""
    connection = _connection(db, connection_id)
    if not connection.fetch_enabled:
        raise HTTPException(status_code=409, detail="This instance does not fetch: turn fetching on first")
    try:
        result = fetch.cycle(db, connection, time.time())
    except fetch.FetchError as error:
        raise HTTPException(status_code=error.status, detail=error.message) from None
    audit.record(db, caller.actor, "fetch.run", f'Fetched from "{connection.name}" by hand', target=connection.name)
    db.commit()
    return {"result": result, "status": fetch.out(db, db.get(Connection, connection_id))}


@router.post("/{connection_id}/resume")
def resume_fetching(
    connection_id: str, caller: Principal = Depends(manager_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Let a paused or failing connection fetch again at its next turn."""
    connection = _connection(db, connection_id)
    fetch.resume(db, connection, time.time())
    audit.record(db, caller.actor, "fetch.resume", f'Fetching from "{connection.name}" goes on', target=connection.name)
    db.commit()
    return fetch.out(db, connection)


@router.get("/{connection_id}/items")
def fetched_items(
    connection_id: str,
    outcome: str = Query("", pattern="^(|created|incomplete|dropped|linked|duplicate)$"),
    limit: int = Query(100, ge=1, le=500),
    _caller: Principal = Depends(manager_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """What the connection fetched lately, the newest first, with what became of each item."""
    _connection(db, connection_id)
    return {"items": fetch.recent(db, connection_id, limit, outcome)}


@router.get("/{connection_id}/sample")
def fetched_sample(
    connection_id: str, _caller: Principal = Depends(manager_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """The last item the connection fetched, as it came: a sample for the mapper editor."""
    connection = _connection(db, connection_id)
    return {"item": fetch.status_of(connection).get("sample")}

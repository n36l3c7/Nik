"""Saved filters over the API.

Anyone who reads Nik keeps filters of their own for the list of incidents and
chooses the one the list opens with. Sharing a filter with everyone is an
administrator's. The rows a filter finds are not here: the list asks
``GET /api/incidents?q=…`` as the person looking.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as OrmSession

from .. import saved_filters
from ..core import audit
from ..core.db import get_db
from ..core.security import Principal, admin_principal, reader_principal

router = APIRouter(prefix="/filters", tags=["saved filters"])


class FilterIn(BaseModel):
    name: str | None = Field(default=None, max_length=200)
    entity: str | None = Field(default=None, max_length=40)
    query: str | None = Field(default=None, max_length=saved_filters.QUERY_MAX)
    sort: dict[str, Any] | None = None
    columns: list[str] | None = Field(default=None, max_length=saved_filters.COLUMNS_MAX)


class SharingIn(BaseModel):
    shared: bool = False


class DefaultIn(BaseModel):
    filterId: str = Field(min_length=1, max_length=32)


def _refuse(error: saved_filters.FilterError) -> HTTPException:
    return HTTPException(status_code=error.status, detail=error.message)


def _one(db: OrmSession, filter_id: str, caller: Principal):
    try:
        return saved_filters.get(db, filter_id, caller.actor)
    except saved_filters.FilterError as error:
        raise _refuse(error) from None


@router.get("")
def list_filters(
    entity: str = Query("incidents", max_length=40, description="The list the filters are for."),
    caller: Principal = Depends(reader_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """The filters the caller sees for a list (their own, then those shared with everyone) and
    ``default``: the id of the one the list opens with for them, or null."""
    try:
        rows = saved_filters.visible(db, caller.actor, entity)
        chosen = saved_filters.default_of(db, caller.actor, entity)
    except saved_filters.FilterError as error:
        raise _refuse(error) from None
    return {"filters": [saved_filters.out(row, caller.actor) for row in rows], "default": chosen}


@router.post("", status_code=status.HTTP_201_CREATED)
def create_filter(
    body: FilterIn, caller: Principal = Depends(reader_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Keep a query under a name: ``{name, query, sort, columns}``. The query is read as the list
    reads it; one that cannot be read is answered ``422`` with the position and the reason."""
    try:
        row = saved_filters.create(db, body.model_dump(exclude_none=True), caller.actor)
    except saved_filters.FilterError as error:
        raise _refuse(error) from None
    db.commit()
    return saved_filters.out(row, caller.actor)


# Declared before the routes of one filter: "default" is not the id of one.
@router.put("/default/{entity}")
def set_default_filter(
    entity: str, body: DefaultIn, caller: Principal = Depends(reader_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Choose the filter a list opens with: one of the caller's own, or one shared with everyone."""
    try:
        row = saved_filters.set_default(db, caller.actor, entity, body.filterId)
    except saved_filters.FilterError as error:
        raise _refuse(error) from None
    db.commit()
    return {"default": row.id}


@router.delete("/default/{entity}", status_code=status.HTTP_204_NO_CONTENT)
def clear_default_filter(
    entity: str, caller: Principal = Depends(reader_principal), db: OrmSession = Depends(get_db)
) -> Response:
    """The list opens with no filter again."""
    try:
        saved_filters.clear_default(db, caller.actor, entity)
    except saved_filters.FilterError as error:
        raise _refuse(error) from None
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.put("/{filter_id}")
def update_filter(
    filter_id: str,
    body: FilterIn,
    caller: Principal = Depends(reader_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Change a filter of one's own: its name, its query, its sort, its columns. What is left out stays."""
    row = _one(db, filter_id, caller)
    try:
        saved_filters.change(db, row, body.model_dump(exclude_unset=True, exclude={"entity"}), caller.actor)
    except saved_filters.FilterError as error:
        raise _refuse(error) from None
    if row.shared:
        audit.record(db, caller.actor, "filter.update", f'Changed the shared filter "{row.name}"', target=row.id)
    db.commit()
    return saved_filters.out(row, caller.actor)


@router.delete("/{filter_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_filter(
    filter_id: str, caller: Principal = Depends(reader_principal), db: OrmSession = Depends(get_db)
) -> Response:
    """Delete a filter of one's own. Whoever had it as their default has none afterwards."""
    row = _one(db, filter_id, caller)
    name, shared = row.name, row.shared
    try:
        saved_filters.remove(db, row, caller.actor)
    except saved_filters.FilterError as error:
        raise _refuse(error) from None
    if shared:
        audit.record(db, caller.actor, "filter.delete", f'Deleted the shared filter "{name}"', target=filter_id)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.put("/{filter_id}/sharing")
def share_filter(
    filter_id: str,
    body: SharingIn,
    caller: Principal = Depends(admin_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Share a filter with everyone, or take it back: ``{shared}``. An administrator shares a filter
    of their own and takes back any that is shared. Everyone finds in it only what their own roles
    let them read."""
    row = _one(db, filter_id, caller)
    saved_filters.share(db, row, body.shared)
    what = "is shared with everyone" if row.shared else "is no longer shared"
    audit.record(db, caller.actor, "filter.share", f'The filter "{row.name}" of {row.owner} {what}', target=row.id)
    db.commit()
    return saved_filters.out(row, caller.actor)

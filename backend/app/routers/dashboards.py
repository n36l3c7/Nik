"""Dashboards over the API.

Anyone who reads Nik has dashboards of their own. Sharing one, and changing
one that is shared, needs ``dashboards.share``. The numbers of a widget are
not here: the page asks ``POST /api/query/aggregate`` as the person looking.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as OrmSession

from .. import dashboards
from ..core import audit
from ..core.db import get_db
from ..core.permissions import DASHBOARDS_SHARE
from ..core.security import Principal, reader_principal, require

router = APIRouter(prefix="/dashboards", tags=["dashboards"])
share_principal = require(DASHBOARDS_SHARE)


class DashboardIn(BaseModel):
    name: str | None = Field(default=None, max_length=120)
    description: str | None = Field(default=None, max_length=1000)
    widgets: list[dict[str, Any]] | None = Field(default=None, max_length=dashboards.WIDGETS_MAX)
    timeRange: str | None = Field(default=None, max_length=20)
    refreshSeconds: int | None = Field(default=None, ge=0, le=3600)
    filter: str | None = Field(default=None, max_length=400)
    filterEntity: str | None = Field(default=None, max_length=40)


class SharingIn(BaseModel):
    everyone: bool = False
    roles: list[str] = Field(default_factory=list, max_length=20)
    users: list[str] = Field(default_factory=list, max_length=200)


def _refuse(error: dashboards.DashboardError) -> HTTPException:
    return HTTPException(status_code=error.status, detail=error.message)


def _one(db: OrmSession, dashboard_id: str, caller: Principal):
    try:
        return dashboards.get(db, dashboard_id, caller)
    except dashboards.DashboardError as error:
        raise _refuse(error) from None


@router.get("")
def list_dashboards(caller: Principal = Depends(reader_principal), db: OrmSession = Depends(get_db)) -> dict:
    """The dashboards the caller sees, without their widgets: Nik's, their own, those shared with them."""
    return {
        "dashboards": [dashboards.out(row, caller, full=False) for row in dashboards.visible(db, caller)],
        "types": list(dashboards.TYPES),
    }


@router.post("", status_code=status.HTTP_201_CREATED)
def create_dashboard(
    body: DashboardIn, caller: Principal = Depends(reader_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Make a dashboard of one's own: ``{name, description, widgets, timeRange, refreshSeconds, filter,
    filterEntity}``. A widget is ``{id, title, type, entity, query, groupBy, measure, options, x, y, w, h}``."""
    try:
        row = dashboards.create(db, body.model_dump(exclude_none=True), caller.actor)
    except dashboards.DashboardError as error:
        raise _refuse(error) from None
    db.commit()
    return dashboards.out(row, caller)


@router.post("/import", status_code=status.HTTP_201_CREATED)
def import_dashboard(
    body: dict[str, Any], caller: Principal = Depends(reader_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Make a dashboard of one's own from an exported one."""
    try:
        row = dashboards.imported(db, body, caller.actor)
    except dashboards.DashboardError as error:
        raise _refuse(error) from None
    db.commit()
    return dashboards.out(row, caller)


@router.get("/{dashboard_id}")
def get_dashboard(
    dashboard_id: str, caller: Principal = Depends(reader_principal), db: OrmSession = Depends(get_db)
) -> dict:
    return dashboards.out(_one(db, dashboard_id, caller), caller)


@router.put("/{dashboard_id}")
def update_dashboard(
    dashboard_id: str,
    body: DashboardIn,
    caller: Principal = Depends(reader_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Change a dashboard: its owner, or whoever may share dashboards once it is shared. What is left out stays."""
    row = _one(db, dashboard_id, caller)
    try:
        dashboards.update(db, row, body.model_dump(exclude_none=True), caller)
    except dashboards.DashboardError as error:
        raise _refuse(error) from None
    if dashboards.is_shared(row):
        audit.record(db, caller.actor, "dashboard.update", f'Changed the shared dashboard "{row.name}"', target=row.id)
    db.commit()
    return dashboards.out(row, caller)


@router.delete("/{dashboard_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_dashboard(
    dashboard_id: str, caller: Principal = Depends(reader_principal), db: OrmSession = Depends(get_db)
) -> Response:
    row = _one(db, dashboard_id, caller)
    if not dashboards.may_edit(row, caller):
        detail = "A dashboard Nik ships is not deleted" if row.builtin else "This dashboard is not yours"
        raise HTTPException(status_code=403, detail=detail)
    if dashboards.is_shared(row):
        audit.record(db, caller.actor, "dashboard.delete", f'Deleted the shared dashboard "{row.name}"', target=row.id)
    db.delete(row)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.put("/{dashboard_id}/sharing")
def share_dashboard(
    dashboard_id: str,
    body: SharingIn,
    caller: Principal = Depends(share_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Say who else sees a dashboard: ``{everyone, roles, users}`` (all empty: nobody else). Each of them sees
    in its widgets only what their own roles let them read."""
    row = _one(db, dashboard_id, caller)
    try:
        dashboards.share(db, row, body.model_dump(), caller)
    except dashboards.DashboardError as error:
        raise _refuse(error) from None
    shared = row.shared_with
    who = "everyone" if shared["everyone"] else ", ".join([*shared["roles"], *shared["users"]]) or "nobody else"
    audit.record(db, caller.actor, "dashboard.share", f'The dashboard "{row.name}" is seen by {who}', target=row.id)
    db.commit()
    return dashboards.out(row, caller)


@router.post("/{dashboard_id}/duplicate", status_code=status.HTTP_201_CREATED)
def duplicate_dashboard(
    dashboard_id: str, caller: Principal = Depends(reader_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """A copy of one's own, of any dashboard one sees."""
    row = _one(db, dashboard_id, caller)
    try:
        copy = dashboards.duplicate(db, row, caller.actor)
    except dashboards.DashboardError as error:
        raise _refuse(error) from None
    db.commit()
    return dashboards.out(copy, caller)


@router.get("/{dashboard_id}/export")
def export_dashboard(
    dashboard_id: str, caller: Principal = Depends(reader_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """The dashboard as a file ``POST /api/dashboards/import`` takes: what it shows, not whose it is."""
    return dashboards.exported(_one(db, dashboard_id, caller))

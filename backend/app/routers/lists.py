"""Lists: what features and playbooks read by a name.

Reading is for whoever reads incidents (a list is what Nik's analysis
compares with); changing one is for ``lists.manage``. The watch lists of the
Indicators page are shown here too, read-only: they are changed where indicators
are. Which list a feature reads is chosen with ``PUT /api/lists/pointers``.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as OrmSession

from .. import lists
from ..core import audit
from ..core.db import get_db
from ..core.models import NamedList
from ..core.permissions import LISTS_MANAGE
from ..core.security import Principal, reader_principal, require

router = APIRouter(prefix="/lists", tags=["lists"])
manage_principal = require(LISTS_MANAGE)


class ListIn(BaseModel):
    name: str = Field(default="", max_length=50)
    label: str | None = Field(default=None, max_length=120)
    description: str | None = Field(default=None, max_length=2000)
    kind: str | None = Field(default=None, max_length=12)
    itemType: str | None = Field(default=None, max_length=16)
    writableByAutomation: bool | None = None


class ItemIn(BaseModel):
    key: str = Field(min_length=1, max_length=lists.KEY_MAX)
    value: Any = None
    note: str = Field(default="", max_length=500)
    # Seconds since the epoch after which the item is dropped; nothing for an item that stays.
    expiresAt: float | None = None


class ItemsIn(BaseModel):
    # Values, or {key, value, note, expiresAt}; for a list that is one document, use ``document``.
    entries: list[Any] | None = Field(default=None, max_length=lists.ITEMS_MAX)
    document: Any = None


class FileIn(BaseModel):
    format: str = Field(pattern="^(csv|json)$")
    text: str = Field(max_length=5_000_000)


class PointersIn(BaseModel):
    # setting → the name of the list it reads, e.g. {"iocAllowlist": "my_allowlist"}.
    pointers: dict[str, str]


def _refuse(error: lists.ListError) -> HTTPException:
    return HTTPException(status_code=error.status, detail=error.message)


def _own(db: OrmSession, name: str) -> NamedList:
    row = lists.find(db, name)
    if row is None:
        if lists.watch_list(db, name) is not None:
            raise HTTPException(status_code=409, detail="A list of the Indicators page is changed where indicators are")
        raise HTTPException(status_code=404, detail="List not found")
    return row


def _pointers(db: OrmSession) -> dict[str, Any]:
    chosen = lists.pointers_of(db)
    return {
        setting: {"list": chosen[setting], "default": name, "kind": lists.BUILTIN[name]["kind"]}
        for setting, name in lists.BY_SETTING.items()
    }


@router.get("")
def list_lists(_caller: Principal = Depends(reader_principal), db: OrmSession = Depends(get_db)) -> dict:
    """Every list, with how many items it holds and where it is used; and which list each feature reads."""
    return {"lists": lists.every(db), "pointers": _pointers(db)}


@router.post("", status_code=status.HTTP_201_CREATED)
def create_list(body: ListIn, caller: Principal = Depends(manage_principal), db: OrmSession = Depends(get_db)) -> dict:
    """Make a list: ``{name, label, description, kind, itemType, writableByAutomation}``."""
    try:
        row = lists.create(db, body.model_dump(exclude_none=True), caller.actor)
    except lists.ListError as error:
        raise _refuse(error) from None
    audit.record(db, caller.actor, "list.create", f'Created the list "{row.name}"', target=row.name)
    db.commit()
    return lists.out(db, row, with_items=True)


@router.put("/pointers")
def set_pointers(
    body: PointersIn, caller: Principal = Depends(manage_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Choose which list a feature reads. The list must exist and be of the kind the feature takes."""
    try:
        for setting, name in body.pointers.items():
            lists.point(db, setting, name)
            audit.record(db, caller.actor, "list.point", f'"{setting}" reads the list "{name}"', target=name)
    except lists.ListError as error:
        db.rollback()
        raise _refuse(error) from None
    db.commit()
    return {"pointers": _pointers(db)}


@router.get("/{name}")
def get_list(name: str, _caller: Principal = Depends(reader_principal), db: OrmSession = Depends(get_db)) -> dict:
    """A list with its items (``entries``), or its ``document`` when it is one."""
    try:
        return lists.one(db, name)
    except lists.ListError as error:
        raise _refuse(error) from None


@router.put("/{name}")
def update_list(
    name: str, body: ListIn, caller: Principal = Depends(manage_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Change the label, the description, what its items are, and whether playbooks may write to it."""
    row = _own(db, name)
    try:
        lists.update(db, row, body.model_dump(exclude_none=True, exclude={"name", "kind"}), caller.actor)
    except lists.ListError as error:
        raise _refuse(error) from None
    audit.record(db, caller.actor, "list.update", f'Changed the list "{row.name}"', target=row.name)
    db.commit()
    return lists.out(db, row, with_items=True)


@router.delete("/{name}", status_code=status.HTTP_204_NO_CONTENT)
def delete_list(name: str, caller: Principal = Depends(manage_principal), db: OrmSession = Depends(get_db)) -> Response:
    """Delete a list of yours that nothing uses."""
    row = _own(db, name)
    try:
        lists.remove(db, row)
    except lists.ListError as error:
        raise _refuse(error) from None
    audit.record(db, caller.actor, "list.delete", f'Deleted the list "{name}"', target=name)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.put("/{name}/items")
def replace_items(
    name: str, body: ItemsIn, caller: Principal = Depends(manage_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Replace everything the list holds: ``entries``, or ``document`` for a list that is one."""
    row = _own(db, name)
    try:
        count = lists.set_items(db, row, body.document if row.kind == "json" else (body.entries or []), caller.actor)
    except lists.ListError as error:
        db.rollback()
        raise _refuse(error) from None
    audit.record(db, caller.actor, "list.set", f'Set the list "{row.name}": {count} items', target=row.name)
    db.commit()
    return lists.out(db, row, with_items=True)


@router.post("/{name}/items", status_code=status.HTTP_201_CREATED)
def add_item(
    name: str, body: ItemIn, caller: Principal = Depends(manage_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Add an item, or change the one with that key."""
    row = _own(db, name)
    try:
        lists.add_item(db, row, body.key, body.value, caller.actor, note=body.note, expires_at=body.expiresAt)
    except lists.ListError as error:
        raise _refuse(error) from None
    audit.record(db, caller.actor, "list.add", f'Added "{body.key[:80]}" to the list "{row.name}"', target=row.name)
    db.commit()
    return lists.out(db, row, with_items=True)


@router.delete("/{name}/items")
def remove_item(
    name: str,
    key: str = Query(min_length=1, max_length=lists.KEY_MAX),
    caller: Principal = Depends(manage_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Remove the item with that key (``404`` when the list does not hold it)."""
    row = _own(db, name)
    if not lists.remove_item(db, row, key, caller.actor):
        raise HTTPException(status_code=404, detail="The list does not hold this item")
    audit.record(db, caller.actor, "list.remove", f'Removed "{key[:80]}" from the list "{row.name}"', target=row.name)
    db.commit()
    return lists.out(db, row, with_items=True)


@router.get("/{name}/export")
def export_list(
    name: str,
    fmt: str = Query("json", alias="format", pattern="^(csv|json)$"),
    _caller: Principal = Depends(reader_principal),
    db: OrmSession = Depends(get_db),
) -> Response:
    """The list as a file: JSON (everything) or CSV (its items as rows)."""
    try:
        text, media = lists.export(db, name, fmt)
    except lists.ListError as error:
        raise _refuse(error) from None
    extension = "json" if media.endswith("json") else "csv"
    return Response(
        content=text,
        media_type=media,
        headers={"Content-Disposition": f'attachment; filename="{name}.{extension}"'},
    )


@router.post("/{name}/import")
def import_list(
    name: str, body: FileIn, caller: Principal = Depends(manage_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Replace what the list holds with what a CSV or JSON file holds."""
    row = _own(db, name)
    try:
        count = lists.set_items(db, row, lists.parse_file(row, body.text, body.format), caller.actor)
    except lists.ListError as error:
        db.rollback()
        raise _refuse(error) from None
    audit.record(db, caller.actor, "list.import", f'Imported {count} items into the list "{row.name}"', target=row.name)
    db.commit()
    return lists.out(db, row, with_items=True)

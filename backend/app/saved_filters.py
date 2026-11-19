"""Saved filters: a query of a list kept under a name.

A filter is what was on screen when it was saved: the query, the order of the
rows and the columns. It belongs to whoever saved it. An administrator may
share one with everyone, and then everyone sees it and may choose it, while
only its owner changes it. Each person has one default at most for a list:
the filter the list opens with.

The query is read here as the list will read it, so a filter that is saved
is one that can be asked. Nothing here runs it: the list asks its own
endpoint as the person looking, so a shared filter never shows anyone what
their roles cannot read.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import delete, func, or_, select, update
from sqlalchemy.orm import Session as OrmSession

from . import query as ql
from .core.models import SavedFilter, SavedFilterDefault
from .core.security import now_iso

# The lists a filter can be saved for, by the name the query language gives them.
ENTITIES = ("incidents",)
NAME_MAX = 80
QUERY_MAX = 2000  # what the ``q`` of a list takes
COLUMNS_MAX = 30
COLUMN_MAX = 60
PER_OWNER_MAX = 100


class FilterError(ValueError):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.message = message
        self.status = status


def _entity(raw: Any) -> str:
    name = str(raw or "incidents").strip().lower()
    if name not in ENTITIES:
        raise FilterError("A filter is saved for one of: " + ", ".join(ENTITIES))
    return name


def _name(raw: Any) -> str:
    name = " ".join(str(raw or "").split())[:NAME_MAX]
    if not name:
        raise FilterError("A filter needs a name")
    return name


def _query(entity: str, raw: Any) -> str:
    """The query as it is kept. One that cannot be read raises ``QueryError``, which the API
    answers with the position and the reason, as the list itself would."""
    text = str(raw or "").strip()
    if len(text) > QUERY_MAX:
        raise FilterError(f"The query is too long ({QUERY_MAX} characters at most)")
    ql.sql(entity, text)
    return text


def _sort(raw: Any) -> dict[str, str] | None:
    if raw in (None, "", {}):
        return None
    if not isinstance(raw, dict) or not isinstance(raw.get("key"), str) or not raw["key"].strip():
        raise FilterError("sort is {key, dir}: a column and asc or desc")
    direction = raw.get("dir", "asc")
    if direction not in ("asc", "desc"):
        raise FilterError("The direction of a sort is asc or desc")
    return {"key": raw["key"].strip()[:COLUMN_MAX], "dir": direction}


def _columns(raw: Any) -> list[str]:
    if raw in (None, ""):
        return []
    if not isinstance(raw, list) or not all(isinstance(item, str) for item in raw):
        raise FilterError("columns is a list of the names of columns")
    kept: list[str] = []
    for item in raw:
        name = item.strip()[:COLUMN_MAX]
        if name and name not in kept:
            kept.append(name)
    if len(kept) > COLUMNS_MAX:
        raise FilterError(f"A filter keeps {COLUMNS_MAX} columns at most")
    return kept


def _taken(db: OrmSession, owner: str, entity: str, name: str, but: str | None = None) -> bool:
    found = db.scalars(
        select(SavedFilter.id).where(
            SavedFilter.owner == owner, SavedFilter.entity == entity, func.lower(SavedFilter.name) == name.lower()
        )
    ).all()
    return any(filter_id != but for filter_id in found)


def out(row: SavedFilter, actor: str) -> dict[str, Any]:
    return {
        "id": row.id,
        "name": row.name,
        "entity": row.entity,
        "query": row.query,
        "sort": row.sort or None,
        "columns": list(row.columns or []),
        "shared": bool(row.shared),
        "owner": row.owner,
        "mine": row.owner == actor,
        "createdAt": row.created_at,
        "updatedAt": row.updated_at,
    }


def visible(db: OrmSession, actor: str, entity: str = "incidents") -> list[SavedFilter]:
    """The filters of a list a person sees: their own first, then those shared with everyone; by name."""
    rows = db.scalars(
        select(SavedFilter).where(
            SavedFilter.entity == _entity(entity), or_(SavedFilter.owner == actor, SavedFilter.shared.is_(True))
        )
    ).all()
    return sorted(rows, key=lambda row: (row.owner != actor, row.name.lower(), row.id))


def get(db: OrmSession, filter_id: str, actor: str) -> SavedFilter:
    row = db.get(SavedFilter, filter_id)
    if row is None or (row.owner != actor and not row.shared):
        raise FilterError("Filter not found", 404)  # one that is not yours does not exist for you
    return row


def _own(row: SavedFilter, actor: str) -> None:
    if row.owner != actor:
        raise FilterError(f"This filter is {row.owner}'s: save it under a name of your own to change it", 403)


def create(db: OrmSession, body: dict[str, Any], actor: str) -> SavedFilter:
    entity = _entity(body.get("entity"))
    name = _name(body.get("name"))
    if _taken(db, actor, entity, name):
        raise FilterError("You have a filter with this name already", 409)
    held = db.scalar(select(func.count()).select_from(SavedFilter).where(SavedFilter.owner == actor)) or 0
    if held >= PER_OWNER_MAX:
        raise FilterError(f"An account keeps {PER_OWNER_MAX} filters at most: delete one first", 409)
    now = now_iso()
    row = SavedFilter(
        id=uuid.uuid4().hex,
        owner=actor[:200],
        name=name,
        entity=entity,
        query=_query(entity, body.get("query")),
        sort=_sort(body.get("sort")),
        columns=_columns(body.get("columns")),
        shared=False,
        created_at=now,
        updated_at=now,
    )
    db.add(row)
    return row


def change(db: OrmSession, row: SavedFilter, body: dict[str, Any], actor: str) -> SavedFilter:
    """Change what the body names; what it leaves out stays. Only the owner changes a filter."""
    _own(row, actor)
    if "name" in body:
        name = _name(body["name"])
        if _taken(db, row.owner, row.entity, name, but=row.id):
            raise FilterError("You have a filter with this name already", 409)
        row.name = name
    if "query" in body:
        row.query = _query(row.entity, body["query"])
    if "sort" in body:
        row.sort = _sort(body["sort"])
    if "columns" in body:
        row.columns = _columns(body["columns"])
    row.updated_at = now_iso()
    return row


def remove(db: OrmSession, row: SavedFilter, actor: str) -> None:
    """Delete a filter of one's own. Whoever had it as their default has none afterwards."""
    _own(row, actor)
    db.execute(delete(SavedFilterDefault).where(SavedFilterDefault.filter_id == row.id))
    db.delete(row)


def share(db: OrmSession, row: SavedFilter, shared: bool) -> SavedFilter:
    """Show a filter to everyone, or to its owner alone again. Taking it back clears the default
    of whoever else had chosen it: they no longer see it."""
    row.shared = bool(shared)
    row.updated_at = now_iso()
    if not row.shared:
        db.execute(
            delete(SavedFilterDefault).where(
                SavedFilterDefault.filter_id == row.id, SavedFilterDefault.username != row.owner
            )
        )
    return row


def default_of(db: OrmSession, actor: str, entity: str = "incidents") -> str | None:
    """The id of the filter a list opens with for this person, or None."""
    held = db.get(SavedFilterDefault, (actor, _entity(entity)))
    if held is None:
        return None
    row = db.get(SavedFilter, held.filter_id)
    return row.id if row is not None and (row.owner == actor or row.shared) else None


def set_default(db: OrmSession, actor: str, entity: str, filter_id: str) -> SavedFilter:
    row = get(db, filter_id, actor)
    if row.entity != _entity(entity):
        raise FilterError(f"This filter is for {row.entity}")
    held = db.get(SavedFilterDefault, (actor, row.entity))
    if held is None:
        db.add(SavedFilterDefault(username=actor[:200], entity=row.entity, filter_id=row.id))
    else:
        held.filter_id = row.id
    return row


def clear_default(db: OrmSession, actor: str, entity: str) -> None:
    db.execute(
        delete(SavedFilterDefault).where(
            SavedFilterDefault.username == actor, SavedFilterDefault.entity == _entity(entity)
        )
    )


def renamed(db: OrmSession, old: str, new: str) -> None:
    """An account was renamed: its filters and its default follow it."""
    db.execute(update(SavedFilter).where(SavedFilter.owner == old).values(owner=new))
    db.execute(update(SavedFilterDefault).where(SavedFilterDefault.username == old).values(username=new))

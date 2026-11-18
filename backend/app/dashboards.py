"""Dashboards: widgets on a grid, each a question asked of what Nik holds.

A dashboard is a row: who owns it, who else sees it, and its widgets. A widget
says what it shows (``type``), of what (``entity`` and ``query``, in the query
language), how it is grouped and measured, and where it sits on a grid of 12
columns. Nothing here runs a query: the page asks ``/api/query/aggregate`` for
each widget **as the person looking**, so a dashboard shared with someone
never shows them what their roles cannot read.

A dashboard is personal until it is shared, which needs ``dashboards.share``.
The ones Nik ships are ``builtin``: seen by everyone, changed by nobody
(duplicate one to make it yours).
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from . import query as ql
from .core.models import Dashboard
from .core.permissions import DASHBOARDS_SHARE, ROLES
from .core.security import now_iso
from .query import aggregate as agg

COLUMNS = 12
HEIGHT_MAX = 12
Y_MAX = 2000
WIDGETS_MAX = 40
OPTIONS_MAX = 8000  # characters of a widget's options, as JSON
TEXT_MAX = 5000
TABLE_COLUMNS_MAX = 12
TABLE_ROWS_MAX = 100

# What a widget is. Those in ASKING ask a query; the others show something of their own.
TYPES = (
    "number",
    "trend",
    "bar",
    "stacked_bar",
    "pie",
    "top",
    "table",
    "duration",
    "gauge",
    "text",
    "storage",
    "fetch",
)
ASKING = frozenset(TYPES) - {"text", "storage", "fetch"}
# How many groups a type takes: (fewest, most).
GROUPS = {
    "number": (0, 0),
    "gauge": (0, 0),
    "table": (0, 0),
    "duration": (0, 1),
    "trend": (1, 2),
    "bar": (1, 1),
    "pie": (1, 1),
    "top": (1, 1),
    "stacked_bar": (2, 2),
}
FORMATS = ("number", "duration", "bytes", "percent")
DEFAULT_SIZE = {"number": (3, 2), "gauge": (3, 2), "duration": (3, 2), "text": (4, 2), "table": (6, 4)}
_ID = re.compile(r"[A-Za-z0-9_-]{1,40}")
_NAME_COPY = re.compile(r"^(.*) \((\d+)\)$")


class DashboardError(ValueError):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.message = message
        self.status = status


# --------------------------------------------------------------------------- #
# Widgets                                                                     #
# --------------------------------------------------------------------------- #
def _whole(value: Any, low: int, high: int, default: int) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return default
    return max(low, min(high, int(value)))


def _asked(what: str, raw: dict, out: dict) -> None:
    """The question of a widget, checked as the query language checks it (for nobody in particular:
    who may ask is decided when someone looks)."""
    try:
        entity = ql.entity_of(str(raw.get("entity") or ""))
        query = str(raw.get("query") or "").strip()
        if len(query) > ql.parser.MAX_LENGTH - 400:
            raise DashboardError(f"{what}: the query is too long")
        if entity.model is None:
            ql.rows(entity.name, query)
        else:
            ql.sql(entity.name, query)
        groups = raw.get("groupBy") or []
        if not isinstance(groups, list):
            raise DashboardError(f"{what}: groupBy is a list of fields")
        fewest, most = GROUPS[out["type"]]
        if not fewest <= len(groups) <= most:
            wanted = "no group" if most == 0 else f"{fewest} group" + ("s" if fewest != 1 else "")
            if fewest != most and most:
                wanted = f"{fewest} to {most} groups"
            raise DashboardError(f"{what}: a widget of this type takes {wanted}")
        found = [agg.group_of(entity, str(text)) for text in groups]
        if out["type"] == "trend" and not found[0].bucket:
            raise DashboardError(f"{what}: a trend is over a date, grouped by a stretch of time (created@day)")
        measure = agg.measure_of(entity, str(raw.get("measure") or "count"))
        if out["type"] == "table":
            measure = agg.Measure()
    except ql.QueryError as error:
        raise DashboardError(f"{what}: {error.message}") from None
    out.update(entity=entity.name, query=query, groupBy=[group.label for group in found], measure=measure.label)


def _options(what: str, raw: Any, out: dict) -> dict[str, Any]:
    given = raw if isinstance(raw, dict) else {}
    kind = out["type"]
    kept: dict[str, Any] = {}
    if kind == "text":
        kept["text"] = str(given.get("text") or "")[:TEXT_MAX]
        return kept
    if kind not in ASKING:
        return kept
    entity = ql.entity_of(out["entity"])
    if given.get("timeField"):
        spec = entity.field(str(given["timeField"]))
        if spec is None or spec.kind != "date":
            raise DashboardError(f"{what}: the time field is a date of {entity.label.lower()}")
        kept["timeField"] = spec.name
    for flag in ("ignoreRange", "ignoreFilter", "compare"):
        if given.get(flag):
            kept[flag] = True
    if given.get("format") in FORMATS:
        kept["format"] = given["format"]
    if kind == "gauge":
        target = given.get("target")
        if isinstance(target, bool) or not isinstance(target, (int, float)) or target <= 0:
            raise DashboardError(f"{what}: a gauge needs a target above zero")
        kept["target"] = target
        if given.get("lowerIsBetter"):
            kept["lowerIsBetter"] = True
    if kind == "table":
        columns = given.get("columns") or []
        if not isinstance(columns, list) or len(columns) > TABLE_COLUMNS_MAX:
            raise DashboardError(f"{what}: a table shows {TABLE_COLUMNS_MAX} columns at most")
        names = []
        for name in columns:
            spec = entity.field(str(name))
            if spec is None:
                raise DashboardError(f'{what}: "{name}" is not a field of {entity.label.lower()}')
            if spec.name not in names:
                names.append(spec.name)
        kept["columns"] = names
    if kind in ("table", "top", "bar", "pie", "stacked_bar"):
        most = TABLE_ROWS_MAX if kind == "table" else 50
        kept["limit"] = _whole(given.get("limit"), 1, most, 10)
    return kept


def clean_widget(raw: Any, index: int) -> dict[str, Any]:
    what = f"Widget {index}"
    if not isinstance(raw, dict):
        raise DashboardError(f"{what} is not a widget")
    kind = str(raw.get("type") or "")
    if kind not in TYPES:
        raise DashboardError(f"{what}: its type is one of {', '.join(TYPES)}")
    identifier = str(raw.get("id") or "")
    out: dict[str, Any] = {
        "id": identifier if _ID.fullmatch(identifier) else uuid.uuid4().hex[:12],
        "title": str(raw.get("title") or "").strip()[:120],
        "type": kind,
    }
    title = out["title"] or kind
    what = f'Widget {index} ("{title}")'
    if kind in ASKING:
        _asked(what, raw, out)
    out["options"] = _options(what, raw.get("options"), out)
    if len(json.dumps(out["options"])) > OPTIONS_MAX:
        raise DashboardError(f"{what}: its options are too large")
    width, height = DEFAULT_SIZE.get(kind, (6, 3))
    out["w"] = _whole(raw.get("w"), 1, COLUMNS, width)
    out["h"] = _whole(raw.get("h"), 1, HEIGHT_MAX, height)
    out["x"] = _whole(raw.get("x"), 0, COLUMNS - out["w"], 0)
    out["y"] = _whole(raw.get("y"), 0, Y_MAX, Y_MAX)
    return out


def compact(widgets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """No two widgets on the same cell and no hole above one: in reading order, each is moved up
    to the highest row where it fits."""
    placed: list[dict[str, Any]] = []
    for widget in sorted(widgets, key=lambda item: (item["y"], item["x"])):
        y = 0
        while True:
            under = [
                other["y"] + other["h"]
                for other in placed
                if other["x"] < widget["x"] + widget["w"]
                and widget["x"] < other["x"] + other["w"]
                and other["y"] < y + widget["h"]
                and y < other["y"] + other["h"]
            ]
            if not under:
                break
            y = max(under)
        placed.append({**widget, "y": y})
    return placed


def clean_widgets(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list) or len(raw) > WIDGETS_MAX:
        raise DashboardError(f"A dashboard holds {WIDGETS_MAX} widgets at most")
    widgets = [clean_widget(item, index) for index, item in enumerate(raw, start=1)]
    seen: set[str] = set()
    for widget in widgets:
        if widget["id"] in seen:
            widget["id"] = uuid.uuid4().hex[:12]
        seen.add(widget["id"])
    return compact(widgets)


# --------------------------------------------------------------------------- #
# The dashboard                                                               #
# --------------------------------------------------------------------------- #
def _time_range(value: Any) -> str:
    text = str(value or "30d").strip().lower()
    try:
        agg.time_range(text, datetime.now(timezone.utc))
    except ql.QueryError as error:
        raise DashboardError(error.message) from None
    return text


def _refresh(value: Any) -> int:
    seconds = _whole(value, 0, 3600, 0)
    return 0 if seconds == 0 else max(30, seconds)


def _filter(body: dict) -> tuple[str, str]:
    """The filter of the whole dashboard: a query, and the entity it is written for."""
    query = str(body.get("filter") or "").strip()
    try:
        entity = ql.entity_of(str(body.get("filterEntity") or "incidents"))
        if len(query) > 400:
            raise DashboardError("The filter of a dashboard is 400 characters at most")
        if entity.model is None:
            ql.rows(entity.name, query)
        else:
            ql.sql(entity.name, query)
    except ql.QueryError as error:
        raise DashboardError(f"The filter: {error.message}") from None
    return query, entity.name


def clean_sharing(raw: Any) -> dict[str, Any]:
    given = raw if isinstance(raw, dict) else {}
    roles = sorted({str(role) for role in given.get("roles") or [] if str(role) in ROLES})
    users = sorted({str(user).strip()[:200] for user in given.get("users") or [] if str(user).strip()})[:200]
    return {"everyone": bool(given.get("everyone")), "roles": roles, "users": users}


def is_shared(row: Dashboard) -> bool:
    shared = row.shared_with or {}
    return bool(shared.get("everyone") or shared.get("roles") or shared.get("users"))


def sees(row: Dashboard, principal: Any) -> bool:
    if row.builtin or row.owner == principal.actor:
        return True
    shared = row.shared_with or {}
    return bool(
        shared.get("everyone")
        or set(shared.get("roles") or []) & set(principal.roles)
        or principal.actor in (shared.get("users") or [])
    )


def may_edit(row: Dashboard, principal: Any) -> bool:
    """Its owner; and, once it is shared, whoever may share dashboards. Never one Nik ships."""
    if row.builtin:
        return False
    return row.owner == principal.actor or (is_shared(row) and principal.has(DASHBOARDS_SHARE))


def out(row: Dashboard, principal: Any = None, *, full: bool = True) -> dict[str, Any]:
    widgets = row.layout if isinstance(row.layout, list) else []
    data: dict[str, Any] = {
        "id": row.id,
        "name": row.name,
        "description": row.description,
        "owner": row.owner,
        "builtin": bool(row.builtin),
        "sharedWith": clean_sharing(row.shared_with),
        "shared": is_shared(row),
        "timeRange": row.time_range,
        "refreshSeconds": row.refresh_seconds,
        "widgetCount": len(widgets),
        "updatedAt": row.updated_at,
        "updatedBy": row.updated_by,
    }
    if principal is not None:
        data["canEdit"] = may_edit(row, principal)
        data["canShare"] = not row.builtin and principal.has(DASHBOARDS_SHARE)
    if full:
        data.update(widgets=widgets, filter=row.filter_query, filterEntity=row.filter_entity)
    return data


def visible(db: OrmSession, principal: Any) -> list[Dashboard]:
    """What the caller sees: Nik's first, then theirs, then what others share with them; by name."""
    rows = [row for row in db.scalars(select(Dashboard)).all() if sees(row, principal)]
    return sorted(rows, key=lambda row: (not row.builtin, row.owner != principal.actor, row.name.lower(), row.id))


def get(db: OrmSession, dashboard_id: str, principal: Any) -> Dashboard:
    row = db.get(Dashboard, dashboard_id)
    if row is None or not sees(row, principal):
        raise DashboardError("Dashboard not found", 404)  # one that is not yours does not exist for you
    return row


def _apply(row: Dashboard, body: dict, actor: str) -> None:
    if "name" in body or not row.name:
        name = str(body.get("name") or "").strip()[:120]
        if not name:
            raise DashboardError("A dashboard needs a name")
        row.name = name
    if "description" in body:
        row.description = str(body.get("description") or "")[:1000]
    if "widgets" in body:
        row.layout = clean_widgets(body.get("widgets"))
    if "timeRange" in body:
        row.time_range = _time_range(body.get("timeRange"))
    if "refreshSeconds" in body:
        row.refresh_seconds = _refresh(body.get("refreshSeconds"))
    if "filter" in body or "filterEntity" in body:
        merged = {"filter": row.filter_query, "filterEntity": row.filter_entity, **body}
        row.filter_query, row.filter_entity = _filter(merged)
    row.updated_at, row.updated_by = now_iso(), actor[:200]


def create(db: OrmSession, body: dict, actor: str, *, builtin: bool = False) -> Dashboard:
    row = Dashboard(
        id=uuid.uuid4().hex,
        name="",
        description="",
        owner="nik" if builtin else actor[:200],
        shared_with={},
        layout=[],
        time_range="30d",
        refresh_seconds=0,
        filter_query="",
        filter_entity="incidents",
        builtin=builtin,
        created_at=now_iso(),
    )
    _apply(row, body, actor)
    db.add(row)
    return row


def update(db: OrmSession, row: Dashboard, body: dict, principal: Any) -> Dashboard:
    if not may_edit(row, principal):
        raise DashboardError(
            "A dashboard Nik ships is not changed: duplicate it" if row.builtin else "This dashboard is not yours", 403
        )
    _apply(row, body, principal.actor)
    return row


def share(db: OrmSession, row: Dashboard, sharing: Any, principal: Any) -> Dashboard:
    if row.builtin:
        raise DashboardError("A dashboard Nik ships is seen by everyone already", 409)
    row.shared_with = clean_sharing(sharing)
    row.updated_at, row.updated_by = now_iso(), principal.actor[:200]
    return row


def free_name(db: OrmSession, owner: str, wanted: str) -> str:
    """The name, or the name with a number, that this owner does not have yet."""
    taken = {name.lower() for name in db.scalars(select(Dashboard.name).where(Dashboard.owner == owner)).all()}
    if wanted.lower() not in taken:
        return wanted
    found = _NAME_COPY.match(wanted)
    stem = found.group(1) if found else wanted
    number = int(found.group(2)) + 1 if found else 2
    while f"{stem} ({number})".lower() in taken:
        number += 1
    return f"{stem[:110]} ({number})"


def exported(row: Dashboard) -> dict[str, Any]:
    """A dashboard as a file: what it shows, not whose it is nor who sees it."""
    return {
        "nik": "dashboard",
        "version": 1,
        "name": row.name,
        "description": row.description,
        "timeRange": row.time_range,
        "refreshSeconds": row.refresh_seconds,
        "filter": row.filter_query,
        "filterEntity": row.filter_entity,
        "widgets": row.layout if isinstance(row.layout, list) else [],
    }


def imported(db: OrmSession, data: Any, actor: str) -> Dashboard:
    if not isinstance(data, dict) or data.get("nik") != "dashboard":
        raise DashboardError("This is not a dashboard exported from Nik")
    body = {key: data.get(key) for key in ("description", "timeRange", "refreshSeconds", "filter", "filterEntity")}
    body = {key: value for key, value in body.items() if value is not None}
    name = str(data.get("name") or "").strip()[:110] or "Dashboard"
    return create(db, {**body, "name": free_name(db, actor[:200], name), "widgets": data.get("widgets") or []}, actor)


def duplicate(db: OrmSession, row: Dashboard, actor: str) -> Dashboard:
    return imported(db, exported(row), actor)

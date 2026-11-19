"""What two widgets of an incident page ask the server (6.2).

**Linked incidents.** Two things link an incident to another today:

- the field ``related_incidents``, which holds ids or numbers: written when an
  incident comes in and is closed as the duplicate of another
  (``preprocess.close_as_duplicate``), and by anyone who edits it. It links
  both ways: the incident that is named sees the one that names it.
- an indicator both hold (``ioc_index``), unless the allowlist says the value
  is a well-known one, which would link everything to everything.

Those named come first, then those that share the most indicators: ten at most.

**A chart of a dashboard, narrowed to the incident.** The widget of a page
names a widget of a dashboard and ONE field; the query of that widget gets
``<field>:"<what this incident holds>"`` added, so the chart counts what this
incident shares with the others. The field is one the query language knows
for the entity the chart counts (``query.entities``), a custom field of the
registry included; the dashboard is read as the person looking, so one that
is not shared with them is not found.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import String, cast, select
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm import aliased

from . import dashboards
from . import fields as registry
from . import query as ql
from .core.models import Connection, Incident, IncidentType, IocEntry
from .iocs import Allowlist
from .query.incident_fields import PREFIX as FIELD_PREFIX

LINKED_MAX = 10
SHOWN_INDICATORS = 3


class ChartError(ValueError):
    """Why a chart cannot be drawn for an incident, as a sentence."""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.message = message
        self.status = status


# --------------------------------------------------------------------------- #
# Linked incidents                                                            #
# --------------------------------------------------------------------------- #
def _named(db: OrmSession, incident: Incident) -> list[Incident]:
    """The incidents ``related_incidents`` links to this one, in either direction."""
    held = (incident.fields or {}).get("related_incidents") if isinstance(incident.fields, dict) else None
    ids, numbers = set(), set()
    for item in held if isinstance(held, list) else []:
        text = str(item).strip()
        if text.lstrip("#").isdigit():
            numbers.add(int(text.lstrip("#")))
        elif text:
            ids.add(text)
    found: dict[str, Incident] = {}
    if ids:
        found.update({row.id: row for row in db.scalars(select(Incident).where(Incident.id.in_(ids)))})
    if numbers:
        found.update({row.id: row for row in db.scalars(select(Incident).where(Incident.number.in_(numbers)))})
    # The other direction: an incident whose own field names this one. The JSON is searched as
    # text for the id (a number alone is too short to search for), then read to be sure.
    like = f"%{incident.id}%"
    for row in db.scalars(select(Incident).where(cast(Incident.fields, String).like(like)).limit(200)):
        named = (row.fields or {}).get("related_incidents") if isinstance(row.fields, dict) else None
        if isinstance(named, list) and incident.id in [str(item).strip() for item in named]:
            found[row.id] = row
    found.pop(incident.id, None)
    return sorted(found.values(), key=lambda row: row.updated_at or "", reverse=True)


def _sharing(db: OrmSession, incident: Incident, allowlist: Allowlist) -> dict[str, list[tuple[str, str]]]:
    """incident id → the indicators it holds that this one holds too (well-known values left out)."""
    other = aliased(IocEntry)
    rows = db.execute(
        select(other.incident_id, IocEntry.type, IocEntry.value)
        .join(
            other,
            (other.type == IocEntry.type)
            & (other.value == IocEntry.value)
            & (other.incident_id != IocEntry.incident_id),
        )
        .where(IocEntry.incident_id == incident.id)
    ).all()
    shared: dict[str, list[tuple[str, str]]] = {}
    verdicts: dict[tuple[str, str], bool] = {}
    for incident_id, kind, value in rows:
        if (kind, value) not in verdicts:
            verdicts[(kind, value)] = allowlist.matches(kind, value)
        if not verdicts[(kind, value)]:
            shared.setdefault(incident_id, []).append((kind, value))
    return shared


def _row(row: Incident, types: dict[str, str]) -> dict[str, Any]:
    return {
        "id": row.id,
        "number": row.number,
        "name": row.name,
        "status": row.status or "open",
        "severity": row.severity or "",
        # An incident that was given no type is Unclassified, whether that type was listed yet or not.
        "type": types.get(row.type_id or registry.UNCLASSIFIED, "" if row.type_id else "Unclassified"),
    }


def linked(db: OrmSession, incident: Incident, allowlist: Allowlist, limit: int = LINKED_MAX) -> dict[str, Any]:
    """The incidents linked to this one: ``{incidents: [...], total}``. Each says why it is there:
    ``related`` (the field names it) and ``shared``, the number of indicators both hold, with the
    first of them."""
    types = dict(db.execute(select(IncidentType.id, IncidentType.name)).all())
    named = _named(db, incident)
    shared = _sharing(db, incident, allowlist)
    found = []
    for row in named:
        both = sorted(shared.pop(row.id, []))
        found.append({**_row(row, types), "related": True, "shared": len(both), "indicators": both})
    if shared and len(found) < limit:
        most = sorted(shared.items(), key=lambda item: (-len(item[1]), item[0]))[: limit - len(found)]
        rows = {row.id: row for row in db.scalars(select(Incident).where(Incident.id.in_([key for key, _ in most])))}
        for incident_id, both in most:
            if incident_id in rows:
                found.append(
                    {
                        **_row(rows[incident_id], types),
                        "related": False,
                        "shared": len(both),
                        "indicators": sorted(both),
                    }
                )
    total = len(named) + len(shared)
    for item in found:
        item["indicators"] = [{"type": kind, "value": value} for kind, value in item["indicators"][:SHOWN_INDICATORS]]
    return {"incidents": found[:limit], "total": total}


# --------------------------------------------------------------------------- #
# A chart of a dashboard, narrowed to the incident                            #
# --------------------------------------------------------------------------- #
def _written(value: Any) -> str:
    """A value as a literal of the query language: quoted, so that nothing in it is read as a wildcard."""
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


def condition(field: str, value: Any) -> str:
    """``field:"value"``, or ``field IN ("a", "b")`` for a field of the incident that holds several."""
    if isinstance(value, (list, tuple)):
        values = [item for item in value if item not in (None, "")]
        if len(values) == 1:
            return f"{field}:{_written(values[0])}"
        return f"{field} IN (" + ", ".join(_written(item) for item in values) + ")"
    return f"{field}:{_written(value)}"


def narrowed(query: str | None, field: str, value: Any) -> str:
    """The query of a widget with the condition of the incident added: both must hold."""
    own = str(query or "").strip()
    added = condition(field, value)
    return f"({own}) ({added})" if own else added


def value_of(db: OrmSession, incident: Incident, name: str) -> Any:
    """What the incident holds for a field of the query language. Most are fields of the registry
    under the same name; a few are written differently there, or are a name where the registry
    keeps an id."""
    held = registry.read(db, incident)
    lowered = name.lower()
    if lowered in ("incident", "incidentid", "uuid", "id"):
        return incident.id
    if lowered in ("number", "no"):
        return incident.number
    if lowered == "type":
        # The query language reads the type an incident was given: one that was given none has none there.
        kind = db.get(IncidentType, incident.type_id) if incident.type_id else None
        return kind.name if kind is not None else None
    if lowered == "source":
        row = db.get(Connection, incident.source_connection_id) if incident.source_connection_id else None
        return row.name if row is not None else None
    aliases = {
        "user": "username",
        "assignee": "owner",
        "ticketid": "ticket",
        "closereason": "close_reason",
        "createdat": "created",
        "updatedat": "modified",
        "updated": "modified",
    }
    # A custom field whose name the language had taken is written field.<name> there.
    plain = name[len(FIELD_PREFIX) :] if lowered.startswith(FIELD_PREFIX) else name
    value = held.get(aliases.get(lowered, plain), held.get(lowered))
    if isinstance(value, dict):
        # An indicator is asked by its value; a timer or a JSON value is nothing a chart is narrowed by.
        value = value.get("value") if isinstance(value.get("value"), str) else None
    if isinstance(value, list):
        # A table is rows, not values: only what a tags field holds is asked one by one.
        value = [item for item in value if isinstance(item, (str, int, float)) and not isinstance(item, bool)]
    if isinstance(value, bool):
        return "true" if value else "false"
    return value


def chart(db: OrmSession, incident: Incident, dashboard_id: str, widget_id: str, field: str, caller: Any) -> dict:
    """The widget of a dashboard as the page of an incident draws it: ``{widget, board, field,
    value}`` with the query of the widget narrowed, or ``{empty: true}`` with no widget when the
    incident holds nothing for the field: a chart of everything would say nothing of this incident.
    Raises ``ChartError`` with what is wrong: the dashboard or the widget is gone or not shared
    with the caller, the widget asks no query, the field is not one of what it counts."""
    try:
        board = dashboards.get(db, dashboard_id, caller)
    except dashboards.DashboardError:
        raise ChartError("The dashboard of this chart is gone, or is not shared with you", 404) from None
    widgets = board.layout if isinstance(board.layout, list) else []
    widget = next((item for item in widgets if isinstance(item, dict) and item.get("id") == widget_id), None)
    if widget is None:
        raise ChartError(f"{board.name} no longer has this widget", 404)
    if widget.get("type") not in dashboards.ASKING:
        raise ChartError("This widget asks no query: there is nothing to narrow to the incident")
    try:
        entity = ql.entity_of(str(widget.get("entity") or ""), db)
    except ql.QueryError as error:
        raise ChartError(error.message) from None
    spec = entity.field(field) if field else None
    if spec is None:
        raise ChartError(
            f'"{field}" is not a field of {entity.label.lower()} in the query language: choose one in the settings '
            "of the widget"
            if field
            else "Choose the field this chart is narrowed by, in the settings of the widget"
        )
    value = value_of(db, incident, spec.name)
    shown = {
        "board": {
            "id": board.id,
            "name": board.name,
            "filter": board.filter_query,
            "filterEntity": board.filter_entity,
            "timeRange": board.time_range,
        },
        "field": spec.name,
        "title": widget.get("title") or "",
    }
    if value in (None, "", [], {}):
        return {**shown, "empty": True, "value": None, "widget": None}
    return {
        **shown,
        "empty": False,
        "value": value,
        "widget": {**widget, "query": narrowed(widget.get("query"), spec.name, value)},
    }

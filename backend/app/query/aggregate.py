"""Counting and measuring what a query finds: the numbers behind a dashboard.

    aggregate.run(db, "incidents", "status:open", caller, group_by=["severity"])
    aggregate.run(db, "incidents", "", caller, group_by=["created@day"], time_field="created", time_range="30d")
    aggregate.run(db, "incidents", "status:closed", caller, measure="median:duration(created,closed)")

The query is compiled as everywhere else, so the answer never holds what the
caller may not read. Groups are fields of the entity (two at most); a date is
grouped by a stretch of time, ``field@hour|day|week|month|year``. A measure is
``count``, or ``sum``, ``avg``, ``min``, ``max``, ``median``, ``p90`` of a
number field or of the time between two dates, ``duration(from,to)`` in
seconds (``to`` may be ``now``).

A plain count is grouped by the database. Everything else is worked out here
from the values of the rows that match, ``MAX_ROWS`` of them at most: past
that the answer says ``truncated``.
"""

from __future__ import annotations

import math
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, null, select
from sqlalchemy.orm import Session as OrmSession

from . import dates
from .fields import Entity, FieldSpec, suggest
from .parser import QueryError

MAX_ROWS = 100_000
MAX_GROUPS = 2
MAX_LIMIT = 500
MAX_FILLED = 800  # buckets of time an answer is filled to, so a line has no holes
FUNCTIONS = ("count", "sum", "avg", "min", "max", "median", "p90")
BUCKETS = {"hour": 13, "day": 10, "week": 10, "month": 7, "year": 4}  # how much of an ISO time names the stretch
_RANGE = re.compile(r"(\d{1,4})\s*(h|d|w|m|y)")
_HOURS = {"h": 1, "d": 24, "w": 24 * 7, "m": 24 * 30, "y": 24 * 365}
_MEASURE = re.compile(r"([a-z0-9]+)(?::(.+))?")
_DURATION = re.compile(r"duration\(\s*([A-Za-z_.]+)\s*,\s*([A-Za-z_.]+)\s*\)")


def _bad(message: str, suggestion: str | None = None) -> QueryError:
    return QueryError("bad_aggregate", 0, message, suggestion)


@dataclass(frozen=True)
class Group:
    spec: FieldSpec
    bucket: str | None = None

    @property
    def label(self) -> str:
        return f"{self.spec.name}@{self.bucket}" if self.bucket else self.spec.name


@dataclass(frozen=True)
class Measure:
    fn: str = "count"
    spec: FieldSpec | None = None  # the number, or where a duration starts
    until: FieldSpec | None = None  # where a duration ends (None with ``to_now``)
    to_now: bool = False

    @property
    def is_duration(self) -> bool:
        return self.until is not None or self.to_now

    @property
    def label(self) -> str:
        if self.fn == "count":
            return "count"
        if self.is_duration:
            return f"{self.fn}:duration({self.spec.name},{self.until.name if self.until else 'now'})"
        return f"{self.fn}:{self.spec.name}"


def _field(entity: Entity, name: str) -> FieldSpec:
    spec = entity.field(name.strip())
    if spec is None:
        hint = suggest(name, entity.names())
        raise _bad(f'"{name}" is not a field of {entity.label.lower()}', hint)
    if entity.model is not None and spec.column is None:
        raise _bad(f'"{spec.name}" can be searched, not counted or measured')
    if entity.model is None and spec.getter is None:
        raise _bad(f'"{spec.name}" can be searched, not counted or measured')
    return spec


def group_of(entity: Entity, text: str) -> Group:
    name, _, bucket = str(text).partition("@")
    spec = _field(entity, name)
    bucket = bucket.strip().lower()
    if spec.kind == "date":
        bucket = bucket or "day"
        if bucket not in BUCKETS:
            raise _bad("A date is grouped by hour, day, week, month or year")
        return Group(spec, bucket)
    if bucket:
        raise _bad(f'"{spec.name}" is not a date: only a date is grouped by a stretch of time')
    return Group(spec)


def measure_of(entity: Entity, text: str | None) -> Measure:
    found = _MEASURE.fullmatch(str(text or "count").strip())
    fn = found.group(1) if found else ""
    if fn not in FUNCTIONS:
        raise _bad("A measure is count, or sum, avg, min, max, median or p90 of a field: avg:score")
    what = (found.group(2) or "").strip()
    if fn == "count":
        if what:
            raise _bad("count takes no field: it counts what the query finds")
        return Measure()
    if not what:
        raise _bad(f"{fn} needs a field: {fn}:score, or {fn}:duration(created,closed)")
    between = _DURATION.fullmatch(what)
    if between is not None:
        start = _field(entity, between.group(1))
        to_now = between.group(2).lower() == "now"
        end = None if to_now else _field(entity, between.group(2))
        for spec in (start, end):
            if spec is not None and spec.kind != "date":
                raise _bad(f'"{spec.name}" is not a date: a duration is the time between two dates')
        return Measure(fn, start, end, to_now)
    spec = _field(entity, what)
    if spec.kind != "number":
        raise _bad(f'"{spec.name}" is not a number: {fn} takes a number, or duration(from,to)')
    return Measure(fn, spec)


# --------------------------------------------------------------------------- #
# Time                                                                        #
# --------------------------------------------------------------------------- #
def _moment(value: Any) -> datetime | None:
    if isinstance(value, bool) or value in (None, ""):
        return None
    try:
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(float(value), timezone.utc)
        moment = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00").replace(" ", "T", 1))
    except (ValueError, OverflowError, OSError):
        return None
    return moment if moment.tzinfo is not None else moment.replace(tzinfo=timezone.utc)


def time_range(value: Any, now: datetime) -> tuple[datetime, datetime] | None:
    """``7d``, ``24h``, ``12w``, ``6m``, ``1y`` back from now, or ``{"from", "to"}``; None for all time."""
    if value in (None, "", "all"):
        return None
    if isinstance(value, dict):
        start, end = _moment(value.get("from")), _moment(value.get("to")) or now
        if start is None or end <= start:
            raise _bad("A time range has a start before its end")
        return start, end
    found = _RANGE.fullmatch(str(value).strip().lower())
    if found is None or int(found.group(1)) == 0:
        raise _bad("A time range is a length of time back from now: 24h, 7d, 12w, 6m, 1y")
    return now - timedelta(hours=int(found.group(1)) * _HOURS[found.group(2)]), now


def _within(query: str | None, field: str, start: datetime, end: datetime, *, to_the_end: bool = True) -> str:
    """The query, and the field inside the range: from the second it starts in to the second it ends
    in (what happened a moment ago counts), or up to it for a period that another one follows."""
    low, high = dates._stamp(start), dates._stamp(end)
    held = f"({query.strip()}) " if (query or "").strip() else ""
    return f'{held}{field}:>="{low}" {field}:{"<=" if to_the_end else "<"}"{high}"'


def bucket_of(value: Any, bucket: str) -> str:
    """The stretch of time a moment falls in, as text that sorts: 2026-11-16, 2026-11, 2026-11-16T08."""
    moment = _moment(value)
    if moment is None:
        return ""
    moment = moment.astimezone(timezone.utc)
    if bucket == "week":
        moment -= timedelta(days=moment.weekday())
    return moment.strftime("%Y-%m-%dT%H:%M:%S")[: BUCKETS[bucket]]


def _buckets(start: datetime, end: datetime, bucket: str) -> list[str]:
    """Every stretch of time from start to end, so that one with nothing in it is a zero and not a hole."""
    out: list[str] = []
    at = start.astimezone(timezone.utc)
    last = bucket_of(end - timedelta(seconds=1), bucket)
    while len(out) < MAX_FILLED:
        key = bucket_of(at, bucket)
        if not out or out[-1] != key:
            out.append(key)
        if key >= last:
            break
        at += timedelta(hours=1) if bucket == "hour" else timedelta(days=1)
    return out


# --------------------------------------------------------------------------- #
# Values                                                                      #
# --------------------------------------------------------------------------- #
def _keys(group: Group, value: Any) -> list[str]:
    """What a value is counted under: itself, each of its tags, the stretch of time it falls in."""
    if group.bucket:
        return [bucket_of(value, group.bucket)]
    if group.spec.kind == "tags":
        tags = [str(tag) for tag in value] if isinstance(value, (list, tuple)) else []
        return tags or [""]
    if isinstance(value, bool):
        return ["true" if value else "false"]
    if group.spec.kind == "bool":
        return ["true" if value else "false"]
    if value is None:
        return [""]
    if isinstance(value, float) and value.is_integer():
        return [str(int(value))]
    return [str(value)]


def _number(measure: Measure, first: Any, second: Any, now: datetime) -> float | None:
    if measure.is_duration:
        start = _moment(first)
        end = now if measure.to_now else _moment(second)
        if start is None or end is None or end < start:
            return None
        return (end - start).total_seconds()
    if isinstance(first, bool) or first is None:
        return None
    try:
        number = float(first)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def _reduce(fn: str, values: list[float], count: int) -> float | int | None:
    if fn == "count":
        return count
    if not values:
        return None
    if fn == "sum":
        return round(sum(values), 3)
    if fn == "avg":
        return round(sum(values) / len(values), 3)
    if fn == "min":
        return min(values)
    if fn == "max":
        return max(values)
    ordered = sorted(values)
    # The value at the rank, between the two it falls between.
    rank = (len(ordered) - 1) * (0.5 if fn == "median" else 0.9)
    low = math.floor(rank)
    high = min(low + 1, len(ordered) - 1)
    return round(ordered[low] + (ordered[high] - ordered[low]) * (rank - low), 3)


# --------------------------------------------------------------------------- #
# Running                                                                     #
# --------------------------------------------------------------------------- #
@dataclass
class _Found:
    groups: dict[tuple, tuple[int, list[float]]]
    count: int
    values: list[float]
    truncated: bool = False


def _counted(db: OrmSession, entity: Entity, conditions: list, groups: list[Group]) -> _Found:
    """A plain count, grouped by the database."""
    columns = [
        func.substr(group.spec.column, 1, BUCKETS[group.bucket]) if group.bucket else group.spec.column
        for group in groups
    ]
    found: dict[tuple, tuple[int, list[float]]] = {}
    total = 0
    for *raw, count in db.execute(select(*columns, func.count()).where(*conditions).group_by(*columns)).all():
        key = tuple(
            (str(value or "") if group.bucket else _keys(group, value)[0])
            for group, value in zip(groups, raw, strict=True)
        )
        held = found.get(key)
        found[key] = ((held[0] if held else 0) + int(count), [])
        total += int(count)
    return _Found(found, total, [])


def _worked(rows: Iterable[tuple], groups: list[Group], measure: Measure, now: datetime) -> _Found:
    """Groups and values worked out from the rows: ``(group values…, first, second)`` each."""
    out = _Found({}, 0, [])
    for row in rows:
        if out.count >= MAX_ROWS:
            out.truncated = True
            break
        out.count += 1
        number = None if measure.fn == "count" else _number(measure, row[-2], row[-1], now)
        if number is not None:
            out.values.append(number)
        keys: list[tuple] = [()]
        for index, group in enumerate(groups):
            keys = [(*key, part) for key in keys for part in _keys(group, row[index])]
        for key in keys:
            held = out.groups.get(key)
            if held is None:
                held = out.groups[key] = (0, [])
            out.groups[key] = (held[0] + 1, held[1])
            if number is not None:
                held[1].append(number)
    return out


def _find(
    db: OrmSession,
    entity: Entity,
    query: str | None,
    principal: Any,
    groups: list[Group],
    measure: Measure,
    now: datetime,
    source: Callable[[], Iterable[dict]] | None,
) -> _Found:
    from . import rows as row_filter
    from . import sql as conditions_of
    from . import statement_timeout

    if entity.model is None:
        keep = row_filter(entity.name, query, principal, now=now)
        first = measure.spec.getter if measure.spec is not None else (lambda _row: None)
        second = measure.until.getter if measure.until is not None else (lambda _row: None)
        held = (
            (*(group.spec.getter(row) for group in groups), first(row), second(row))
            for row in (source() if source is not None else ())
            if keep(row)
        )
        return _worked(held, groups, measure, now)
    conditions = conditions_of(entity.name, query, principal, now=now)
    statement_timeout(db)
    plain = all(group.spec.kind != "tags" and group.bucket != "week" for group in groups)
    if measure.fn == "count" and plain:
        return _counted(db, entity, conditions, groups)
    columns = [group.spec.column for group in groups]
    columns.append(measure.spec.column if measure.spec is not None else null().label("first"))
    columns.append(measure.until.column if measure.until is not None else null().label("second"))
    rows = db.execute(select(*columns).select_from(entity.model).where(*conditions).limit(MAX_ROWS + 1)).all()
    return _worked(rows, groups, measure, now)


def run(
    db: OrmSession,
    name: str,
    query: str | None,
    principal: Any = None,
    *,
    group_by: Iterable[str] = (),
    measure: str | None = None,
    time_field: str | None = None,
    time_range_: Any = None,
    compare: str | None = None,
    limit: int = 50,
    now: datetime | None = None,
    source: Callable[[], Iterable[dict]] | None = None,
) -> dict[str, Any]:
    """``{columns, rows, total, previous?, more, truncated, range}``: a row is its group values, then the measure."""
    from . import _allowed, entity_of

    entity = entity_of(name)
    _allowed(entity, principal)
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).replace(microsecond=0)
    groups = [group_of(entity, text) for text in group_by]
    if len(groups) > MAX_GROUPS:
        raise _bad(f"A widget groups by {MAX_GROUPS} fields at most")
    if len({group.label for group in groups}) != len(groups):
        raise _bad("The same field twice is one group")
    what = measure_of(entity, measure)
    limit = max(1, min(int(limit or 50), MAX_LIMIT))
    span = time_range(time_range_, now)
    stamp = None
    if span is not None:
        stamp = _field(entity, time_field or "")
        if stamp.kind != "date":
            raise _bad(f'"{stamp.name}" is not a date: a time range needs a date field')
    elif compare:
        raise _bad("A comparison with the period before needs a time range")
    if compare not in (None, "", "previous"):
        raise _bad('"compare" is "previous" or nothing')

    asked = _within(query, stamp.name, *span) if span is not None else query
    found = _find(db, entity, asked, principal, groups, what, now, source)

    rows = [[*key, _reduce(what.fn, values, count)] for key, (count, values) in found.groups.items()]
    more = 0
    timed = bool(groups) and groups[0].bucket is not None
    if timed:
        if len(groups) == 1 and span is not None and stamp is not None and groups[0].spec.name == stamp.name:
            have = {row[0] for row in rows}
            empty = 0 if what.fn in ("count", "sum") else None
            rows += [[key, empty] for key in _buckets(*span, groups[0].bucket) if key not in have]
        rows.sort(key=lambda row: tuple(str(part) for part in row[:-1]))
    elif groups:
        ranks = {word: index for index, word in enumerate(groups[0].spec.values)}
        if groups[0].spec.kind == "ordered":
            rows.sort(key=lambda row: (ranks.get(row[0], -1), *(str(part) for part in row[1:-1])), reverse=True)
        else:
            rows.sort(key=lambda row: (-(row[-1] or 0), *(str(part) for part in row[:-1])))
        if len(rows) > limit:
            more, rows = len(rows) - limit, rows[:limit]
    out: dict[str, Any] = {
        "entity": entity.name,
        "columns": [
            *({"name": group.spec.name, "kind": group.spec.kind, "bucket": group.bucket} for group in groups),
            {"name": what.label, "kind": "measure", "bucket": None},
        ],
        "rows": rows if groups else [],
        "total": _reduce(what.fn, found.values, found.count),
        "more": more,
        "truncated": found.truncated,
        "range": {"from": dates._stamp(span[0]) + "Z", "to": dates._stamp(span[1]) + "Z"} if span else None,
    }
    if compare == "previous" and span is not None and stamp is not None:
        before = (span[0] - (span[1] - span[0]), span[0])
        earlier = _find(
            db, entity, _within(query, stamp.name, *before, to_the_end=False), principal, [], what, now, source
        )
        out["previous"] = {
            "total": _reduce(what.fn, earlier.values, earlier.count),
            "range": {"from": dates._stamp(before[0]) + "Z", "to": dates._stamp(before[1]) + "Z"},
        }
    return out

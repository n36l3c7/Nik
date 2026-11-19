"""What a field of an entity is, and what a condition on it means.

A condition has the same meaning wherever the entity lives: in a table
(``sql``: SQLAlchemy expressions with bound parameters, never SQL text) or in
rows assembled in Python (``test``: the indicator library). Both are built
here, side by side, so they cannot drift apart.

Kinds of field::

    text      contains the value (case-insensitive); wildcards anchor it
    keyword   equals the value (case-insensitive); wildcards allowed
    ordered   a keyword with a rank: severity:>=high
    number    =, !, >, >=, <, <=, [a TO b]
    date      a span of time (dates.py)
    bool      true / false (yes / no)
    tags      a list of strings: holds the value

``field:""`` is an empty field and ``field:*`` one that holds something, for
every kind.
"""

from __future__ import annotations

import difflib
import json
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import String, and_, cast, false, func, not_, or_, true

from . import dates
from .parser import ANY, QueryError, Value, Wild

MAX_WILDCARDS = 8
_TRUE = {"true", "yes", "1", "on"}
_FALSE = {"false", "no", "0", "off"}


# --------------------------------------------------------------------------- #
# Patterns                                                                    #
# --------------------------------------------------------------------------- #
def like_pattern(value: Value, *, contains: bool) -> str:
    """The LIKE pattern of a value, with ``\\`` as the escape character: what
    the user typed is matched as text, only their ``*`` and ``?`` are wildcards."""
    out = []
    for part in value.parts:
        if isinstance(part, Wild):
            out.append("%" if part.kind == ANY else "_")
        else:
            out.append(part.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_"))
    pattern = "".join(out)
    return f"%{pattern}%" if contains and not value.wildcard else pattern


def _glob(parts: tuple, text: str) -> bool:
    """Whether ``text`` matches the literal parts and wildcards, whole. A plain
    loop with one point to go back to: no regular expression is built from
    what the user typed."""
    tokens: list = []
    for part in parts:
        if isinstance(part, Wild):
            tokens.append(part)
        else:
            tokens.extend(part)
    t = p = 0
    star = mark = -1
    while t < len(text):
        if p < len(tokens) and (tokens[p] == text[t] or (isinstance(tokens[p], Wild) and tokens[p].kind != ANY)):
            t += 1
            p += 1
        elif p < len(tokens) and isinstance(tokens[p], Wild):
            star, mark = p, t
            p += 1
        elif star >= 0:
            p = star + 1
            mark += 1
            t = mark
        else:
            return False
    while p < len(tokens) and isinstance(tokens[p], Wild) and tokens[p].kind == ANY:
        p += 1
    return p == len(tokens)


def text_matches(value: Value, text: str, *, contains: bool) -> bool:
    """The Python twin of ``like_pattern`` (case-insensitive)."""
    haystack = str(text or "").casefold()
    if not value.wildcard:
        needle = value.text.casefold()
        return needle in haystack if contains else needle == haystack
    parts = tuple(part.casefold() if isinstance(part, str) else part for part in value.parts)
    return _glob(parts, haystack)


# --------------------------------------------------------------------------- #
# Fields                                                                      #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class FieldSpec:
    """One field of an entity.

    ``column`` is its SQL expression (table entities), ``getter`` reads it
    from a row (row entities). ``sql`` / ``test`` replace the built-in meaning
    for a field that is not a plain column (an artifact being linked, say).
    """

    name: str
    kind: str  # text | keyword | ordered | number | date | bool | tags
    description: str = ""
    aliases: tuple[str, ...] = ()
    column: Any = None
    getter: Callable[[dict], Any] | None = None
    values: tuple[str, ...] = ()  # what a keyword can be (also the rank order of an ordered field)
    nullable: bool = False
    sql: Callable[[str, Value, "Context"], Any] | None = None
    test: Callable[[str, Value, "Context"], Callable[[dict], bool]] | None = None
    label: str = ""  # what the registry calls it, for a field that comes from there
    custom: bool = False  # made in Settings, not one Nik always had


@dataclass(frozen=True)
class Entity:
    name: str
    label: str
    permission: str
    fields: tuple[FieldSpec, ...]
    text_fields: tuple[str, ...]
    model: Any = None  # the table (None for an entity assembled in rows)
    # Conditions every query on the entity carries: what is never part of it.
    base: tuple = ()
    _index: dict = field(default_factory=dict, compare=False)

    def __post_init__(self):
        for spec in self.fields:
            for name in (spec.name, *spec.aliases):
                self._index[name.lower()] = spec

    def field(self, name: str) -> FieldSpec | None:
        return self._index.get(name.lower())

    def names(self) -> list[str]:
        return sorted(self._index)

    def schema(self) -> dict:
        return {
            "entity": self.name,
            "label": self.label,
            "textFields": list(self.text_fields),
            "fields": [
                {
                    "name": spec.name,
                    "aliases": list(spec.aliases),
                    "kind": spec.kind,
                    "values": list(spec.values),
                    "description": spec.description,
                    "label": spec.label,
                    "custom": spec.custom,
                }
                for spec in self.fields
            ],
        }


@dataclass(frozen=True)
class Context:
    """What a compilation knows: who asks, and what time it is."""

    principal: Any = None
    now: datetime | None = None


def _bad(code: str, position: int, message: str, suggestion: str | None = None) -> QueryError:
    return QueryError(code, position, message, suggestion)


def suggest(word: str, candidates: Iterable[str]) -> str | None:
    found = difflib.get_close_matches(word.lower(), [c.lower() for c in candidates], n=1, cutoff=0.6)
    return found[0] if found else None


def _check_wildcards(value: Value, position: int) -> None:
    if sum(1 for part in value.parts if isinstance(part, Wild)) > MAX_WILDCARDS:
        raise _bad("too_many_wildcards", position, f"A value holds at most {MAX_WILDCARDS} wildcards")


def _number(value: Value, position: int) -> float:
    try:
        number = float(value.text)
    except ValueError:
        number = float("nan")
    if number != number or number in (float("inf"), float("-inf")):
        raise _bad("bad_value", position, "A number is expected here")
    return int(number) if number == int(number) else number


def _boolean(value: Value, position: int) -> bool:
    word = value.text.strip().lower()
    if word in _TRUE:
        return True
    if word in _FALSE:
        return False
    raise _bad("bad_value", position, "true or false is expected here")


def _span(value: Value, position: int, ctx: Context) -> tuple[str, str]:
    found = dates.span(value.text, ctx.now)
    if found is None:
        raise _bad(
            "bad_value",
            position,
            'A date is expected here: 2026-11-10, today, now-7d or "7 days ago"',
        )
    start, end = found
    # An instant ("now-7d") is its second: "after it" starts at the next one.
    return (start, _next_second(start)) if start == end else found


def _next_second(stamp: str) -> str:
    moment = datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%S") + timedelta(seconds=1)
    return moment.strftime("%Y-%m-%dT%H:%M:%S")


def _is_instant(value: Value, ctx: Context) -> bool:
    found = dates.span(value.text, ctx.now)
    return found is not None and found[0] == found[1]


def _day(stamp: str) -> tuple[str, str]:
    """The calendar day an instant falls in."""
    start = stamp[:10] + "T00:00:00"
    end = dates.span(stamp[:10])
    return start, end[1] if end else start


def _keyword_value(spec: FieldSpec, value: Value, position: int) -> str:
    """The value of a keyword field, checked against what it can be (the choices of a field of
    the registry are written as their author wrote them: case does not matter here either)."""
    word = value.text.lower()
    if spec.values and not value.wildcard and word not in {known.lower() for known in spec.values}:
        hint = suggest(word, spec.values)
        raise _bad(
            "bad_value",
            position,
            f'"{spec.name}" is one of: {", ".join(spec.values)}',
            hint,
        )
    return word


# --------------------------------------------------------------------------- #
# A condition as SQL                                                          #
# --------------------------------------------------------------------------- #
def _text_column(spec: FieldSpec):
    return func.coalesce(spec.column, "") if spec.nullable else spec.column


def _tags_text(spec: FieldSpec):
    # A JSON list read as its text: ["a", "b"]. Portable (SQLite, PostgreSQL).
    return func.lower(cast(spec.column, String))


def _tag_like(value: Value) -> str:
    inner = like_pattern(value, contains=False).lower()
    # The value between the quotes of one item; a quote typed by the user cannot close it.
    return '%"' + inner.replace('"', '\\\\"') + '"%'


def _as_json_writes(value: Value) -> Value:
    """The value with each character outside ASCII as the escape JSON may write it with (u and its number)."""
    parts = tuple(
        part
        if isinstance(part, Wild)
        else "".join(ch if ord(ch) < 128 else json.dumps(ch)[1:-1] for ch in part.lower())
        for part in value.parts
    )
    return Value(text=value.text, quoted=value.quoted, parts=parts)


def _tags_match(spec: FieldSpec, value: Value):
    """One item of the list is the value. The list is searched as the JSON text it is kept as,
    and that text holds a character outside ASCII either as itself or as its escape, by the
    database and by who wrote it: both writings are looked for."""
    text = _tags_text(spec)
    plain, escaped = _tag_like(value), _tag_like(_as_json_writes(value))
    match = text.like(plain, escape="\\")
    return match if escaped == plain else or_(match, text.like(escaped, escape="\\"))


def sql_condition(spec: FieldSpec, op: str, value: Value, position: int, ctx: Context):
    """The SQLAlchemy expression of ``field op value``."""
    if spec.sql is not None:
        return spec.sql(op, value, ctx)
    _check_wildcards(value, position)
    kind = spec.kind
    column = spec.column

    # Empty and "holds something", for every kind.
    if value.is_empty or value.is_any:
        if op not in ("=", "!"):
            raise _bad("bad_operator", position, 'An empty field is asked with field:"", a filled one with field:*')
        if kind == "tags":
            # No list at all (SQL NULL or JSON null) or a list with nothing in it.
            empty = or_(column.is_(None), func.replace(cast(column, String), " ", "").in_(("[]", "null")))
        elif kind in ("number", "bool"):
            empty = column.is_(None)
        else:
            empty = func.coalesce(column, "") == ""
        wants_empty = value.is_empty == (op == "=")
        return empty if wants_empty else not_(empty)

    if kind in ("text", "keyword", "ordered", "tags") and op in (">", ">=", "<", "<=") and kind != "ordered":
        raise _bad("bad_operator", position, f'"{spec.name}" is compared with field:value or !field:value only')

    if kind == "text":
        match = func.lower(_text_column(spec)).like(like_pattern(value, contains=True).lower(), escape="\\")
        return match if op == "=" else not_(match)

    if kind == "keyword":
        word = _keyword_value(spec, value, position)
        target = func.lower(_text_column(spec))
        match = (
            target.like(like_pattern(value, contains=False).lower(), escape="\\") if value.wildcard else target == word
        )
        return match if op == "=" else not_(match)

    if kind == "ordered":
        word = _keyword_value(spec, value, position)
        target = func.lower(_text_column(spec))
        if op in ("=", "!"):
            match = (
                target.like(like_pattern(value, contains=False).lower(), escape="\\")
                if value.wildcard
                else target == word
            )
            return match if op == "=" else not_(match)
        if value.wildcard:
            raise _bad("bad_value", position, "A comparison needs one value, without wildcards")
        rank = spec.values.index(word)
        kept = [
            name
            for index, name in enumerate(spec.values)
            if (op == ">" and index > rank)
            or (op == ">=" and index >= rank)
            or (op == "<" and index < rank)
            or (op == "<=" and index <= rank)
        ]
        return target.in_(kept) if kept else false()

    if kind == "number":
        number = _number(value, position)
        return {
            "=": column == number,
            "!": or_(column != number, column.is_(None)),
            ">": column > number,
            ">=": column >= number,
            "<": column < number,
            "<=": column <= number,
        }[op]

    if kind == "date":
        start, end = _span(value, position, ctx)
        target = _text_column(spec)
        if op in ("=", "!"):
            if _is_instant(value, ctx):
                start, end = _day(start)
            match = and_(target >= start, target < end)
            return match if op == "=" else not_(match)
        return {
            ">": target >= end,
            ">=": target >= start,
            "<": and_(target < start, target != ""),
            "<=": and_(target < end, target != ""),
        }[op]

    if kind == "bool":
        if op not in ("=", "!"):
            raise _bad("bad_operator", position, f'"{spec.name}" is true or false')
        wanted = _boolean(value, position) == (op == "=")
        return column.is_(True) if wanted else or_(column.is_(False), column.is_(None))

    if kind == "tags":
        match = _tags_match(spec, value)
        return match if op == "=" else or_(not_(match), column.is_(None))

    raise _bad("bad_operator", position, "This field cannot be searched")


def sql_range(spec: FieldSpec, low: Value | None, high: Value | None, position: int, ctx: Context):
    if spec.kind not in ("number", "date", "ordered") or spec.sql is not None:
        raise _bad("bad_range", position, f'"{spec.name}" does not take a range')
    parts = []
    if low is not None:
        parts.append(sql_condition(spec, ">=", low, position, ctx))
    if high is not None:
        parts.append(sql_condition(spec, "<=", high, position, ctx))
    return and_(*parts) if parts else true()


def sql_text(entity: Entity, value: Value, position: int):
    """A value on its own: in any of the entity's text fields."""
    _check_wildcards(value, position)
    if value.is_empty:
        return true()
    conditions = []
    for name in entity.text_fields:
        spec = entity.field(name)
        if spec.kind == "tags":
            contains = Value(text=value.text, quoted=value.quoted, parts=(Wild(ANY), *value.parts, Wild(ANY)))
            conditions.append(_tags_match(spec, contains))
        else:
            pattern = like_pattern(value, contains=True).lower()
            conditions.append(func.lower(_text_column(spec)).like(pattern, escape="\\"))
    return or_(*conditions)


# --------------------------------------------------------------------------- #
# A condition on a row                                                        #
# --------------------------------------------------------------------------- #
def _is_empty(found: Any) -> bool:
    return found is None or found == "" or found == [] or found == ()


def row_condition(spec: FieldSpec, op: str, value: Value, position: int, ctx: Context) -> Callable[[dict], bool]:
    """A predicate over a row with the meaning of ``sql_condition``."""
    if spec.test is not None:
        return spec.test(op, value, ctx)
    _check_wildcards(value, position)
    kind = spec.kind
    get = spec.getter

    if value.is_empty or value.is_any:
        if op not in ("=", "!"):
            raise _bad("bad_operator", position, 'An empty field is asked with field:"", a filled one with field:*')
        wants_empty = value.is_empty == (op == "=")
        return lambda row: _is_empty(get(row)) == wants_empty

    if kind in ("text", "keyword", "tags") and op in (">", ">=", "<", "<="):
        raise _bad("bad_operator", position, f'"{spec.name}" is compared with field:value or !field:value only')

    if kind == "text":
        return lambda row: text_matches(value, get(row), contains=True) == (op == "=")

    if kind == "keyword":
        _keyword_value(spec, value, position)
        return lambda row: text_matches(value, get(row), contains=False) == (op == "=")

    if kind == "ordered":
        word = _keyword_value(spec, value, position)
        if op in ("=", "!"):
            return lambda row: text_matches(value, get(row), contains=False) == (op == "=")
        if value.wildcard:
            raise _bad("bad_value", position, "A comparison needs one value, without wildcards")
        rank = spec.values.index(word)
        ranks = {name: index for index, name in enumerate(spec.values)}

        def compare(row: dict) -> bool:
            found = ranks.get(str(get(row) or "").lower())
            if found is None:
                return False
            return {">": found > rank, ">=": found >= rank, "<": found < rank, "<=": found <= rank}[op]

        return compare

    if kind == "number":
        number = _number(value, position)

        def compare_number(row: dict) -> bool:
            found = get(row)
            if found is None:
                return op == "!"
            return {
                "=": found == number,
                "!": found != number,
                ">": found > number,
                ">=": found >= number,
                "<": found < number,
                "<=": found <= number,
            }[op]

        return compare_number

    if kind == "date":
        start, end = _span(value, position, ctx)
        if op in ("=", "!") and _is_instant(value, ctx):
            start, end = _day(start)

        def compare_date(row: dict) -> bool:
            found = str(get(row) or "")
            if op in ("=", "!"):
                return (bool(found) and start <= found < end) == (op == "=")
            if not found:
                return False
            return {">": found >= end, ">=": found >= start, "<": found < start, "<=": found < end}[op]

        return compare_date

    if kind == "bool":
        if op not in ("=", "!"):
            raise _bad("bad_operator", position, f'"{spec.name}" is true or false')
        wanted = _boolean(value, position) == (op == "=")
        return lambda row: bool(get(row)) == wanted

    if kind == "tags":
        return lambda row: any(text_matches(value, item, contains=False) for item in (get(row) or [])) == (op == "=")

    raise _bad("bad_operator", position, "This field cannot be searched")


def row_range(spec: FieldSpec, low: Value | None, high: Value | None, position: int, ctx: Context):
    if spec.kind not in ("number", "date", "ordered") or spec.test is not None:
        raise _bad("bad_range", position, f'"{spec.name}" does not take a range')
    tests = []
    if low is not None:
        tests.append(row_condition(spec, ">=", low, position, ctx))
    if high is not None:
        tests.append(row_condition(spec, "<=", high, position, ctx))
    return lambda row: all(test(row) for test in tests)


def row_text(entity: Entity, value: Value, position: int) -> Callable[[dict], bool]:
    _check_wildcards(value, position)
    if value.is_empty:
        return lambda row: True
    specs = [entity.field(name) for name in entity.text_fields]

    def found(row: dict) -> bool:
        for spec in specs:
            held = spec.getter(row)
            items = held if isinstance(held, (list, tuple)) else [held]
            if any(text_matches(value, item, contains=True) for item in items):
                return True
        return False

    return found

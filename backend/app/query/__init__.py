"""One query language over what Nik holds.

    from app import query
    conditions = query.sql("incidents", "status:open severity:>=high", caller)
    keep = query.rows("indicators", "verdict:>=suspicious -tag:test", caller)

``sql`` gives SQLAlchemy conditions for an entity that is a table, ``rows`` a
predicate for an entity assembled in Python. Both check that the caller may
query the entity: the permission is part of the compilation, not something
each caller of this module has to remember.

A query that cannot be read or compiled raises ``QueryError`` (a position and
a fixed sentence); the API answers it with 422 through ``query_error_response``.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Any

from sqlalchemy import and_, not_, or_, text, true
from sqlalchemy.orm import Session as OrmSession

from . import fields as _fields
from . import incident_fields as _incident_fields
from .entities import ENTITIES
from .fields import Context, Entity, suggest
from .parser import And, Not, Or, QueryError, Range, Term, Text, Value, literal, modern, parse, to_json

__all__ = [
    "ENTITIES",
    "And",
    "Not",
    "modern",
    "Or",
    "QueryError",
    "QueryForbidden",
    "Range",
    "Term",
    "Text",
    "condition",
    "entity_of",
    "parse",
    "rows",
    "schema",
    "sql",
    "statement_timeout",
    "to_json",
]

STATEMENT_TIMEOUT_MS = 10_000
MAX_PAGE = 500


class QueryForbidden(PermissionError):
    """The caller may not query this entity."""


def entity_of(name: str, db: OrmSession | None = None) -> Entity:
    """The entity of this name. With ``db``, the incidents come with the custom fields of the
    registry as it is now; without, with the fields every installation has."""
    found = ENTITIES.get(str(name or "").lower())
    if found is None:
        raise QueryError(
            "unknown_entity", 0, "Unknown entity: " + ", ".join(sorted(ENTITIES)), suggest(str(name), ENTITIES)
        )
    if db is not None and found.name == "incidents":
        return _incident_fields.entity(db, found)
    return found


def _allowed(entity: Entity, principal: Any) -> None:
    if principal is not None and not principal.has(entity.permission):
        raise QueryForbidden(entity.name)


def schema(name: str, principal: Any = None, *, db: OrmSession | None = None) -> dict:
    """The fields of an entity, for the builder and the autocomplete."""
    entity = entity_of(name, db)
    _allowed(entity, principal)
    return entity.schema()


def condition(field: str, value: str, op: str = "=") -> Term:
    """A condition built by code (an old query parameter), the value taken as it is."""
    return Term(field=field, op=op, value=literal(value))


# What looks like ``field:value`` and is not: an address, a path, an IPv6 or MAC address.
def _reads_as_text(term: Term) -> bool:
    value = term.raw.split(":", 1)[1] if ":" in term.raw else term.value.text
    if value.startswith(("//", "\\", ":")):
        return True
    hexadecimal = set("0123456789abcdefABCDEF")
    return set(term.field) <= hexadecimal and set(value) <= hexadecimal | {":"}


def _spec(entity: Entity, node: Term | Range):
    spec = entity.field(node.field)
    if spec is None:
        hint = suggest(node.field, entity.names())
        raise QueryError(
            "unknown_field",
            node.position,
            f'"{node.field}" is not a field of {entity.label.lower()}' + (f': did you mean "{hint}"?' if hint else ""),
            hint,
        )
    return spec


def _relocate(error: QueryError, position: int) -> QueryError:
    """Errors raised inside a field are placed at the condition they belong to."""
    return QueryError(error.code, position, error.message, error.suggestion)


def _as_text(term: Term) -> Value:
    return Value(text=term.raw, quoted=True, parts=(term.raw,))


def _walk(node, entity: Entity, ctx: Context, leaf, combine):
    if isinstance(node, And):
        return combine("and", [_walk(item, entity, ctx, leaf, combine) for item in node.nodes])
    if isinstance(node, Or):
        return combine("or", [_walk(item, entity, ctx, leaf, combine) for item in node.nodes])
    if isinstance(node, Not):
        return combine("not", [_walk(node.node, entity, ctx, leaf, combine)])
    return leaf(node)


def sql(
    name: str,
    query: str | None,
    principal: Any = None,
    *,
    extra=(),
    now: datetime | None = None,
    db: OrmSession | None = None,
) -> list:
    """The conditions of a query on a table entity (an empty list for an empty
    query). ``extra`` are conditions built by code (``condition(...)``), all
    of which must hold as well. ``db`` is what lets a query name a custom field
    (``entity_of``): whoever compiles a query a person wrote passes it."""
    entity = entity_of(name, db)
    _allowed(entity, principal)
    if entity.model is None:
        raise QueryError("unknown_entity", 0, f"{entity.label} are not searched in the database")
    ctx = Context(principal=principal, now=now)
    tree = parse(query)
    nodes = ([tree] if tree is not None else []) + list(extra)

    def leaf(node):
        try:
            if isinstance(node, Text):
                return _fields.sql_text(entity, node.value, node.position)
            if isinstance(node, Term) and entity.field(node.field) is None and _reads_as_text(node):
                return _fields.sql_text(entity, _as_text(node), node.position)
            spec = _spec(entity, node)
            if isinstance(node, Range):
                return _fields.sql_range(spec, node.low, node.high, node.position, ctx)
            return _fields.sql_condition(spec, node.op, node.value, node.position, ctx)
        except QueryError as error:
            raise _relocate(error, node.position) from None

    def combine(how: str, parts: list):
        if how == "and":
            return and_(*parts)
        if how == "or":
            return or_(*parts)
        return not_(parts[0])

    return [*entity.base, *(_walk(node, entity, ctx, leaf, combine) for node in nodes)] or [true()]


def rows(name: str, query: str | None, principal: Any = None, *, now: datetime | None = None) -> Callable[[dict], bool]:
    """A predicate over the rows of an entity assembled in Python."""
    entity = entity_of(name)
    _allowed(entity, principal)
    ctx = Context(principal=principal, now=now)
    tree = parse(query)
    if tree is None:
        return lambda row: True

    def leaf(node):
        try:
            if isinstance(node, Text):
                return _fields.row_text(entity, node.value, node.position)
            if isinstance(node, Term) and entity.field(node.field) is None and _reads_as_text(node):
                return _fields.row_text(entity, _as_text(node), node.position)
            spec = _spec(entity, node)
            if isinstance(node, Range):
                return _fields.row_range(spec, node.low, node.high, node.position, ctx)
            return _fields.row_condition(spec, node.op, node.value, node.position, ctx)
        except QueryError as error:
            raise _relocate(error, node.position) from None

    def combine(how: str, parts: list):
        if how == "and":
            return lambda row: all(part(row) for part in parts)
        if how == "or":
            return lambda row: any(part(row) for part in parts)
        return lambda row: not parts[0](row)

    return _walk(tree, entity, ctx, leaf, combine)


def statement_timeout(db: OrmSession) -> None:
    """A query written by a user runs for ten seconds at most (PostgreSQL; the
    setting lasts until the end of the transaction)."""
    if db.get_bind().dialect.name == "postgresql":
        db.execute(text(f"SET LOCAL statement_timeout = {int(STATEMENT_TIMEOUT_MS)}"))

"""The fields of the registry as fields of the query language.

Every field an incident can hold is asked by its name: ``customer:acme``,
``amount:>=100``, ``due:[2026-11-01 TO *]``, ``labels:phish``. What a
condition means follows the type of the field, and is what the same type means
on a field Nik always had, so that nothing about a custom field is special to
whoever writes the query::

    text, long text, address   text      contains the value
    user, role                 keyword   equals the value, as owner does
    choice                     keyword   one of its choices
    number                     number    comparisons and ranges
    timer                      number    the seconds it counted
    date                       date      a span of time
    yes / no                   bool      true / false
    tags, several choices      tags      holds the value
    indicator                  text      the value of the indicator
    table, JSON                text      a word found anywhere in it; no more than that

A field that is not a column lives in ``incidents.fields``; it is read there
only when it is of the kind its type says (``held.py``), and the same reading
is written for a row (the ``getter``), so a condition means the same in SQL
and on rows.

**Names.** A name the language already uses wins: the fields Nik always had
keep their names and their other names (``user``, ``source``, ``number``,
``updated``…). A custom field is also written ``field.<name>``, always, and
that is the only way to write one whose name was taken.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from sqlalchemy import func, not_, or_, select
from sqlalchemy.orm import Session as OrmSession

from ..core.models import Field, Incident
from .fields import Context, Entity, FieldSpec, _bad, _check_wildcards, like_pattern, text_matches
from .held import held_bool, held_list, held_number, held_raw, held_text
from .parser import ANY, Value, Wild

PREFIX = "field."

# The type of a field of the registry → the kind of field it is in a query.
KINDS = {
    "text": "text",
    "long_text": "text",
    "url": "text",
    "user": "keyword",
    "role": "keyword",
    "choice": "keyword",
    "number": "number",
    "timer": "number",
    "date": "date",
    "bool": "bool",
    "tags": "tags",
    "multi_choice": "tags",
    "indicator": "text",
    "list": "text",
    "json": "text",
}
_EMPTY = (None, "", [], {})


def _stored(row: dict) -> dict:
    held = row.get("fields")
    return held if isinstance(held, dict) else {}


def _reader(name: str, wanted: type | tuple, *path: str) -> Callable[[dict], Any]:
    """What a row holds for a field when it is of the kind wanted, as ``held.py`` reads it in SQL."""

    def get(row: dict) -> Any:
        value = _stored(row).get(name)
        for key in path:
            value = value.get(key) if isinstance(value, dict) else None
        if isinstance(value, bool) and wanted is not bool:
            return None  # true is not the number 1
        return value if isinstance(value, wanted) else None

    return get


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    return value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)


def _whole(name: str, written: str) -> tuple[Callable, Callable]:
    """A table or a JSON value, searched as the text it is kept as: the value is found anywhere
    in it or is not. There is nothing in it to compare or to count by."""
    raw = held_raw(Incident.fields, name)

    def checked(op: str, value: Value) -> Value:
        if op not in ("=", "!"):
            raise _bad("bad_operator", 0, f'"{written}" is searched as text: field:value or !field:value only')
        _check_wildcards(value, 0)
        return Value(text=value.text, quoted=value.quoted, parts=(Wild(ANY), *value.parts, Wild(ANY)))

    def sql(op: str, value: Value, ctx: Context):
        anywhere = checked(op, value)
        if value.is_empty or value.is_any:
            empty = or_(raw.is_(None), func.replace(raw, " ", "").in_(("", "[]", "{}")))
            return empty if value.is_empty == (op == "=") else not_(empty)
        match = func.lower(func.coalesce(raw, "")).like(like_pattern(anywhere, contains=False).lower(), escape="\\")
        return match if op == "=" else not_(match)

    def test(op: str, value: Value, ctx: Context):
        anywhere = checked(op, value)
        if value.is_empty or value.is_any:
            wants_empty = value.is_empty == (op == "=")
            return lambda row: (_stored(row).get(name) in _EMPTY) == wants_empty
        return lambda row: text_matches(anywhere, _as_text(_stored(row).get(name)), contains=False) == (op == "=")

    return sql, test


def spec_of(
    name: str,
    kind: str,
    *,
    label: str = "",
    description: str = "",
    options: dict | None = None,
    custom: bool = False,
    written: str | None = None,
    aliases: tuple[str, ...] = (),
) -> FieldSpec | None:
    """The field of the query language for a field of the registry kept in ``incidents.fields``;
    None for a type this release does not know. ``written`` is the name it is asked by when
    that is not its own."""
    if kind not in KINDS:
        return None
    written = written or name
    says = description.strip() or label or name
    if label and description.strip() and custom:
        says = f"{label}: {description.strip()}"
    common = {
        "description": says[:200],
        "aliases": aliases,
        "label": label or name,
        "custom": custom,
        "nullable": True,
    }
    choices = tuple(str(choice) for choice in (options or {}).get("choices") or [])
    column = held_text(Incident.fields, name)
    reader = _reader(name, str)
    if kind in ("list", "json"):
        sql, test = _whole(name, written)
        return FieldSpec(written, "text", sql=sql, test=test, **common)
    if kind == "indicator":
        column, reader = held_text(Incident.fields, name, "value"), _reader(name, str, "value")
    elif kind == "number":
        column, reader = held_number(Incident.fields, name), _reader(name, (int, float))
    elif kind == "timer":
        column = held_number(Incident.fields, name, "accumulated_s")
        reader = _reader(name, (int, float), "accumulated_s")
    elif kind == "bool":
        column, reader = held_bool(Incident.fields, name), _reader(name, bool)
    elif kind in ("tags", "multi_choice"):
        column, reader = held_list(Incident.fields, name), _reader(name, list)
    return FieldSpec(written, KINDS[kind], column=column, getter=reader, values=choices, **common)


def entity(db: OrmSession, base: Entity) -> Entity:
    """The incidents with the custom fields of the registry as it is now. Read at each
    compilation: a field made a moment ago can be asked, one that was deleted is unknown again."""
    rows = db.execute(
        select(Field.name, Field.label, Field.description, Field.type, Field.options)
        .where(Field.system.is_(False), Field.applies_to == "incident")
        .order_by(Field.name)
    ).all()
    added = []
    for name, label, description, kind, options in rows:
        taken = base.field(name) is not None
        spec = spec_of(
            name,
            kind,
            label=label or name,
            description=description or "",
            options=options if isinstance(options, dict) else {},
            custom=True,
            written=PREFIX + name if taken else name,
            aliases=() if taken else (PREFIX + name,),
        )
        if spec is not None:
            added.append(spec)
    if not added:
        return base
    return Entity(
        name=base.name,
        label=base.label,
        permission=base.permission,
        fields=(*base.fields, *added),
        text_fields=base.text_fields,
        model=base.model,
        base=base.base,
    )

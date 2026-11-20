"""What a JSON column holds under a name, as SQL that is right on SQLite and on PostgreSQL.

The fields of the registry that are not columns live in ``incidents.fields``. A
condition on one of them reads the value there, and reads it **only when it is of
the kind the field is**: a text where a number is expected is no value at all
(NULL), on both databases. Without that, PostgreSQL refuses the whole query (a
cast of ``"abc"`` to a number is an error there) and SQLite compares a text with
a number as if it meant something.

    held_text(Incident.fields, "customer")           the text, or NULL
    held_number(Incident.fields, "amount")           the number, or NULL
    held_bool(Incident.fields, "confirmed")          true / false, or NULL
    held_list(Incident.fields, "labels")             the list (as JSON), or NULL
    held_raw(Incident.fields, "contacts")            whatever is there, as text
    held_number(Incident.fields, "timer", "accumulated_s")   one level down

The keys are written into the SQL as literals, not as parameters: an expression
that is selected and grouped by must read the same in both places, which two
parameters do not on PostgreSQL. That is why a key is checked here against the
shape of a name of the registry before anything is built.
"""

from __future__ import annotations

import re

from sqlalchemy import Boolean, Float, String, literal_column
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.sql.functions import FunctionElement
from sqlalchemy.types import JSON

_KEY = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,60}")


class _Held(FunctionElement):
    """``column``, then the keys that lead to the value."""

    inherit_cache = True
    wanted = ""  # what the value must be: text | number | bool | list | raw

    def __init__(self, column, *keys: str):
        if not keys or not all(_KEY.fullmatch(key) for key in keys):
            raise ValueError("A key of a JSON field is a letter, then letters, digits or _")
        super().__init__(column, *(literal_column(f"'{key}'") for key in keys))


class held_text(_Held):
    type = String()
    wanted = "text"
    inherit_cache = True


class held_number(_Held):
    type = Float()
    wanted = "number"
    inherit_cache = True


class held_bool(_Held):
    type = Boolean()
    wanted = "bool"
    inherit_cache = True


class held_list(_Held):
    type = JSON()
    wanted = "list"
    inherit_cache = True


class held_raw(_Held):
    type = String()
    wanted = "raw"
    inherit_cache = True


def _pieces(element: _Held, compiler, kw) -> tuple[str, list[str]]:
    column, *keys = element.clauses
    return compiler.process(column, **kw), [compiler.process(key, **kw) for key in keys]


@compiles(_Held)
def _sqlite(element: _Held, compiler, **kw) -> str:
    """SQLite (and what the tests run on): ``json_type`` says what is there, ``json_extract`` reads it."""
    column, keys = _pieces(element, compiler, kw)
    path = "'$.' || " + " || '.' || ".join(keys)
    kind, value = f"json_type({column}, {path})", f"json_extract({column}, {path})"
    if element.wanted == "text":
        return f"CASE WHEN {kind} = 'text' THEN {value} END"
    if element.wanted == "number":
        return f"CASE WHEN {kind} IN ('integer', 'real') THEN {value} END"
    if element.wanted == "bool":
        return f"CASE {kind} WHEN 'true' THEN 1 WHEN 'false' THEN 0 END"
    if element.wanted == "list":
        return f"CASE WHEN {kind} = 'array' THEN {value} END"
    return f"CAST({value} AS TEXT)"


@compiles(_Held, "postgresql")
def _postgresql(element: _Held, compiler, **kw) -> str:
    """PostgreSQL: ``jsonb_typeof`` says what is there; the cast is reached only for the right kind."""
    column, keys = _pieces(element, compiler, kw)
    inner = f"CAST({column} AS JSONB)" + "".join(f" -> {key}" for key in keys[:-1])
    found, text = f"{inner} -> {keys[-1]}", f"{inner} ->> {keys[-1]}"
    kind = f"jsonb_typeof({found})"
    if element.wanted == "text":
        return f"CASE WHEN {kind} = 'string' THEN {text} END"
    if element.wanted == "number":
        return f"CASE WHEN {kind} = 'number' THEN CAST({text} AS DOUBLE PRECISION) END"
    if element.wanted == "bool":
        return f"CASE WHEN {kind} = 'boolean' THEN CAST({text} AS BOOLEAN) END"
    if element.wanted == "list":
        return f"CASE WHEN {kind} = 'array' THEN {found} END"
    return f"({text})"

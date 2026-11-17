"""The ``{{ }}`` language of playbooks and connectors.

    {{ trigger.mail.sender }}
    {{ search.recipients[*].office | unique | join(", ") }}
    {{ args.urgency | default("3") }}

Only paths and filters: no arithmetic, no comparisons, no calls, no code.
Logic belongs to condition nodes and to scripts. Hand-written: nothing here
evaluates text as Python, and no template engine is involved.

    template := (text | "{{" expr "}}")*
    expr     := path ( "|" filter )*
    path     := name ( "." name | "[" index "]" )*
    index    := integer | "*" | string
    filter   := name [ "(" arg ("," arg)* ")" ]
    arg      := string | number | true | false | null | name "=" literal

A field that is exactly one ``{{ }}`` keeps the type of what it names; mixed
with text it becomes a string. A path that leads nowhere is an error unless
``default`` follows it.

**Classes of data travel with values.** A value read from a scope carries the
classes of the place it was read from (``e-mail address``, ``mail body`` …:
see guard.py), a filter keeps the classes of what it was given, and a
rendered string carries the classes of everything put into it. That is what
lets the data guard decide on what is about to leave without guessing.

The frontend has the same parser (``src/domain/automation/expressions.js``);
both read ``backend/tests/data/expressions.json``.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

MAX_TEMPLATE = 20_000
MAX_EXPRESSIONS = 200
MAX_DEPTH = 12  # nesting of the data a config is rendered through
MAX_STRING = 1_000_000


class ExpressionError(ValueError):
    """An expression that cannot be read or evaluated: where, and a fixed sentence."""

    def __init__(self, position: int, message: str):
        self.position = position
        self.message = message
        super().__init__(message)


@dataclass(frozen=True)
class Value:
    """What an expression gives: the data, and the classes of data it holds."""

    data: Any
    classes: frozenset = frozenset()


class _Missing:
    def __repr__(self) -> str:  # pragma: no cover
        return "MISSING"


MISSING = _Missing()


# --------------------------------------------------------------------------- #
# The scope: what the names of an expression stand for                        #
# --------------------------------------------------------------------------- #
def _class_path(steps: tuple) -> tuple:
    """A path as the class maps know it: names only (a list has the classes of its items)."""
    return tuple(step for step in steps if isinstance(step, str))


@dataclass
class Scope:
    """Names (``trigger``, a node id, ``item`` …) with their data, and for each
    a map of the classes its fields hold: ``{"mail.sender": ["email_address"]}``.
    A key of the map covers what is under it and what it is part of: reading
    ``trigger.mail`` carries the classes of every field of the mail."""

    values: dict[str, Any] = field(default_factory=dict)
    classes: dict[str, dict[str, list]] = field(default_factory=dict)
    # Whether a value is in a list by its name (``| in_list('vip_users')``); None where lists cannot be read.
    in_list: Any = None

    def classes_at(self, name: str, steps: tuple) -> frozenset:
        found: set = set()
        wanted = _class_path(steps)
        for key, held in (self.classes.get(name) or {}).items():
            parts = tuple(part for part in key.split(".") if part)
            shared = min(len(parts), len(wanted))
            if parts[:shared] == wanted[:shared]:
                found.update(held)
        return frozenset(found)


# --------------------------------------------------------------------------- #
# Reading                                                                     #
# --------------------------------------------------------------------------- #
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_NUMBER = re.compile(r"-?\d+(?:\.\d+)?")
_SPACE = " \t\r\n"


@dataclass(frozen=True)
class Filter:
    name: str
    args: tuple = ()
    named: tuple = ()  # ((name, value), …)
    position: int = 0


@dataclass(frozen=True)
class Expr:
    root: str
    steps: tuple  # names (str), indices (int), "*" as Star
    filters: tuple
    position: int  # of the opening braces
    end: int


class _Star:
    def __repr__(self) -> str:  # pragma: no cover
        return "*"


STAR = _Star()


class _Reader:
    def __init__(self, text: str, i: int):
        self.text = text
        self.i = i

    def skip(self) -> None:
        while self.i < len(self.text) and self.text[self.i] in _SPACE:
            self.i += 1

    def peek(self, count: int = 1) -> str:
        return self.text[self.i : self.i + count]

    def fail(self, message: str, at: int | None = None):
        raise ExpressionError(self.i if at is None else at, message)

    def name(self) -> str:
        match = _NAME.match(self.text, self.i)
        if not match:
            self.fail("A name is expected here")
        self.i = match.end()
        return match.group()

    def string(self) -> str:
        quote = self.text[self.i]
        start = self.i
        self.i += 1
        out = []
        while self.i < len(self.text):
            char = self.text[self.i]
            if char == "\\" and self.i + 1 < len(self.text):
                out.append({"n": "\n", "t": "\t"}.get(self.text[self.i + 1], self.text[self.i + 1]))
                self.i += 2
            elif char == quote:
                self.i += 1
                return "".join(out)
            else:
                out.append(char)
                self.i += 1
        self.fail("A quote is not closed", start)

    def literal(self) -> Any:
        if self.peek() in ('"', "'"):
            return self.string()
        match = _NUMBER.match(self.text, self.i)
        if match:
            self.i = match.end()
            text = match.group()
            return float(text) if "." in text else int(text)
        for word, value in (("true", True), ("false", False), ("null", None)):
            if self.text.startswith(word, self.i) and not _NAME.match(self.text, self.i + len(word)):
                self.i += len(word)
                return value
        self.fail("A text in quotes, a number, true, false or null is expected here")

    def path(self) -> tuple[str, tuple]:
        root = self.name()
        steps: list = []
        while True:
            if self.peek() == ".":
                self.i += 1
                steps.append(self.name())
            elif self.peek() == "[":
                self.i += 1
                self.skip()
                if self.peek() == "*":
                    self.i += 1
                    steps.append(STAR)
                elif self.peek() in ('"', "'"):
                    steps.append(self.string())
                else:
                    match = re.compile(r"-?\d+").match(self.text, self.i)
                    if not match:
                        self.fail("A number, * or a text in quotes is expected between the brackets")
                    self.i = match.end()
                    steps.append(int(match.group()))
                self.skip()
                if self.peek() != "]":
                    self.fail("A bracket is not closed: add ]")
                self.i += 1
            else:
                return root, tuple(steps)

    def filter(self) -> Filter:
        at = self.i
        name = self.name()
        if name not in FILTERS:
            self.fail(f'There is no filter "{name}"', at)
        args: list = []
        named: list = []
        if self.peek() == "(":
            self.i += 1
            self.skip()
            while self.peek() != ")":
                key = _NAME.match(self.text, self.i)
                rest = self.text[key.end() :].lstrip(_SPACE) if key else ""
                if key and rest.startswith("=") and key.group() not in ("true", "false", "null"):
                    self.i = key.end()
                    self.skip()
                    self.i += 1  # =
                    self.skip()
                    named.append((key.group(), self.literal()))
                else:
                    args.append(self.literal())
                self.skip()
                if self.peek() == ",":
                    self.i += 1
                    self.skip()
                elif self.peek() != ")":
                    self.fail("A comma or a closing parenthesis is expected here")
            self.i += 1
        return Filter(name, tuple(args), tuple(named), at)

    def expression(self, start: int) -> Expr:
        self.skip()
        root, steps = self.path()
        filters = []
        self.skip()
        while self.peek() == "|":
            self.i += 1
            self.skip()
            filters.append(self.filter())
            self.skip()
        if self.peek(2) != "}}":
            self.fail("The expression is not closed: add }}" if self.i >= len(self.text) else "}} is expected here")
        self.i += 2
        return Expr(root, steps, tuple(filters), start, self.i)


def parse(template: str) -> list:
    """A template as its parts: text (``str``) and expressions (``Expr``)."""
    if len(template) > MAX_TEMPLATE:
        raise ExpressionError(MAX_TEMPLATE, f"The text is longer than {MAX_TEMPLATE} characters")
    parts: list = []
    i = 0
    count = 0
    while True:
        start = template.find("{{", i)
        if start == -1:
            if i < len(template):
                parts.append(template[i:])
            return parts
        if start > i:
            parts.append(template[i:start])
        count += 1
        if count > MAX_EXPRESSIONS:
            raise ExpressionError(start, f"More than {MAX_EXPRESSIONS} expressions in one text")
        reader = _Reader(template, start + 2)
        expr = reader.expression(start)
        parts.append(expr)
        i = expr.end


def references(value: Any) -> list[tuple[str, int]]:
    """The root names the expressions of a value (a text, or a structure of
    texts) read, with the position of each: what a graph is validated with."""
    found: list[tuple[str, int]] = []
    if isinstance(value, str):
        if "{{" in value:
            found += [(part.root, part.position) for part in parse(value) if isinstance(part, Expr)]
    elif isinstance(value, dict):
        for item in value.values():
            found += references(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            found += references(item)
    return found


# --------------------------------------------------------------------------- #
# Filters: pure functions of data                                             #
# --------------------------------------------------------------------------- #
def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return str(value)


def _listed(value: Any) -> list:
    if value is None:
        return []
    return list(value) if isinstance(value, (list, tuple)) else [value]


def _defang(value: Any) -> Any:
    if isinstance(value, list):
        return [_defang(item) for item in value]
    text = _text(value)
    return text.replace("http", "hxxp").replace("://", "[://]").replace(".", "[.]").replace("@", "[@]")


def _date(value: Any, fmt: str = "%Y-%m-%d %H:%M") -> str:
    if len(fmt) > 60:
        raise ValueError("The date format is too long")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        moment = datetime.fromtimestamp(float(value), tz=timezone.utc)
    else:
        moment = datetime.fromisoformat(_text(value).replace("Z", "+00:00"))
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).strftime(fmt)


def lookup(data: Any, path: str) -> Any:
    """``a.b.0.c`` in nested data; MISSING when it leads nowhere."""
    for part in [p for p in str(path).split(".") if p != ""]:
        if isinstance(data, dict) and part in data:
            data = data[part]
        elif isinstance(data, (list, tuple)) and part.lstrip("-").isdigit() and -len(data) <= int(part) < len(data):
            data = data[int(part)]
        else:
            return MISSING
    return data


def compare(left: Any, op: str, right: Any) -> bool:
    """The operators of a condition (and of the ``where`` filter)."""
    if op == "exists":
        return left is not None and left is not MISSING
    if op == "empty":
        return left is None or left is MISSING or left == "" or left == [] or left == {}
    if left is MISSING:
        left = None
    if op in ("eq", "ne"):
        same = left == right or (
            _text(left).casefold() == _text(right).casefold() and not isinstance(left, (dict, list))
        )
        return same == (op == "eq")
    if op in ("gt", "gte", "lt", "lte"):
        try:
            a, b = float(left), float(right)
        except (TypeError, ValueError):
            a, b = _text(left), _text(right)
        return {"gt": a > b, "gte": a >= b, "lt": a < b, "lte": a <= b}[op]
    if op == "contains":
        if isinstance(left, (list, tuple)):
            return any(compare(item, "eq", right) for item in left)
        return _text(right).casefold() in _text(left).casefold()
    if op == "in":
        return any(compare(left, "eq", item) for item in _listed(right))
    raise ValueError(f'There is no operator "{op}"')


def _where(value: Any, key: str, op: str | None = None, wanted: Any = None) -> list:
    """The items whose field compares so; with the field alone, those where it is set and not false."""
    if op is None:
        return [item for item in _listed(value) if lookup(item, key) not in (MISSING, None, False, "", 0, [], {})]
    return [item for item in _listed(value) if compare(lookup(item, key), op, wanted)]


def _map(value: Any, **pairs: Any) -> Any:
    fallback = pairs.pop("else", value)
    for key, mapped in pairs.items():
        if _text(value).casefold() == key.casefold():
            return mapped
    return fallback


def _number(kind, value: Any) -> Any:
    try:
        return kind(float(value)) if kind is int else kind(value)
    except (TypeError, ValueError):
        raise ValueError("That is not a number") from None


def _add(value: Any, amount: Any = 1) -> Any:
    """A number plus a number: the next version of a page, the next page of a list."""
    for item in (value, amount):
        if isinstance(item, bool) or not isinstance(item, (int, float)):
            raise ValueError("That is not a number")
    return value + amount


def _sorted(value: Any) -> list:
    items = _listed(value)
    try:
        return sorted(items)
    except TypeError:
        return sorted(items, key=_text)


def _unique(value: Any) -> list:
    seen: list = []
    for item in _listed(value):
        if item not in seen:
            seen.append(item)
    return seen


_SEVERITY_WORDS = {
    "informational": "low", "info": "low", "none": "low", "low": "low", "minor": "low", "trivial": "low",
    "lowest": "low", "medium": "medium", "moderate": "medium", "warning": "medium", "normal": "medium",
    "high": "high", "major": "high", "important": "high", "critical": "critical", "severe": "critical",
    "highest": "critical", "blocker": "critical", "urgent": "critical", "fatal": "critical",
}  # fmt: skip


def _severity(value: Any, scale: Any = "") -> str:
    """A severity of another product as Nik's: low, medium, high or critical ("" when it is none).

    Words are read as they are (``Critical``, ``moderate``…). A number from 1 to 5 counts up
    (5 is the worst), or down with ``severity('inverse')`` for a scale where 1 is the worst (a
    priority); a number from 0 to 100 is cut at 25, 50 and 75."""
    text = _text(value).strip().lower()
    if not text:
        return ""
    if text in _SEVERITY_WORDS:
        return _SEVERITY_WORDS[text]
    try:
        number = float(text.split(" ")[0].strip("p-"))
    except ValueError:
        return ""
    inverse = _text(scale).strip().lower() == "inverse"
    if number != number or number < 0:
        return ""
    if number <= 5:
        step = max(1, min(5, int(round(number)) or 1))
        up = ("low", "low", "medium", "high", "critical")
        down = ("critical", "high", "medium", "low", "low")
        return (down if inverse else up)[step - 1]
    return "low" if number < 25 else "medium" if number < 50 else "high" if number < 75 else "critical"


def _regex_extract(value: Any, pattern: Any, group: Any = 0) -> str:
    """The part of a text a pattern finds (a group of it, by number or by name); "" when it finds none.
    The pattern is matched with a time limit, never with the unbounded ``re``."""
    import regex

    source = _text(pattern)
    if not source or len(source) > 500:
        raise ValueError("pattern")
    try:
        found = regex.search(source, _text(value)[:100_000], timeout=0.5)
    except (TimeoutError, regex.error):
        raise ValueError("pattern") from None
    if found is None:
        return ""
    try:
        part = found.group(group if isinstance(group, str) else int(group))
    except (IndexError, ValueError, TypeError):
        raise ValueError("group") from None
    return part or ""


FILTERS = {
    "default": None,  # handled by the evaluator: it is the one filter that takes a missing value
    "severity": _severity,
    "regex_extract": _regex_extract,
    "in_list": None,  # handled by the evaluator: the scope knows the lists
    "length": lambda v: len(v) if isinstance(v, (list, tuple, dict, str)) else 0,
    "join": lambda v, sep=", ": _text(sep).join(_text(item) for item in _listed(v)),
    "lower": lambda v: _text(v).lower(),
    "upper": lambda v: _text(v).upper(),
    "trim": lambda v: _text(v).strip(),
    "first": lambda v: (_listed(v) or [None])[0],
    "last": lambda v: (_listed(v) or [None])[-1],
    "unique": _unique,
    "sort": _sorted,
    "json": lambda v: json.dumps(v, ensure_ascii=False, separators=(",", ":")),
    "defang": _defang,
    "date": _date,
    "get": lambda v, path: None if (found := lookup(v, path)) is MISSING else found,
    "map": _map,
    "split": lambda v, sep=",": [part.strip() for part in _text(v).split(_text(sep) or ",") if part.strip()],
    "replace": lambda v, old, new="": _text(v).replace(_text(old), _text(new)),
    "add": _add,
    "int": lambda v: _number(int, v),
    "float": lambda v: _number(float, v),
    "bool": lambda v: bool(v) and _text(v).lower() not in ("false", "no", "0", "off"),
    "keys": lambda v: list(v) if isinstance(v, dict) else [],
    "values": lambda v: list(v.values()) if isinstance(v, dict) else [],
    "where": _where,
    "pluck": lambda v, key: [None if (found := lookup(item, key)) is MISSING else found for item in _listed(v)],
}


# --------------------------------------------------------------------------- #
# Evaluating                                                                  #
# --------------------------------------------------------------------------- #
def _walk(data: Any, steps: tuple) -> Any:
    for index, step in enumerate(steps):
        if step is STAR:
            if not isinstance(data, (list, tuple)):
                return MISSING
            rest = steps[index + 1 :]
            out: list = []
            for item in data:
                found = _walk(item, rest)
                if found is MISSING:
                    continue
                # One level is flattened: the tags of every item are one list of tags.
                if isinstance(found, list):
                    out.extend(found)
                else:
                    out.append(found)
            return out
        if isinstance(step, int):
            if not isinstance(data, (list, tuple)) or not -len(data) <= step < len(data):
                return MISSING
            data = data[step]
        elif isinstance(data, dict) and step in data:
            data = data[step]
        else:
            return MISSING
    return data


def path_text(expr: Expr) -> str:
    out = expr.root
    for step in expr.steps:
        out += (
            f".{step}"
            if isinstance(step, str) and _NAME.fullmatch(step)
            else f"[{'*' if step is STAR else json.dumps(step)}]"
        )
    return out


def evaluate(expr: Expr, scope: Scope) -> Value:
    if expr.root not in scope.values:
        raise ExpressionError(expr.position, f'"{expr.root}" is not a name that can be read here')
    data = _walk(scope.values[expr.root], expr.steps)
    classes = scope.classes_at(expr.root, expr.steps)
    for item in expr.filters:
        if item.name == "default":
            if data is MISSING or data is None:
                data = item.args[0] if item.args else ""
            continue
        if data is MISSING:
            break
        if item.name == "in_list":
            if scope.in_list is None or len(item.args) != 1:
                raise ExpressionError(item.position, "in_list takes the name of a list, where lists can be read")
            data = bool(scope.in_list(_text(item.args[0]), data))
            classes = frozenset({"verdict"})  # a yes or a no, not the value it was asked about
            continue
        try:
            data = FILTERS[item.name](data, *item.args, **dict(item.named))
        except (TypeError, ValueError, KeyError, IndexError, OverflowError):
            raise ExpressionError(item.position, f'The filter "{item.name}" cannot be applied to this value') from None
    if data is MISSING:
        raise ExpressionError(
            expr.position, f"There is nothing at {path_text(expr)}: add | default(…) if it may be absent"
        )
    return Value(data, classes)


def render_text(template: str, scope: Scope) -> Value:
    """A text with its expressions replaced. Exactly one expression and nothing
    else keeps the type of what it names."""
    if "{{" not in template:
        return Value(template)
    parts = parse(template)
    if len(parts) == 1 and isinstance(parts[0], Expr):
        return evaluate(parts[0], scope)
    out: list[str] = []
    classes: set = set()
    for part in parts:
        if isinstance(part, Expr):
            value = evaluate(part, scope)
            out.append(_text(value.data))
            classes |= value.classes
        else:
            out.append(part)
    text = "".join(out)
    if len(text) > MAX_STRING:
        raise ExpressionError(0, "The text this gives is too long")
    return Value(text, frozenset(classes))


def render(value: Any, scope: Scope, _depth: int = 0) -> Value:
    """A structure (the config of a node, the request of a connector) with every
    text in it rendered. The classes are those of everything put into it."""
    if _depth > MAX_DEPTH:
        raise ExpressionError(0, "The structure nests too deep")
    if isinstance(value, str):
        return render_text(value, scope)
    if isinstance(value, dict):
        out = {}
        classes: set = set()
        for key, item in value.items():
            rendered = render(item, scope, _depth + 1)
            out[key] = rendered.data
            classes |= rendered.classes
        return Value(out, frozenset(classes))
    if isinstance(value, (list, tuple)):
        items = [render(item, scope, _depth + 1) for item in value]
        return Value([item.data for item in items], frozenset().union(*(item.classes for item in items)))
    return Value(value)


def render_classes(value: Any, scope: Scope, _depth: int = 0, _path: str = "") -> dict[str, list]:
    """The class map of a rendered structure: for each field of ``value`` that
    holds classed data, its path and the classes. What a step stores beside
    its output, so the classes survive in the run's context."""
    if _depth > MAX_DEPTH:
        return {}
    if isinstance(value, dict):
        out: dict[str, list] = {}
        for key, item in value.items():
            out.update(render_classes(item, scope, _depth + 1, f"{_path}.{key}" if _path else str(key)))
        return out
    held = render(value, scope, _depth).classes
    return {_path: sorted(held)} if held else {}

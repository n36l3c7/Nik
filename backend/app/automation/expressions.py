"""The ``{{ }}`` language of playbooks and connectors.

    {{ trigger.mail.sender }}
    {{ search.recipients[*].office | unique | join(", ") }}
    {{ args.urgency | default("3") }}
    {{ if(response.stats.malicious >= 3, "malicious", "unknown") }}
    {{ now | date_diff(response.registered, "days") < 30 }}

Paths, filters, and what it takes to decide and to count: comparisons,
``and`` / ``or`` / ``not``, ``in``, the four operations on numbers, ``~`` to
join texts, lists, and four functions (``if``, ``first_of``, ``min``,
``max``). Still no code: a name is a path into the data or one of those four
functions, nothing is called that is not in the tables below, and nothing
here evaluates text as Python. No template engine is involved.

    template := (text | "{{" expr "}}")*
    expr     := and ( "or" and )*
    and      := not ( "and" not )*
    not      := "not" not | compared
    compared := joined [ ("==" | "!=" | "<" | "<=" | ">" | ">=" | "in" | "not" "in") joined ]
    joined   := sum ( "~" sum )*
    sum      := product ( ("+" | "-") product )*
    product  := signed ( ("*" | "/") signed )*
    signed   := "-" signed | piped
    piped    := value ( "|" filter )*
    value    := path | string | number | true | false | null
              | "[" [ expr ("," expr)* ] "]" | "(" expr ")" | function "(" expr ("," expr)* ")"
    path     := name ( "." name | "[" index "]" )*
    index    := integer | "*" | string
    filter   := name [ "(" arg ("," arg)* ")" ]
    arg      := expr | name "=" expr

A filter applies to the value just before it (``a + b | round`` rounds ``b``:
write ``(a + b) | round``). Comparing is what a condition node does: texts
regardless of case, a number written as a text as that number.

A field that is exactly one ``{{ }}`` keeps the type of what it gives; mixed
with text it becomes a string. A path that leads nowhere is an error unless
``default`` follows it, or it is given to ``first_of`` or asked by ``if``.

**The work is bounded.** A text has a most of characters and of expressions,
an expression a most of parts and of nesting, a number a largest size; the
filters that compare every item with every other have a most of items, and a
pattern is matched with a time limit.

**Classes of data travel with values.** A value read from a scope carries the
classes of the place it was read from (``e-mail address``, ``mail body`` …:
see guard.py), a filter keeps the classes of what it was given, and a
rendered string carries the classes of everything put into it. What is
computed from several values carries the classes of all of them, a yes or a
no included: nothing is ever lost on the way. That is what lets the data
guard decide on what is about to leave without guessing.

The frontend has the same parser (``src/domain/automation/expressions.js``);
both read ``backend/tests/data/expressions.json``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

MAX_TEMPLATE = 20_000
MAX_EXPRESSIONS = 200
MAX_DEPTH = 12  # nesting of the data a config is rendered through
MAX_STRING = 1_000_000
MAX_NODES = 200  # the parts of one expression: values, operators, filters' arguments
MAX_NESTING = 40  # parentheses, lists and arguments inside one another
MAX_NUMBER = 1e15  # beyond it the two parsers would not count alike
MAX_COMPARED = 1_000_000  # items of one list times items of the other, for the filters that compare them all


# Stored credentials (credentials.py) are named in the fields of an instance and nowhere else: no scope
# ever holds them, and whoever reads the name in an expression is told so rather than "not a name".
CREDENTIALS_ELSEWHERE = (
    "A stored credential is read only in a field of an instance of a connector: "
    '"credentials" cannot be read in a playbook, a script or a connector file'
)


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
    def __repr__(self) -> str:
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
_WORDS = {"true": True, "false": False, "null": None}
_COMPARISONS = (("==", "eq"), ("!=", "ne"), ("<=", "lte"), (">=", "gte"), ("<", "lt"), (">", "gt"))
# What a name followed by a parenthesis may be, and how many values each takes.
FUNCTIONS = {"if": (2, 3), "first_of": (1, 40), "min": (1, 40), "max": (1, 40)}
# One of these where a value is expected, by where it is: the wording of before there were operators is kept.
_A_NAME = "A name is expected here"
_A_LITERAL = "A text in quotes, a number, true, false or null is expected here"


@dataclass(frozen=True)
class Literal:
    value: Any


@dataclass(frozen=True)
class Path:
    root: str
    steps: tuple  # names (str), indices (int), "*" as Star
    position: int  # of the root


@dataclass(frozen=True)
class ListOf:
    items: tuple


@dataclass(frozen=True)
class Filter:
    name: str
    args: tuple = ()  # each an expression
    named: tuple = ()  # ((name, expression), …)
    position: int = 0


@dataclass(frozen=True)
class Piped:
    operand: Any
    filters: tuple


@dataclass(frozen=True)
class Unary:
    op: str  # "not", "neg"
    operand: Any
    position: int


@dataclass(frozen=True)
class Binary:
    op: str  # or, and, eq, ne, lt, lte, gt, gte, in, not_in, ~, +, -, *, /
    left: Any
    right: Any
    position: int


@dataclass(frozen=True)
class Call:
    name: str
    args: tuple
    position: int


@dataclass(frozen=True)
class Expr:
    """One ``{{ }}``: what it computes, where it is, and every path it reads."""

    node: Any
    position: int  # of the opening braces
    end: int
    paths: tuple = ()

    @property
    def _path(self) -> Path | None:
        node = self.node.operand if isinstance(self.node, Piped) else self.node
        return node if isinstance(node, Path) else None

    @property
    def root(self) -> str:
        """The name read, when the expression is one path (with or without filters); "" otherwise."""
        return self._path.root if self._path is not None else ""

    @property
    def steps(self) -> tuple:
        return self._path.steps if self._path is not None else ()

    @property
    def filters(self) -> tuple:
        return self.node.filters if isinstance(self.node, Piped) else ()


class _Star:
    def __repr__(self) -> str:
        return "*"


STAR = _Star()


class _Reader:
    def __init__(self, text: str, i: int):
        self.text = text
        self.i = i
        self.depth = 0
        self.nodes = 0
        self.paths: list[Path] = []

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
            self.fail(_A_NAME)
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

    # ------------------------------------------------------------ operators --
    def word(self, wanted: str) -> bool:
        """Whether the word ``wanted`` is next (after spaces), as a whole word; nothing is consumed."""
        at = self.i
        while at < len(self.text) and self.text[at] in _SPACE:
            at += 1
        match = _NAME.match(self.text, at)
        return bool(match) and match.group() == wanted

    def take(self, wanted: str) -> int:
        """Consume the word ``wanted`` and give where it was."""
        self.skip()
        at = self.i
        self.i += len(wanted)
        return at

    def made(self, node: Any) -> Any:
        """Count what an expression is made of: its evaluation walks every part, so there is a most."""
        self.nodes += 1
        if self.nodes > MAX_NODES:
            self.fail("The expression is too long: compute it in several steps")
        return node

    def deeper(self) -> None:
        self.depth += 1
        if self.depth > MAX_NESTING:
            self.fail("The expression nests too deep")

    def either(self, message: str) -> Any:
        left = self.both(message)
        while self.word("or"):
            at = self.take("or")
            self.skip()
            left = self.made(Binary("or", left, self.both(_A_NAME), at))
        return left

    def both(self, message: str) -> Any:
        left = self.negation(message)
        while self.word("and"):
            at = self.take("and")
            self.skip()
            left = self.made(Binary("and", left, self.negation(_A_NAME), at))
        return left

    def negation(self, message: str) -> Any:
        # "not" is the operator unless it is the start of a path (a node may be called "not").
        if self.word("not") and self.text[self.i + 3 : self.i + 4] not in (".", "["):
            at = self.take("not")
            self.skip()
            self.deeper()
            node = self.made(Unary("not", self.negation(_A_NAME), at))
            self.depth -= 1
            return node
        return self.comparison(message)

    def comparison(self, message: str) -> Any:
        left = self.joined(message)
        self.skip()
        at = self.i
        op = next((name for sign, name in _COMPARISONS if self.peek(len(sign)) == sign), None)
        if op is not None:
            self.i += 2 if self.peek(2) in ("==", "!=", "<=", ">=") else 1
        elif self.word("in"):
            self.take("in")
            op = "in"
        elif self.word("not"):
            self.take("not")
            if not self.word("in"):
                self.i = at
                return left
            self.take("in")
            op = "not_in"
        else:
            return left
        self.skip()
        return self.made(Binary(op, left, self.joined(_A_NAME), at))

    def joined(self, message: str) -> Any:
        left = self.summed(message)
        while True:
            self.skip()
            if self.peek() != "~":
                return left
            at = self.i
            self.i += 1
            self.skip()
            left = self.made(Binary("~", left, self.summed(_A_NAME), at))

    def summed(self, message: str) -> Any:
        left = self.multiplied(message)
        while True:
            self.skip()
            if self.peek() not in ("+", "-"):
                return left
            at = self.i
            self.i += 1
            self.skip()
            left = self.made(Binary(self.text[at], left, self.multiplied(_A_NAME), at))

    def multiplied(self, message: str) -> Any:
        left = self.signed(message)
        while True:
            self.skip()
            if self.peek() not in ("*", "/"):
                return left
            at = self.i
            self.i += 1
            self.skip()
            left = self.made(Binary(self.text[at], left, self.signed(_A_NAME), at))

    def signed(self, message: str) -> Any:
        if self.peek() == "-" and not _NUMBER.match(self.text, self.i):
            at = self.i
            self.i += 1
            self.skip()
            self.deeper()
            node = self.made(Unary("neg", self.signed(_A_NAME), at))
            self.depth -= 1
            return node
        return self.piped(message)

    def piped(self, message: str) -> Any:
        """A value and the filters that follow it: a filter applies to what is just before it."""
        operand = self.primary(message)
        filters = []
        while True:
            self.skip()
            if self.peek() != "|":
                break
            self.i += 1
            self.skip()
            filters.append(self.filter())
        return self.made(Piped(operand, tuple(filters))) if filters else operand

    def primary(self, message: str) -> Any:
        char = self.peek()
        if char == "(":
            start = self.i
            self.i += 1
            self.skip()
            self.deeper()
            node = self.either(_A_NAME)
            self.depth -= 1
            self.skip()
            if self.peek() != ")":
                self.fail("A parenthesis is not closed: add )", start if self.i >= len(self.text) else None)
            self.i += 1
            return node
        if char == "[":
            self.i += 1
            self.skip()
            self.deeper()
            items = []
            while self.peek() != "]":
                items.append(self.either(_A_LITERAL))
                self.skip()
                if self.peek() == ",":
                    self.i += 1
                    self.skip()
                elif self.peek() != "]":
                    self.fail("A comma or a closing bracket is expected here")
            self.i += 1
            self.depth -= 1
            return self.made(ListOf(tuple(items)))
        if char in ('"', "'"):
            return self.made(Literal(self.string()))
        number = _NUMBER.match(self.text, self.i)
        if number:
            self.i = number.end()
            # A whole number is a whole number however it is written (2.0): both parsers write it alike.
            value = float(number.group())
            return self.made(Literal(int(value) if value.is_integer() else value))
        found = _NAME.match(self.text, self.i)
        if not found:
            self.fail(message)
        word, after = found.group(), self.text[found.end() : found.end() + 1]
        if word in _WORDS and after not in (".", "["):
            self.i = found.end()
            return self.made(Literal(_WORDS[word]))
        if after == "(":
            return self.call(word)
        at = self.i
        root, steps = self.path()
        node = Path(root, steps, at)
        self.paths.append(node)
        return self.made(node)

    def arguments(self, named: list | None) -> list:
        """What is between the parentheses of a filter or of a function, the opening one being next."""
        self.i += 1
        self.skip()
        self.deeper()
        args: list = []
        while self.peek() != ")":
            key = _NAME.match(self.text, self.i)
            rest = self.text[key.end() :].lstrip(_SPACE) if key else ""
            if (
                named is not None
                and key
                and rest.startswith("=")
                and not rest.startswith("==")
                and key.group() not in _WORDS
            ):
                self.i = key.end()
                self.skip()
                self.i += 1  # =
                self.skip()
                named.append((key.group(), self.either(_A_LITERAL)))
            else:
                args.append(self.either(_A_LITERAL))
            self.skip()
            if self.peek() == ",":
                self.i += 1
                self.skip()
            elif self.peek() != ")":
                self.fail("A comma or a closing parenthesis is expected here")
        self.i += 1
        self.depth -= 1
        return args

    def call(self, name: str) -> Call:
        at = self.i
        if name not in FUNCTIONS:
            self.fail(f'There is no function "{name}"', at)
        self.i += len(name)
        args = self.arguments(None)
        least, most = FUNCTIONS[name]
        if not least <= len(args) <= most:
            self.fail(_ARITY[name], at)
        return self.made(Call(name, tuple(args), at))

    def filter(self) -> Filter:
        at = self.i
        name = self.name()
        if name not in FILTERS:
            self.fail(f'There is no filter "{name}"', at)
        args: list = []
        named: list = []
        if self.peek() == "(":
            args = self.arguments(named)
        return Filter(name, tuple(args), tuple(named), at)

    def expression(self, start: int) -> Expr:
        self.skip()
        node = self.either(_A_NAME)
        self.skip()
        if self.peek(2) != "}}":
            self.fail("The expression is not closed: add }}" if self.i >= len(self.text) else "}} is expected here")
        self.i += 2
        return Expr(node, start, self.i, tuple(self.paths))


_ARITY = {
    "if": "if takes a condition, the value when it holds and, if wanted, the value when it does not",
    "first_of": "first_of takes one value at least",
    "min": "min takes one value at least",
    "max": "max takes one value at least",
}


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
    texts) read, with the position of the expression each is in: what a graph is validated with."""
    found: list[tuple[str, int]] = []
    if isinstance(value, str):
        if "{{" in value:
            for part in parse(value):
                if isinstance(part, Expr):
                    found += [(path.root, part.position) for path in part.paths]
    elif isinstance(value, dict):
        for item in value.values():
            found += references(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            found += references(item)
    return found


def first_names(value: Any, root: str) -> set[str]:
    """The first names read under ``root`` by the templates of a value: ``config.url`` → ``url``.
    Raises ``ExpressionError`` on a text that cannot be read."""
    found: set[str] = set()
    if isinstance(value, str) and "{{" in value:
        for part in parse(value):
            if isinstance(part, Expr):
                for path in part.paths:
                    if path.root == root and path.steps and isinstance(path.steps[0], str):
                        found.add(path.steps[0])
    elif isinstance(value, dict):
        for item in value.values():
            found |= first_names(item, root)
    elif isinstance(value, (list, tuple)):
        for item in value:
            found |= first_names(item, root)
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


def _moment(value: Any) -> datetime:
    """A moment as it is written: a number of seconds since 1970, or an ISO 8601 text (UTC when it names no zone)."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    moment = datetime.fromisoformat(_text(value).replace("Z", "+00:00"))
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment


def _date(value: Any, fmt: str = "%Y-%m-%d %H:%M") -> str:
    if len(fmt) > 60:
        raise ValueError("The date format is too long")
    return _moment(value).astimezone(timezone.utc).strftime(fmt)


_UNITS = {"second": 1, "minute": 60, "hour": 3600, "day": 86_400, "week": 604_800}


def _unit(name: Any) -> int:
    return _UNITS[_text(name).strip().lower().removesuffix("s")]


def _timestamp(value: Any) -> int:
    """A moment as whole seconds since 1970: what two dates are compared and subtracted as."""
    return math.floor(_moment(value).timestamp())


def _date_add(value: Any, amount: Any, unit: Any = "days") -> str:
    """The moment that is so much later (earlier, with a negative amount), written as ISO 8601 in UTC."""
    seconds = math.floor(_moment(value).timestamp() + _numeric(amount) * _unit(unit))
    return datetime.fromtimestamp(seconds, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _date_diff(value: Any, other: Any, unit: Any = "days") -> int:
    """How many whole units the value is after ``other`` (negative when it is before)."""
    return math.trunc((_moment(value).timestamp() - _moment(other).timestamp()) / _unit(unit))


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


def _map(value: Any, *flat: Any, **pairs: Any) -> Any:
    """Another value for each value named: ``map(high='1')``, or, for what is not a name,
    pairs one after the other: ``map('1', 'open', '2', 'in_progress')``."""
    if len(flat) % 2:
        raise ValueError("pairs")
    fallback = pairs.pop("else", value)
    wanted = _text(value).casefold()
    for at in range(0, len(flat), 2):
        if wanted == _text(flat[at]).casefold():
            return flat[at + 1]
    for key, mapped in pairs.items():
        if wanted == key.casefold():
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


def _urlencode(value: Any) -> str:
    """A text as it is written inside an address: everything but letters, digits and ``-._~`` percent-encoded,
    so that a value put in a path or a query cannot change either."""
    return quote(_text(value), safe="")


def _base64url(value: Any) -> str:
    """A text in base64 as an address takes it (``-`` and ``_``, no padding): how some APIs name a URL."""
    return base64.urlsafe_b64encode(_text(value).encode("utf-8")).decode("ascii").rstrip("=")


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _numeric(value: Any) -> Any:
    if not _is_number(value):
        raise ValueError("That is not a number")
    return value


def _tidy(number: Any) -> Any:
    """A number that was computed, as both parsers write it: whole when it is whole, and never beyond
    what they count alike."""
    if isinstance(number, float):
        if number != number or abs(number) > MAX_NUMBER:
            raise ValueError("too large")
        return int(number) if number.is_integer() else number
    if abs(number) > MAX_NUMBER:
        raise ValueError("too large")
    return number


def _true(value: Any) -> bool:
    """What counts as yes: anything but nothing, false, zero and what is empty."""
    return value is not MISSING and value not in (None, False, "", 0, [], {})


def _contained(left: Any, right: Any) -> bool:
    """``in``: an item of a list, a part of a text, a key of an object."""
    if isinstance(right, str):
        return _text(left).casefold() in right.casefold()
    if isinstance(right, dict):
        return _text(left) in right
    return any(compare(left, "eq", item) for item in _listed(right))


def _round(value: Any, digits: Any = 0) -> Any:
    """To so many decimals, a half away from zero (2.5 is 3, -2.5 is -3), in both parsers alike."""
    number = _numeric(value)
    if isinstance(digits, bool) or not isinstance(digits, int) or not 0 <= digits <= 10:
        raise ValueError("digits")
    scale = 10**digits
    out = math.floor(abs(number) * scale + 0.5) / scale
    return _tidy(-out if number < 0 else out)


def _numbers(value: Any) -> list:
    return [_numeric(item) for item in _listed(value)]


def _total(value: Any) -> Any:
    total = 0
    for item in _numbers(value):
        total += item
    return _tidy(total)


def _least(value: Any) -> Any:
    return min(_numbers(value), default=None)


def _most(value: Any) -> Any:
    return max(_numbers(value), default=None)


def _percent(value: Any, total: Any, digits: Any = 0) -> Any:
    """The value as a percentage of a total (0 of nothing is 0)."""
    part, whole = _numeric(value), _numeric(total)
    return 0 if whole == 0 else _round(part * 100 / whole, digits)


def _count(value: Any, key: Any = None, op: Any = None, wanted: Any = None) -> int:
    """How many items; with a field (and a comparison), how many of them satisfy it, as ``where`` reads it."""
    return len(_listed(value)) if key is None else len(_where(value, key, op, wanted))


def _both(value: Any, other: Any) -> tuple[list, list]:
    """Two lists some filter compares item by item: together they are not too many."""
    left, right = _listed(value), _listed(other)
    if len(left) * len(right) > MAX_COMPARED:
        raise ValueError("too many")
    return left, right


def _intersect(value: Any, other: Any) -> list:
    left, right = _both(value, other)
    return [item for item in left if any(compare(item, "eq", wanted) for wanted in right)]


def _without(value: Any, other: Any) -> list:
    left, right = _both(value, other)
    return [item for item in left if not any(compare(item, "eq", wanted) for wanted in right)]


def _union(value: Any, other: Any) -> list:
    """The items of the list, then those of the other that it does not have already."""
    left, right = _both(value, other)
    return left + [item for item in right if not any(compare(item, "eq", have) for have in left)]


def _has_all(value: Any, other: Any) -> bool:
    left, right = _both(value, other)
    return all(any(compare(item, "eq", wanted) for item in left) for wanted in right)


def _plural(value: Any, one: Any, many: Any = None) -> str:
    """A count with its noun: "1 report", "2 reports". A list counts as its length."""
    number = len(value) if isinstance(value, (list, tuple, dict)) else _numeric(value)
    noun = _text(one) if number == 1 else _text(one) + "s" if many is None else _text(many)
    return f"{_text(number)} {noun}"


def _limit(value: Any, count: Any) -> Any:
    """The first items of a list, or the first characters of a text."""
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        raise ValueError("count")
    return list(value[:count]) if isinstance(value, (list, tuple)) else _text(value)[:count]


def _pick(value: Any, **paths: Any) -> Any:
    """Each item as a new object: ``pick(name='attributes.name', id='id')``. One object gives one object."""

    def shaped(item: Any) -> dict:
        return {key: None if (found := lookup(item, _text(path))) is MISSING else found for key, path in paths.items()}

    if not paths:
        raise ValueError("fields")
    return [shaped(item) for item in value] if isinstance(value, (list, tuple)) else shaped(value)


def _sort_by(value: Any, key: Any, order: Any = "asc") -> list:
    """The items in the order of one of their fields: numbers as numbers, anything else as text."""
    if _text(order) not in ("asc", "desc"):
        raise ValueError("order")
    items = _listed(value)
    keys = [None if (found := lookup(item, _text(key))) is MISSING else found for item in items]
    if not all(_is_number(found) for found in keys):
        keys = [_text(found) for found in keys]
    order_of = sorted(range(len(items)), key=lambda at: keys[at], reverse=_text(order) == "desc")
    return [items[at] for at in order_of]


FILTERS = {
    "default": None,  # handled by the evaluator: it is the one filter that takes a missing value
    "urlencode": _urlencode,
    "base64url": _base64url,
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
    # Counting and deciding (6.5).
    "round": _round,
    "abs": lambda v: abs(_numeric(v)),
    "sum": _total,
    "min": _least,
    "max": _most,
    "percent": _percent,
    "count": _count,
    "intersect": _intersect,
    "without": _without,
    "union": _union,
    "has_any": lambda v, other: bool(_intersect(v, other)),
    "has_all": _has_all,
    "plural": _plural,
    "starts_with": lambda v, start: _text(v).casefold().startswith(_text(start).casefold()),
    "ends_with": lambda v, end: _text(v).casefold().endswith(_text(end).casefold()),
    "limit": _limit,
    "entries": lambda v: [{"key": key, "value": item} for key, item in v.items()] if isinstance(v, dict) else [],
    "pick": _pick,
    "sort_by": _sort_by,
    "sha256": lambda v: hashlib.sha256(_text(v).encode("utf-8")).hexdigest(),
    "timestamp": _timestamp,
    "date_add": _date_add,
    "date_diff": _date_diff,
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


def path_text(expr: Any) -> str:
    """A path as it is written (of an ``Expr`` that is one path, or of a ``Path``)."""
    out = expr.root
    for step in expr.steps:
        out += (
            f".{step}"
            if isinstance(step, str) and _NAME.fullmatch(step)
            else f"[{'*' if step is STAR else json.dumps(step)}]"
        )
    return out


def _present(value: Value, node: Any, expr: Expr) -> Value:
    """``value``, unless it is a path that led nowhere and nothing took its place."""
    if value.data is MISSING:
        path = node.operand if isinstance(node, Piped) else node
        raise ExpressionError(
            expr.position, f"There is nothing at {path_text(path)}: add | default(…) if it may be absent"
        )
    return value


def _compute(node: Any, scope: Scope, expr: Expr) -> Value:
    """What a part of an expression gives. A path that leads nowhere gives MISSING, which only
    ``default``, ``first_of`` and the condition of ``if`` accept: everything else asks ``_present``."""
    if isinstance(node, Literal):
        return Value(node.value)
    if isinstance(node, Path):
        if node.root not in scope.values:
            if node.root == "credentials":
                raise ExpressionError(expr.position, CREDENTIALS_ELSEWHERE)
            raise ExpressionError(expr.position, f'"{node.root}" is not a name that can be read here')
        return Value(_walk(scope.values[node.root], node.steps), scope.classes_at(node.root, node.steps))
    if isinstance(node, Piped):
        value = _compute(node.operand, scope, expr)
        data, classes = value.data, value.classes
        for item in node.filters:
            if item.name == "default":
                if data is MISSING or data is None:
                    # Read only when it is needed: the other value may be absent too.
                    if item.args:
                        other = _present(_compute(item.args[0], scope, expr), item.args[0], expr)
                        data, classes = other.data, classes | other.classes
                    else:
                        data = ""
                continue
            if data is MISSING:
                break
            args = [_present(_compute(arg, scope, expr), arg, expr) for arg in item.args]
            named = [(key, _present(_compute(arg, scope, expr), arg, expr)) for key, arg in item.named]
            if item.name == "in_list":
                if scope.in_list is None or len(args) != 1:
                    raise ExpressionError(item.position, "in_list takes the name of a list, where lists can be read")
                data = bool(scope.in_list(_text(args[0].data), data))
                classes = frozenset({"verdict"})  # a yes or a no, not the value it was asked about
                continue
            try:
                data = FILTERS[item.name](data, *(arg.data for arg in args), **{key: arg.data for key, arg in named})
            except (TypeError, ValueError, KeyError, IndexError, OverflowError, ZeroDivisionError):
                raise ExpressionError(
                    item.position, f'The filter "{item.name}" cannot be applied to this value'
                ) from None
            for arg in (*args, *(arg for _key, arg in named)):
                classes |= arg.classes
        return Value(data, classes)
    if isinstance(node, ListOf):
        items = [_present(_compute(item, scope, expr), item, expr) for item in node.items]
        return Value([item.data for item in items], frozenset().union(*(item.classes for item in items)))
    if isinstance(node, Unary):
        value = _present(_compute(node.operand, scope, expr), node.operand, expr)
        if node.op == "not":
            return Value(not _true(value.data), value.classes)
        if not _is_number(value.data):
            raise ExpressionError(node.position, "Only a number has an opposite: use | int or | float on a text")
        return Value(_tidy(-value.data), value.classes)
    if isinstance(node, Call):
        if node.name == "if":
            asked = _compute(node.args[0], scope, expr)
            chosen = node.args[1] if _true(asked.data) else node.args[2] if len(node.args) > 2 else None
            if chosen is None:
                return Value(None, asked.classes)
            value = _present(_compute(chosen, scope, expr), chosen, expr)
            return Value(value.data, value.classes | asked.classes)
        if node.name == "first_of":
            for arg in node.args:
                value = _compute(arg, scope, expr)
                if not compare(value.data, "empty", None):
                    return value
            return Value(None)
        values = [_present(_compute(arg, scope, expr), arg, expr) for arg in node.args]
        given = values[0].data if len(values) == 1 else [value.data for value in values]
        try:
            data = _least(given) if node.name == "min" else _most(given)
        except ValueError:
            raise ExpressionError(node.position, f"{node.name} takes numbers") from None
        return Value(data, frozenset().union(*(value.classes for value in values)))
    left = _present(_compute(node.left, scope, expr), node.left, expr)
    if node.op in ("or", "and"):
        # As a person reads it: the right side is not looked at when the left one decides.
        if _true(left.data) == (node.op == "or"):
            return left
        right = _present(_compute(node.right, scope, expr), node.right, expr)
        return Value(right.data, left.classes | right.classes)
    right = _present(_compute(node.right, scope, expr), node.right, expr)
    classes = left.classes | right.classes
    if node.op in ("in", "not_in"):
        return Value(_contained(left.data, right.data) == (node.op == "in"), classes)
    if node.op == "~":
        text = _text(left.data) + _text(right.data)
        if len(text) > MAX_STRING:
            raise ExpressionError(node.position, "The text this gives is too long")
        return Value(text, classes)
    if node.op in ("+", "-", "*", "/"):
        if not _is_number(left.data) or not _is_number(right.data):
            raise ExpressionError(
                node.position, f'"{node.op}" takes two numbers: use | int or | float on a text, ~ to join texts'
            )
        if node.op == "/" and right.data == 0:
            raise ExpressionError(node.position, "A number cannot be divided by zero")
        a, b = left.data, right.data
        try:
            data = _tidy(a + b if node.op == "+" else a - b if node.op == "-" else a * b if node.op == "*" else a / b)
        except (ValueError, OverflowError):
            raise ExpressionError(node.position, "The number this gives is too large") from None
        return Value(data, classes)
    return Value(compare(left.data, node.op, right.data), classes)


def evaluate(expr: Expr, scope: Scope) -> Value:
    return _present(_compute(expr.node, scope, expr), expr.node, expr)


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

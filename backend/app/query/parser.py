"""The query language: text to a tree.

    type:Phishing and !status:closed and severity:>=high and owner:"" and
    created:>="7 days ago" and category IN (malware, "data loss")

Grammar (hand-written, no regular expression runs on the whole input)::

    query   := or
    or      := and ( "or" and )*
    and     := unary ( ["and"] unary )*
    unary   := ( "not" | "-" | "!" ) unary | group | term
    group   := "(" query ")"
    term    := field ":" [op] value | field ":" range | field list | value
    op      := ">=" | "<=" | ">" | "<" | "!"
    range   := "[" value " TO " value "]"
    list    := [ "not" ] "in" "(" value ( [","] value )* ")"
    value   := bare | quoted
    field   := name ( "." name )*

A bare value may hold the wildcards ``*`` (any run of characters) and ``?``
(one character); a backslash before a wildcard, a parenthesis, a quote or a
space takes it literally, and is itself anywhere else (a Windows path). A quoted
value is literal, with ``\\"`` and ``\\\\`` as escapes. ``field:""`` asks for an
empty field, ``field:*`` for one that holds something.

"Is not" is written before the field: ``!status:closed``. Until 5.0 the same
condition was written ``status:!closed``: that writing was read through 5.x and
is refused since 6.0, with where the "!" goes (``modern`` gives a query in
today's writing, which is what the query box does). A list is a shorter way
to write the same conditions: ``field IN (a, b)`` is ``field:a or field:b``,
``field NOT IN (a, b)`` is ``!field:a !field:b``, and the tree holds those.

The same grammar is implemented in ``frontend/src/domain/query/parse.js``;
both are checked against ``backend/tests/data/query_vectors.json``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

MAX_LENGTH = 2000
MAX_DEPTH = 20
MAX_TERMS = 200

# Messages are fixed sentences, by code: the API returns them, never an exception's text.
MESSAGES = {
    "too_long": f"The query is longer than {MAX_LENGTH} characters",
    "too_deep": f"The query nests more than {MAX_DEPTH} levels",
    "too_many_terms": f"The query has more than {MAX_TERMS} conditions",
    "unclosed_quote": 'A quote is not closed: add the closing "',
    "unclosed_group": "A parenthesis is not closed: add the closing )",
    "unexpected_close": "A closing parenthesis has no opening one",
    "empty_group": "The parentheses hold nothing",
    "missing_value": "A value is expected after the colon",
    "bad_range": "A range is written [from TO to]",
    "old_not": '"Is not" is written before the field: !status:closed',
    "bad_list": "A list is written IN (a, b, c)",
    "dangling_operator": "A condition is expected here",
}


class QueryError(ValueError):
    """A query that cannot be read or compiled: where, and a fixed sentence."""

    def __init__(self, code: str, position: int, message: str | None = None, suggestion: str | None = None):
        self.code = code
        self.position = position
        self.message = message or MESSAGES[code]
        self.suggestion = suggestion
        super().__init__(self.message)

    def as_dict(self) -> dict:
        out = {"code": self.code, "position": self.position, "message": self.message}
        if self.suggestion:
            out["suggestion"] = self.suggestion
        return out


# --------------------------------------------------------------------------- #
# The tree                                                                    #
# --------------------------------------------------------------------------- #
ANY = "*"  # a run of characters
ONE = "?"  # one character


@dataclass(frozen=True)
class Value:
    """What a condition compares with.

    ``parts`` is the value as literal strings and wildcards (``ANY``, ``ONE``
    as ``Wild`` items); ``text`` is the same without marking them, for the
    cases that take the value as it reads (a date, a number).
    """

    text: str
    quoted: bool = False
    parts: tuple = ()

    @property
    def wildcard(self) -> bool:
        return any(isinstance(part, Wild) for part in self.parts)

    @property
    def is_any(self) -> bool:
        """``*`` alone: the field holds something."""
        return not self.quoted and len(self.parts) == 1 and self.parts[0] == Wild(ANY)

    @property
    def is_empty(self) -> bool:
        """``""``: the field is empty."""
        return self.quoted and self.text == ""


@dataclass(frozen=True)
class Wild:
    kind: str  # ANY | ONE


@dataclass(frozen=True)
class Term:
    """``field:value`` with its operator: ``=`` ``!`` ``>`` ``>=`` ``<`` ``<=``."""

    field: str
    op: str
    value: Value
    position: int = 0
    raw: str = ""


@dataclass(frozen=True)
class Range:
    """``field:[low TO high]``; an end written ``*`` is open (None)."""

    field: str
    low: Value | None
    high: Value | None
    position: int = 0
    raw: str = ""


@dataclass(frozen=True)
class Text:
    """A value on its own: looked for in the text fields of the entity."""

    value: Value
    position: int = 0


@dataclass(frozen=True)
class Not:
    node: object


@dataclass(frozen=True)
class And:
    nodes: tuple = field(default_factory=tuple)


@dataclass(frozen=True)
class Or:
    nodes: tuple = field(default_factory=tuple)


def literal(text: str) -> Value:
    """A value taken as it is (no wildcards): for conditions built by code."""
    return Value(text=text, quoted=True, parts=(text,) if text else ())


# --------------------------------------------------------------------------- #
# Reading                                                                     #
# --------------------------------------------------------------------------- #
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*")
_SPACE = " \t\r\n"
_OPS = (">=", "<=", ">", "<", "!")


def _list_opening(text: str, at: int) -> tuple[int, bool] | None:
    """``field IN (`` and ``field NOT IN (``, read after the name of a field: where the values start
    and whether the list is negated, or None when what follows the name is not a list. Read a
    character at a time, like the rest: no expression runs over what a person typed."""

    def spaces(i: int) -> int:
        while i < len(text) and text[i] in _SPACE:
            i += 1
        return i

    i = spaces(at)
    if i == at:
        return None
    negated = False
    if text[i : i + 3].lower() == "not":
        after = spaces(i + 3)
        if after == i + 3:
            return None
        negated, i = True, after
    if text[i : i + 2].lower() != "in":
        return None
    i = spaces(i + 2)
    if i < len(text) and text[i] == "(":
        return i + 1, negated
    return None


# What a backslash takes literally in a bare value; before anything else it is itself.
_ESCAPED = '*?()" '


class _Reader:
    def __init__(self, text: str):
        self.text = text
        self.i = 0
        self.terms = 0
        # Where "is not" is written as it was before 5.0 (``field:!value``): the start of the
        # condition and the place of its "!".
        self.old: list[tuple[int, int]] = []

    # -- helpers --------------------------------------------------------------
    def skip(self) -> None:
        while self.i < len(self.text) and self.text[self.i] in _SPACE:
            self.i += 1

    def peek(self) -> str:
        return self.text[self.i] if self.i < len(self.text) else ""

    def keyword(self) -> str:
        """The connective at the cursor (``and``, ``or``, ``not``), or ""."""
        for word in ("and", "or", "not"):
            end = self.i + len(word)
            if self.text[self.i : end].lower() == word and (end >= len(self.text) or self.text[end] in _SPACE + "()"):
                return word
        return ""

    def counted(self) -> None:
        self.terms += 1
        if self.terms > MAX_TERMS:
            raise QueryError("too_many_terms", self.i)

    # -- grammar --------------------------------------------------------------
    def query(self, depth: int):
        nodes = [self.conjunction(depth)]
        while True:
            self.skip()
            if self.keyword() != "or":
                break
            at = self.i
            self.i += 2
            self.skip()
            if not self.peek() or self.peek() == ")" or self.keyword() in ("and", "or"):
                raise QueryError("dangling_operator", at)
            nodes.append(self.conjunction(depth))
        return nodes[0] if len(nodes) == 1 else Or(tuple(nodes))

    def conjunction(self, depth: int):
        nodes = []
        while True:
            self.skip()
            if not self.peek() or self.peek() == ")":
                break
            word = self.keyword()
            if word == "or":
                if not nodes:
                    raise QueryError("dangling_operator", self.i)
                break
            if word == "and":
                at = self.i
                self.i += 3
                self.skip()
                if not nodes or not self.peek() or self.peek() == ")" or self.keyword() in ("and", "or"):
                    raise QueryError("dangling_operator", at)
            nodes.append(self.unary(depth))
        if not nodes:
            raise QueryError("dangling_operator", self.i)
        return nodes[0] if len(nodes) == 1 else And(tuple(nodes))

    def unary(self, depth: int):
        if depth > MAX_DEPTH:
            raise QueryError("too_deep", self.i)
        if self.keyword() == "not":
            at = self.i
            self.i += 3
            self.skip()
            if not self.peek() or self.peek() == ")" or self.keyword() in ("and", "or"):
                raise QueryError("dangling_operator", at)
            return Not(self.unary(depth + 1))
        if self.peek() == "-" and self.i + 1 < len(self.text) and self.text[self.i + 1] not in _SPACE + ")":
            self.i += 1
            return Not(self.unary(depth + 1))
        if self.peek() == "!" and self.i + 1 < len(self.text) and self.text[self.i + 1] not in _SPACE + ")":
            at = self.i
            self.i += 1
            node = self.unary(depth + 1)
            if isinstance(node, Term) and node.op == "=":
                # "Is not", empty fields included: one condition, not the negation of one.
                return Term(node.field, "!", node.value, at, self.text[at : self.i])
            return Not(node)
        if self.peek() == "(":
            at = self.i
            self.i += 1
            self.skip()
            if self.peek() == ")":
                raise QueryError("empty_group", at)
            if not self.peek():
                raise QueryError("unclosed_group", at)
            node = self.query(depth + 1)
            self.skip()
            if self.peek() != ")":
                raise QueryError("unclosed_group", at)
            self.i += 1
            return node
        return self.term()

    def term(self):
        start = self.i
        self.counted()
        if self.peek() == '"':
            return Text(self.quoted(), start)
        name = _NAME.match(self.text, self.i)
        if name and name.end() < len(self.text) and self.text[name.end()] == ":":
            self.i = name.end() + 1
            op = "="
            for candidate in _OPS:
                if self.text.startswith(candidate, self.i):
                    op = candidate
                    if op == "!":
                        self.old.append((start, self.i))
                    self.i += len(candidate)
                    break
            if self.peek() == "[":
                if op != "=":
                    raise QueryError("bad_range", self.i)
                low, high = self.range()
                return Range(name.group(), low, high, start, self.text[start : self.i])
            at = self.i
            value = self.quoted() if self.peek() == '"' else self.bare()
            if not value.quoted and not value.parts:
                raise QueryError("missing_value", at)
            return Term(name.group(), op, value, start, self.text[start : self.i])
        if name:
            listed = _list_opening(self.text, name.end())
            if listed:
                return self.listed(name.group(), start, listed[0], listed[1])
        return Text(self.bare(), start)

    def listed(self, name: str, start: int, opened: int, negated: bool):
        """``field IN (a, b)``: the conditions it stands for, one for each value."""
        self.i = opened
        terms = []
        while True:
            while self.peek() and (self.peek() in _SPACE or self.peek() == ","):
                self.i += 1
            if not self.peek():
                raise QueryError("bad_list", start)
            if self.peek() == ")":
                self.i += 1
                break
            if terms:
                self.counted()
            value = self.quoted() if self.peek() == '"' else self.bare(stop=",")
            terms.append(Term(name, "!" if negated else "=", value, start, self.text[start:opened]))
        if not terms:
            raise QueryError("bad_list", start)
        if len(terms) == 1:
            return terms[0]
        return And(tuple(terms)) if negated else Or(tuple(terms))

    def quoted(self) -> Value:
        start = self.i
        self.i += 1
        out = []
        while self.i < len(self.text):
            char = self.text[self.i]
            if char == "\\" and self.i + 1 < len(self.text) and self.text[self.i + 1] in '"\\':
                out.append(self.text[self.i + 1])
                self.i += 2
            elif char == '"':
                self.i += 1
                text = "".join(out)
                return Value(text=text, quoted=True, parts=(text,) if text else ())
            else:
                out.append(char)
                self.i += 1
        raise QueryError("unclosed_quote", start)

    def bare(self, stop: str = "") -> Value:
        """Characters up to a space or the parenthesis that closes the group
        (parentheses opened inside the value are part of it)."""
        parts: list = []
        run: list[str] = []
        opened = 0

        def flush() -> None:
            if run:
                parts.append("".join(run))
                run.clear()

        while self.i < len(self.text):
            char = self.text[self.i]
            if char in _SPACE or char in stop:
                break
            if char == ")":
                if opened == 0:
                    break
                opened -= 1
            elif char == "(":
                opened += 1
            if char == "\\" and self.i + 1 < len(self.text) and self.text[self.i + 1] in _ESCAPED:
                run.append(self.text[self.i + 1])
                self.i += 2
                continue
            if char in (ANY, ONE):
                flush()
                # A run of stars is one star.
                if not (char == ANY and parts and parts[-1] == Wild(ANY)):
                    parts.append(Wild(char))
            else:
                run.append(char)
            self.i += 1
        flush()
        text = "".join(part if isinstance(part, str) else part.kind for part in parts)
        return Value(text=text, quoted=False, parts=tuple(parts))

    def range(self) -> tuple[Value | None, Value | None]:
        start = self.i
        self.i += 1  # [
        ends = []
        for index in (0, 1):
            self.skip()
            if not self.peek() or self.peek() == "]":
                raise QueryError("bad_range", start)
            value = self.quoted() if self.peek() == '"' else self.bare(stop="]")
            ends.append(None if value.is_any else value)
            if index == 0:
                self.skip()
                if self.text[self.i : self.i + 2].lower() != "to" or self.text[self.i + 2 : self.i + 3] not in (
                    " ",
                    "\t",
                ):
                    raise QueryError("bad_range", start)
                self.i += 2
        self.skip()
        if self.peek() != "]":
            raise QueryError("bad_range", start)
        self.i += 1
        return ends[0], ends[1]


def _read(source: str):
    if len(source) > MAX_LENGTH:
        raise QueryError("too_long", MAX_LENGTH)
    reader = _Reader(source)
    reader.skip()
    if not reader.peek():
        return None, reader
    node = reader.query(0)
    reader.skip()
    if reader.peek() == ")":
        raise QueryError("unexpected_close", reader.i)
    return node, reader


def parse(text: str | None):
    """The tree of a query; None for an empty one (it matches everything).
    Raises ``QueryError`` with the position of what cannot be read."""
    node, reader = _read(text or "")
    if reader.old:
        # The writing before 5.0: refused, with the query as it is written now.
        raise QueryError("old_not", min(bang for _start, bang in reader.old), suggestion=_rewritten(text or "", reader))
    return node


def _rewritten(source: str, reader: "_Reader") -> str:
    for start, bang in sorted(reader.old, reverse=True):
        source = source[:start] + "!" + source[start:bang] + source[bang + 1 :]
    return source


def modern(text: str | None) -> str:
    """A query in today's writing: ``status:!closed`` becomes ``!status:closed``. The tree is the
    same. A query that cannot be read is given back as it is."""
    source = text or ""
    try:
        reader = _read(source)[1]
    except QueryError:
        return source
    return _rewritten(source, reader)


# --------------------------------------------------------------------------- #
# The tree as JSON (the test vectors shared with the frontend)                #
# --------------------------------------------------------------------------- #
def _value_json(value: Value | None):
    if value is None:
        return None
    out: dict = {"text": value.text, "quoted": value.quoted}
    if value.wildcard:
        out["pattern"] = [part if isinstance(part, str) else {"wild": part.kind} for part in value.parts]
    return out


def to_json(node):
    """The tree as plain data, the same the frontend's parser gives."""
    if node is None:
        return None
    if isinstance(node, And):
        return {"and": [to_json(item) for item in node.nodes]}
    if isinstance(node, Or):
        return {"or": [to_json(item) for item in node.nodes]}
    if isinstance(node, Not):
        return {"not": to_json(node.node)}
    if isinstance(node, Range):
        return {
            "field": node.field,
            "range": [_value_json(node.low), _value_json(node.high)],
            "position": node.position,
        }
    if isinstance(node, Term):
        return {"field": node.field, "op": node.op, "value": _value_json(node.value), "position": node.position}
    return {"text": _value_json(node.value), "position": node.position}

"""One parsed Sigma rule -> a predicate over the fields of a record.

pySigma has parsed the rule (modifiers resolved, the condition a tree); this module turns the tree into closures.
The fields of a record are a dict made by ``engine.py``:

    * keys are the lower-case field names (Sigma names are matched without regard to case);
    * string values are lower-cased, so a plain comparison is case-insensitive without work per rule;
    * ``r[ORIG]`` holds the same fields with the values as they were: ``|cased`` and ``|re`` read those;
    * a value may be a list (any element may match), a number, a bool, or None.

What a rule may mean is decided here and nowhere else:

    * a field that is missing never matches ``*``; ``null`` is true for a field that is missing, None or ``""``;
    * ``exists`` is true for a field that is present and not None;
    * a keyword (a value without a field) is searched in all the values of the record joined by newlines;
    * regular expressions run in RE2 (``google-re2``): no backtracking, so a hostile rule cannot hang the job.
      A pattern RE2 refuses makes the rule unsupported, with the reason;
    * ``|expand``, the timestamp-part modifiers and condition nodes we do not know are unsupported (``Unsupported``
      carries the sentence shown to the analyst).

Besides the predicate a compiled rule says which fields must be present for any match to be possible
(``required``): the engine checks that before it runs the predicate.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import re2
import sigma.conditions as conditions
from sigma.rule import SigmaRule
from sigma.types import (
    CompareOperators,
    SigmaBool,
    SigmaCasedString,
    SigmaCIDRExpression,
    SigmaCompareExpression,
    SigmaExists,
    SigmaExpansion,
    SigmaFieldReference,
    SigmaNull,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaRegularExpressionFlag,
    SigmaString,
    SigmaTimestampPart,
    SpecialChars,
)

Pred = Callable[[dict], bool]
ORIG = "\0o"
RAW = "\0raw"
RAW_ORIG = "\0rawo"
MULTI, SINGLE = SpecialChars.WILDCARD_MULTI, SpecialChars.WILDCARD_SINGLE
_FLAGS = {
    SigmaRegularExpressionFlag.IGNORECASE: "i",
    SigmaRegularExpressionFlag.MULTILINE: "m",
    SigmaRegularExpressionFlag.DOTALL: "s",
}


class Unsupported(Exception):
    """The rule cannot be run by Nik; the message is the reason shown to the analyst."""


@dataclass
class Compiled:
    pred: Pred
    required: frozenset[str]
    used: frozenset[str]


_Node = tuple[Pred, frozenset, frozenset]
_NONE: frozenset[str] = frozenset()


def _low(value: Any) -> str:
    return value if value.__class__ is str else str(value).lower()


def _text(value: Any) -> str:
    return value if value.__class__ is str else str(value)


def _each(value: Any):
    """A record value may be a list (a field with several values): any element may match."""
    return value if value.__class__ in (list, tuple) else (value,)


def _number(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _re2(pattern: str) -> Any:
    try:
        return re2.compile(pattern)
    except re2.error as error:
        raise Unsupported(f"the regular expression is refused by RE2 (no backtracking): {error}") from None


def _wildcards(items: tuple, lower: bool) -> str:
    """A string with wildcards as an RE2 pattern (``*`` any run, ``?`` one character; the dot matches a newline)."""
    parts = []
    for item in items:
        if isinstance(item, str):
            parts.append(re2.escape(item.lower() if lower else item))
        else:
            parts.append(".*" if item is MULTI else ".")
    return "(?s)" + "".join(parts)


def _pattern(value: SigmaRegularExpression) -> str:
    """The expression as the rule wrote it, with the flags (i, m, s) in front."""
    expression = value.regexp
    text = getattr(expression, "original", None)
    if not isinstance(text, str):
        text = str(expression)
    flags = "".join(sorted(_FLAGS[flag] for flag in value.flags))
    return f"(?{flags}){text}" if flags else text


# --------------------------------------------------------------------------- #
# Leaves: ``field: value``                                                    #
# --------------------------------------------------------------------------- #
def _string(field: str, value: SigmaString) -> Pred:
    if value.contains_placeholder():
        raise Unsupported("the |expand modifier needs values Nik does not have (a placeholder is not filled)")
    cased = isinstance(value, SigmaCasedString)
    items = value.s
    lead, trail = bool(items) and items[0] is MULTI, bool(items) and items[-1] is MULTI
    core = items[(1 if lead else 0) : len(items) - (1 if trail else 0)]
    conv = _text if cased else _low
    if all(isinstance(item, str) for item in core):
        needle = "".join(core) if cased else "".join(core).lower()
        if lead and trail:

            def test(x: str) -> bool:
                return needle in x

        elif lead:
            test = lambda x: x.endswith(needle)  # noqa: E731
        elif trail:
            test = lambda x: x.startswith(needle)  # noqa: E731
        else:
            test = lambda x: x == needle  # noqa: E731
    else:
        match = _re2(_wildcards(items, lower=not cased)).fullmatch
        test = lambda x: match(x) is not None  # noqa: E731

    def pred(r: dict) -> bool:
        v = (r[ORIG] if cased else r).get(field)
        if v is None:
            return False
        if v.__class__ in (list, tuple):
            return any(test(conv(e)) for e in v if e is not None)
        return test(conv(v))

    return pred


def _leaf(field: str, value: Any) -> _Node:
    """The predicate of ``field: value`` with the fields it needs and the fields it names."""
    used = frozenset({field})
    if isinstance(value, SigmaTimestampPart):
        raise Unsupported("the timestamp modifiers (|minute, |hour, |day, |week, |month, |year) are not run by Nik")
    if isinstance(value, SigmaNull):
        return (lambda r: r.get(field) is None or r.get(field) == ""), _NONE, used
    if isinstance(value, SigmaExists):
        want = bool(value.exists)
        return (lambda r: (r.get(field) is not None) == want), (used if want else _NONE), used
    if isinstance(value, SigmaBool):
        flag = bool(value)
        return (lambda r: r.get(field) is flag or _low(r.get(field)) == str(flag).lower()), used, used
    if isinstance(value, SigmaNumber):
        number = float(value.number)
        return (lambda r: any(_number(e) == number for e in _each(r.get(field)))), used, used
    if isinstance(value, SigmaCompareExpression):
        number = float(value.number.number)
        compare = {
            CompareOperators.LT: lambda a: a < number,
            CompareOperators.LTE: lambda a: a <= number,
            CompareOperators.GT: lambda a: a > number,
            CompareOperators.GTE: lambda a: a >= number,
            CompareOperators.NEQ: lambda a: a != number,
        }[value.op]
        return (lambda r: any((x := _number(e)) is not None and compare(x) for e in _each(r.get(field)))), used, used
    if isinstance(value, SigmaCIDRExpression):
        network = value.network

        def cidr(r: dict) -> bool:
            for e in _each(r.get(field)):
                try:
                    if ipaddress.ip_address(str(e)) in network:
                        return True
                except ValueError:
                    continue
            return False

        return cidr, used, used
    if isinstance(value, SigmaFieldReference):
        other = value.field.lower()
        starts, ends = value.starts_with, value.ends_with

        def reference(r: dict) -> bool:
            x, y = r.get(field), r.get(other)
            if x is None or y is None:
                return False
            x, y = _low(x), _low(y)
            if starts and ends:
                return y in x
            return x.startswith(y) if starts else x.endswith(y) if ends else x == y

        return reference, frozenset({field, other}), frozenset({field, other})
    if isinstance(value, SigmaRegularExpression):
        search = _re2(_pattern(value)).search
        return (lambda r: any(search(_text(e)) for e in _each(r[ORIG].get(field)) if e is not None)), used, used
    if isinstance(value, SigmaExpansion):  # base64offset, windash…: any of the forms
        parts = [_leaf(field, inner) for inner in value.values]
        preds = [part[0] for part in parts]
        required = frozenset.intersection(*(part[1] for part in parts)) if parts else _NONE
        return (lambda r: any(p(r) for p in preds)), required, used
    if isinstance(value, SigmaString):
        return _string(field, value), used, used
    raise Unsupported(f"a value of the kind {type(value).__name__} is not run by Nik")


def _raw(r: dict, original: bool) -> str:
    key = RAW_ORIG if original else RAW
    if key not in r:
        source = r[ORIG] if original else r
        r[key] = "\n".join(_text(v) for name, v in source.items() if v is not None and name[0] != "\0")
    return r[key]


def _keyword(value: Any) -> _Node:
    """A value without a field is searched in all the values of the record."""
    if isinstance(value, SigmaExpansion):
        parts = [_keyword(inner)[0] for inner in value.values]
        return (lambda r: any(p(r) for p in parts)), _NONE, _NONE
    if isinstance(value, SigmaRegularExpression):
        search = _re2(_pattern(value)).search
        return (lambda r: search(_raw(r, True)) is not None), _NONE, _NONE
    if isinstance(value, SigmaTimestampPart):
        raise Unsupported("the timestamp modifiers (|minute, |hour, |day, |week, |month, |year) are not run by Nik")
    if isinstance(value, SigmaNumber):
        needle = str(value.number).lower()
        return (lambda r: needle in _raw(r, False)), _NONE, _NONE
    if isinstance(value, SigmaString) and not value.contains_placeholder():
        items = value.s
        if all(isinstance(item, str) for item in items):
            needle = "".join(items).lower()
            return (lambda r: needle in _raw(r, False)), _NONE, _NONE
        search = _re2(_wildcards(items, lower=True)).search
        return (lambda r: search(_raw(r, False)) is not None), _NONE, _NONE
    raise Unsupported(f"a keyword of the kind {type(value).__name__} is not run by Nik")


# --------------------------------------------------------------------------- #
# The condition tree                                                          #
# --------------------------------------------------------------------------- #
def _and(preds: list[Pred]) -> Pred:
    if len(preds) == 1:
        return preds[0]
    if len(preds) == 2:
        a, b = preds
        return lambda r: a(r) and b(r)

    def run(r: dict) -> bool:
        for p in preds:
            if not p(r):
                return False
        return True

    return run


def _any(preds: list[Pred]) -> Pred:
    if len(preds) == 1:
        return preds[0]
    if len(preds) == 2:
        a, b = preds
        return lambda r: a(r) or b(r)

    def run(r: dict) -> bool:
        for p in preds:
            if p(r):
                return True
        return False

    return run


def _or(args: list) -> _Node:
    """The plain ``field: exact`` leaves of an OR on one field become one lookup in a set."""
    exact: dict[str, set[str]] = {}
    rest: list[_Node] = []
    for arg in args:
        value = getattr(arg, "value", None)
        if (
            isinstance(arg, conditions.ConditionFieldEqualsValueExpression)
            and type(value) is SigmaString
            and not value.contains_special()
            and not value.contains_placeholder()
        ):
            exact.setdefault(arg.field.lower(), set()).add("".join(value.s).lower())
        else:
            rest.append(_node(arg))
    nodes: list[_Node] = []
    for name, values in exact.items():
        nodes.append(
            (
                lambda r, name=name, values=values: any(_low(e) in values for e in _each(r.get(name)) if e is not None),
                frozenset({name}),
                frozenset({name}),
            )
        )
    nodes.extend(rest)
    required = frozenset.intersection(*(n[1] for n in nodes)) if nodes else _NONE
    used = frozenset().union(*(n[2] for n in nodes))
    return _any([n[0] for n in nodes]), required, used


def _node(node: Any) -> _Node:
    if isinstance(node, conditions.ConditionAND):
        parts = [_node(arg) for arg in node.args]
        return (
            _and([p[0] for p in parts]),
            frozenset().union(*(p[1] for p in parts)),
            frozenset().union(*(p[2] for p in parts)),
        )
    if isinstance(node, conditions.ConditionOR):
        return _or(list(node.args))
    if isinstance(node, conditions.ConditionNOT):
        pred, _required, used = _node(node.args[0])
        return (lambda r: not pred(r)), _NONE, used
    if isinstance(node, conditions.ConditionFieldEqualsValueExpression):
        return _leaf(node.field.lower(), node.value)
    if isinstance(node, conditions.ConditionValueExpression):
        return _keyword(node.value)
    raise Unsupported(f"a condition of the kind {type(node).__name__} is not run by Nik")


def compile_rule(rule: SigmaRule) -> Compiled:
    """The predicate of a detection rule. Raises ``Unsupported`` with the reason; pySigma errors (a condition
    that does not parse) are ``Unsupported`` too: the rule is listed with that reason, never dropped."""
    from sigma.exceptions import SigmaError

    try:
        parts = []
        for condition in rule.detection.parsed_condition:
            if condition.parsed is None:
                raise Unsupported("the condition could not be read")
            parts.append(_node(condition.parsed))
    except SigmaError as error:
        raise Unsupported(f"pySigma cannot read the detection: {error}") from None
    except RecursionError:
        raise Unsupported("the condition is nested too deep") from None
    if not parts:
        raise Unsupported("the rule has no condition")
    required = frozenset.intersection(*(p[1] for p in parts))
    return Compiled(_any([p[0] for p in parts]), required, frozenset().union(*(p[2] for p in parts)))


def extra_pred(extra: dict) -> Pred:
    """The extra condition of a log source place (``{"eventtype": ["createkey"]}``): any of the values."""
    checks = [(name, frozenset(values)) for name, values in extra.items()]

    def run(r: dict) -> bool:
        for name, values in checks:
            if not any(_low(e) in values for e in _each(r.get(name)) if e is not None):
                return False
        return True

    return run


def refused(error: Exception) -> str:
    """The sentence for a regular expression RE2 does not take (pySigma checks them with RE2 too)."""
    return f"the regular expression is refused by RE2, which has no backtracking: {error}"


def from_source(source: str) -> Compiled:
    """Read the YAML of one rule, have pySigma parse it, and compile it. Raises ``Unsupported`` with the reason."""
    from sigma.exceptions import SigmaError, SigmaRegularExpressionError

    from .documents import DocumentError, load

    try:
        _node, document = load(source)
    except DocumentError as error:
        raise Unsupported(f"the rule cannot be read: {error.message}") from None
    if not isinstance(document, dict):
        raise Unsupported("the rule is not a mapping")
    try:
        rule = SigmaRule.from_dict(document, collect_errors=True)
        if rule.errors:
            raise rule.errors[0]
    except SigmaRegularExpressionError as error:
        raise Unsupported(refused(error)) from None
    except SigmaError as error:
        raise Unsupported(f"pySigma cannot read the rule: {error}") from None
    except (KeyError, TypeError, ValueError, AttributeError) as error:
        raise Unsupported(f"the rule is not a Sigma rule ({type(error).__name__}: {error})") from None
    return compile_rule(rule)

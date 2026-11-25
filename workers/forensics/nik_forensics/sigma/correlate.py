"""Sigma correlation rules: ``event_count``, ``value_count``, ``temporal`` and ``temporal_ordered``.

A correlation names base rules (by ``name`` or ``id``). While a file is read the engine keeps, for every match of a
base rule, a small tuple (time, record key, which base rule, the group-by values, the value of the counted field);
when the parser ends the matches are sorted by time and ``run`` walks them. A group starts again after it fires:
one detection per episode, not one per record past the threshold.

Not run (and said so, never dropped): ``value_sum``, ``value_avg``, ``value_percentile``, ``value_median``,
extended temporal conditions (``condition: a and b``), and a correlation of correlations.
"""

from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass
from typing import Any

from sigma.correlations import (
    SigmaCorrelationCondition,
    SigmaCorrelationConditionOperator,
    SigmaCorrelationRule,
    SigmaCorrelationType,
)
from sigma.exceptions import SigmaError

from . import documents
from .compile import Unsupported

MAX_RECORDS = 50
EVENT_COUNT, VALUE_COUNT, TEMPORAL, TEMPORAL_ORDERED = "event_count", "value_count", "temporal", "temporal_ordered"
_TYPES = {
    SigmaCorrelationType.EVENT_COUNT: EVENT_COUNT,
    SigmaCorrelationType.VALUE_COUNT: VALUE_COUNT,
    SigmaCorrelationType.TEMPORAL: TEMPORAL,
    SigmaCorrelationType.TEMPORAL_ORDERED: TEMPORAL_ORDERED,
}
_Op = SigmaCorrelationConditionOperator
_COMPARE = {
    _Op.LT: lambda n, c: n < c,
    _Op.LTE: lambda n, c: n <= c,
    _Op.GT: lambda n, c: n > c,
    _Op.GTE: lambda n, c: n >= c,
    _Op.EQ: lambda n, c: n == c,
    _Op.NEQ: lambda n, c: n != c,
}


@dataclass
class Plan:
    """What the engine needs of a correlation rule."""

    kind: str
    refs: list[str]
    span_ms: int
    group_by: bool
    groups: list[tuple[str, ...]]  # per base rule (in the order of ``refs``): the lower-case fields to group by
    op: Any
    count: int
    value_field: str
    generate: bool
    group_names: tuple[str, ...] = ()  # the group-by fields as the rule names them, lower case


def refs_of(source: str) -> tuple[list[str], bool]:
    """The base rules a correlation names and whether it generates their alerts, without pySigma (cheap)."""
    _node, document = documents.load(source)
    body = document.get("correlation") if isinstance(document, dict) else None
    if not isinstance(body, dict):
        raise Unsupported("the correlation could not be read")
    rules = body.get("rules")
    if isinstance(rules, str):
        rules = [rules]
    if not isinstance(rules, list) or not all(isinstance(item, str) for item in rules):
        raise Unsupported("the correlation names no base rules")
    return [str(item) for item in rules], bool(body.get("generate"))


def plan(source: str) -> Plan:
    """Parse a correlation with pySigma and keep what is run. Raises ``Unsupported``."""
    _node, document = documents.load(source)
    try:
        rule = SigmaCorrelationRule.from_dict(document, collect_errors=True)
        if rule.errors:
            raise rule.errors[0]
    except SigmaError as error:
        raise Unsupported(f"pySigma cannot read the correlation: {error}") from None
    kind = _TYPES.get(rule.type)
    if kind is None:
        raise Unsupported(f"the correlation type {rule.type.name.lower()} is not run by Nik")
    condition = rule.condition
    if not isinstance(condition, SigmaCorrelationCondition):
        raise Unsupported("a temporal condition written as an expression (a and b) is not run by Nik")
    refs = [item.reference for item in rule.rules or []]
    if not refs:
        raise Unsupported("the correlation names no base rules")
    groups = []
    for ref in refs:
        names = []
        for name in rule.group_by or []:
            alias = rule.aliases.aliases.get(name)
            mapping = {key.reference: value for key, value in alias.mapping.items()} if alias else {}
            names.append(str(mapping.get(ref, name)).lower())
        groups.append(tuple(names))
    value_field = condition.fieldref
    if isinstance(value_field, list):
        value_field = value_field[0] if value_field else ""
    if kind == VALUE_COUNT and not value_field:
        raise Unsupported("a value_count correlation must name the field it counts")
    return Plan(
        kind,
        refs,
        int(rule.timespan.seconds) * 1000,
        bool(rule.group_by),
        groups,
        condition.op,
        int(condition.count or 0),
        str(value_field or "").lower(),
        bool(rule.generate),
        tuple(str(name).lower() for name in rule.group_by or []),
    )


def run(plan: Plan, matches: list[tuple], limit: int) -> tuple[list[dict], bool]:
    """The detections of a correlation over the matches of its base rules.

    ``matches`` are ``(ts, key, ref index, group values, value)``. Returns the detections, each
    ``{"key": <the record that completed it>, "records": [keys], "count": n}``, and whether ``limit`` cut them."""
    matches = sorted(matches, key=lambda m: m[0])
    if plan.kind == TEMPORAL_ORDERED:
        return _ordered(plan, matches, limit)
    span = plan.span_ms
    alerts: list[dict] = []
    windows: dict[tuple, deque] = {}
    counters: dict[tuple, Counter] = {}
    wanted = len(plan.refs)
    kind = plan.kind
    for ts, key, ref, group, value in matches:
        if kind == VALUE_COUNT and value is None:
            continue  # the record has no value to count
        window = windows.setdefault(group, deque())
        counter = counters.setdefault(group, Counter())
        token = ref if kind == TEMPORAL else (str(value) if kind == VALUE_COUNT else 0)
        window.append((ts, token, key))
        counter[token] += 1
        while window[0][0] < ts - span:
            _old_ts, old, _old_key = window.popleft()
            counter[old] -= 1
            if not counter[old]:
                del counter[old]
        if kind == EVENT_COUNT:
            size = len(window)
            hit = _COMPARE[plan.op](size, plan.count)
        elif kind == VALUE_COUNT:
            size = len(counter)
            hit = _COMPARE[plan.op](size, plan.count)
        else:
            size = len(window)
            hit = len(counter) == wanted
        if hit:
            if len(alerts) >= limit:
                return alerts, True
            alerts.append({"key": key, "records": _last(window), "count": size, "ts": ts, "group": group})
            window.clear()
            counter.clear()
    return alerts, False


class Hit(str):
    """The key of a match that is itself the alert of a correlation: the completing record's key, and the keys of the
    records behind the alert (what a correlation built on a correlation lists)."""

    records: tuple = ()

    def __new__(cls, key: str, records) -> Hit:
        made = super().__new__(cls, key)
        made.records = tuple(records)
        return made


def _flat(keys) -> list:
    """The keys of the records behind some matches, in order, each once, the last ``MAX_RECORDS``."""
    seen = dict.fromkeys(inner for key in keys for inner in (getattr(key, "records", None) or (key,)))
    return list(seen)[-MAX_RECORDS:]


def _last(window: deque) -> list:
    return _flat(item[2] for item in window)


def _ordered(plan: Plan, matches: list[tuple], limit: int) -> tuple[list[dict], bool]:
    """``temporal_ordered``: the base rules match in the order they are named, all inside the timespan. For every
    group, ``best[j]`` is the chain through the first ``j + 1`` rules whose first match is the latest (so the most
    likely to fit the timespan); no window is kept."""
    refs = len(plan.refs)
    best: dict[tuple, list[tuple | None]] = {}
    alerts: list[dict] = []
    for ts, key, ref, group, _value in matches:
        chains = best.setdefault(group, [None] * refs)
        previous = (ts, (key,)) if ref == 0 else chains[ref - 1]
        if previous is None or previous[0] < ts - plan.span_ms:
            continue
        chain = (previous[0], (*previous[1], key) if ref else previous[1])
        if ref + 1 == refs:
            if len(alerts) >= limit:
                return alerts, True
            alerts.append({"key": key, "records": _flat(chain[1]), "count": refs, "ts": ts, "group": group})
            best[group] = [None] * refs
        else:
            chains[ref] = chain if chains[ref] is None or chains[ref][0] <= chain[0] else chains[ref]
    return alerts, False

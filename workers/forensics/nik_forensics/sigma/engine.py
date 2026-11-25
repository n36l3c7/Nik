"""A set of Sigma rules, indexed by log source, evaluated on the records a parser finds.

The set is a list of rule lines (``{"id", "title", "level", "kind", "product", "category", "service",
"source"}``, the YAML of one document in ``source``). Nothing of the YAML is read when the set is loaded: the
rules are indexed by their ``product/category/service`` alone. The first time a record of a given
``(kind, channel, event id)`` is seen, the rules that may apply to it are found, parsed and compiled (``compile.py``),
and the result is kept for that key; a rule that no record ever reaches is never parsed. A record that no rule
applies to costs one dictionary lookup.

Per record, the engine makes the fields the rules read (``_fields``) from what the parser gave, **before** the
values are cut for the stream: a script of a megabyte is matched whole. A compiled rule says which fields must
be there for any match; that is checked before its predicate runs.

Nothing is dropped in silence: a rule that cannot be compiled (or whose log source Nik has no records for) is
listed with its reason (``failed``), and ``finish`` hands back the correlations and the notes for the end of the file.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from . import logsource
from .hours import BadHours, Hours

# At most this many matches of base rules are held for the correlations of one file.
MAX_HELD = 2_000_000
# At most this many detections of one correlation are written for a file.
MAX_CORRELATION_DETECTIONS = 5000
_READY_LIMIT = 20000
_NAME = re.compile(r"^name:[ \t]*(.*?)[ \t]*(?:#.*)?$", re.MULTILINE)

NEW, READY, FAILED = 0, 1, 2


class Slot:
    """One rule of the set."""

    __slots__ = (
        "line",
        "rid",
        "source",
        "corr",
        "state",
        "reason",
        "pred",
        "required",
        "used",
        "emit",
        "feeds",
        "plan",
        "matches",
        "refs",
        "generate",
        "bases",
        "no_time",
        "live",
    )

    def __init__(self, line: dict, rid: str) -> None:
        self.line, self.rid, self.source = line, rid, str(line.get("source") or "")
        self.corr = line.get("kind") == "correlation"
        self.state, self.reason = NEW, ""
        self.pred = None
        self.required: frozenset[str] = frozenset()
        self.used: frozenset[str] = frozenset()
        self.emit = True
        self.feeds: list[tuple[Slot, int]] = []  # the correlations this rule is a base of, and its place in each
        self.plan = None
        self.matches: list[tuple] = []
        self.refs: list[str] = []
        self.generate = False
        self.bases: list[Slot] = []
        self.no_time = 0
        self.live = True


@dataclass
class _Ready:
    candidates: tuple  # (required fields, predicate, slot)
    hours: bool  # a candidate reads NikOffHours


class _Index:
    """Rules by the places of their records."""

    def __init__(self) -> None:
        self.exact: dict[tuple, list] = {}
        self.channel: dict[tuple, list] = {}
        self.anything: dict[str, list] = {}

    def add(self, slot: Slot, kind: str, place: logsource.Place) -> None:
        channel, ids, extra = place
        entry = (slot, extra)
        if channel is None:
            self.anything.setdefault(kind, []).append(entry)
        elif ids is None:
            self.channel.setdefault((kind, channel), []).append(entry)
        else:
            for event_id in ids:
                self.exact.setdefault((kind, channel, event_id), []).append(entry)

    def lookup(self, kind: str, channel: str, event_id: int | None) -> list:
        return [
            *self.exact.get((kind, channel, event_id), ()),
            *self.channel.get((kind, channel), ()),
            *self.anything.get(kind, ()),
        ]


def _lower_list(value: Any) -> Any:
    if value.__class__ in (list, tuple):
        return [item.lower() if item.__class__ is str else item for item in value]
    return value


def _hashable(value: Any) -> Any:
    if value.__class__ in (list, tuple):
        return tuple(_hashable(item) for item in value)
    return value if isinstance(value, (str, int, float, bool)) or value is None else str(value)


class Engine:
    def __init__(self, lines: Iterable[dict], hours: dict | None = None) -> None:
        self.slots: list[Slot] = []
        self.by_id: dict[str, Slot] = {}
        self.failed: dict[str, str] = {}  # rule id -> why it is not evaluated (never dropped in silence)
        self.errors = 0  # records the engine failed on (a bug, not a rule)
        self.first_error = ""
        self.held = 0
        self.held_cut = False
        self.hours: Hours | None = None
        self.hours_error = ""
        self._index = _Index()
        self._ready: dict[tuple, _Ready] = {}
        self.kind = ""
        if hours:
            try:
                self.hours = Hours(hours)
            except BadHours as error:
                self.hours_error = str(error)
        for number, line in enumerate(lines, start=1):
            self._add(line, number)
        self._link_correlations()

    # -- loading -------------------------------------------------------------- #
    def _add(self, line: Any, number: int) -> None:
        if not isinstance(line, dict) or not isinstance(line.get("id"), str) or not isinstance(line.get("source"), str):
            self.failed[f"line {number}"] = "a line of the rule set is not a rule (it needs an id and a source)"
            return
        slot = Slot(line, line["id"])
        if slot.rid in self.by_id:
            self.failed[slot.rid] = "the rule set holds this id twice"
            return
        self.slots.append(slot)
        self.by_id[slot.rid] = slot
        if slot.corr:
            return  # a correlation reads no records itself
        try:
            kind, places = logsource.places(line.get("product"), line.get("category"), line.get("service"))
        except logsource.NoRecords as error:
            self._fail(slot, str(error))
            return
        for place in places:
            self._index.add(slot, kind, place)

    def _fail(self, slot: Slot, reason: str) -> None:
        slot.state, slot.reason = FAILED, reason
        self.failed[slot.rid] = reason
        if slot.corr:
            slot.live = False
            for base in slot.bases:
                self._emit_of(base)

    def _link_correlations(self) -> None:
        """Name the base rules of every correlation (by id or by ``name``, found by a line scan) and decide
        which base rules still write their own detections (``generate``)."""
        corrs = [slot for slot in self.slots if slot.corr]
        if not corrs:
            return
        names: dict[str, Slot] = {}
        for slot in self.slots:
            match = _NAME.search(slot.source)
            if match and match.group(1).strip("'\" "):
                names.setdefault(match.group(1).strip("'\" "), slot)
        from . import correlate
        from .compile import Unsupported

        for corr in corrs:
            try:
                corr.refs, corr.generate = correlate.refs_of(corr.source)
            except Unsupported as error:
                self._fail(corr, str(error))
                continue
            except Exception as error:  # noqa: BLE001 - a rule that cannot be read is listed, not fatal
                self._fail(corr, f"the correlation cannot be read: {error}")
                continue
            bases: list[Slot] = []
            for ref in corr.refs:
                base = self.by_id.get(ref) or names.get(ref)
                if base is None:
                    self._fail(corr, f"its base rule {ref} is not in the rule set (disabled, unsupported or absent)")
                    break
                bases.append(base)
            else:
                corr.bases = bases
                for place, base in enumerate(bases):
                    base.feeds.append((corr, place))
        for corr in corrs:  # one level of correlations as bases is run, not a chain of them
            for base in corr.bases:
                if base.corr and any(inner.corr for inner in base.bases) and corr.live:
                    self._fail(
                        corr,
                        f"its base correlation {base.rid} is built on correlations: Nik runs one level of them",
                    )
        for corr in corrs:
            for base in corr.bases:
                self._emit_of(base)

    @staticmethod
    def _emit_of(base: Slot) -> None:
        """A base rule writes its own detections unless a working correlation names it without ``generate``."""
        live = [corr for corr, _place in base.feeds if corr.live]
        base.emit = not live or any(corr.generate for corr in live)

    # -- compiling ------------------------------------------------------------ #
    def _compile(self, slot: Slot) -> None:
        from .compile import Unsupported, from_source

        try:
            compiled = from_source(slot.source)
        except Unsupported as error:
            self._fail(slot, str(error))
            return
        slot.pred, slot.required, slot.used, slot.state = compiled.pred, compiled.required, compiled.used, READY

    def compile_all(self) -> None:
        """Compile every rule and plan every correlation now (a try over a few rules wants all the reasons)."""
        for slot in self.slots:
            if slot.state == NEW:
                if slot.corr:
                    self._plan(slot)
                else:
                    self._compile(slot)
        for slot in self.slots:
            if slot.corr and slot.live and slot.plan is not None:
                reason = self._nesting(slot)
                if reason:
                    self._fail(slot, reason)

    def _plan(self, corr: Slot) -> bool:
        if corr.plan is not None:
            return True
        if corr.state == FAILED:
            return False
        from . import correlate
        from .compile import Unsupported

        try:
            corr.plan = correlate.plan(corr.source)
        except Unsupported as error:
            self._fail(corr, str(error))
            return False
        corr.state = READY
        return True

    def _nesting(self, outer: Slot) -> str | None:
        """Why a correlation built on correlations cannot run, or None. The group-by fields of the outer one
        (aliases honoured) must be fields the inner one groups by: the group of an alert is mapped by name."""
        for place, base in enumerate(outer.bases):
            if not base.corr:
                continue
            if not self._plan(base):
                return f"its base correlation {base.rid} is not evaluated: {base.reason}"
            for name in outer.plan.groups[place]:
                if name not in base.plan.group_names:
                    return (
                        f"its group-by field {name} is not one of the group-by fields of the correlation "
                        f"{base.rid} it is built on"
                    )
        return None

    @staticmethod
    def _take_alerts(outer: Slot, alerts_of: dict[str, list[dict]]) -> None:
        """The alerts of the inner correlations are matches of the outer one: at the time and under the key of the
        record that completed them, with the group of the alert mapped onto the outer group-by fields by name."""
        from .correlate import Hit

        for place, base in enumerate(outer.bases):
            if not base.corr:
                continue
            names = base.plan.group_names
            fields = [names.index(name) for name in outer.plan.groups[place]]
            counted = names.index(outer.plan.value_field) if outer.plan.value_field in names else None
            for alert in alerts_of.get(base.rid, []):
                group = alert["group"]
                outer.matches.append(
                    (
                        alert["ts"],
                        Hit(alert["key"], alert["records"]),
                        place,
                        tuple(group[at] for at in fields),
                        group[counted] if counted is not None else None,
                    )
                )

    def _prepare(self, kind: str, channel: str, event_id: int | None) -> _Ready:
        from .compile import extra_pred

        candidates = []
        hours = False
        for slot, extra in self._index.lookup(kind, channel, event_id):
            if slot.state == NEW:
                self._compile(slot)
            if slot.state != READY:
                continue
            pred, required = slot.pred, slot.required
            if extra:
                first, second = extra_pred(extra), pred
                pred = lambda r, first=first, second=second: first(r) and second(r)  # noqa: E731
                required = required | frozenset(extra)
            hours = hours or "nikoffhours" in slot.used
            candidates.append((required, pred, slot))
        ready = _Ready(tuple(candidates), hours)
        if len(self._ready) >= _READY_LIMIT:
            self._ready.clear()
        self._ready[(kind, channel, event_id)] = ready
        return ready

    # -- the fields of a record ----------------------------------------------- #
    def _fields(
        self,
        kind: str,
        rtype: str,
        ts: int | None,
        host: str,
        username: str,
        event_id: int | None,
        channel: str,
        summary: str,
        data: dict,
        source: str,
        hours: bool,
    ) -> dict:
        orig: dict[str, Any] = {}
        inner: list[tuple[str, Any]] = []
        for name, value in data.items():
            if value.__class__ is bytes:
                value = value.hex()
            name = str(name).lower()
            orig[name] = value
            if name[:5] == "data.":
                inner.append((name[5:], value))
        for name, value in inner:  # a name that collided with a fixed one (Data.<name>) is also seen as <name>
            orig.setdefault(name, value)
        if kind == "eventlog":
            orig["eventid"] = event_id
            orig["channel"] = channel
            orig["computer"] = host
            if "provider" in data:
                orig["provider_name"] = data["provider"]
            for name, read in logsource.ALIASES.get((channel.lower(), event_id), {}).items():
                if name not in orig and orig.get(read) is not None:
                    orig[name] = orig[read]
            if username and "user" not in orig:
                orig["user"] = username
        elif kind == logsource.PROCESS_CHAIN:
            # The API gives the fields of a process by their own names (``Host``, ``User``): the arguments fill in.
            orig.setdefault("summary", summary)
            orig.setdefault("host", host)
            orig.setdefault("user", username)
        else:
            orig["summary"] = summary
            orig["type"] = rtype
            orig["source"] = source
            orig["host"] = host
            orig["user"] = username
            if kind == logsource.SYSLOG:
                logsource.syslog_fields(channel.lower(), rtype, orig)
        if hours and self.hours is not None and ts is not None:
            orig["nikoffhours"] = "true" if self.hours.off(ts) else "false"
        record = {
            name: (value.lower() if value.__class__ is str else _lower_list(value)) for name, value in orig.items()
        }
        record["\0o"] = orig
        return record

    # -- a record ------------------------------------------------------------- #
    def see(
        self,
        kind: str,
        key: str,
        rtype: str,
        ts: int | None,
        host: str,
        username: str,
        event_id: int | None,
        channel: str,
        summary: str,
        data: dict,
        source: str = "",
    ) -> list[str]:
        """The ids of the rules that match the record (the ones that write detections of their own)."""
        low = channel.lower() if channel else ""
        ready = self._ready.get((kind, low, event_id))
        if ready is None:
            ready = self._prepare(kind, low, event_id)
        if not ready.candidates:
            return []
        try:
            record = self._fields(
                kind, rtype, ts, host, username, event_id, channel, summary, data, source, ready.hours
            )
            hits = self._run(ready, record)
        except Exception as error:  # noqa: BLE001 - the engine must never end the parse
            self.errors += 1
            self.first_error = self.first_error or f"{type(error).__name__}: {error}"
            return []
        out: list[str] = []
        for slot in hits:
            if slot.feeds:
                self._feed(slot, record, key, ts)
            if slot.emit and slot.rid not in out:
                out.append(slot.rid)
        return out

    def _run(self, ready: _Ready, record: dict) -> list[Slot]:
        keys = record.keys()
        hits = []
        try:
            for required, pred, slot in ready.candidates:
                if required and not keys >= required:
                    continue
                if pred(record):
                    hits.append(slot)
            return hits
        except Exception:  # noqa: BLE001 - one rule that fails is put aside, the others go on
            hits = []
            for required, pred, slot in ready.candidates:
                if slot.state != READY or (required and not keys >= required):
                    continue
                try:
                    if pred(record):
                        hits.append(slot)
                except Exception as error:  # noqa: BLE001
                    self._fail(slot, f"the rule failed on a record: {type(error).__name__}: {error}")
            return hits

    def _feed(self, base: Slot, record: dict, key: str, ts: int | None) -> None:
        for corr, place in base.feeds:
            if not corr.live or not self._plan(corr):
                continue
            plan = corr.plan
            group = tuple(_hashable(record.get(name)) for name in plan.groups[place])
            if plan.group_by and any(part is None for part in group):
                continue  # the record lacks a field to group by
            if ts is None:
                corr.no_time += 1
                continue
            if self.held >= MAX_HELD:
                self.held_cut = True
                continue
            value = _hashable(record.get(plan.value_field)) if plan.value_field else None
            corr.matches.append((ts, key, place, group, value))
            self.held += 1

    # -- the end of a file ---------------------------------------------------- #
    def finish(self) -> tuple[list[dict], list[tuple[str, int, str]]]:
        """The detections of the correlations and the notes for the end of the file:
        ``([det lines], [(reason, count, detail)])``."""
        from . import correlate

        dets: list[dict] = []
        notes: list[tuple[str, int, str]] = []
        cut: list[str] = []
        no_time = 0
        alerts_of: dict[str, list[dict]] = {}
        inner_first = sorted((slot for slot in self.slots if slot.corr), key=lambda c: any(b.corr for b in c.bases))
        for corr in inner_first:
            for base in corr.bases:
                if (base.state == FAILED or not base.live) and corr.live:
                    self._fail(corr, f"its base rule {base.rid} is not evaluated: {base.reason}")
            no_time += corr.no_time
            if corr.live and any(base.corr for base in corr.bases) and self._plan(corr):
                reason = self._nesting(corr)
                if reason:
                    self._fail(corr, reason)
                else:
                    self._take_alerts(corr, alerts_of)
            if corr.matches and corr.live and corr.plan is not None:
                alerts, was_cut = correlate.run(corr.plan, corr.matches, MAX_CORRELATION_DETECTIONS)
                alerts_of[corr.rid] = alerts
                if corr.emit:  # an inner correlation that does not generate writes nothing of its own
                    dets.extend(
                        {"t": "det", "key": a["key"], "rule": corr.rid, "records": a["records"], "count": a["count"]}
                        for a in alerts
                    )
                if was_cut:
                    cut.append(corr.rid)
            corr.matches = []
        if cut:
            notes.append(
                (
                    "correlation limit reached",
                    len(cut),
                    f"{', '.join(cut[:5])}: more than {MAX_CORRELATION_DETECTIONS} detections in this file, "
                    "the rest are left out",
                )
            )
        if self.held_cut:
            notes.append(
                (
                    "correlations incomplete",
                    1,
                    f"more than {MAX_HELD} matches of base rules in this file: its correlations are not complete",
                )
            )
        if no_time:
            notes.append(("records without a time left out of correlations", no_time, ""))
        if self.hours_error:
            notes.append(("working hours not understood", 1, f"NikOffHours is not set: {self.hours_error}"))
        if self.errors:
            notes.append(("detection failed on records", self.errors, self.first_error))
        if self.failed:
            first = list(self.failed.items())
            ids = ", ".join(rid for rid, _reason in first[:5])
            notes.append(("rule not evaluated", len(first), f"{ids}{'…' if len(first) > 5 else ''}: {first[0][1]}"))
        return dets, notes

    def not_evaluated(self) -> list[tuple[str, str]]:
        return list(self.failed.items())

"""SLA timers: how long an incident has taken to be assigned, contained, closed.

A timer is a field of type ``timer`` whose value is

    {"state": "running" | "paused" | "stopped", "started_at": <epoch of the
     stretch that runs>, "accumulated_s": <what ran before it>, "due_s": <the
     time allowed, or null>, "breached_at": <ISO, once past it>,
     "business": <counts only inside business hours>, "own_due": <the time
     allowed was given when it was started, by hand or by a playbook>}

It is never written like another field: it is started, paused and stopped, by
the rules of the type of the incident (``sla``), by the nodes ``timer.start``,
``timer.pause`` and ``timer.stop`` of a playbook, or by hand. Three ship:
``time_to_assign`` stops when the incident has an owner, ``time_to_close``
when it is closed (and goes on if it is opened again), ``time_to_contain``
when a playbook or a person says so. Closing stops them all.

The worker looks every minute (``tick``): a running timer past its time is
*breached*, once: the incident is marked (``sla_breached``), its War Room and
its owner are told, and ``sla.breached`` is published for playbooks and
webhooks. A timer that counts business hours advances only inside them.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone, tzinfo
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm.attributes import flag_modified

from . import fields as registry
from .core.models import Incident, IncidentType, User
from .core.permissions import clean_roles
from .core.security import now_iso
from .defaults import DEFAULT_BUSINESS_HOURS

SHIPPED = ("time_to_assign", "time_to_contain", "time_to_close")
BREACHED = "sla_breached"
# A timer found past its time by more than this was not noticed when it ran out (the worker was stopped).
LATE = 300
STATES = ("running", "paused", "stopped")
MINUTES_MAX = 60 * 24 * 365
SLA_MAX = 12
DAYS_MAX = 800  # how far the count of business time looks: more than two years is not an SLA


class TimerError(ValueError):
    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


# --------------------------------------------------------------------------- #
# Business hours                                                              #
# --------------------------------------------------------------------------- #
def zone_name(value: Any) -> str:
    """An IANA time zone name as ``zoneinfo`` knows it. Raises ``ValueError`` with a sentence."""
    name = str(value or "").strip()
    try:
        if not name or name.startswith(("/", ".")) or ".." in name:
            raise ZoneInfoNotFoundError(name)
        ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError, OSError):
        raise ValueError(f'"{name[:60]}" is not a time zone name: use one such as Europe/Rome or UTC') from None
    return name


def _zone(name: Any) -> tzinfo:
    try:
        return ZoneInfo(zone_name(name)) if name else timezone.utc
    except ValueError:
        return timezone.utc


def business_hours(db: OrmSession, incident: Incident | None = None) -> dict[str, Any]:
    """The hours the organisation works, as Settings hold them, and the time zone they are read in:
    the one of the incident when it has one, else the one of Settings (UTC by default)."""
    from . import lists

    held = lists.settings_value(db, "businessHours", None)
    hours = {**DEFAULT_BUSINESS_HOURS, **(held if isinstance(held, dict) else {})}
    try:
        start, end = int(hours["startHour"]), int(hours["endHour"])
    except (TypeError, ValueError):
        start, end = DEFAULT_BUSINESS_HOURS["startHour"], DEFAULT_BUSINESS_HOURS["endHour"]
    if not 0 <= start < end <= 24:
        start, end = DEFAULT_BUSINESS_HOURS["startHour"], DEFAULT_BUSINESS_HOURS["endHour"]
    name = "UTC"
    for candidate in (incident.tz if incident is not None else None, hours.get("tz")):
        if not candidate:
            continue
        try:
            name = zone_name(candidate)
        except ValueError:
            continue  # a name that is not a zone any more is as if it was not given
        break
    return {"startHour": start, "endHour": end, "flagWeekends": bool(hours.get("flagWeekends")), "tz": name}


def business_seconds(start: float, end: float, hours: dict[str, Any]) -> float:
    """How much of the time between two moments falls inside business hours, the days and the hours
    read on the wall clock of ``hours["tz"]`` (UTC when it has none): a day that changes the clock
    has 23 or 25 hours, and the hours of work stay at the same time on the clock."""
    if end <= start:
        return 0.0
    zone = _zone(hours.get("tz"))
    first = datetime.fromtimestamp(start, zone)
    day = first.replace(hour=0, minute=0, second=0, microsecond=0)
    total = 0.0
    for _ in range(DAYS_MAX):
        if day.timestamp() >= end:
            break
        if not (hours["flagWeekends"] and day.weekday() >= 5):
            opens = (day + timedelta(hours=hours["startHour"])).timestamp()
            closes = (day + timedelta(hours=hours["endHour"])).timestamp()
            total += max(0.0, min(end, closes) - max(start, opens))
        day += timedelta(days=1)
    return total


# --------------------------------------------------------------------------- #
# One timer                                                                   #
# --------------------------------------------------------------------------- #
def _stretch(timer: dict[str, Any], now: float, hours: dict[str, Any]) -> float:
    if timer.get("state") != "running":
        return 0.0
    started = float(timer.get("started_at") or now)
    return business_seconds(started, now, hours) if timer.get("business") else max(0.0, now - started)


def elapsed(timer: dict[str, Any] | None, now: float, hours: dict[str, Any]) -> float:
    """The seconds a timer has counted so far."""
    if not isinstance(timer, dict):
        return 0.0
    return float(timer.get("accumulated_s") or 0) + _stretch(timer, now, hours)


def view(name: str, label: str, timer: dict[str, Any] | None, now: float, hours: dict[str, Any]) -> dict[str, Any]:
    """A timer as it is shown: its state, what it counted, what is left."""
    timer = timer if isinstance(timer, dict) else {}
    counted = int(elapsed(timer, now, hours))
    due = timer.get("due_s")
    return {
        "field": name,
        "label": label,
        "state": timer.get("state") or "idle",
        "elapsedS": counted,
        "dueS": due,
        "remainingS": (int(due) - counted) if due else None,
        "breached": bool(timer.get("breached_at")) or bool(due and counted >= due),
        "breachedAt": timer.get("breached_at"),
        "business": bool(timer.get("business")),
    }


def _held(incident: Incident) -> dict[str, Any]:
    return dict(incident.fields) if isinstance(incident.fields, dict) else {}


def _keep(incident: Incident, stored: dict[str, Any]) -> None:
    incident.fields = stored
    flag_modified(incident, "fields")


def timer_fields(db: OrmSession) -> dict[str, str]:
    """name → label of every timer an incident can have."""
    return {
        name: field.label or name
        for name, field in registry.registry(db).items()
        if field.type == "timer" and field.applies_to == "incident"
    }


def start(
    db: OrmSession,
    incident: Incident,
    name: str,
    now: float,
    *,
    due_s: int | None = None,
    business: bool | None = None,
    restart: bool = False,
    by_rule: bool = False,
) -> dict[str, Any]:
    """Start a timer, or let it go on from where it was paused or stopped (the caller commits).
    ``restart`` counts again from nothing. A time allowed given by a person or a playbook
    (``by_rule`` false) is the timer's own: the rules of the type do not change it afterwards."""
    _known(db, name)
    stored = _held(incident)
    hours = business_hours(db, incident)
    timer = dict(stored[name]) if isinstance(stored.get(name), dict) and not restart else {}
    counted = elapsed(timer, now, hours)
    timer.update({"state": "running", "started_at": now, "accumulated_s": counted})
    if due_s is not None:
        timer["due_s"] = int(due_s) or None
        timer["own_due"] = not by_rule
    timer.setdefault("due_s", None)
    if business is not None:
        timer["business"] = bool(business)
    timer.setdefault("business", False)
    timer["breached_at"] = None if restart else timer.get("breached_at")
    timer.pop("stopped_by_rule", None)
    stored[name] = timer
    _keep(incident, stored)
    return timer


def halt(
    db: OrmSession, incident: Incident, name: str, now: float, *, state: str, by_rule: bool = False
) -> dict | None:
    """Pause or stop a timer that runs (the caller commits). None when it was not running."""
    _known(db, name)
    stored = _held(incident)
    timer = stored.get(name)
    if not isinstance(timer, dict) or timer.get("state") != "running":
        if isinstance(timer, dict) and state == "stopped" and timer.get("state") == "paused":
            timer = {**timer, "state": "stopped", "stopped_at": now_iso()}
            stored[name] = timer
            _keep(incident, stored)
            return timer
        return None
    timer = {
        **timer,
        "accumulated_s": elapsed(timer, now, business_hours(db, incident)),
        "state": state,
        "started_at": None,
    }
    if state == "stopped":
        timer["stopped_at"] = now_iso()
        if by_rule:
            timer["stopped_by_rule"] = True
    stored[name] = timer
    _keep(incident, stored)
    return timer


def _known(db: OrmSession, name: str) -> None:
    if name not in timer_fields(db):
        raise TimerError(f'"{name}" is not a timer: ' + ", ".join(sorted(timer_fields(db))))


def of(db: OrmSession, incident: Incident, now: float) -> list[dict[str, Any]]:
    """The timers of an incident that were started, the shipped ones first."""
    stored = _held(incident)
    hours = business_hours(db, incident)
    labels = timer_fields(db)
    names = [name for name in SHIPPED if name in labels] + sorted(name for name in labels if name not in SHIPPED)
    return [view(name, labels[name], stored[name], now, hours) for name in names if isinstance(stored.get(name), dict)]


# --------------------------------------------------------------------------- #
# The rules of a type                                                         #
# --------------------------------------------------------------------------- #
def clean_sla(db: OrmSession, raw: Any) -> list[dict[str, Any]]:
    """The SLA of a type: for each timer, the minutes allowed (by severity if wanted)
    and whether only business hours count."""
    if raw in (None, []):
        return []
    if not isinstance(raw, list) or len(raw) > SLA_MAX:
        raise TimerError(f"The SLA of a type is a list of {SLA_MAX} timers at most")
    known = timer_fields(db)
    out: list[dict[str, Any]] = []
    for item in raw:
        name = str(item.get("field") or "") if isinstance(item, dict) else ""
        if name not in known or any(rule["field"] == name for rule in out):
            raise TimerError("Each rule of an SLA names a timer, once: " + ", ".join(sorted(known)))
        rule: dict[str, Any] = {"field": name, "minutes": _minutes(item.get("minutes"), known[name])}
        by_severity = item.get("bySeverity", item.get("by_severity")) or {}
        if not isinstance(by_severity, dict) or any(key not in registry.SEVERITIES for key in by_severity):
            raise TimerError("The times by severity are for: " + ", ".join(registry.SEVERITIES))
        kept = {key: _minutes(value, known[name]) for key, value in by_severity.items() if value not in (None, "")}
        if kept:
            rule["by_severity"] = kept
        rule["business_hours"] = bool(item.get("businessHours", item.get("business_hours")))
        out.append(rule)
    return out


def _minutes(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not 1 <= int(value) <= MINUTES_MAX:
        raise TimerError(f"{label}: the time allowed is in minutes, from 1 to a year")
    return int(value)


def sla_out(rules: list | None) -> list[dict[str, Any]]:
    return [
        {
            "field": rule["field"],
            "minutes": rule["minutes"],
            "bySeverity": rule.get("by_severity") or {},
            "businessHours": bool(rule.get("business_hours")),
        }
        for rule in rules or []
        if isinstance(rule, dict) and rule.get("field")
    ]


def _due(rule: dict[str, Any], incident: Incident) -> int:
    severity = str((incident.doc or {}).get("severity") or "")
    return int((rule.get("by_severity") or {}).get(severity) or rule["minutes"]) * 60


def sync(db: OrmSession, incident: Incident, now: float, known: dict[str, str] | None = None) -> bool:
    """Apply the rules of the incident's type to its timers as things stand (the caller
    commits): start what the type times, stop what is over. Says whether anything changed."""
    kind = registry.type_of(db, incident) or db.get(IncidentType, registry.UNCLASSIFIED)
    rules = [rule for rule in (kind.sla if kind is not None else None) or [] if isinstance(rule, dict)]
    stored = _held(incident)
    doc = incident.doc or {}
    closed = (doc.get("status") or "") == "closed"
    owned = bool(doc.get("assignee"))
    if not rules and not any(isinstance(value, dict) and value.get("state") == "running" for value in stored.values()):
        return False  # nothing is timed here, and nothing runs
    known = known if known is not None else timer_fields(db)
    changed = False
    for rule in rules:
        name = rule.get("field")
        if name not in known:
            continue
        timer = stored.get(name) if isinstance(stored.get(name), dict) else None
        over = closed or (name == "time_to_assign" and owned)
        if timer is None:
            if not over:
                start(
                    db,
                    incident,
                    name,
                    now,
                    due_s=_due(rule, incident),
                    business=bool(rule.get("business_hours")),
                    by_rule=True,
                )
                changed = True
        elif timer.get("state") == "running":
            # A time given when it was started stays; the rule's follows the severity.
            own = bool(timer.get("own_due"))
            due = timer.get("due_s") if own else _due(rule, incident)
            if timer.get("due_s") != due or bool(timer.get("business")) != bool(rule.get("business_hours")):
                # The severity changed, or the rule did: the time allowed follows.
                start(db, incident, name, now, due_s=due, business=bool(rule.get("business_hours")), by_rule=not own)
                changed = True
        elif timer.get("state") == "stopped" and timer.get("stopped_by_rule") and not over:
            # Opened again, or left without an owner: the clock goes on.
            start(db, incident, name, now)
            changed = True
        stored = _held(incident)
    # What is over stops, whoever started it: nothing breaches on a closed incident.
    for name, timer in list(stored.items()):
        if name not in known or not isinstance(timer, dict) or timer.get("state") != "running":
            continue
        if closed or (name == "time_to_assign" and owned and any(rule.get("field") == name for rule in rules)):
            halt(db, incident, name, now, state="stopped", by_rule=True)
            changed = True
    return changed


# --------------------------------------------------------------------------- #
# What time does                                                              #
# --------------------------------------------------------------------------- #
def _tell(db: OrmSession, incident: Incident, label: str) -> None:
    from . import tasks

    owner = str((incident.doc or {}).get("assignee") or "")
    names = (
        [owner]
        if owner
        else [
            user.username
            for user in db.scalars(select(User).where(User.disabled.is_(False)))
            if "admin" in clean_roles(user.roles)
        ]
    )
    for name in names:
        tasks.notify(db, name, "sla.breached", f"{label} is past its time: {incident.name}", f"/incident/{incident.id}")


def tick(db: OrmSession, now: float) -> int:
    """Apply the rules and mark what is past its time (the worker, every minute; it commits).
    Returns how many timers breached."""
    from . import war_room
    from .automation import triggers

    breached = 0
    labels = timer_fields(db)
    for incident in db.scalars(
        select(Incident).where(Incident.status != "closed", Incident.archived_at.is_(None))
    ).all():
        touched = sync(db, incident, now, labels)
        stored = _held(incident)
        for name, timer in list(stored.items()):
            if name not in labels or not isinstance(timer, dict) or timer.get("state") != "running":
                continue
            due = timer.get("due_s")
            counted = elapsed(timer, now, business_hours(db, incident))  # in the zone of the incident
            if not due or counted < due or timer.get("breached_at"):
                continue
            # Its real time: the moment it ran out, which is before now when the worker was stopped
            # then. The timer fires late, once, and says since when it is past its time.
            late = max(0.0, float(counted) - float(due))
            since = datetime.fromtimestamp(now - late, timezone.utc)
            stored[name] = {**timer, "breached_at": since.isoformat() if late >= LATE else now_iso()}
            stored[BREACHED] = True
            _keep(incident, stored)
            said = f"{labels[name]} is past its time ({_span(due)})"
            if late >= LATE:
                said += f", since {since.strftime('%Y-%m-%d %H:%M UTC')}: it was noticed late"
            war_room.system(db, incident.id, said)
            _tell(db, incident, labels[name])
            triggers.sla_breached(db, incident, name, labels[name], int(due), int(counted))
            breached += 1
            touched = True
        if touched:
            db.commit()
    return breached


def _span(seconds: float) -> str:
    minutes = int(seconds // 60)
    if minutes < 120:
        return f"{minutes} min"
    hours = minutes / 60
    return f"{hours:g} h" if hours < 48 else f"{hours / 24:g} d"

"""Schedules: when a cron expression fires next, in its time zone.

**A time that passed while the server was stopped.** A schedule is a row with
its next time. When the worker starts again and that time is behind, the
playbook runs **once**, now, however many of its times went by: a server that
was down a week does not start a week of runs. The run is told when it was
due and how many times were missed (``trigger.due``, ``trigger.late_seconds``,
``trigger.missed``), and the next time is counted from now.
"""

from __future__ import annotations

from datetime import datetime, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from croniter import croniter

# A schedule fires at most every five minutes: a playbook is not a polling loop.
MIN_INTERVAL = 300


def _zone(name: str) -> ZoneInfo | None:
    try:
        return ZoneInfo(name or "UTC")
    except (ZoneInfoNotFoundError, ValueError, OSError):
        return None


def next_after(cron: str, zone: str, after: float) -> float:
    """The next firing after ``after`` (epoch seconds)."""
    start = datetime.fromtimestamp(after, tz=timezone.utc).astimezone(_zone(zone) or timezone.utc)
    return croniter(cron, start).get_next(datetime).timestamp()


MISSED_MAX = 1000


def missed_between(cron: str, zone: str, due: float, now: float) -> int:
    """How many firings after ``due`` are already past at ``now`` (counted up to ``MISSED_MAX``)."""
    count, moment = 0, due
    while count < MISSED_MAX:
        moment = next_after(cron, zone, moment)
        if moment > now:
            break
        count += 1
    return count


def cron_problem(cron: object, zone: object) -> str | None:
    """Why a schedule cannot be used, in a fixed sentence; None when it can."""
    if not isinstance(cron, str) or not cron.strip() or len(cron) > 120:
        return "A schedule is five fields: minute, hour, day of the month, month, day of the week"
    if len(cron.split()) != 5 or not croniter.is_valid(cron):
        return "A schedule is five fields: minute, hour, day of the month, month, day of the week"
    if not isinstance(zone, str) or _zone(zone) is None:
        return "Unknown time zone: use a name such as Europe/Rome or UTC"
    first = next_after(cron, zone, 0.0)
    if next_after(cron, zone, first) - first < MIN_INTERVAL:
        return "A schedule fires every five minutes at most"
    return None

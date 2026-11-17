"""Schedules: when a cron expression fires next, in its time zone."""

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

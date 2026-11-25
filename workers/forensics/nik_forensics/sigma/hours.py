"""The working hours of a request, and the ``NikOffHours`` field of a record.

``{"tz": "Europe/Rome", "days": [1, 2, 3, 4, 5], "start": "08:00", "end": "18:00"}``: ``days`` are ISO weekdays
(1 Monday … 7 Sunday) that are working days; the time of a record is read in ``tz``. When ``start`` is later than
``end`` the working time crosses midnight (a night shift): it begins on a working day at ``start`` and goes on
until ``end`` of the next morning, which belongs to the day it began on.
"""

from __future__ import annotations

from datetime import datetime
from zoneinfo import ZoneInfo


class BadHours(ValueError):
    """The hours of the request cannot be understood: the message says why."""


def _minutes(text: object, name: str) -> int:
    try:
        hour, minute = str(text).split(":")[:2]
        value = int(hour) * 60 + int(minute)
    except ValueError:
        raise BadHours(f"{name} must be a time like 08:00") from None
    if not 0 <= value <= 24 * 60:
        raise BadHours(f"{name} must be a time of the day")
    return value


class Hours:
    def __init__(self, spec: dict) -> None:
        if not isinstance(spec, dict):
            raise BadHours("hours must be an object")
        try:
            self.zone = ZoneInfo(str(spec.get("tz") or "UTC"))
        except (KeyError, ValueError, OSError):
            raise BadHours(f"the time zone {spec.get('tz')!r} is not known") from None
        days = spec.get("days")
        if not isinstance(days, list) or not all(isinstance(day, int) and 1 <= day <= 7 for day in days):
            raise BadHours("days must be a list of ISO weekdays (1 to 7)")
        self.days = frozenset(days)
        self.start = _minutes(spec.get("start", "00:00"), "start")
        self.end = _minutes(spec.get("end", "24:00"), "end")

    def off(self, ts_ms: int) -> bool:
        """True when the instant (milliseconds since the epoch) is outside the working hours."""
        try:
            when = datetime.fromtimestamp(ts_ms / 1000, self.zone)
        except (OverflowError, OSError, ValueError):
            return False  # an instant that cannot be placed is not called off hours
        minute = when.hour * 60 + when.minute
        day = when.isoweekday()
        if self.start <= self.end:
            return not (day in self.days and self.start <= minute < self.end)
        if minute >= self.start:
            return day not in self.days
        if minute < self.end:
            return (day - 2) % 7 + 1 not in self.days  # the morning belongs to the day before
        return True

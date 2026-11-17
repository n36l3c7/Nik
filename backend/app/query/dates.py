"""Dates in a query: what a value means as a span of time (UTC).

    2026-11-10              that day
    2026-11                 that month
    2026-11-10T14:30        that minute (seconds, a Z or an offset are read too)
    today, yesterday        those days
    now                     this instant
    now-7d, now-12h         that long ago (m, h, d, w)
    "7 days ago"            the same, in words (minutes, hours, days, weeks,
                            months of 30 days, years of 365)

A value is a span ``[start, end)``: ``created:2026-11-10`` is the whole day,
``created:>=2026-11-10`` from its start, ``created:>2026-11-10`` after its
end. An instant is a span of no length.

Timestamps are stored as ISO-8601 strings in UTC, some ending in ``Z`` and
some in ``+00:00``: they compare as text up to the second, which is what the
bounds returned here are cut to.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

_UNITS = {
    "m": 60,
    "min": 60,
    "minute": 60,
    "h": 3600,
    "hour": 3600,
    "d": 86400,
    "day": 86400,
    "w": 604800,
    "week": 604800,
    "month": 30 * 86400,
    "y": 365 * 86400,
    "year": 365 * 86400,
}
_AGO = re.compile(r"(\d{1,6}) ?([a-z]+?)s? ago")
_NOW = re.compile(r"now(?:-(\d{1,6})([mhdw]))?")
_DAY = re.compile(r"(\d{4})-(\d{2})-(\d{2})")
_MONTH = re.compile(r"(\d{4})-(\d{2})")
_TIME = re.compile(
    r"(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2})(?:\.\d{1,9})?)?(Z|[+-]\d{2}:?\d{2})?", re.IGNORECASE
)


def _stamp(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def span(text: str, now: datetime | None = None) -> tuple[str, str] | None:
    """``(start, end)`` of the value as comparable ISO text, or None when it is not a date."""
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).replace(microsecond=0)
    value = " ".join(str(text).strip().lower().split())
    try:
        if value == "now":
            return _stamp(now), _stamp(now)
        if value in ("today", "yesterday"):
            start = now.replace(hour=0, minute=0, second=0) - timedelta(days=1 if value == "yesterday" else 0)
            return _stamp(start), _stamp(start + timedelta(days=1))
        match = _NOW.fullmatch(value)
        if match:
            moment = now - timedelta(seconds=int(match.group(1)) * _UNITS[match.group(2)])
            return _stamp(moment), _stamp(moment)
        match = _AGO.fullmatch(value)
        if match and match.group(2) in _UNITS:
            moment = now - timedelta(seconds=int(match.group(1)) * _UNITS[match.group(2)])
            return _stamp(moment), _stamp(moment)
        match = _TIME.fullmatch(value)
        if match:
            year, month, day, hour, minute = (int(match.group(i)) for i in range(1, 6))
            start = datetime(year, month, day, hour, minute, int(match.group(6) or 0), tzinfo=timezone.utc)
            zone = (match.group(7) or "").upper()
            if zone and zone != "Z":
                sign = -1 if zone[0] == "-" else 1
                digits = zone[1:].replace(":", "")
                start -= sign * timedelta(hours=int(digits[:2]), minutes=int(digits[2:]))
            # Written to the minute: that minute; to the second: that second.
            length = timedelta(seconds=1) if match.group(6) else timedelta(minutes=1)
            return _stamp(start), _stamp(start + length)
        match = _DAY.fullmatch(value)
        if match:
            start = datetime(int(match.group(1)), int(match.group(2)), int(match.group(3)), tzinfo=timezone.utc)
            return _stamp(start), _stamp(start + timedelta(days=1))
        match = _MONTH.fullmatch(value)
        if match:
            year, month = int(match.group(1)), int(match.group(2))
            start = datetime(year, month, 1, tzinfo=timezone.utc)
            end = datetime(year + (month == 12), month % 12 + 1, 1, tzinfo=timezone.utc)
            return _stamp(start), _stamp(end)
    except (ValueError, OverflowError):
        return None
    return None

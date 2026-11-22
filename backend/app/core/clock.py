"""Moments, written and read one way.

Nik keeps a moment in two forms: an ISO-8601 string in UTC with its offset
(every ``created_at``, what the API serves) and seconds since the epoch (the
clocks the loops compare: ``next_at``, a lease, a setting). These are the
functions that go from one to the other, and the one form a moment takes
inside a sentence for a person. Standard library only: the command-line tools
use them too.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def now_iso() -> str:
    """Current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


def iso(at: float) -> str:
    """Seconds since the epoch as the ISO-8601 string of that moment in UTC."""
    return datetime.fromtimestamp(at, timezone.utc).isoformat()


def iso_or_none(at: Any) -> str | None:
    """The same for a moment that may not have come yet (None, 0): None then."""
    return iso(float(at)) if at else None


def stamp(text: Any) -> float:
    """An ISO-8601 string as seconds since the epoch; 0 when it cannot be read. A string without
    an offset is taken as UTC, which is what every string Nik wrote is."""
    try:
        moment = datetime.fromisoformat(str(text))
    except (TypeError, ValueError):
        return 0.0
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.timestamp()


def when(at: float) -> str:
    """Seconds since the epoch as a moment inside a sentence: ``2026-11-21 10:00 UTC``."""
    return datetime.fromtimestamp(at, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

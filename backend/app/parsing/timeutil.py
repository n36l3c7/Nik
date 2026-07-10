"""Timestamp conversions — port of ``src/utils/time.js``.

All functions return Unix epoch **milliseconds** (int) or ``None``.
"""

from __future__ import annotations

from datetime import datetime, timezone

# Milliseconds between the 1601 (WebKit/Windows FILETIME) and 1970 epochs.
WEBKIT_EPOCH_OFFSET_MS = 11644473600000
# Seconds between the 2001 (Mac absolute time) and 1970 epochs.
MAC_EPOCH_OFFSET_S = 978307200


def _num(value):
    try:
        n = float(value)
    except (TypeError, ValueError):
        return None
    return n if n == n else None  # reject NaN


def webkit_to_ms(us):
    """WebKit time (µs since 1601) → Unix ms."""
    n = _num(us)
    if n is None or n <= 0:
        return None
    return round(n / 1000) - WEBKIT_EPOCH_OFFSET_MS


def firefox_to_ms(us):
    """Firefox PRTime (µs since 1970) → Unix ms."""
    n = _num(us)
    if n is None or n <= 0:
        return None
    return round(n / 1000)


def mac_to_ms(seconds):
    """Mac absolute time (s since 2001) → Unix ms."""
    n = _num(seconds)
    if n is None:
        return None
    return round((n + MAC_EPOCH_OFFSET_S) * 1000)


def any_to_ms(value):
    """Best-effort conversion of a CSV/JSON timestamp value to Unix ms.

    Mirrors ``anyToMs`` in time.js: numeric magnitudes select the epoch/unit,
    otherwise the string is parsed as a date.
    """
    if value is None or value == "":
        return None
    n = _num(value)
    if n is not None:
        if n > 1e14:
            return webkit_to_ms(n)
        if n > 1e11:
            return round(n)
        if n > 1e8:
            return round(n * 1000)
        return None
    s = str(value).strip().replace(" ", "T").replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return round(dt.timestamp() * 1000)

"""The cursor of the lists of processes and logons (7.0): the sort key of the last row sent, never an offset.

The same shape as the cursor of the records (``browse.py``): base64 (URL-safe) of a JSON list ``[tag, ts, id]``,
the tag naming the list and its order (``p``/``P`` processes by time and by time reversed, ``l``/``L`` logons). A
row with no time is sorted after the ones that have one, in both orders, and its ``ts`` in the cursor is null.
The id breaks every tie.
"""

from __future__ import annotations

import base64
import binascii
import json
from typing import Any

from sqlalchemy import and_, case, or_

from .browse import BadQuery

ORDERS = ("time", "-time")


def encode(tag: str, ts: Any, last_id: int) -> str:
    return base64.urlsafe_b64encode(json.dumps([tag, ts, last_id], separators=(",", ":")).encode()).decode().rstrip("=")


def decode(tag: str, cursor: str) -> tuple[Any, int]:
    """The sort key a cursor holds; ``BadQuery`` for one that is not of this list and order."""
    try:
        parsed = json.loads(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)))
    except (ValueError, binascii.Error):
        raise BadQuery("The cursor is not one this list gave") from None
    ok = isinstance(parsed, list) and len(parsed) == 3 and parsed[0] == tag
    ok = ok and isinstance(parsed[2], int) and not isinstance(parsed[2], bool)
    ok = ok and (parsed[1] is None or (isinstance(parsed[1], int) and not isinstance(parsed[1], bool)))
    if not ok:
        raise BadQuery("The cursor is not one this list gave")
    return parsed[1], parsed[2]


def tag_of(prefix: str, order: str) -> str:
    return prefix.upper() if order == "-time" else prefix


def after(ts_column: Any, id_column: Any, order: str, ts: Any, last_id: int) -> Any:
    """What comes after the row of the cursor, written out."""
    if order == "time":
        if ts is None:
            return and_(ts_column.is_(None), id_column > last_id)
        return or_(ts_column > ts, and_(ts_column == ts, id_column > last_id), ts_column.is_(None))
    if ts is None:
        return and_(ts_column.is_(None), id_column < last_id)
    return or_(ts_column < ts, and_(ts_column == ts, id_column < last_id), ts_column.is_(None))


def sort(ts_column: Any, id_column: Any, order: str) -> list[Any]:
    none_last = case((ts_column.is_(None), 1), else_=0)
    return [none_last, ts_column, id_column] if order == "time" else [none_last, ts_column.desc(), id_column.desc()]


def check(order: str) -> None:
    if order not in ORDERS:
        raise BadQuery("order is one of " + ", ".join(ORDERS))

"""The filters of host evidence (7.0), declared once: the list of records, its histogram and its stack
read the same names, the same way (``evidence.browse._filters`` says what each one keeps)."""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException, Query

from ..evidence.browse import KEY

TYPES_MAX = 40


def keys_of(text: str, most: int, what: str) -> list[str]:
    """A comma-separated list of keys of ``data``: 1 to ``most``, each of them one ``KEY`` allows."""
    names = [name.strip() for name in text.split(",") if name.strip()]
    if not names or len(names) > most or not all(KEY.fullmatch(name) for name in names):
        raise HTTPException(
            status_code=400, detail=f"{what} is 1 to {most} keys of letters, digits and _ . : - (80 at most each)"
        )
    return names


def filters(
    kind: str = Query(default="", max_length=16),
    type: str = Query(default="", max_length=1700),  # noqa: A002 - the API's own name; a comma-separated list
    sourceId: str = Query(default="", max_length=32),  # noqa: N803
    source: str = Query(default="", max_length=60),
    sourcePrefix: str = Query(default="", max_length=60),  # noqa: N803
    profile: str = Query(default="", max_length=120),
    host: str = Query(default="", max_length=255),
    username: str = Query(default="", max_length=255),
    channel: str = Query(default="", max_length=120),
    eventId: int | None = Query(default=None),  # noqa: N803
    level: int | None = Query(default=None, ge=1, le=5),
    flagged: bool = False,
    dated: bool | None = None,
    matter: bool | None = None,
    dataKey: str | None = Query(default=None, max_length=80),  # noqa: N803
    dataValue: str | None = Query(default=None, max_length=500),  # noqa: N803
    q: str = Query(default="", max_length=200),
    from_: int | None = Query(default=None, alias="from"),
    to: int | None = None,
) -> dict[str, Any]:
    """The filters of the list of records, read the same way."""
    types = [name.strip() for name in type.split(",") if name.strip()]
    if len(types) > TYPES_MAX or any(len(name) > 40 for name in types):
        raise HTTPException(status_code=400, detail=f"type is {TYPES_MAX} values at most, 40 characters each")
    if (dataKey is None) != (dataValue is None):
        raise HTTPException(status_code=400, detail="dataKey and dataValue come together")
    if dataKey is not None and not KEY.fullmatch(dataKey):
        raise HTTPException(status_code=400, detail="dataKey is made of letters, digits and _ . : - (80 at most)")
    return {
        "kind": kind,
        "type": types,
        "sourceId": sourceId,
        "source": source,
        "sourcePrefix": sourcePrefix,
        "profile": profile,
        "host": host,
        "username": username,
        "channel": channel,
        "eventId": eventId,
        "level": level,
        "flagged": flagged,
        "dated": dated,
        "matter": matter,
        "dataKey": dataKey,
        "dataValue": dataValue,
        "q": q,
        "from": from_,
        "to": to,
    }

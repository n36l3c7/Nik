"""The filters of host evidence (7.0), declared once: the list of records, its histogram and its stack
read the same names, the same way (``evidence.browse._filters`` says what each one keeps)."""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException, Query

from ..evidence.browse import KEY

TYPES_MAX = 40
DATA_MAX = 4  # pairs of dataKey/dataValue, and dataHas, at once
KIND_NOT_MAX = 10


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
    rule: str = Query(default="", max_length=64),
    flagged: bool = False,
    dated: bool | None = None,
    matter: bool | None = None,
    kindNot: str = Query(default="", max_length=200),  # noqa: N803 - a comma-separated list of sections to leave out
    dataKey: list[str] | None = Query(default=None),  # noqa: N803
    dataValue: list[str] | None = Query(default=None),  # noqa: N803
    dataHas: list[str] | None = Query(default=None),  # noqa: N803
    q: str = Query(default="", max_length=200),
    from_: int | None = Query(default=None, alias="from"),
    to: int | None = None,
) -> dict[str, Any]:
    """The filters of the list of records, read the same way."""
    types = [name.strip() for name in type.split(",") if name.strip()]
    if len(types) > TYPES_MAX or any(len(name) > 40 for name in types):
        raise HTTPException(status_code=400, detail=f"type is {TYPES_MAX} values at most, 40 characters each")
    keys, values, has = dataKey or [], dataValue or [], dataHas or []
    if len(keys) != len(values) or len(keys) > DATA_MAX or len(has) > DATA_MAX:
        raise HTTPException(
            status_code=400, detail=f"dataKey and dataValue come together, {DATA_MAX} pairs at most (dataHas too)"
        )
    if any(len(text) > 500 for text in values):
        raise HTTPException(status_code=422, detail="dataValue is 500 characters at most")
    if not all(KEY.fullmatch(key) for key in keys):
        raise HTTPException(status_code=400, detail="dataKey is made of letters, digits and _ . : - (80 at most)")
    if any(not KEY.fullmatch(held.partition(":")[0]) or ":" not in held or len(held) > 580 for held in has):
        raise HTTPException(
            status_code=400, detail="dataHas is key:value, the key of letters, digits and _ . - (80 at most)"
        )
    not_kinds = [name.strip() for name in kindNot.split(",") if name.strip()]
    if len(not_kinds) > KIND_NOT_MAX or any(len(name) > 16 for name in not_kinds):
        raise HTTPException(status_code=400, detail=f"kindNot is {KIND_NOT_MAX} sections at most")
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
        "rule": rule,
        "flagged": flagged,
        "dated": dated,
        "matter": matter,
        "kindNot": not_kinds,
        "dataKey": keys,
        "dataValue": values,
        "dataHas": has,
        "q": q,
        "from": from_,
        "to": to,
    }

"""The set of rules the worker is given with a file, and the hours it reads time by.

The set is every rule that is enabled and supported, one JSON line each, in the order of their ids,
so that the same rules always give the same bytes and the same SHA-256: the digest. The worker keeps
the sets it was given by their digest (the three it used last), and a ``/parse`` that names a digest
it lacks is answered ``409`` with ``missingRules``; ``give`` sends it (``PUT /rules/<digest>``).

The set is built once and kept; any change to the rules (``rules.bump``) makes the next reader build
it again, in whichever process of the server it is.
"""

from __future__ import annotations

import hashlib
import json
import threading
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from ..core.models import Incident, SigmaRule
from . import rules, worker

KEPT = 3  # the sets whose bytes are held, for a worker that asks for the one of a file read a moment ago
GIVE_TIMEOUT = 300
DAYS_ALL = [1, 2, 3, 4, 5, 6, 7]


@dataclass
class Set:
    """A set of rules: its digest, the bytes the worker is given, how many rules, and what each says of
    itself (what a detection copies: title, author, level, tags)."""

    digest: str
    body: bytes
    count: int
    meta: dict[str, dict[str, Any]] = field(default_factory=dict)


_lock = threading.Lock()
_held: dict[str, Any] = {"gen": None, "set": None}
_recent: OrderedDict[str, bytes] = OrderedDict()


def forget() -> None:
    with _lock:
        _held.update(gen=None, set=None)
        _recent.clear()


def build(db: OrmSession) -> Set | None:
    """The set as the database has it now; None when no rule is both enabled and supported."""
    row = SigmaRule
    found = db.execute(
        select(
            row.id,
            row.title,
            row.author,
            row.level,
            row.kind,
            row.product,
            row.category,
            row.service,
            row.tags,
            row.source,
        )
        .where(row.enabled.is_(True), row.supported.is_(True))
        .order_by(row.id)
    ).all()
    if not found:
        return None
    lines = []
    meta: dict[str, dict[str, Any]] = {}
    for (
        rule_id,
        title,
        author,
        level,
        kind,
        product,
        category,
        service,
        tags,
        source,
    ) in found:
        lines.append(
            json.dumps(
                {
                    "id": rule_id,
                    "title": title,
                    "level": level,
                    "kind": kind,
                    "product": product,
                    "category": category,
                    "service": service,
                    "source": source,
                },
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        meta[rule_id] = {
            "title": title,
            "author": author,
            "level": level,
            "tags": list(tags or []),
        }
    body = ("\n".join(lines) + "\n").encode("utf-8")
    return Set(hashlib.sha256(body).hexdigest(), body, len(lines), meta)


def current(db: OrmSession) -> Set | None:
    """The set to read a file with: kept until the rules change. None when there is nothing to run."""
    gen = rules.generation(db)
    with _lock:
        if _held["gen"] == gen and _held["gen"] is not None:
            return _held["set"]
    made = build(db)
    with _lock:
        _held.update(gen=gen, set=made)
        if made is not None:
            _recent[made.digest] = made.body
            _recent.move_to_end(made.digest)
            while len(_recent) > KEPT:
                _recent.popitem(last=False)
    return made


def body_of(digest: str) -> bytes | None:
    with _lock:
        return _recent.get(digest)


def give(digest: str) -> str | None:
    """Send the worker the set it asked for. None when it took it; else a sentence saying why not."""
    body = body_of(digest)
    if body is None:
        return "The rules of this reading changed while it began: it is read again with the new ones"
    status, answer = worker.ask(f"/rules/{digest}", method="PUT", raw=body, timeout=GIVE_TIMEOUT)
    if status != 200:
        return worker.sentence(status, answer)
    return None


def hours(db: OrmSession, incident: Incident | None) -> dict[str, Any]:
    """The working hours of the organisation as the worker reads them (``params.hours``): the rules that
    ask whether a time is outside them. They are the business hours of the settings, read in the time
    zone of the incident, else the one of Nik (UTC unless the settings say another)."""
    from ..timers import business_hours

    held = business_hours(db, incident)
    end = f"{min(held['endHour'], 24):02d}:00"
    return {
        "tz": held["tz"],
        "days": [1, 2, 3, 4, 5] if held["flagWeekends"] else list(DAYS_ALL),
        "start": f"{held['startHour']:02d}:00",
        "end": end,
    }

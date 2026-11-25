"""Trying a rule on an incident: the text of the rule is run over the records the incident holds.

Nothing is saved. The records are taken in time order, 20,000 at a time, and each page is given to the
worker (``POST /sigma/try``) with the rules and the hours; the worker answers the matches, by key. The run
stops at 200,000 records or after 60 seconds, whichever comes first, and says that it did: a rule tried
on a larger incident is tried on its first 200,000 records. A page is judged alone, so a correlation rule
(a count over time, a sequence) sees only the records of one page; the answer says so for each such rule.
"""

from __future__ import annotations

import time
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from ..core.models import EvidenceRecord, Incident
from ..evidence import browse
from . import checking, manage, ruleset, worker
from .rules import SigmaError

PAGE = 20_000
RECORDS_MAX = 200_000
SECONDS_MAX = 60
SHOWN_MAX = 1000
CORRELATION_NOTE = "A correlation is judged within a page of 20,000 records at a time"


def _line(info: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(info["id"]),
        "title": str(info.get("title") or ""),
        "level": checking.level_of(info.get("level")),
        "kind": "correlation" if info.get("kind") == "correlation" else "rule",
        "product": str(info.get("product") or ""),
        "category": str(info.get("category") or ""),
        "service": str(info.get("service") or ""),
        "source": str(info["source"]),
    }


def _page(
    db: OrmSession,
    incident_id: str,
    f: dict[str, Any],
    after: tuple[Any, int] | None,
    limit: int,
) -> list[Any]:
    record = EvidenceRecord
    query = select(
        record.id,
        record.kind,
        record.channel,
        record.event_id,
        record.key,
        record.ts,
        record.host,
        record.username,
        record.summary,
        record.data,
    ).where(*browse._filters(incident_id, f))
    if after is not None:
        query = query.where(browse._after("time", *after))
    return list(db.execute(query.order_by(*browse._sort("time")).limit(limit + 1)))


def _given(row: Any) -> dict[str, Any]:
    return {
        "kind": row.kind,
        "channel": row.channel,
        "event_id": row.event_id,
        "key": row.key,
        "ts": row.ts,
        "host": row.host,
        "username": row.username,
        "summary": row.summary,
        "data": row.data if isinstance(row.data, dict) else {},
    }


def run(db: OrmSession, incident_id: str, text: str, f: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run the rules of ``text`` over the records of an incident (``f``: ``kind``, ``sourceId``, ``source``
    as the list of records takes them). Raises ``SigmaError``."""
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise SigmaError("Incident not found", 404)
    engine, found, errors = manage.read(text)
    if errors:
        first = errors[0]
        where = f" (line {first['line']})" if first["line"] else ""
        raise SigmaError(f"This is not a Sigma rule: {first['message']}{where}", 400, errors)
    if not found:
        raise SigmaError("The text holds no rule")
    lines = [_line(info) for info in found if info.get("supported", True)]
    answer: dict[str, Any] = {
        "engine": engine,
        "rules": [manage.shown(info) for info in found],
        "ran": [line["id"] for line in lines],
        "scanned": 0,
        "cut": False,
        "cutReason": "",
        "limits": {"records": RECORDS_MAX, "seconds": SECONDS_MAX, "page": PAGE},
        "matchCount": 0,
        "matches": [],
        "notEvaluated": [],
        "notes": [CORRELATION_NOTE] if any(line["kind"] == "correlation" for line in lines) else [],
        "seconds": 0.0,
    }
    if not lines:
        return answer
    hours = ruleset.hours(db, incident)
    filter_ = {key: value for key, value in (f or {}).items() if key in ("kind", "sourceId", "source", "type")}
    began = time.monotonic()
    after: tuple[Any, int] | None = None
    scanned = 0
    matched: list[dict[str, Any]] = []
    not_evaluated: dict[str, str] = {}
    while True:
        room = min(PAGE, RECORDS_MAX - scanned)
        if room <= 0:
            if _more(db, incident_id, filter_, after):
                answer["cut"], answer["cutReason"] = True, "records"
            break
        rows = _page(db, incident_id, filter_, after, room)
        more = len(rows) > room
        rows = rows[:room]
        if not rows:
            break
        left = SECONDS_MAX - (time.monotonic() - began)
        status, said = worker.ask(
            "/sigma/try",
            {"rules": lines, "hours": hours, "records": [_given(row) for row in rows]},
            timeout=max(30, left + 30),
        )
        if status != 200:
            raise SigmaError(worker.sentence(status, said), 502 if status >= 500 else 400)
        for match in said.get("matches") or []:
            if isinstance(match, dict) and isinstance(match.get("rule"), str) and isinstance(match.get("key"), str):
                matched.append(match)
        for item in said.get("notEvaluated") or []:
            if isinstance(item, dict) and isinstance(item.get("rule"), str):
                not_evaluated.setdefault(item["rule"], str(item.get("reason") or "")[:400])
        scanned += len(rows)
        last = rows[-1]
        after = (last.ts, last.id)
        if not more:
            break
        if time.monotonic() - began >= SECONDS_MAX:
            answer["cut"], answer["cutReason"] = True, "time"
            break
    answer["scanned"] = scanned
    answer["seconds"] = round(time.monotonic() - began, 1)
    answer["notEvaluated"] = [{"rule": rule, "reason": reason} for rule, reason in not_evaluated.items()]
    answer["matchCount"] = len(matched)
    answer["matches"] = _shown(db, incident_id, matched[:SHOWN_MAX], {line["id"]: line for line in lines})
    return answer


def _more(db: OrmSession, incident_id: str, f: dict[str, Any], after: tuple[Any, int] | None) -> bool:
    """Whether the incident holds records after the last one that was tried."""
    return bool(_page(db, incident_id, f, after, 0))


def _shown(
    db: OrmSession,
    incident_id: str,
    matched: list[dict[str, Any]],
    lines: dict[str, Any],
) -> list[dict[str, Any]]:
    """The matches with what the records are: their id, time and summary."""
    keys = sorted({match["key"] for match in matched})
    held: dict[str, Any] = {}
    for start in range(0, len(keys), 500):
        found = db.execute(
            select(
                EvidenceRecord.key,
                EvidenceRecord.id,
                EvidenceRecord.ts,
                EvidenceRecord.summary,
            ).where(
                EvidenceRecord.incident_id == incident_id,
                EvidenceRecord.key.in_(keys[start : start + 500]),
            )
        )
        held.update({key: (record_id, ts, summary) for key, record_id, ts, summary in found})
    out = []
    for match in matched:
        record_id, ts, summary = held.get(match["key"], (None, None, ""))
        rule = lines.get(match["rule"], {})
        shown = {
            "ruleId": match["rule"],
            "title": rule.get("title", ""),
            "level": rule.get("level", 3),
            "recordId": record_id,
            "key": match["key"],
            "ts": ts,
            "summary": summary or "",
        }
        if isinstance(match.get("records"), list):
            shown["records"] = [item for item in match["records"] if isinstance(item, str)][:50]
        out.append(shown)
    return out

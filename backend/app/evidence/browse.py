"""What the screens of host evidence read (7.0): sources, one page of records, marks, the summary.

An incident may hold ten million records, so nothing here loads a whole incident and a list is
paged by key, never by OFFSET: the cursor is the sort key of the last row sent, and the next page
asks for what comes after it. The queries work on SQLite and PostgreSQL alike and read no JSON.

**The cursor** is base64 (URL-safe) of a JSON list: ``["t", ts, id]`` for the order ``time``,
``["T", ts, id]`` for ``-time`` and ``["f", seq, id]`` for ``file``. A record with no time is
sorted after the ones that have one, in both time orders, and its ``ts`` in the cursor is null.
The id breaks every tie, so two records at the same millisecond come once each.
"""

from __future__ import annotations

import base64
import binascii
import json
from typing import Any

from sqlalchemy import and_, case, func, or_, select
from sqlalchemy.orm import Session as OrmSession

from ..core.models import EvidenceDetection, EvidenceMark, EvidenceRecord, EvidenceSource

COUNT_CAP = 100_001
LIMIT_MAX = 500
ORDERS = ("time", "-time", "file")
_TAGS = {"time": "t", "-time": "T", "file": "f"}


class BadQuery(Exception):
    """A request that cannot be answered as asked: a sentence for the caller (400)."""


# --------------------------------------------------------------------------- #
# Sources                                                                     #
# --------------------------------------------------------------------------- #
def source_of(row: EvidenceSource, work: dict[str, Any] | None = None) -> dict[str, Any]:
    """A source as the screens read it, without its report (which can be large)."""
    return {
        "id": row.id,
        "kind": row.kind,
        "source": row.source,
        "fileName": row.file_name,
        "filePath": row.file_path,
        "size": row.size,
        "sha256": row.sha256,
        "host": row.host,
        "username": row.username,
        "profile": row.profile,
        "parser": row.parser,
        "parserVersion": row.parser_version,
        "state": row.state,
        "legacy": bool(row.legacy),
        "read": row.read,
        "inFile": row.in_file,
        "readCount": row.read_count,
        "kept": row.kept,
        "duplicates": row.duplicates,
        "skipped": row.skipped,
        "notes": row.notes,
        "truncated": row.truncated,
        "indicators": row.indicators,
        "firstTs": row.first_ts,
        "lastTs": row.last_ts,
        "error": row.error,
        "seen": {"by": row.seen_by, "at": row.seen_at, "note": row.seen_note or ""} if row.seen_at else None,
        "createdAt": row.created_at,
        "createdBy": row.created_by,
        "parsedAt": row.parsed_at,
        "collectionId": row.collection_id,
        "work": work,
    }


def sources(db: OrmSession, incident_id: str, kind: str | None = None) -> list[EvidenceSource]:
    """The sources of an incident, newest first."""
    query = select(EvidenceSource).where(EvidenceSource.incident_id == incident_id)
    if kind:
        query = query.where(EvidenceSource.kind == kind)
    return list(db.scalars(query.order_by(EvidenceSource.created_at.desc(), EvidenceSource.id.desc())))


def source(db: OrmSession, incident_id: str, source_id: str) -> EvidenceSource | None:
    row = db.get(EvidenceSource, source_id)
    return row if row is not None and row.incident_id == incident_id else None


# --------------------------------------------------------------------------- #
# Records                                                                     #
# --------------------------------------------------------------------------- #
def _like(text: str) -> str:
    escaped = text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def _filters(incident_id: str, f: dict[str, Any]) -> list[Any]:
    record = EvidenceRecord
    where: list[Any] = [record.incident_id == incident_id]
    for name, column in (
        ("kind", record.kind),
        ("type", record.type),
        ("sourceId", record.source_id),
        ("host", record.host),
        ("username", record.username),
        ("channel", record.channel),
        ("eventId", record.event_id),
    ):
        if f.get(name) not in (None, ""):
            where.append(column == f[name])
    if f.get("level") is not None:
        where.append(record.level >= f["level"])
    if f.get("q"):
        where.append(record.summary.ilike(_like(f["q"]), escape="\\"))
    if f.get("from") is not None:
        where.append(record.ts >= f["from"])
    if f.get("to") is not None:
        where.append(record.ts <= f["to"])
    if f.get("flagged"):
        where.append(EvidenceMark.flagged.is_(True))
    return where


def encode(order: str, first: Any, last_id: int) -> str:
    raw = json.dumps([_TAGS[order], first, last_id], separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode(order: str, cursor: str) -> tuple[Any, int]:
    """The sort key a cursor holds; ``BadQuery`` for one that is not of this order."""
    try:
        parsed = json.loads(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)))
    except (ValueError, binascii.Error):
        raise BadQuery("The cursor is not one this list gave") from None
    ok = isinstance(parsed, list) and len(parsed) == 3 and parsed[0] == _TAGS[order]
    ok = ok and isinstance(parsed[2], int) and not isinstance(parsed[2], bool)
    ok = ok and (parsed[1] is None or (isinstance(parsed[1], int) and not isinstance(parsed[1], bool)))
    ok = ok and (parsed[1] is not None or order != "file")
    if not ok:
        raise BadQuery("The cursor is not one this list gave")
    return parsed[1], parsed[2]


def _after(order: str, first: Any, last_id: int) -> Any:
    """What comes after the row of the cursor, written out (no OFFSET). In the time orders the
    records with no time are the last ones, and are themselves ordered by id."""
    record = EvidenceRecord
    if order == "file":
        return or_(record.seq > first, and_(record.seq == first, record.id > last_id))
    if order == "time":
        if first is None:
            return and_(record.ts.is_(None), record.id > last_id)
        return or_(record.ts > first, and_(record.ts == first, record.id > last_id), record.ts.is_(None))
    if first is None:
        return and_(record.ts.is_(None), record.id < last_id)
    return or_(record.ts < first, and_(record.ts == first, record.id < last_id), record.ts.is_(None))


def _sort(order: str) -> list[Any]:
    record = EvidenceRecord
    none_last = case((record.ts.is_(None), 1), else_=0)
    if order == "time":
        return [none_last, record.ts, record.id]
    if order == "-time":
        return [none_last, record.ts.desc(), record.id.desc()]
    return [record.seq, record.id]


def record_of(row: EvidenceRecord, flagged: bool | None, note: str | None) -> dict[str, Any]:
    """A record as the lists show it: light, without its fields and its place in the file."""
    return {
        "id": row.id,
        "key": row.key,
        "kind": row.kind,
        "type": row.type,
        "ts": row.ts,
        "seq": row.seq,
        "host": row.host,
        "username": row.username,
        "eventId": row.event_id,
        "channel": row.channel,
        "summary": row.summary,
        "level": row.level,
        "truncated": bool(row.truncated),
        "sourceId": row.source_id,
        "flagged": bool(flagged),
        "note": note or "",
    }


def records(
    db: OrmSession, incident_id: str, f: dict[str, Any], order: str, limit: int, cursor: str | None
) -> dict[str, Any]:
    """One page of records: ``{"records", "next", "count", "countCapped"}``. ``f`` holds the filters
    by their names in the API; the count is made on the first page only."""
    if order not in ORDERS:
        raise BadQuery("order is one of " + ", ".join(ORDERS))
    if order == "file" and not f.get("sourceId"):
        raise BadQuery("The order file needs a sourceId")
    after = _after(order, *decode(order, cursor)) if cursor else None
    where = _filters(incident_id, f)
    record = EvidenceRecord
    mark_on = and_(EvidenceMark.incident_id == record.incident_id, EvidenceMark.key == record.key)
    query = select(record, EvidenceMark.flagged, EvidenceMark.note).outerjoin(EvidenceMark, mark_on).where(*where)
    if after is not None:
        query = query.where(after)
    rows = db.execute(query.order_by(*_sort(order)).limit(limit + 1)).all()
    more = len(rows) > limit
    rows = rows[:limit]
    answer: dict[str, Any] = {
        "records": [record_of(row, flagged, note) for row, flagged, note in rows],
        "next": None,
        "count": None,
        "countCapped": False,
    }
    if more and rows:
        last = rows[-1][0]
        answer["next"] = encode(order, last.seq if order == "file" else last.ts, last.id)
    if not cursor:
        counted = select(record.id).where(*where)
        if f.get("flagged"):
            counted = counted.join(EvidenceMark, mark_on)
        total = db.scalar(select(func.count()).select_from(counted.limit(COUNT_CAP).subquery())) or 0
        answer["count"], answer["countCapped"] = total, total >= COUNT_CAP
    return answer


def record(db: OrmSession, incident_id: str, record_id: int) -> dict[str, Any] | None:
    """The whole record: its fields, where it is in the original, its file and its detections."""
    row = db.get(EvidenceRecord, record_id)
    if row is None or row.incident_id != incident_id:
        return None
    mark = db.get(EvidenceMark, (incident_id, row.key))
    answer = record_of(row, mark.flagged if mark else False, mark.note if mark else "")
    answer["data"] = row.data or {}
    answer["locator"] = row.locator or {}
    held = db.get(EvidenceSource, row.source_id)
    answer["source"] = (
        {"id": held.id, "fileName": held.file_name, "sha256": held.sha256, "parser": held.parser, "read": held.read}
        if held is not None
        else None
    )
    found = db.scalars(
        select(EvidenceDetection).where(EvidenceDetection.record_id == row.id).order_by(EvidenceDetection.level.desc())
    )
    answer["detections"] = [
        {
            "ruleId": d.rule_id,
            "ruleTitle": d.rule_title,
            "ruleAuthor": d.rule_author,
            "level": d.level,
            "tags": list(d.tags or []),
        }
        for d in found
    ]
    return answer


def key_exists(db: OrmSession, incident_id: str, key: str) -> bool:
    found = select(EvidenceRecord.id).where(EvidenceRecord.incident_id == incident_id, EvidenceRecord.key == key)
    return db.scalar(found.limit(1)) is not None


# --------------------------------------------------------------------------- #
# The summary                                                                 #
# --------------------------------------------------------------------------- #
def summary(db: OrmSession, incident_id: str) -> dict[str, Any]:
    """Per section: its files, its records, the files read in part and not acknowledged, the
    failed ones and the ones being read. Aggregates over ``evidence_sources`` only."""
    s = EvidenceSource
    rows = db.execute(
        select(
            s.kind,
            func.count(),
            func.coalesce(func.sum(s.kept), 0),
            func.coalesce(func.sum(case((and_(s.read == "partial", s.seen_at.is_(None)), 1), else_=0)), 0),
            func.coalesce(func.sum(case((s.state == "failed", 1), else_=0)), 0),
            func.coalesce(func.sum(case((s.state.in_(("queued", "parsing")), 1), else_=0)), 0),
        )
        .where(s.incident_id == incident_id)
        .group_by(s.kind)
    ).all()
    kinds = {
        kind: {
            "sources": int(n),
            "records": int(kept),
            "partial": int(partial),
            "failed": int(failed),
            "parsing": int(parsing),
        }
        for kind, n, kept, partial, failed, parsing in rows
    }
    return {"kinds": kinds, "partialUnseen": sum(item["partial"] for item in kinds.values())}

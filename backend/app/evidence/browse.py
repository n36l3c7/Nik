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
import re
from typing import Any

from sqlalchemy import Boolean, String, and_, bindparam, case, func, or_, select
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.sql.functions import FunctionElement

from ..core.models import LEVELS, EvidenceDetection, EvidenceMark, EvidenceRecord, EvidenceSource
from .curated import CURATED

COUNT_CAP = 100_001
LIMIT_MAX = 500
ORDERS = ("time", "-time", "file")
_TAGS = {"time": "t", "-time": "T", "file": "f"}
KEY = re.compile(r"[A-Za-z0-9_.:-]{1,80}")
_LEVEL_NAMES = {number: name for name, number in LEVELS.items()}
FIELD_CUT = 500
CHANNELS_SHOWN = 5


class BadQuery(Exception):
    """A request that cannot be answered as asked: a sentence for the caller (400)."""


class json_text(FunctionElement):  # noqa: N801 - named as the helpers of query/held.py
    """The top-level key of a JSON column as text, or NULL: ``column ->> key`` on PostgreSQL (the key
    bound), ``json_extract(column, '$."key"')`` on SQLite (the key is checked against ``KEY``, so it holds
    no double quote). A true or false is ``true`` or ``false`` on both."""

    type = String()
    inherit_cache = False

    def __init__(self, column: Any, key: str):
        if not KEY.fullmatch(key or ""):
            raise BadQuery("A key of data is made of letters, digits and _ . : - (80 at most)")
        self.key = key
        super().__init__(column, bindparam(None, key, type_=String, unique=True))


@compiles(json_text)
def _json_text_sqlite(element: json_text, compiler: Any, **kw: Any) -> str:
    column = compiler.process(element.clauses.clauses[0], **kw)
    path = "'$.\"" + element.key + "\"'"
    return (
        f"CASE json_type({column}, {path}) WHEN 'true' THEN 'true' WHEN 'false' THEN 'false' "
        f"WHEN 'null' THEN NULL ELSE CAST(json_extract({column}, {path}) AS TEXT) END"
    )


@compiles(json_text, "postgresql")
def _json_text_postgresql(element: json_text, compiler: Any, **kw: Any) -> str:
    column, key = (compiler.process(clause, **kw) for clause in element.clauses.clauses)
    return f"({column} ->> CAST({key} AS TEXT))"


class json_has(FunctionElement):  # noqa: N801 - named as json_text
    """True when the array at the top-level key of a JSON column holds the text ``value``: JSONB containment on
    PostgreSQL, a ``json_each`` of the key on SQLite. A key that is no array holds nothing."""

    type = Boolean()
    inherit_cache = False

    def __init__(self, column: Any, key: str, value: str):
        if not KEY.fullmatch(key or ""):
            raise BadQuery("A key of data is made of letters, digits and _ . : - (80 at most)")
        self.key = key
        super().__init__(
            column,
            bindparam(None, key, type_=String, unique=True),
            bindparam(None, json.dumps({key: [value]}), type_=String, unique=True),
            bindparam(None, value, type_=String, unique=True),
        )


@compiles(json_has)
def _json_has_sqlite(element: json_has, compiler: Any, **kw: Any) -> str:
    column = compiler.process(element.clauses.clauses[0], **kw)
    value = compiler.process(element.clauses.clauses[3], **kw)
    path = "'$.\"" + element.key + "\"'"
    return (
        f"(json_type({column}, {path}) = 'array' AND EXISTS "
        f"(SELECT 1 FROM json_each({column}, {path}) AS held WHERE held.value = {value}))"
    )


@compiles(json_has, "postgresql")
def _json_has_postgresql(element: json_has, compiler: Any, **kw: Any) -> str:
    column = compiler.process(element.clauses.clauses[0], **kw)
    held = compiler.process(element.clauses.clauses[2], **kw)
    return f"({column} @> CAST({held} AS JSONB))"


# --------------------------------------------------------------------------- #
# Sources                                                                     #
# --------------------------------------------------------------------------- #
def first_reason(row: EvidenceSource) -> str | None:
    """The reason that cost a file read in part (or not at all) the most records, in its reasons table's
    wording. Chosen by count and then by name: a JSON object keeps no order of its own on PostgreSQL."""
    if row.read not in ("partial", "failed"):
        return None
    reasons = (row.report or {}).get("reasons")
    if not isinstance(reasons, dict) or not reasons:
        return None

    def weight(name: str) -> tuple[int, str]:
        held = reasons[name]
        return (-int(held.get("count") or 0) if isinstance(held, dict) else 0, name)

    return min(reasons, key=weight)


def channels_of(row: EvidenceSource) -> list[str]:
    """The channels a file's records name, the most records first and then by name (at most 5)."""
    held = (row.report or {}).get("channels")
    if not isinstance(held, dict):
        return []
    count = {name: n for name, n in held.items() if isinstance(n, int) and not isinstance(n, bool)}
    return sorted(count, key=lambda name: (-count[name], name))[:CHANNELS_SHOWN]


def _members_of(row: EvidenceSource) -> dict[str, Any] | None:
    if row.kind != "collection" or row.source != "collection.zip":
        return None
    held = (row.report or {}).get("collection")
    return held if isinstance(held, dict) else {}


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
        "channels": channels_of(row),
        "truncated": row.truncated,
        "indicators": row.indicators,
        "firstTs": row.first_ts,
        "lastTs": row.last_ts,
        "error": row.error,
        "firstReason": first_reason(row),
        "seen": {"by": row.seen_by, "at": row.seen_at, "note": row.seen_note or ""} if row.seen_at else None,
        "createdAt": row.created_at,
        "createdBy": row.created_by,
        "parsedAt": row.parsed_at,
        "collectionId": row.collection_id,
        # A collection (a triage zip): what it holds and how far its import is (``report.collection``); None otherwise.
        "members": _members_of(row),
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


def _prefix(text: str) -> str:
    escaped = text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"{escaped}%"


def _curated() -> Any:
    """The event-log records the curated list names: an OR over channels of (channel and its ids). The
    channel is compared in lower case, as the worker does (a log is spelled as its file spelled it)."""
    record = EvidenceRecord
    return or_(*(and_(func.lower(record.channel) == name, record.event_id.in_(ids)) for name, ids in CURATED.items()))


def _listed(value: Any) -> list[Any]:
    """A filter that may come once as a text or several times as a list."""
    if value is None or value == "":
        return []
    return list(value) if isinstance(value, (list, tuple)) else [value]


def _filters(incident_id: str, f: dict[str, Any]) -> list[Any]:
    record = EvidenceRecord
    where: list[Any] = [record.incident_id == incident_id]
    for name, column in (
        ("kind", record.kind),
        ("sourceId", record.source_id),
        ("host", record.host),
        ("username", record.username),
        ("channel", record.channel),
        ("eventId", record.event_id),
    ):
        if f.get(name) not in (None, ""):
            where.append(column == f[name])
    # One type or a list of them (the API gives a list, the callers of the fields a text).
    types = [f["type"]] if isinstance(f.get("type"), str) and f["type"] else list(f.get("type") or ())
    if len(types) == 1:
        where.append(record.type == types[0])
    elif types:
        where.append(record.type.in_(types))
    # What the file is, asked of its row: no join on the main query.
    # A record may say its own source (an export of Plaso holds records of every section): that one counts, and
    # the file's own only for the records that say none.
    held, own = [], []
    if f.get("source"):
        held.append(EvidenceSource.source == f["source"])
        own.append(record.source == f["source"])
    if f.get("sourcePrefix"):
        held.append(EvidenceSource.source.like(_prefix(f["sourcePrefix"]), escape="\\"))
        own.append(record.source.like(_prefix(f["sourcePrefix"]), escape="\\"))
    if held:
        files = select(EvidenceSource.id).where(EvidenceSource.incident_id == incident_id, *held)
        where.append(or_(and_(*own), and_(record.source.is_(None), record.source_id.in_(files))))
    if f.get("profile"):
        files = select(EvidenceSource.id).where(
            EvidenceSource.incident_id == incident_id, EvidenceSource.profile == f["profile"]
        )
        where.append(record.source_id.in_(files))
    if f.get("dated") is not None:
        where.append(record.ts.is_not(None) if f["dated"] else record.ts.is_(None))
    # Several keys at once (a pair is a key and the value at the same place); one text keeps working.
    keys, values = _listed(f.get("dataKey")), _listed(f.get("dataValue"))
    for key, value in zip(keys, values or [""] * len(keys), strict=False):
        where.append(json_text(record.data, key) == str(value or ""))
    for pair in _listed(f.get("dataHas")):
        key, _, value = str(pair).partition(":")
        where.append(json_has(record.data, key, value))
    if f.get("kindNot"):
        where.append(or_(record.kind.is_(None), record.kind.not_in(_listed(f["kindNot"]))))
    if f.get("matter"):
        where.append(_curated())
    if f.get("level") is not None:
        where.append(record.level >= f["level"])
    if f.get("rule"):
        # The records a rule of Sigma matched (``evidence_detections``): asked of the table, no join.
        matched = select(EvidenceDetection.record_id).where(
            EvidenceDetection.incident_id == incident_id, EvidenceDetection.rule_id == f["rule"]
        )
        where.append(record.id.in_(matched))
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


def _projected(data: Any, names: list[str]) -> dict[str, Any]:
    """Only the asked keys of a record's data that exist; a long text is cut."""
    held = data if isinstance(data, dict) else {}
    return {
        name: held[name][:FIELD_CUT] if isinstance(held[name], str) else held[name] for name in names if name in held
    }


def records(
    db: OrmSession,
    incident_id: str,
    f: dict[str, Any],
    order: str,
    limit: int,
    cursor: str | None,
    fields: list[str] | None = None,
) -> dict[str, Any]:
    """One page of records: ``{"records", "next", "count", "countCapped"}``. ``f`` holds the filters
    by their names in the API; the count is made on the first page only. ``fields`` names keys of
    ``data`` that each record of the page carries (under ``data``)."""
    for name in fields or ():
        if not KEY.fullmatch(name):
            raise BadQuery("A key of data is made of letters, digits and _ . : - (80 at most)")
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
    if fields:
        for shown, (row, _flagged, _note) in zip(answer["records"], rows, strict=True):
            shown["data"] = _projected(row.data, fields)
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
            # A correlation: the keys of the records that made it (up to 50); empty for a rule on one record.
            "records": list(d.records or []),
        }
        for d in found
    ]
    return answer


EXPORT_VERSION = 1
EXPORT_MARKS = 20_000


def exported(db: OrmSession, incident_id: str) -> dict[str, Any]:
    """What an export of the incident carries of its host evidence: every file with its SHA-256,
    its counts and its parse report, and the flags and notes on records. Neither the records nor
    the originals: whoever imports it sees what was there, and gives the files again
    (``imports.restore`` takes this back)."""
    listed = []
    for row in sources(db, incident_id):
        listed.append({**source_of(row), "report": row.report or {}})
    marks = []
    held = (
        select(EvidenceMark, EvidenceRecord.summary, EvidenceRecord.type, EvidenceRecord.ts, EvidenceRecord.kind)
        .outerjoin(
            EvidenceRecord,
            and_(EvidenceRecord.incident_id == EvidenceMark.incident_id, EvidenceRecord.key == EvidenceMark.key),
        )
        .where(EvidenceMark.incident_id == incident_id)
        .order_by(EvidenceMark.key)
        .limit(EXPORT_MARKS)
    )
    for mark, summary, kind, ts, section in db.execute(held):
        marks.append(
            {
                "key": mark.key,
                "flagged": bool(mark.flagged),
                "note": mark.note or "",
                "updatedBy": mark.updated_by,
                "updatedAt": mark.updated_at,
                # What the record was, for a reader that has the export and not the file.
                "summary": summary or "",
                "type": kind or "",
                "kind": section or "",
                "ts": ts,
            }
        )
    return {"version": EXPORT_VERSION, "sources": listed, "marks": marks}


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
            # A file an import listed and that is not here was read in part elsewhere, not here.
            func.coalesce(
                func.sum(case((and_(s.read == "partial", s.seen_at.is_(None), s.state == "done"), 1), else_=0)), 0
            ),
            func.coalesce(func.sum(case((s.state == "failed", 1), else_=0)), 0),
            func.coalesce(func.sum(case((s.state.in_(("queued", "parsing")), 1), else_=0)), 0),
            func.coalesce(func.sum(case((s.state == "absent", 1), else_=0)), 0),
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
            "absent": int(absent),
        }
        for kind, n, kept, partial, failed, parsing, absent in rows
    }
    # What the rules found, per section and level (1 informational to 5 critical).
    d, r = EvidenceDetection, EvidenceRecord
    levels = db.execute(
        select(r.kind, d.level, func.count())
        .select_from(d)
        .join(r, r.id == d.record_id)
        .where(d.incident_id == incident_id)
        .group_by(r.kind, d.level)
    ).all()
    for item in kinds.values():
        item["detections"] = dict.fromkeys(("1", "2", "3", "4", "5"), 0)
        item["processes"] = item["logons"] = 0
    # The processes and the logons the files gave, as their reports count them (no scan of the tables).
    for kind, report in db.execute(select(s.kind, s.report).where(s.incident_id == incident_id, s.state != "archived")):
        if kind in kinds and isinstance(report, dict):
            for name in ("processes", "logons"):
                held = report.get(name)
                if isinstance(held, int) and not isinstance(held, bool):
                    kinds[kind][name] += held
    for kind, level, n in levels:
        if kind in kinds and str(level) in kinds[kind]["detections"]:
            kinds[kind]["detections"][str(level)] = int(n)
    return {"kinds": kinds, "partialUnseen": sum(item["partial"] for item in kinds.values())}


# --------------------------------------------------------------------------- #
# Detections                                                                  #
# --------------------------------------------------------------------------- #
RULES_MAX = 1000
HOSTS_SHOWN = 10


def detections(db: OrmSession, incident_id: str, f: dict[str, Any], limit: int = 200) -> dict[str, Any]:
    """What the rules found, one row for each rule: ``{"rules", "total", "detections", "byLevel"}``.

    ``f`` keeps ``kind`` (the section of the record), ``sourceId`` (the file), ``source`` (the kind of
    file, as the parser names it) and ``level`` (the lowest). A row says the rule's id, title, author,
    level (the highest it matched with), tags, how many records it matched, the time of the first and the
    last of them, and the hosts they are of (``hosts`` the first ten by name, ``hostCount`` all of them).
    Highest level first, then the rule that matched most."""
    d, r = EvidenceDetection, EvidenceRecord
    where: list[Any] = [d.incident_id == incident_id]
    if f.get("level") is not None:
        where.append(d.level >= f["level"])
    for name, column in (("kind", r.kind), ("sourceId", r.source_id)):
        if f.get(name):
            where.append(column == f[name])
    if f.get("source"):
        files = select(EvidenceSource.id).where(
            EvidenceSource.incident_id == incident_id, EvidenceSource.source == f["source"]
        )
        where.append(or_(r.source == f["source"], and_(r.source.is_(None), r.source_id.in_(files))))
    joined = select(d.rule_id).select_from(d).join(r, r.id == d.record_id).where(*where)
    top = func.max(d.level)
    count = func.count()
    grouped = db.execute(
        select(d.rule_id, top, count, func.min(r.ts), func.max(r.ts), func.min(d.id))
        .select_from(d)
        .join(r, r.id == d.record_id)
        .where(*where)
        .group_by(d.rule_id)
        .order_by(top.desc(), count.desc(), d.rule_id)
        .limit(min(limit, RULES_MAX))
    ).all()
    total_rules = db.scalar(select(func.count()).select_from(joined.group_by(d.rule_id).subquery())) or 0
    levels = dict(
        db.execute(
            select(d.level, func.count()).select_from(d).join(r, r.id == d.record_id).where(*where).group_by(d.level)
        ).all()
    )
    ids = [row[0] for row in grouped]
    hosts: dict[str, set[str]] = {}
    held: dict[int, tuple[str, str, list[str]]] = {}
    if ids:
        pairs = joined.with_only_columns(d.rule_id, r.host).where(d.rule_id.in_(ids)).distinct()
        for rule_id, host in db.execute(pairs):
            hosts.setdefault(rule_id, set()).add(host or "")
        first = [row[5] for row in grouped]
        found = db.execute(select(d.id, d.rule_title, d.rule_author, d.tags).where(d.id.in_(first)))
        held = {detection_id: (title, author, list(tags or [])) for detection_id, title, author, tags in found}
    rules = []
    for rule_id, level, n, first_ts, last_ts, first_id in grouped:
        title, author, tags = held.get(first_id, ("", "", []))
        names = sorted(name for name in hosts.get(rule_id, ()) if name)
        rules.append(
            {
                "ruleId": rule_id,
                "title": title or rule_id,
                "author": author,
                "level": level,
                "levelName": _LEVEL_NAMES.get(level, ""),
                "tags": tags,
                "count": n,
                "firstTs": first_ts,
                "lastTs": last_ts,
                "hosts": names[:HOSTS_SHOWN],
                "hostCount": len(names),
            }
        )
    return {
        "rules": rules,
        "total": total_rules,
        "detections": sum(levels.values()),
        "byLevel": {str(level): int(levels.get(level, 0)) for level in range(1, 6)},
    }

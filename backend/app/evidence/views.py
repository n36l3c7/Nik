"""Looking at host evidence from above and from below (7.0): the shape of its time, what is rare in it,
and the original behind a record.

Three questions are answered on all the records of an incident that a filter keeps, in the database,
never by loading them: when did things happen (a histogram, the gaps with nothing in them, the bursts),
what is rare or common in a column or in a field of ``data`` (a stack), and which fields do the records
have. Three more are about the original file: what the worker's viewer shows of a record, a page of the
bytes of a file, and the file itself in an encrypted zip.

The filters are the ones of the list of records (``browse._filters``), the same names.

**Whole numbers.** A bucket of the histogram is the whole number ``(ts - from) / width``, cut by the
database (an integer division on SQLite and on PostgreSQL: both numbers are whole). The two numbers are
written into the SQL, not bound: a value that is selected and grouped by must read the same in both.
"""

from __future__ import annotations

import json
import statistics
import urllib.error
import urllib.request
from typing import Any

from sqlalchemy import Integer, and_, cast, func, literal_column, or_, select
from sqlalchemy.orm import Session as OrmSession

from ..core import store
from ..core.config import settings
from ..core.models import EvidenceMark, EvidenceRecord, EvidenceSource
from ..workers import handover
from . import originals, parse
from .browse import KEY, BadQuery, _filters, json_text  # noqa: F401 - KEY is read by the routers

GAPS_MAX = 200
BURST_MIN = 20
DISTINCT_CAP = 100_001
FIELDS_OF = 500
VIEW_TIMEOUT = 40
COLUMNS = ("host", "username", "channel", "eventId", "type", "kind", "source")

LEGACY = "This evidence was imported before 7.0: there is no original to show"
NO_ORIGINAL = "The original of this file is not kept: import the file again to see it"
ARCHIVED = "This evidence is archived: take the incident out of the archive to see the original"


class NoOriginal(Exception):
    """A source with no original to show: the sentence says why (404)."""


# --------------------------------------------------------------------------- #
# The records a filter keeps                                                  #
# --------------------------------------------------------------------------- #
def _kept(query: Any, incident_id: str, f: dict[str, Any], *, sources: bool = False) -> Any:
    """``query`` limited to the records of the filter, with the marks joined when it asks for the flagged."""
    record = EvidenceRecord
    query = query.select_from(record)
    if f.get("flagged"):
        mark_on = and_(EvidenceMark.incident_id == record.incident_id, EvidenceMark.key == record.key)
        query = query.join(EvidenceMark, mark_on)
    if sources:
        query = query.join(EvidenceSource, EvidenceSource.id == record.source_id)
    return query.where(*_filters(incident_id, f))


# --------------------------------------------------------------------------- #
# The histogram                                                               #
# --------------------------------------------------------------------------- #
def histogram(
    db: OrmSession, incident_id: str, f: dict[str, Any], buckets: int, gap_minutes: int, burst_factor: int
) -> dict[str, Any]:
    """``{"from", "to", "width", "buckets", "gaps", "bursts", "undated", "total"}``: the records per
    slice of time (only the slices that hold some), the stretches with no record at all, and the
    slices that hold far more than the usual."""
    record = EvidenceRecord
    shape = select(func.count(), func.count(record.ts), func.min(record.ts), func.max(record.ts))
    total, dated, first, last = db.execute(_kept(shape, incident_id, f)).one()
    answer: dict[str, Any] = {
        "from": None,
        "to": None,
        "width": 0,
        "buckets": [],
        "gaps": [],
        "bursts": [],
        "undated": total - dated,
        "total": total,
    }
    if not dated:
        return answer
    start = f["from"] if f.get("from") is not None else first
    end = f["to"] if f.get("to") is not None else last
    if end < start:
        return answer
    width = max(1, -(-(end - start + 1) // buckets))
    answer.update({"from": start, "to": end, "width": width})
    # Both numbers are whole and written in: the grouped expression must be the selected one.
    # ``op`` writes a plain ``/``: SQLAlchemy's own ``/`` turns into a division with decimals on PostgreSQL.
    shifted = literal_column(f"(evidence_records.ts - {int(start)})")
    index = cast(shifted.op("/")(literal_column(str(int(width)))), Integer)
    grouped = (
        _kept(select(index.label("i"), record.kind, func.count().label("n")), incident_id, f)
        .where(record.ts.is_not(None))
        .group_by(literal_column("1"), record.kind)
        .order_by(literal_column("1"))
    )
    held: dict[int, dict[str, Any]] = {}
    for i, kind, count in db.execute(grouped):
        slot = held.setdefault(int(i), {"t": start + int(i) * width, "count": 0, "byKind": {}})
        slot["count"] += count
        slot["byKind"][kind] = count
    answer["buckets"] = [held[i] for i in sorted(held)]
    answer["gaps"] = gaps(db, incident_id, f, gap_minutes)
    answer["bursts"] = bursts(answer["buckets"], burst_factor)
    return answer


def gaps(db: OrmSession, incident_id: str, f: dict[str, Any], minutes: int) -> list[dict[str, Any]]:
    """The stretches of at least ``minutes`` with no dated record, exactly: each record is set beside
    the one before it (``LAG``), at most 200, the longest first and then by time."""
    record = EvidenceRecord
    before = func.lag(record.ts).over(order_by=(record.ts, record.id)).label("before")
    inner = _kept(select(record.ts.label("at"), before), incident_id, f).where(record.ts.is_not(None)).subquery()
    wide = inner.c.at - inner.c.before
    rows = db.execute(
        select(inner.c.before, inner.c.at)
        .where(wide >= minutes * 60_000)
        .order_by(wide.desc(), inner.c.at)
        .limit(GAPS_MAX)
    )
    return [{"from": int(a), "to": int(b), "minutes": (int(b) - int(a)) // 60_000} for a, b in rows]


def bursts(buckets: list[dict[str, Any]], factor: int) -> list[dict[str, Any]]:
    """The slices with at least ``factor`` times the median of the slices that hold any, and at least 20."""
    if not buckets:
        return []
    median = statistics.median(slot["count"] for slot in buckets)
    return [
        {"t": slot["t"], "count": slot["count"], "factor": round(slot["count"] / median, 1)}
        for slot in buckets
        if slot["count"] >= BURST_MIN and slot["count"] >= factor * median
    ]


# --------------------------------------------------------------------------- #
# The stack                                                                   #
# --------------------------------------------------------------------------- #
def _expression(field: str) -> tuple[Any, bool, bool]:
    """What a field of the stack reads: the SQL expression, whether it is text, whether it needs the sources."""
    record = EvidenceRecord
    columns = {
        "host": record.host,
        "username": record.username,
        "channel": record.channel,
        "type": record.type,
        "kind": record.kind,
    }
    if field in columns:
        return columns[field], True, False
    if field == "eventId":
        return record.event_id, False, False
    if field == "source":
        return EvidenceSource.source, True, True
    if field.startswith("data."):
        return json_text(record.data, field[5:]), True, False
    raise BadQuery("field is one of " + ", ".join(COLUMNS) + ", or data.<Key>")


def stack(db: OrmSession, incident_id: str, f: dict[str, Any], field: str, order: str, limit: int) -> dict[str, Any]:
    """The values of a field with how many records hold each and when they first and last were: the
    rare ones first, or the common ones. ``missing`` counts the records with no value (not listed)."""
    if order not in ("rare", "common"):
        raise BadQuery("order is rare or common")
    expression, text, joined = _expression(field)
    record = EvidenceRecord
    # A subquery, so the value is computed once and grouped by its name (a bound key twice does not group).
    held = _kept(select(expression.label("v"), record.ts.label("ts")), incident_id, f, sources=joined).subquery()
    present = and_(held.c.v.is_not(None), held.c.v != "") if text else held.c.v.is_not(None)
    count = func.count().label("n")
    rows = db.execute(
        select(held.c.v, count, func.min(held.c.ts), func.max(held.c.ts))
        .where(present)
        .group_by(held.c.v)
        .order_by(count if order == "rare" else count.desc(), held.c.v)
        .limit(limit)
    )
    values = [{"value": v, "count": n, "first": first, "last": last} for v, n, first, last in rows]
    capped = select(held.c.v).where(present).group_by(held.c.v).limit(DISTINCT_CAP).subquery()
    distinct = db.scalar(select(func.count()).select_from(capped)) or 0
    missing = db.scalar(select(func.count()).select_from(held).where(or_(held.c.v.is_(None), ~present))) or 0
    return {
        "field": field,
        "values": values,
        "distinct": distinct,
        "distinctCapped": distinct >= DISTINCT_CAP,
        "missing": missing,
    }


def fields(db: OrmSession, incident_id: str, f: dict[str, Any]) -> dict[str, Any]:
    """The keys of ``data`` in the first 500 records of the filter (by id), with how many of the 500
    have each, the most seen first. Counted here, from those rows: no JSON in the SQL."""
    record = EvidenceRecord
    query = _kept(select(record.data), incident_id, f).order_by(record.id).limit(FIELDS_OF)
    seen: dict[str, int] = {}
    for (data,) in db.execute(query):
        for name in data if isinstance(data, dict) else ():
            seen[name] = seen.get(name, 0) + 1
    return {"fields": [{"name": name, "seen": n} for name, n in sorted(seen.items(), key=lambda it: (-it[1], it[0]))]}


# --------------------------------------------------------------------------- #
# The original                                                                #
# --------------------------------------------------------------------------- #
def original_of(source: EvidenceSource) -> str:
    """The SHA-256 of the original a source keeps in the store; ``NoOriginal`` with the sentence when
    there is none to show."""
    if source.legacy:
        raise NoOriginal(LEGACY)
    if source.state == "archived":
        raise NoOriginal(ARCHIVED)
    if source.state == "absent" or not source.sha256 or not originals.has(source.sha256):
        raise NoOriginal(NO_ORIGINAL)
    return source.sha256


def _answer(raw: bytes) -> dict[str, Any]:
    try:
        answer = json.loads(raw or b"{}")
    except ValueError:
        return {}
    return answer if isinstance(answer, dict) else {}


def ask_view(sha256: str, body: dict[str, Any], route: str = "view") -> tuple[int, dict[str, Any]]:
    """Ask the worker what the viewer shows (``route`` ``"find"``: where a needle is): ``(status, answer)``.
    The original is given to the worker when it says it does not hold it, and the question is asked once
    more. A worker that cannot be reached is a 502."""
    name = f"{sha256}.bin"
    url, token = settings.FORENSICS_URL, settings.FORENSICS_TOKEN
    data = json.dumps({**body, "name": name}).encode("utf-8")
    for attempt in (1, 2):
        request = urllib.request.Request(  # noqa: S310 - operator-configured URL
            f"{url}/{route}",
            data=data,
            method="POST",
            headers={parse.HEADER: token, "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=VIEW_TIMEOUT) as response:  # noqa: S310
                return response.status, _answer(response.read())
        except urllib.error.HTTPError as error:
            answer = _answer(error.read())
            if attempt == 1 and handover.missing_of(error, answer):
                try:
                    handover.give(url, parse.HEADER, token, name, originals.path_of(sha256))
                except handover.NotGiven as refused:
                    return 502, {"detail": str(refused)}
                continue
            return error.code, answer
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            return 502, {"detail": f"The forensics worker cannot be reached: {getattr(error, 'reason', error)}"}
    return 502, {"detail": "The forensics worker did not take the file"}


def find(sha256: str, needle: str, how: str, start: int, limit: int) -> tuple[int, dict[str, Any]]:
    """Ask the worker where a text or some bytes are in an original, from an offset: ``(status, answer)``.
    The worker reads the file in blocks, under a clock, and says where to go on from (``next``)."""
    body = {"sha256": sha256, "needle": needle, "as": how, "from": start, "limit": limit}
    code, answer = ask_view(sha256, body, "find")
    if code == 200:
        answer["size"] = store.size(originals.path_of(sha256))
    return code, answer


def page(sha256: str, offset: int, length: int, how: str) -> dict[str, Any]:
    """Bytes ``[offset, offset + length)`` of an original, read from the sealed store: as lower-case hex,
    or as UTF-8 text with replacement characters (a character cut by the edge of the page may show as
    one). An offset beyond the end gives no bytes."""
    path = originals.path_of(sha256)
    size = store.size(path)
    end = min(size, offset + length)
    data = b"".join(store.pieces(path, offset, end)) if offset < size else b""
    shown = data.hex() if how == "hex" else data.decode("utf-8", errors="replace")
    return {"offset": offset, "length": len(data), "size": size, "as": how, "data": shown}

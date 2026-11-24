"""What the incident report reads of host evidence (7.0).

The report is made for an incident of any size, so nothing here loads the records of an incident:
a count, a group, or a list that is capped. Each function answers one question of the report and
returns plain dicts and lists, so ``report.py`` is left with the layout.

The queries read the tables only: no JSON column is searched, except in the few rows of a cleared
log (an event 104 names the log in its data).
"""

from __future__ import annotations

import re
from typing import Any

from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session as OrmSession

from ..core.models import LEVELS, EvidenceDetection, EvidenceMark, EvidenceRecord, EvidenceSource

MAX_FLAGGED = 2000
MAX_CLEARS = 500
MAX_DETECTIONS = 500
MAX_SOURCES = 5000

_SEVERITY = {number: name for name, number in LEVELS.items()}
# A Sigma tag of a technique: ``attack.t1059.001``.
_TECHNIQUE_TAG = re.compile(r"attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)


def sources(db: OrmSession, incident_id: str) -> list[dict[str, Any]]:
    """Every file of the incident, oldest first, with its counts and its reading. The parse report is
    read only for a file that was read in part, failed or imported before 7.0: it holds the reasons and
    the hash 6.x noted."""
    columns = [c for c in EvidenceSource.__table__.columns if c.name != "report"]
    rows = db.execute(
        select(*columns)
        .where(EvidenceSource.incident_id == incident_id)
        .order_by(EvidenceSource.created_at, EvidenceSource.id)
        .limit(MAX_SOURCES)
    ).mappings()
    out = [dict(row) for row in rows]
    told = [row["id"] for row in out if row["read"] in ("partial", "failed") or row["legacy"]]
    reports: dict[str, Any] = {}
    if told:
        reports = dict(
            db.execute(select(EvidenceSource.id, EvidenceSource.report).where(EvidenceSource.id.in_(told))).all()
        )
    for row in out:
        report = reports.get(row["id"])
        row["report"] = report if isinstance(report, dict) else {}
    return out


def flagged(db: OrmSession, incident_id: str, limit: int = MAX_FLAGGED) -> dict[str, Any]:
    """The records an analyst flagged: ``{"records": [...], "total": n, "sources": {ids}, "channels": {names}}``.
    A record is listed with its summary, its time, its kind and type, the file it is in and the note
    that was written on it. At most ``limit`` records are read, the oldest first; ``total`` is all of them."""
    joined = and_(EvidenceMark.incident_id == EvidenceRecord.incident_id, EvidenceMark.key == EvidenceRecord.key)
    where = (EvidenceRecord.incident_id == incident_id, EvidenceMark.flagged.is_(True))
    total = db.scalar(select(func.count()).select_from(EvidenceRecord).join(EvidenceMark, joined).where(*where)) or 0
    rows = db.execute(
        select(
            EvidenceRecord.key,
            EvidenceRecord.ts,
            EvidenceRecord.kind,
            EvidenceRecord.type,
            EvidenceRecord.summary,
            EvidenceRecord.channel,
            EvidenceSource.file_name,
            EvidenceMark.note,
            EvidenceMark.updated_by,
        )
        .join(EvidenceMark, joined)
        .join(EvidenceSource, EvidenceSource.id == EvidenceRecord.source_id)
        .where(*where)
        .order_by(EvidenceRecord.ts.is_(None), EvidenceRecord.ts, EvidenceRecord.id)
        .limit(limit)
    ).all()
    holding = db.execute(
        select(EvidenceRecord.source_id, EvidenceRecord.channel)
        .join(EvidenceMark, joined)
        .where(*where)
        .group_by(EvidenceRecord.source_id, EvidenceRecord.channel)
    ).all()
    return {
        "records": [
            {
                "key": key,
                "time": ts,
                "kind": kind,
                "type": type_,
                "summary": summary,
                "channel": channel,
                "file": file_name,
                "note": note,
                "by": by,
            }
            for key, ts, kind, type_, summary, channel, file_name, note, by in rows
        ],
        "total": total,
        "sources": {source_id for source_id, _channel in holding},
        "channels": {channel for _source, channel in holding if channel},
    }


def channels(db: OrmSession, incident_id: str) -> list[dict[str, Any]]:
    """The event logs of the incident, one row per channel: how many events, from when to when, and the
    files they are in. One grouped query over the records, one over the few sources."""
    rows = db.execute(
        select(
            EvidenceRecord.channel,
            EvidenceRecord.source_id,
            func.count(),
            func.min(EvidenceRecord.ts),
            func.max(EvidenceRecord.ts),
        )
        .where(EvidenceRecord.incident_id == incident_id, EvidenceRecord.kind == "eventlog")
        .group_by(EvidenceRecord.channel, EvidenceRecord.source_id)
    ).all()
    names = dict(
        db.execute(
            select(EvidenceSource.id, EvidenceSource.file_name).where(
                EvidenceSource.id.in_({source_id for _c, source_id, *_rest in rows})
            )
        ).all()
        if rows
        else ()
    )
    merged: dict[str, dict[str, Any]] = {}
    for channel, source_id, count, first, last in rows:
        held = merged.setdefault(channel, {"channel": channel, "events": 0, "first": None, "last": None, "files": []})
        held["events"] += count
        if first is not None and (held["first"] is None or first < held["first"]):
            held["first"] = first
        if last is not None and (held["last"] is None or last > held["last"]):
            held["last"] = last
        name = names.get(source_id) or ""
        if name and name not in held["files"]:
            held["files"].append(name)
    for held in merged.values():
        held["files"].sort()
    return sorted(merged.values(), key=lambda held: held["channel"])


def cleared(db: OrmSession, incident_id: str, known: list[str]) -> dict[str, list[int]]:
    """Channel → the times it was cleared. Event 1102 of Security clears Security, event 104 of System
    names the log it cleared. ``known`` are the channels the incident holds, to name a log by its
    case. At most ``MAX_CLEARS`` events are read."""
    rows = db.execute(
        select(EvidenceRecord.channel, EvidenceRecord.event_id, EvidenceRecord.ts, EvidenceRecord.data)
        .where(
            EvidenceRecord.incident_id == incident_id,
            EvidenceRecord.kind == "eventlog",
            or_(
                and_(EvidenceRecord.event_id == 1102, EvidenceRecord.channel == "Security"),
                and_(EvidenceRecord.event_id == 104, EvidenceRecord.channel == "System"),
            ),
        )
        .order_by(EvidenceRecord.ts, EvidenceRecord.id)
        .limit(MAX_CLEARS)
    ).all()
    lookup = {name.lower(): name for name in known}
    out: dict[str, list[int]] = {}
    for _channel, event_id, ts, data in rows:
        if event_id == 1102:
            target = "Security"
        else:
            named = str((data if isinstance(data, dict) else {}).get("Channel") or "")
            target = lookup.get(named.lower(), named or "System")
        out.setdefault(target, []).append(ts)
    return out


def detections(db: OrmSession, incident_id: str, limit: int = MAX_DETECTIONS) -> list[dict[str, Any]]:
    """The rules that matched records of the incident, as the report takes them from the browser:
    ``{id, label, severity, count, attack}``, with the summary and the time of the first record they
    matched. One row per rule, the highest level first, at most ``limit``."""
    top = func.max(EvidenceDetection.level)
    grouped = db.execute(
        select(
            EvidenceDetection.rule_id,
            func.max(EvidenceDetection.rule_title),
            top,
            func.count(),
            func.min(EvidenceDetection.id),
        )
        .where(EvidenceDetection.incident_id == incident_id)
        .group_by(EvidenceDetection.rule_id)
        .order_by(top.desc(), func.count().desc(), EvidenceDetection.rule_id)
        .limit(limit)
    ).all()
    first = [row[4] for row in grouped]
    held = (
        {
            detection_id: (tags, summary, ts)
            for detection_id, tags, summary, ts in db.execute(
                select(EvidenceDetection.id, EvidenceDetection.tags, EvidenceRecord.summary, EvidenceRecord.ts)
                .join(EvidenceRecord, EvidenceRecord.id == EvidenceDetection.record_id)
                .where(EvidenceDetection.id.in_(first))
            )
        }
        if first
        else {}
    )
    out = []
    for rule_id, title, level, count, detection_id in grouped:
        tags, summary, ts = held.get(detection_id, ([], "", None))
        attack = sorted(
            {
                match.group(1).upper()
                for tag in tags or []
                if isinstance(tag, str) and (match := _TECHNIQUE_TAG.match(tag))
            }
        )
        out.append(
            {
                "id": rule_id,
                "label": title or rule_id,
                "severity": _SEVERITY.get(level, "medium"),
                "level": level,
                "count": count,
                "attack": attack,
                "summary": summary or "",
                "time": ts,
            }
        )
    return out


def gather(db: OrmSession, incident_id: str) -> dict[str, Any]:
    """Everything the report reads of host evidence, in a bounded number of queries."""
    files = sources(db, incident_id)
    overview = channels(db, incident_id)
    return {
        "sources": files,
        "flagged": flagged(db, incident_id),
        "channels": overview,
        "cleared": cleared(db, incident_id, [row["channel"] for row in overview]) if overview else {},
        "detections": detections(db, incident_id),
    }

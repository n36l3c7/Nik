"""What the list of incidents shows of one incident without opening it.

The quick view of the list is drawn for the row under the pointer, and the
document of an incident can weigh megabytes: this gives the few things the
quick view needs (the fields, how much evidence there is, the timers, the
last lines of the War Room) and nothing of the evidence itself.
"""

from __future__ import annotations

import time
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session as OrmSession

from . import fields as field_registry
from . import timers, war_room
from .core.models import EvidenceRecord, Incident

LAST_ENTRIES = 3


def _dict(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _length(value: Any) -> int:
    return len(value) if isinstance(value, list) else 0


def counts_for(db: OrmSession, docs: dict[str, dict[str, Any] | None]) -> dict[str, dict[str, int]]:
    """The numbers of several incidents at once (``{incident id: document}``): one grouped query over
    the records of all of them, however many there are. Counting is an index scan of
    ``(incident_id, kind, type, ts)``, no record is loaded."""
    found: dict[str, dict[str, int]] = {key: {} for key in docs}
    if docs:
        rows = db.execute(
            select(EvidenceRecord.incident_id, EvidenceRecord.kind, EvidenceRecord.type, func.count())
            .where(EvidenceRecord.incident_id.in_(list(docs)))
            .group_by(EvidenceRecord.incident_id, EvidenceRecord.kind, EvidenceRecord.type)
        ).all()
        for incident_id, kind, type_, total in rows:
            slot = found[incident_id]
            slot[kind] = slot.get(kind, 0) + total
            if kind == "browser":
                slot[f"browser:{type_}"] = total
    out: dict[str, dict[str, int]] = {}
    for incident_id, doc in docs.items():
        doc = _dict(doc)
        slot = found[incident_id]
        marks = slot.get("browser:bookmark", 0)
        out[incident_id] = {
            "browserEvents": slot.get("browser", 0) - marks - slot.get("browser:shortcut", 0),
            "commands": slot.get("commands", 0),
            "endpointArtifacts": slot.get("endpoint", 0),
            "eventLogs": slot.get("eventlog", 0),
            "flagged": len(_dict(doc.get("flags"))),
            "bookmarks": marks,
            "notes": _length(doc.get("notes")),
        }
    return out


def counts(db: OrmSession, incident_id: str, doc: dict[str, Any] | None) -> dict[str, int]:
    """How much evidence an incident holds: the numbers the Summary shows, counted from the tables."""
    return counts_for(db, {incident_id: doc})[incident_id]


def quick(db: OrmSession, incident: Incident) -> dict[str, Any]:
    doc = incident.doc or {}
    return {
        "id": incident.id,
        "number": incident.number,
        "type": incident.type_id or field_registry.UNCLASSIFIED,
        "fields": field_registry.stored_fields(incident),
        "createdBy": doc.get("createdBy"),
        "suspiciousStart": doc.get("suspiciousStart"),
        "suspiciousEnd": doc.get("suspiciousEnd"),
        "counts": counts(db, incident.id, doc),
        "timers": timers.of(db, incident, time.time()),
        "last": war_room.entries(db, incident, limit=LAST_ENTRIES),
    }

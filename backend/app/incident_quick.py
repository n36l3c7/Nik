"""What the list of incidents shows of one incident without opening it.

The quick view of the list is drawn for the row under the pointer, and the
document of an incident can weigh megabytes: this gives the few things the
quick view needs (the fields, how much evidence there is, the timers, the
last lines of the War Room) and nothing of the evidence itself.
"""

from __future__ import annotations

import time
from typing import Any

from sqlalchemy.orm import Session as OrmSession

from . import fields as field_registry
from . import timers, war_room
from .core.models import Incident

LAST_ENTRIES = 3


def _dict(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _length(value: Any) -> int:
    return len(value) if isinstance(value, list) else 0


def counts(doc: dict[str, Any] | None) -> dict[str, int]:
    """How much evidence a document holds: the numbers the Summary shows, counted the same way."""
    doc = _dict(doc)
    data = _dict(doc.get("data"))
    events = bookmarks = 0
    for slot in _dict(_dict(data.get("browser")).get("browsers")).values():
        for profile in _dict(_dict(slot).get("profiles")).values():
            profile = _dict(profile)
            events += _length(profile.get("history")) + _length(profile.get("downloads"))
            bookmarks += _length(profile.get("bookmarks"))
    commands = sum(
        _length(_dict(shell).get("commands")) for shell in _dict(_dict(data.get("commands")).get("shells")).values()
    )
    artifacts = 0
    for category in _dict(_dict(data.get("endpoint")).get("categories")).values():
        for source in _dict(_dict(category).get("sources")).values():
            artifacts += _length(_dict(source).get("records"))
    return {
        "browserEvents": events,
        "commands": commands,
        "endpointArtifacts": artifacts,
        "flagged": len(_dict(doc.get("flags"))),
        "bookmarks": bookmarks,
        "notes": _length(doc.get("notes")),
    }


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
        "counts": counts(doc),
        "timers": timers.of(db, incident, time.time()),
        "last": war_room.entries(db, incident, limit=LAST_ENTRIES),
    }

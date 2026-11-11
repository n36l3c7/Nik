"""The audit trail, written by the server.

Every change is recorded by the handler that makes it, for every caller: a
browser session and an API key leave the same entry, and a request sent by
hand cannot skip it. The browser no longer reports what it did.

A merge patch says what changed but not what it means, so ``describe_patch``
reads the document before and after and names the changes an analyst would
recognise: a flag, a comment, a note, the status, an evidence file.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from typing import Any

from sqlalchemy.orm import Session as OrmSession

from .models import AuditEntry, Incident
from .security import now_iso

# Incident fields shown as "attributes" in the log, with the name used there.
ATTRIBUTES = {
    "ticketId": "ticket",
    "title": "title",
    "host": "host",
    "username": "user",
    "os": "operating system",
    "severity": "severity",
    "status": "status",
    "assignee": "assignee",
    "suspiciousStart": "suspicious window",
    "suspiciousEnd": "suspicious window",
}
MAX_DETAILS = 500
MAX_ENTRIES_PER_CHANGE = 20


def record(
    db: OrmSession,
    actor: str,
    action: str,
    details: str,
    incident: Incident | None = None,
    *,
    target: str | None = None,
) -> None:
    """Add an audit entry to the session (the caller commits)."""
    doc = (incident.doc if incident is not None else {}) or {}
    db.add(
        AuditEntry(
            id=str(uuid.uuid4()),
            at=now_iso(),
            actor=actor,
            action=action,
            target=target if target is not None else doc.get("name"),
            details=details[:MAX_DETAILS],
            incident_id=incident.id if incident is not None else None,
            incident_name=doc.get("name"),
        )
    )


def _label(flag: Any) -> str:
    if not isinstance(flag, dict):
        return "an entry"
    return str(flag.get("title") or flag.get("url") or flag.get("key") or "an entry")[:160]


def _flags(old: dict, new: dict) -> list[tuple[str, str]]:
    before = old.get("flags") if isinstance(old.get("flags"), dict) else {}
    after = new.get("flags") if isinstance(new.get("flags"), dict) else {}
    entries = []
    for key in after.keys() - before.keys():
        entries.append(("flag.add", f"Flagged: {_label(after[key])}"))
    for key in before.keys() - after.keys():
        entries.append(("flag.remove", f"Unflagged: {_label(before[key])}"))
    for key in before.keys() & after.keys():
        was = len((before[key] or {}).get("comments") or []) if isinstance(before[key], dict) else 0
        now = len((after[key] or {}).get("comments") or []) if isinstance(after[key], dict) else 0
        if now > was:
            entries.append(("flag.comment", f"Commented a flagged entry: {_label(after[key])}"))
        elif now < was:
            entries.append(("flag.comment.remove", f"Removed a comment from a flagged entry: {_label(after[key])}"))
    return entries


def _notes(old: dict, new: dict) -> list[tuple[str, str]]:
    def by_id(doc: dict) -> dict[str, dict]:
        notes = doc.get("notes") if isinstance(doc.get("notes"), list) else []
        return {str(note.get("id")): note for note in notes if isinstance(note, dict) and note.get("id")}

    before, after = by_id(old), by_id(new)
    entries = [("note.add", "Added a note") for _ in after.keys() - before.keys()]
    entries += [("note.remove", "Removed a note") for _ in before.keys() - after.keys()]
    entries += [
        ("note.update", "Edited a note")
        for key in before.keys() & after.keys()
        if before[key].get("text") != after[key].get("text")
    ]
    return entries


def _file_names(old: Any, new: Any, depth: int = 0) -> list[str]:
    """Names of the evidence files whose record is new or changed under ``new``."""
    if not isinstance(new, dict) or depth > 8 or old == new:
        return []
    if isinstance(new.get("fileName"), str):
        return [new["fileName"]]
    previous = old if isinstance(old, dict) else {}
    names: list[str] = []
    for key, value in new.items():
        if isinstance(value, dict):
            names += _file_names(previous.get(key), value, depth + 1)
    return names


def _evidence(old: dict, new: dict, changed: Iterable[str] | None) -> list[tuple[str, str]]:
    before = old.get("data") if isinstance(old.get("data"), dict) else {}
    after = new.get("data") if isinstance(new.get("data"), dict) else {}
    tabs = sorted(key for key in (changed if changed is not None else after.keys() | before.keys()))
    touched = [tab for tab in tabs if before.get(tab) != after.get(tab)]
    if not touched:
        return []
    files = sorted({name for tab in touched for name in _file_names(before.get(tab), after.get(tab))})
    what = ", ".join(touched)
    if files:
        return [("evidence.update", f"Updated the evidence of {what}: {', '.join(files[:10])}")]
    return [("evidence.update", f"Updated the evidence of {what}")]


def describe_patch(old: dict, new: dict, partial: dict | None = None) -> list[tuple[str, str]]:
    """The audit entries, ``(action, details)``, of a document going from ``old`` to ``new``.

    ``partial`` is the patch that was applied: only the evidence tabs it names
    are compared, so a flag toggle never walks the artifact arrays.
    """
    name = new.get("name") or new.get("id") or ""
    entries: list[tuple[str, str]] = []
    fields = sorted({label for key, label in ATTRIBUTES.items() if old.get(key) != new.get(key)})
    if fields:
        entries.append(("incident.update", f'Updated {", ".join(fields)} of "{name}"'))
    entries += _flags(old, new)
    entries += _notes(old, new)
    if partial is None or "data" in partial:
        data = partial.get("data") if partial is not None else None
        entries += _evidence(old, new, data.keys() if isinstance(data, dict) else None)
    return entries[:MAX_ENTRIES_PER_CHANGE]

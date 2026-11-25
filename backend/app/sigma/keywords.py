"""The suspicious keywords of before 7.0, as Sigma rules (used by migration 0057).

Until 7.0 the browser looked for keywords in the addresses and titles of what it showed: a list of
entries (``id``, ``label``, ``pattern`` as a regular expression, ``severity``, ``description``), the ones
Nik shipped and the ones people added or changed. Host evidence is read against Sigma rules now, so the
entries a person wrote or changed become rules written here, on the records of browsers
(``product: nik``, ``service: browser``), matching the pattern in the address or in the title. The ones Nik
shipped are not moved: they were the same on every server.

The rules are stored **not checked** (the migration cannot ask the worker); they are checked when the
worker answers, as any rule stored without it.
"""

from __future__ import annotations

import uuid
from typing import Any

import yaml

from ..core.models import LEVELS
from .rules import NOT_CHECKED

KEYS = ("label", "pattern", "severity", "description")


def changed(entries: list[dict[str, Any]], shipped: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The entries that are not the ones Nik shipped, as shipped: a new one, or a shipped one a person changed."""
    known = {item["id"]: item for item in shipped}
    out = []
    for entry in entries:
        if not isinstance(entry, dict) or not str(entry.get("id") or "").strip() or not str(entry.get("pattern") or ""):
            continue
        original = known.get(entry["id"])
        if original is not None and all(entry.get(key) == original.get(key) for key in KEYS):
            continue
        out.append(entry)
    return out


def text_of(entry: dict[str, Any], rule_id: str) -> str:
    """The rule an entry becomes: its pattern, in the address or in the title of a page."""
    label = str(entry.get("label") or entry["id"]).strip()
    severity = str(entry.get("severity") or "medium").lower()
    level = severity if severity in LEVELS and severity != "informational" else "medium"
    pattern = "(?i)" + str(entry["pattern"])
    doc = {
        "title": label,
        "id": rule_id,
        "status": "stable",
        "description": str(entry.get("description") or f"The pattern {entry['pattern']} in an address or a title"),
        "author": "Nik (a suspicious keyword of an earlier version)",
        "logsource": {"product": "nik", "service": "browser"},
        "detection": {
            "url": {"url|re": pattern},
            "title": {"title|re": pattern},
            "condition": "url or title",
        },
        "level": level,
    }
    return yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, width=100)


def row_of(entry: dict[str, Any], now: str) -> dict[str, Any]:
    """A row of ``sigma_rules`` for an entry: a new id, not checked, switched on (it is run once the worker
    has read it, and only if it can run it)."""
    rule_id = str(uuid.uuid4())
    severity = str(entry.get("severity") or "medium").lower()
    level = LEVELS.get(severity, LEVELS["medium"]) if severity != "informational" else LEVELS["medium"]
    return {
        "id": rule_id,
        "pack": "",
        "name": "",
        "title": str(entry.get("label") or entry["id"]).strip()[:300],
        "author": "Nik (a suspicious keyword of an earlier version)",
        "kind": "rule",
        "level": level,
        "status": "stable",
        "product": "nik",
        "category": "",
        "service": "browser",
        "tags": [],
        "source": text_of(entry, rule_id),
        "enabled": True,
        "supported": False,
        "reason": NOT_CHECKED,
        "engine": "",
        "original": None,
        "created_at": now,
        "created_by": "nik",
        "updated_at": now,
        "updated_by": "nik",
    }

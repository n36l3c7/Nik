"""Incident types: the fields of a kind of incident, its page, how it is closed.

A type lists the custom fields its incidents have (each ``required`` or
``required_on_close``), arranges the Summary in sections (its **layout**),
orders the tabs of the page, and says with which reasons an incident of it is
closed. Seven ship; ``Unclassified`` is the type of every incident that was
given no other, so that nothing that exists changes.

    layout = {"sections": [{"id", "title", "key": bool, "columns": 1|2, "fields": [names]}],
              "tabs": [ids in order], "hidden": [ids]}

The first section flagged ``key`` is the side panel of the incident page. A
type without a layout gets a generated one: its fields, in order.
"""

from __future__ import annotations

import re
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session as OrmSession

from . import fields as registry
from .core.models import Field, Incident, IncidentType, Playbook
from .core.permissions import ROLE_PERMISSIONS, SYSTEM_ROLE
from .core.security import now_iso

UNCLASSIFIED = registry.UNCLASSIFIED
ID_RE = re.compile(r"^[a-z][a-z0-9-]{1,31}$")
COLOURS = ("slate", "red", "amber", "emerald", "cyan", "blue", "violet", "pink")
# The tabs of the incident page a layout can order and hide (frontend/src/config/tabs.js).
TABS = (
    "summary",
    "timeline",
    "automation",
    "iocs",
    "mail",
    "malware",
    "network",
    "urls",
    "endpoint",
    "eventlogs",
    "browser",
    "commands",
)
SECTIONS_MAX, FIELDS_MAX, REASONS_MAX = 20, 100, 30
# What the side panel shows of an incident of any type, and the Summary under it.
KEY_FIELDS = ("status", "severity", "owner", "ticket", "occurred", "tlp")
MORE_FIELDS = ("host", "username", "os", "category", "labels", "affected_hosts", "affected_users", "details")
CLOSE_REASONS = ("Resolved", "False positive", "Duplicate", "Not an incident")


class TypeError_(ValueError):
    """What is wrong with a type, as a sentence."""

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


def _shipped(
    type_id: str, name: str, colour: str, icon: str, description: str, more: tuple, reasons: tuple = ()
) -> dict:
    return {
        "id": type_id,
        "name": name,
        "colour": colour,
        "icon": icon,
        "description": description,
        "layout": {
            "sections": [
                {"id": "key", "title": "Key facts", "key": True, "columns": 1, "fields": list(KEY_FIELDS)},
                {"id": "about", "title": "What it is about", "key": False, "columns": 2, "fields": list(more)},
            ],
            "tabs": [],
            "hidden": [],
        },
        "closeReasons": list(reasons or CLOSE_REASONS),
    }


SHIPPED = (
    _shipped(
        UNCLASSIFIED,
        "Unclassified",
        "slate",
        "folder",
        "An incident that was given no type: the page as it always was.",
        MORE_FIELDS,
    ),
    _shipped(
        "phishing",
        "Phishing",
        "amber",
        "mail",
        "A deceptive e-mail: who received it, what it led to, who acted on it.",
        ("affected_users", "category", "labels", "details", "related_incidents"),
        ("Resolved", "False positive", "Awareness test", "Duplicate"),
    ),
    _shipped(
        "malware",
        "Malware",
        "red",
        "bug",
        "Malicious code on a host: what ran, where, what it reached.",
        ("host", "username", "os", "affected_hosts", "category", "labels", "details"),
    ),
    _shipped(
        "network-intrusion",
        "Network intrusion",
        "violet",
        "network",
        "Someone inside the network who should not be: how they came in, where they moved.",
        ("affected_hosts", "affected_users", "category", "labels", "details", "related_incidents"),
    ),
    _shipped(
        "data-leak",
        "Data leak",
        "pink",
        "file-warning",
        "Data that left, or may have: what, how much, towards whom.",
        ("affected_users", "affected_hosts", "category", "labels", "details"),
        ("Resolved", "No data left", "False positive", "Duplicate"),
    ),
    _shipped(
        "access-abuse",
        "Access abuse",
        "blue",
        "key",
        "An account used by who should not, or for what it should not.",
        ("username", "affected_users", "affected_hosts", "category", "labels", "details"),
    ),
    _shipped(
        "vulnerability",
        "Vulnerability",
        "cyan",
        "shield-alert",
        "A weakness found before, or after, someone used it.",
        ("affected_hosts", "category", "labels", "due", "details"),
        ("Fixed", "Mitigated", "Risk accepted", "False positive", "Duplicate"),
    ),
)


# --------------------------------------------------------------------------- #
# Checking                                                                    #
# --------------------------------------------------------------------------- #
def _text(value: Any, limit: int) -> str:
    return str(value or "").strip()[:limit]


def clean_fields(known: dict[str, Field], listed: Any) -> list[dict[str, Any]]:
    """The custom fields of a type: each a field of the registry, once."""
    if listed is None:
        return []
    if not isinstance(listed, list) or len(listed) > FIELDS_MAX:
        raise TypeError_(f"The fields of a type are a list, {FIELDS_MAX} at most")
    cleaned, seen = [], set()
    for item in listed:
        name = item.get("name") if isinstance(item, dict) else item
        field = known.get(str(name or ""))
        if field is None or field.applies_to != "incident":
            raise TypeError_(f'There is no field of incidents called "{name}"')
        if field.system:
            raise TypeError_(f"{field.label} is a system field: every type has it already")
        if field.name in seen:
            raise TypeError_(f"{field.label} is listed twice")
        seen.add(field.name)
        flags = item if isinstance(item, dict) else {}
        cleaned.append(
            {
                "name": field.name,
                "required": bool(flags.get("required")),
                "required_on_close": bool(flags.get("required_on_close", flags.get("requiredOnClose"))),
            }
        )
    return cleaned


def clean_layout(known: dict[str, Field], own: set[str], layout: Any) -> dict[str, Any] | None:
    """A layout whose sections name fields this type has, and whose tabs exist."""
    if layout is None:
        return None
    if not isinstance(layout, dict):
        raise TypeError_("A layout is an object with sections and tabs")
    sections = layout.get("sections") or []
    if not isinstance(sections, list) or len(sections) > SECTIONS_MAX:
        raise TypeError_(f"A layout has {SECTIONS_MAX} sections at most")
    cleaned, ids, placed = [], set(), set()
    for index, section in enumerate(sections):
        if not isinstance(section, dict):
            raise TypeError_("A section is an object with a title and fields")
        section_id = _text(section.get("id"), 32) or f"s{index + 1}"
        if section_id in ids:
            raise TypeError_("Two sections have the same id")
        ids.add(section_id)
        names = section.get("fields") or []
        if not isinstance(names, list) or len(names) > FIELDS_MAX:
            raise TypeError_("The fields of a section are a list of names")
        for name in names:
            field = known.get(str(name))
            if field is None or field.applies_to != "incident":
                raise TypeError_(f'A section names "{name}", which is not a field of incidents')
            if not (field.system or field.all_types or field.name in own):
                raise TypeError_(f"{field.label} is in a section but is not a field of this type: add it to the type")
            if field.name in placed:
                raise TypeError_(f"{field.label} is in two sections")
            placed.add(field.name)
        cleaned.append(
            {
                "id": section_id,
                "title": _text(section.get("title"), 80) or "Section",
                "key": bool(section.get("key")),
                "columns": 2 if section.get("columns") == 2 else 1,
                "fields": [str(name) for name in names],
            }
        )
    if sum(1 for section in cleaned if section["key"]) > 1:
        raise TypeError_("One section at most is the side panel")
    tabs = [str(tab) for tab in layout.get("tabs") or []]
    hidden = [str(tab) for tab in layout.get("hidden") or []]
    for tab in (*tabs, *hidden):
        if tab not in TABS:
            raise TypeError_(f'There is no tab called "{tab}": ' + ", ".join(TABS))
    if len(set(tabs)) != len(tabs):
        raise TypeError_("A tab is listed twice")
    if "summary" in hidden:
        raise TypeError_("The Summary cannot be hidden: it is where the fields are")
    return {"sections": cleaned, "tabs": tabs, "hidden": sorted(set(hidden))}


def generated_layout(known: dict[str, Field], kind: IncidentType | None) -> dict[str, Any]:
    """The layout of a type that has none: the key facts, then its own fields, in order."""
    own = [item["name"] for item in (kind.fields if kind is not None else None) or [] if item.get("name") in known]
    everywhere = sorted(
        (
            field.name
            for field in known.values()
            if field.all_types and not field.system and field.applies_to == "incident"
        ),
        key=lambda name: (known[name].label or name).lower(),
    )
    extra = [name for name in everywhere if name not in own]
    sections = [
        {"id": "key", "title": "Key facts", "key": True, "columns": 1, "fields": list(KEY_FIELDS)},
        {"id": "about", "title": "What it is about", "key": False, "columns": 2, "fields": list(MORE_FIELDS)},
    ]
    if own or extra:
        sections.append({"id": "fields", "title": "More", "key": False, "columns": 2, "fields": [*own, *extra]})
    return {"sections": sections, "tabs": [], "hidden": []}


def clean(db: OrmSession, body: dict[str, Any], existing: IncidentType | None = None) -> dict[str, Any]:
    """What a type is saved with, checked. Keys left out keep what the type has."""
    known = registry.registry(db)
    out: dict[str, Any] = {}
    if "name" in body or existing is None:
        name = _text(body.get("name"), 80)
        if not name:
            raise TypeError_("A type needs a name")
        taken = db.scalars(select(IncidentType).where(func.lower(IncidentType.name) == name.lower())).first()
        if taken is not None and (existing is None or taken.id != existing.id):
            raise TypeError_("There is a type with this name already")
        out["name"] = name
    if "description" in body:
        out["description"] = _text(body.get("description"), 1000)
    if "colour" in body:
        colour = str(body.get("colour") or "slate")
        if colour not in COLOURS:
            raise TypeError_("A colour is one of: " + ", ".join(COLOURS))
        out["colour"] = colour
    if "icon" in body:
        out["icon"] = _text(body.get("icon"), 32)
    if "fields" in body:
        out["fields"] = clean_fields(known, body.get("fields"))
    own = {item["name"] for item in out.get("fields", existing.fields if existing is not None else []) or []}
    if "layout" in body:
        out["layout"] = clean_layout(known, own, body.get("layout"))
    elif "fields" in out and existing is not None and existing.layout:
        # A field taken off the type leaves its sections too.
        kept = dict(existing.layout)
        kept["sections"] = [
            {
                **section,
                "fields": [
                    name
                    for name in section.get("fields") or []
                    if name in known and (known[name].system or known[name].all_types or name in own)
                ],
            }
            for section in kept.get("sections") or []
        ]
        out["layout"] = kept
    if "closeReasons" in body:
        reasons = body.get("closeReasons") or []
        if not isinstance(reasons, list) or len(reasons) > REASONS_MAX:
            raise TypeError_(f"The close reasons are a list, {REASONS_MAX} at most")
        out["close_reasons"] = list(dict.fromkeys(_text(item, 80) for item in reasons if _text(item, 80)))
    if "defaultPlaybookId" in body:
        playbook_id = body.get("defaultPlaybookId") or None
        if playbook_id is not None and db.get(Playbook, str(playbook_id)) is None:
            raise TypeError_("The playbook of the type does not exist")
        out["default_playbook_id"] = str(playbook_id) if playbook_id else None
    if "autoRun" in body:
        out["auto_run"] = bool(body.get("autoRun"))
    if out.get("auto_run", existing.auto_run if existing is not None else False) and not out.get(
        "default_playbook_id", existing.default_playbook_id if existing is not None else None
    ):
        raise TypeError_("To run by itself a type needs its playbook")
    if "visibleToRoles" in body:
        roles = body.get("visibleToRoles")
        if roles is not None:
            if not isinstance(roles, list) or any(
                role not in ROLE_PERMISSIONS or role == SYSTEM_ROLE for role in roles
            ):
                raise TypeError_("The roles that see a type are roles that exist")
            roles = sorted(set(roles))
        out["visible_to_roles"] = roles or None
    return out


# --------------------------------------------------------------------------- #
# Storing                                                                     #
# --------------------------------------------------------------------------- #
def seed(db: OrmSession) -> int:
    """Add the shipped types that are missing (the caller commits). One that is there is the team's: left alone."""
    known = {row.id for row in db.scalars(select(IncidentType))}
    names = {row.name.lower() for row in db.scalars(select(IncidentType))}
    added = 0
    for item in SHIPPED:
        if item["id"] in known or item["name"].lower() in names:
            continue
        stamp = now_iso()
        db.add(
            IncidentType(
                id=item["id"],
                name=item["name"],
                description=item["description"],
                colour=item["colour"],
                icon=item["icon"],
                fields=[],
                layout=item["layout"],
                sla=[],
                close_reasons=item["closeReasons"],
                builtin=True,
                created_at=stamp,
                updated_at=stamp,
                updated_by="nik",
            )
        )
        added += 1
    return added


def every(db: OrmSession) -> list[IncidentType]:
    """The types, ``Unclassified`` first, then by name; the shipped ones are added when missing."""
    rows = db.scalars(select(IncidentType)).all()
    if not any(row.id == UNCLASSIFIED for row in rows):
        seed(db)
        db.flush()
        rows = db.scalars(select(IncidentType)).all()
    return sorted(rows, key=lambda row: (row.id != UNCLASSIFIED, row.name.lower()))


def new_id(db: OrmSession, name: str) -> str:
    """An id read in addresses and files: the name in lower case, with dashes."""
    base = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:28] or "type"
    if not base[0].isalpha():
        base = "t-" + base
    candidate, counter = base, 2
    while db.get(IncidentType, candidate) is not None:
        candidate = f"{base[:28]}-{counter}"
        counter += 1
    return candidate


def incidents_of(db: OrmSession, type_id: str) -> int:
    if type_id == UNCLASSIFIED:
        condition = Incident.type_id.is_(None) | (Incident.type_id == UNCLASSIFIED)
    else:
        condition = Incident.type_id == type_id
    return db.scalar(select(func.count()).select_from(Incident).where(condition)) or 0


def out(db: OrmSession, row: IncidentType, known: dict[str, Field] | None = None) -> dict[str, Any]:
    known = known if known is not None else registry.registry(db)
    return {
        "id": row.id,
        "name": row.name,
        "description": row.description,
        "colour": row.colour,
        "icon": row.icon,
        "builtin": bool(row.builtin),
        "fields": [
            {
                "name": item["name"],
                "required": bool(item.get("required")),
                "requiredOnClose": bool(item.get("required_on_close")),
            }
            for item in row.fields or []
            if item.get("name") in known
        ],
        # What the page is drawn from: the saved layout, or one made from the fields.
        "layout": row.layout or generated_layout(known, row),
        "customLayout": bool(row.layout),
        "sla": row.sla or [],
        "closeReasons": row.close_reasons or [],
        "defaultPlaybookId": row.default_playbook_id,
        "autoRun": bool(row.auto_run),
        "visibleToRoles": row.visible_to_roles,
        "incidents": incidents_of(db, row.id),
        "updatedAt": row.updated_at,
        "updatedBy": row.updated_by,
    }

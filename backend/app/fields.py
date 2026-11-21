"""The field registry: one name for one thing, and the only writer of fields.

Every field an incident can hold is a row of ``fields``. **System** fields are
seeded and cannot be deleted; those Nik always had (name, status, severity,
owner…) keep living where they live, in the incident document and the columns
mirrored from it, and are only *named* here. **Custom** fields are made in
Settings and live in ``incidents.fields``.

``update()`` is the only writer. It refuses a name the registry does not know
(that is what enforces "one name for one thing"), a field that is not of the
incident's type, a value that is not of the field's type; it coerces what it
accepts, writes it where the field lives, bumps ``fields_rev``, writes the
audit log and tells the playbooks what changed.

Where a system field lives (``SYSTEM_FIELDS``):

- ``doc:<key>``   a key of the incident document, mirrored to a column
- ``column:<n>``  a column of ``incidents`` only
- ``json``        ``incidents.fields``, like a custom field
- ``type``        the type of the incident (``incidents.type_id``)
"""

from __future__ import annotations

import json
import math
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm.attributes import flag_modified

from .core import audit
from .core.models import Field, Incident, IncidentType, User
from .core.security import now_iso

NAME_RE = re.compile(r"^[a-z][a-z0-9_]{1,40}$")
TYPES = (
    "text",
    "long_text",
    "number",
    "bool",
    "date",
    "choice",
    "multi_choice",
    "user",
    "role",
    "url",
    "tags",
    "indicator",
    "list",
    "timer",
    "json",
)
APPLIES_TO = ("incident", "indicator", "task")
COLUMN_TYPES = ("text", "number", "bool", "date", "choice", "url")  # of a column of a "list" field
TEXT_MAX, LONG_TEXT_MAX, JSON_MAX = 1000, 100_000, 64_000
ITEMS_MAX, ROWS_MAX, CHOICES_MAX, COLUMNS_MAX = 100, 500, 200, 20
UNCLASSIFIED = "unclassified"  # the id of the type every incident has until it is given another

SEVERITIES = ("low", "medium", "high", "critical")
STATUSES = ("open", "in_progress", "closed")
TLP = ("clear", "green", "amber", "amber+strict", "red")


class FieldError(ValueError):
    """What is wrong with a field or a value, as a sentence for the person who sent it."""

    def __init__(self, message: str, field: str | None = None):
        super().__init__(message)
        self.message = message
        self.field = field


@dataclass(frozen=True)
class System:
    label: str
    type: str
    where: str  # doc:<key> | column:<name> | json | type | id
    writable: bool = True
    options: tuple = ()
    description: str = ""


def _s(label: str, kind: str, where: str, writable: bool = True, options: tuple = (), description: str = "") -> System:
    return System(label, kind, where, writable, options, description)


# name → where it lives. The order is the order they are listed in.
SYSTEM_FIELDS: dict[str, System] = {
    "id": _s("Id", "text", "id", False, description="The id of the incident in Nik."),
    "name": _s("Name", "text", "doc:name"),
    "type": _s("Type", "choice", "type", description="The type of incident: its fields, its page, how it is closed."),
    "status": _s("Status", "choice", "doc:status", options=STATUSES),
    "severity": _s("Severity", "choice", "doc:severity", options=SEVERITIES),
    "owner": _s("Owner", "user", "doc:assignee", description="The analyst who has it."),
    "ticket": _s("Ticket", "text", "doc:ticketId", description="Its id in your organisation's tracker."),
    "host": _s("Host", "text", "doc:host"),
    "username": _s("User", "text", "doc:username"),
    "os": _s("Operating system", "text", "doc:os"),
    "created": _s("Created", "date", "doc:createdAt", False),
    "modified": _s("Modified", "date", "doc:updatedAt", False),
    "closed": _s("Closed", "date", "column:closed_at", False),
    "close_reason": _s("Close reason", "text", "column:close_reason"),
    "close_notes": _s("Close notes", "long_text", "column:close_notes"),
    "occurred": _s("Occurred", "date", "column:occurred_at", description="When what the incident is about happened."),
    "source_connector": _s("Source connector", "text", "json", False),
    "source_instance": _s("Source instance", "text", "column:source_connection_id", False),
    "source_id": _s("Source id", "text", "column:source_id", False),
    "source_url": _s("Source address", "url", "json", False),
    "details": _s("Details", "long_text", "json"),
    # The tags of the incident: called ``labels`` where they are stored and wherever they are named,
    # Tags where a person reads them (incident_tags.py holds the rules of a tag).
    "labels": _s("Tags", "tags", "json", description="Short words to group incidents by and to find them with."),
    "playbook": _s("Playbook", "text", "json", description="The playbook set for this incident."),
    "phase": _s("Phase", "text", "json"),
    "due": _s("Due", "date", "json"),
    "tlp": _s("TLP", "choice", "json", options=TLP),
    "category": _s("Category", "text", "json"),
    "affected_hosts": _s("Affected hosts", "tags", "json"),
    "affected_users": _s("Affected users", "tags", "json"),
    "related_incidents": _s("Related incidents", "tags", "json"),
    "mirror_direction": _s("Mirror direction", "text", "json", False),
    "mirror_id": _s("Mirror id", "text", "json", False),
    "mirror_last_sync": _s("Last mirrored", "date", "json", False),
    # SLA timers: started and stopped (timers.py), never written like another field.
    "time_to_assign": _s("Time to assign", "timer", "json", False, description="Until the incident has an owner."),
    "time_to_contain": _s("Time to contain", "timer", "json", False, description="Until it is contained."),
    "time_to_close": _s("Time to close", "timer", "json", False, description="Until the incident is closed."),
    "sla_breached": _s("SLA breached", "bool", "json", False, description="A timer of the incident passed its time."),
}

# What a system field was called by an older release → it takes the name it has now when the
# database is next started. One an administrator gave another name keeps that name.
RENAMED = {"labels": "Labels"}


# --------------------------------------------------------------------------- #
# The registry                                                                #
# --------------------------------------------------------------------------- #
def new_id() -> str:
    import uuid

    return uuid.uuid4().hex


def seed(db: OrmSession) -> int:
    """Add the system fields that are missing (the caller commits); returns how many."""
    known = {row.name: row for row in db.scalars(select(Field))}
    added = 0
    for name, spec in SYSTEM_FIELDS.items():
        row = known.get(name)
        options = {"choices": list(spec.options)} if spec.options else {}
        if row is None:
            db.add(
                Field(
                    id=new_id(),
                    name=name,
                    label=spec.label,
                    description=spec.description,
                    type=spec.type,
                    options=options,
                    system=True,
                    applies_to="incident",
                    all_types=True,
                    created_at=now_iso(),
                    created_by="nik",
                )
            )
            added += 1
        elif not row.system:
            # A custom field took the name before a release made it a system one: the system one wins.
            row.system, row.all_types, row.type, row.options = True, True, spec.type, options
            added += 1
        elif row.label == RENAMED.get(name) and row.label != spec.label:
            row.label = spec.label
            row.description = row.description or spec.description
            added += 1
    return added


def registry(db: OrmSession) -> dict[str, Field]:
    """Every field by name. The system ones are added here when a database does not have
    them yet (the start of the server adds them; this is for whatever runs before it)."""
    rows = {row.name: row for row in db.scalars(select(Field))}
    if any(
        name not in rows or not rows[name].system or rows[name].label == RENAMED.get(name) for name in SYSTEM_FIELDS
    ):
        seed(db)
        db.flush()
        rows = {row.name: row for row in db.scalars(select(Field))}
    return rows


def clean_options(kind: str, options: Any) -> dict[str, Any]:
    """The options of a field of this type, checked: the choices, the columns of a list."""
    options = options if isinstance(options, dict) else {}
    if kind in ("choice", "multi_choice"):
        choices = options.get("choices")
        if not isinstance(choices, list) or not choices:
            raise FieldError("A choice needs its choices: a list of texts", "options")
        cleaned = list(dict.fromkeys(str(item).strip() for item in choices if str(item).strip()))
        if not cleaned or len(cleaned) > CHOICES_MAX or any(len(item) > 100 for item in cleaned):
            raise FieldError(f"1 to {CHOICES_MAX} choices, of 100 characters at most each", "options")
        return {"choices": cleaned}
    if kind == "list":
        columns = options.get("columns")
        if not isinstance(columns, list) or not columns or len(columns) > COLUMNS_MAX:
            raise FieldError(f"A list needs its columns: 1 to {COLUMNS_MAX}", "options")
        cleaned_columns, seen = [], set()
        for column in columns:
            if not isinstance(column, dict):
                raise FieldError("A column is an object with a name and a type", "options")
            name, column_type = str(column.get("name") or ""), str(column.get("type") or "text")
            if not NAME_RE.match(name) or name in seen:
                raise FieldError("A column's name is a lower-case letter, then letters, digits or _, once", "options")
            if column_type not in COLUMN_TYPES:
                raise FieldError("A column is one of: " + ", ".join(COLUMN_TYPES), "options")
            seen.add(name)
            entry = {"name": name, "label": str(column.get("label") or name)[:80], "type": column_type}
            if column_type == "choice":
                entry["choices"] = clean_options("choice", column)["choices"]
            cleaned_columns.append(entry)
        return {"columns": cleaned_columns}
    return {}


def create(db: OrmSession, body: dict[str, Any], actor: str) -> Field:
    """Make a custom field (the caller commits). A name is for ever: it is checked hard."""
    name = str(body.get("name") or "").strip()
    if not NAME_RE.match(name):
        raise FieldError("A name is a lower-case letter, then lower-case letters, digits or _ (2 to 41)", "name")
    if name in SYSTEM_FIELDS or db.scalars(select(Field).where(Field.name == name)).first() is not None:
        raise FieldError("There is a field with this name already", "name")
    kind = str(body.get("type") or "text")
    if kind not in TYPES:
        raise FieldError("A type is one of: " + ", ".join(TYPES), "type")
    applies = str(body.get("appliesTo") or "incident")
    if applies not in APPLIES_TO:
        raise FieldError("A field is of an incident, an indicator or a task", "appliesTo")
    row = Field(
        id=new_id(),
        name=name,
        label=str(body.get("label") or name).strip()[:80],
        description=str(body.get("description") or "")[:1000],
        type=kind,
        options=clean_options(kind, body.get("options")),
        system=False,
        applies_to=applies,
        all_types=bool(body.get("allTypes")),
        created_at=now_iso(),
        created_by=actor,
    )
    db.add(row)
    return row


def used_by(db: OrmSession, field: Field) -> dict[str, Any]:
    """Where a field is used: the types that list it, and how many incidents hold a value of it."""
    types = [
        row.name
        for row in db.scalars(select(IncidentType).order_by(IncidentType.name))
        if any(isinstance(item, dict) and item.get("name") == field.name for item in row.fields or [])
    ]
    held = 0
    if not field.system or SYSTEM_FIELDS[field.name].where == "json":
        for stored in db.scalars(select(Incident.fields).where(Incident.fields_rev > 0)):
            if isinstance(stored, dict) and stored.get(field.name) not in (None, "", [], {}):
                held += 1
    return {"types": types, "incidents": held}


# --------------------------------------------------------------------------- #
# Values                                                                      #
# --------------------------------------------------------------------------- #
def _text(value: Any, limit: int, name: str) -> str:
    if isinstance(value, (dict, list)):
        raise FieldError(f"{name} is a text", name)
    text = str(value)
    if len(text) > limit:
        raise FieldError(f"{name} is longer than {limit} characters", name)
    return text


def _date(value: Any, name: str) -> str:
    """An ISO-8601 moment, stored as UTC. A number is seconds since 1970."""
    try:
        if isinstance(value, bool):
            raise ValueError
        if isinstance(value, (int, float)):
            moment = datetime.fromtimestamp(float(value), tz=timezone.utc)
        else:
            moment = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
            if moment.tzinfo is None:
                moment = moment.replace(tzinfo=timezone.utc)
    except (ValueError, OverflowError, OSError):
        raise FieldError(f"{name} is a date: 2026-11-17 or 2026-11-17T09:30:00Z", name) from None
    return moment.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _number(value: Any, name: str) -> int | float:
    if isinstance(value, bool):
        raise FieldError(f"{name} is a number", name)
    if isinstance(value, int):
        return value
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise FieldError(f"{name} is a number", name) from None
    if math.isnan(number) or math.isinf(number):
        raise FieldError(f"{name} is a number", name)
    return int(number) if number.is_integer() and not isinstance(value, float) else number


def _bool(value: Any, name: str) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in ("true", "yes", "1", "on"):
        return True
    if text in ("false", "no", "0", "off"):
        return False
    raise FieldError(f"{name} is true or false", name)


def _strings(value: Any, name: str) -> list[str]:
    items = value if isinstance(value, (list, tuple)) else str(value).split(",")
    cleaned = list(dict.fromkeys(str(item).strip() for item in items if str(item).strip()))
    if len(cleaned) > ITEMS_MAX or any(len(item) > 200 for item in cleaned):
        raise FieldError(f"{name} holds {ITEMS_MAX} values at most, of 200 characters each", name)
    return cleaned


def _choice(value: Any, choices: list[str], name: str) -> str:
    text = str(value)
    if text not in choices:
        raise FieldError(f"{name} is one of: {', '.join(choices)}", name)
    return text


def coerce(db: OrmSession, name: str, kind: str, options: dict[str, Any], value: Any) -> Any:
    """The value as the field's type stores it. None (or an empty text) means "no value"."""
    if value is None or value == "":
        return None
    if kind == "text":
        return _text(value, TEXT_MAX, name)
    if kind == "long_text":
        return _text(value, LONG_TEXT_MAX, name)
    if kind == "url":
        text = _text(value, 2000, name).strip()
        if not re.match(r"^https?://[^\s]+$", text):
            raise FieldError(f"{name} is an http:// or https:// address", name)
        return text
    if kind == "number":
        return _number(value, name)
    if kind == "bool":
        return _bool(value, name)
    if kind in ("date", "timer"):
        return _date(value, name)
    if kind == "choice":
        return _choice(value, list(options.get("choices") or []), name)
    if kind == "multi_choice":
        chosen = _strings(value, name)
        for item in chosen:
            _choice(item, list(options.get("choices") or []), name)
        return chosen
    if kind == "tags":
        return _strings(value, name)
    if kind == "user":
        text = _text(value, 200, name).strip()
        known = db.scalars(
            select(User).where(func.lower(User.username) == text.lower(), User.disabled.is_(False))
        ).first()
        if known is None:
            raise FieldError(f"{name}: there is no account called {text}", name)
        return known.username
    if kind == "role":
        from .core.permissions import ROLE_PERMISSIONS, SYSTEM_ROLE

        text = str(value)
        if text not in ROLE_PERMISSIONS or text == SYSTEM_ROLE:
            raise FieldError(f"{name} is a role", name)
        return text
    if kind == "indicator":
        from .iocs import TYPES as IOC_TYPES
        from .iocs import normalize

        if not isinstance(value, dict) or value.get("type") not in IOC_TYPES:
            raise FieldError(f"{name} is an indicator: a type and a value", name)
        cleaned = normalize(value["type"], str(value.get("value") or ""))
        if not cleaned:
            raise FieldError(f"{name}: that is not a valid {value['type']}", name)
        return {"type": value["type"], "value": cleaned}
    if kind == "list":
        columns = list(options.get("columns") or [])
        if not isinstance(value, list) or len(value) > ROWS_MAX:
            raise FieldError(f"{name} is a list of rows, {ROWS_MAX} at most", name)
        known = {column["name"]: column for column in columns}
        rows = []
        for row in value:
            if not isinstance(row, dict) or set(row) - set(known):
                raise FieldError(f"{name}: a row has the columns {', '.join(known)}", name)
            cleaned_row = {}
            for key, cell in row.items():
                column = known[key]
                cleaned_cell = coerce(db, f"{name}.{key}", column["type"], column, cell)
                if cleaned_cell is not None:
                    cleaned_row[key] = cleaned_cell
            rows.append(cleaned_row)
        return rows
    if kind == "json":
        try:
            size = len(json.dumps(value))
        except (TypeError, ValueError):
            raise FieldError(f"{name} is not JSON", name) from None
        if size > JSON_MAX:
            raise FieldError(f"{name} is larger than 64 kB", name)
        return value
    raise FieldError(f"{name} has a type Nik does not know", name)


def type_of(db: OrmSession, incident: Incident) -> IncidentType | None:
    return db.get(IncidentType, incident.type_id) if incident.type_id else None


def type_fields(kind: IncidentType | None) -> dict[str, dict[str, Any]]:
    """name → {required, required_on_close} of the custom fields of a type."""
    listed = (kind.fields if kind is not None else None) or []
    return {item["name"]: item for item in listed if isinstance(item, dict) and item.get("name")}


def read(db: OrmSession, incident: Incident) -> dict[str, Any]:
    """Every field of the incident with a value: the system ones, and what ``fields`` holds."""
    doc = incident.doc or {}
    stored = incident.fields if isinstance(incident.fields, dict) else {}
    out: dict[str, Any] = {}
    for name, spec in SYSTEM_FIELDS.items():
        where, _, key = spec.where.partition(":")
        if where == "id":
            value: Any = incident.id
        elif where == "type":
            value = incident.type_id or UNCLASSIFIED
        elif where == "doc":
            value = doc.get(key)
            if name == "status":
                value = value if value in STATUSES else "open"
        elif where == "column":
            value = getattr(incident, key)
        else:
            value = stored.get(name)
        if value not in (None, "", [], {}):
            out[name] = value
    for name, value in stored.items():
        if name not in SYSTEM_FIELDS and value not in (None, "", [], {}):
            out[name] = value
    return out


def update(
    db: OrmSession,
    incident: Incident,
    changes: dict[str, Any],
    actor: str,
    source: str | None = None,
    *,
    if_rev: int | None = None,
    signature: str = "",
) -> list[str]:
    """Write field values on an incident (locked by the caller, who commits). Returns the names that changed.

    ``source`` says who the values come from (``user:<name>``, ``connector:<id>``,
    ``run:<id>``, ``nik``): it is what decides, later, whether a fetch may overwrite them.
    """
    from .automation import triggers
    from .routers.incidents import _sync_columns

    if not isinstance(changes, dict) or not changes:
        raise FieldError("Nothing to change")
    if if_rev is not None and if_rev != (incident.fields_rev or 0):
        raise FieldError("The fields were changed by someone else: read them again", "ifRev")
    known = registry(db)
    kind = type_of(db, incident)
    of_type = type_fields(kind)
    doc = dict(incident.doc or {})
    stored = dict(incident.fields) if isinstance(incident.fields, dict) else {}
    before = read(db, incident)
    changed: list[str] = []
    # The type first, whatever the order they were sent in: the other fields are judged against it.
    for name, raw in sorted(changes.items(), key=lambda pair: pair[0] != "type"):
        field = known.get(name)
        if field is None or field.applies_to != "incident":
            raise FieldError(f'There is no field called "{name}": fields are made in Settings', name)
        spec = SYSTEM_FIELDS.get(name) if field.system else None
        if spec is not None and not spec.writable:
            raise FieldError(f"{field.label} cannot be set", name)
        if spec is None and not field.all_types and name not in of_type:
            what = kind.name if kind is not None else "Unclassified"
            raise FieldError(f'{field.label} is not a field of the type "{what}"', name)
        if field.type == "timer":
            raise FieldError(f"{field.label} is a timer: it is started and stopped, not written", name)
        if name == "type":
            wanted = None if raw in (None, "", UNCLASSIFIED) else str(raw)
            if wanted is not None and db.get(IncidentType, wanted) is None:
                raise FieldError("There is no such type of incident", name)
            if (incident.type_id or None) != wanted:
                incident.type_id = wanted
                kind = type_of(db, incident)
                of_type = type_fields(kind)
                changed.append(name)
            continue
        value = coerce(db, field.label or name, field.type, field.options or {}, raw)
        if name == "labels" and value is not None:
            # The tags: what is added is held to the rules of a tag, what was there is kept.
            from . import incident_tags

            held = before.get(name)
            value = incident_tags.clean(value, held if isinstance(held, list) else ()) or None
        if value == before.get(name) or (value is None and name not in before):
            continue
        where, _, key = (spec.where if spec is not None else "json").partition(":")
        if where == "doc":
            if name == "name" and value is None:
                raise FieldError("An incident needs a name", name)
            if value is None:
                doc.pop(key, None)
            else:
                doc[key] = value
        elif where == "column":
            setattr(incident, key, value if value is not None or key.endswith("_at") else "")
        elif value is None:
            stored.pop(name, None)
        else:
            stored[name] = value
        changed.append(name)
    if not changed:
        return []
    now = now_iso()
    doc["updatedAt"] = now
    incident.doc = doc
    flag_modified(incident, "doc")
    _sync_columns(incident)  # the columns the lists read; closing stamps the moment there
    incident.fields = stored
    flag_modified(incident, "fields")
    if "status" in changed and incident.status == "closed":
        problem = closing_problem(db, incident)
        if problem:
            raise FieldError(problem, "status")
    incident.fields_rev = (incident.fields_rev or 0) + 1
    emptied = required_problem(db, incident, changed)
    if emptied:
        raise FieldError(emptied)
    after = read(db, incident)
    for name in changed:
        label = known[name].label or name
        audit.record(
            db,
            actor,
            "incident.field",
            f"Set {label}: {_shown(before.get(name))} → {_shown(after.get(name))}" + signature,
            incident,
        )
    # The names the playbooks have always been told: the keys of the document where a field is one.
    told = [SYSTEM_FIELDS[name].where.partition(":")[2] if name in _DOC_KEYS else name for name in changed]
    triggers.incident_changed(db, incident, "incident.updated", sorted(set(told) | set(changed)))
    # An owner, a closing, another type or severity: the SLA timers follow at once.

    from . import timers

    timers.sync(db, incident, time.time())
    # Who set each field last: what decides whether a fetch or a mirror may write over it.
    note_source(db, incident, changed, source or f"user:{actor}")
    # A mirrored incident: what changed here goes to the other side, unless it came from there.
    from . import mirror

    mirror.on_fields_changed(db, incident, changed, source or f"user:{actor}", time.time())
    if changed:
        # What a connector brings to an incident that was read for indicators is read again.
        from . import indicators_found

        indicators_found.after_update(db, incident, source or "")
    return changed


def note_source(db: OrmSession, incident: Incident, names: list[str], source: str) -> None:
    """Remember who set these fields of an incident last (the caller commits)."""
    from .core.models import IncidentContextMeta

    stamp = now_iso()
    for name in names:
        key = f"field:{name}"
        meta = db.get(IncidentContextMeta, (incident.id, key))
        if meta is None:
            db.add(IncidentContextMeta(incident_id=incident.id, path_key=key, source=source[:120], at=stamp))
        else:
            meta.source, meta.at = source[:120], stamp


def source_of(db: OrmSession, incident: Incident, name: str) -> str | None:
    """Who set a field of an incident last; None when nobody is remembered."""
    from .core.models import IncidentContextMeta

    meta = db.get(IncidentContextMeta, (incident.id, f"field:{name}"))
    return meta.source if meta is not None else None


# A key of the document → the name of its field in the registry.
DOC_FIELDS = {
    spec.where.partition(":")[2]: name for name, spec in SYSTEM_FIELDS.items() if spec.where.startswith("doc:")
}


def closing_problem(db: OrmSession, incident: Incident) -> str | None:
    """Why the incident cannot be closed as it is (None when it can): a field its type wants
    filled on closing is empty, or its close reason is not one of the type's."""
    kind = type_of(db, incident) or db.get(IncidentType, UNCLASSIFIED)
    if kind is None:
        return None
    held = read(db, incident)
    known = registry(db)
    missing = [
        known[name].label or name
        for name, item in type_fields(kind).items()
        if item.get("required_on_close") and name in known and name not in held
    ]
    if missing:
        return "To close this incident, fill in: " + ", ".join(missing)
    reasons = list(kind.close_reasons or [])
    reason = held.get("close_reason")
    if reason and reasons and reason not in reasons:
        return "The close reason is one of: " + ", ".join(reasons)
    return None


def required_problem(db: OrmSession, incident: Incident, names: list[str]) -> str | None:
    """A field the type wants always filled was emptied."""
    of_type = type_fields(type_of(db, incident))
    held = read(db, incident)
    known = registry(db)
    emptied = [known[n].label or n for n in names if of_type.get(n, {}).get("required") and n not in held]
    return ("A required field cannot be emptied: " + ", ".join(emptied)) if emptied else None


def stored_fields(incident: Incident) -> dict[str, Any]:
    """What an incident document shows under ``fields``: every field that is not a key of the
    document itself. The values kept in ``incidents.fields``, and how it was closed, when it occurred."""
    shown = dict(incident.fields) if isinstance(incident.fields, dict) else {}
    for name in ("closed", "close_reason", "close_notes", "occurred"):
        value = getattr(incident, SYSTEM_FIELDS[name].where.partition(":")[2])
        if value:
            shown[name] = value
    return shown


_DOC_KEYS = frozenset(name for name, spec in SYSTEM_FIELDS.items() if spec.where.startswith("doc:"))


def _shown(value: Any) -> str:
    if value in (None, "", [], {}):
        return "empty"
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    return text if len(text) <= 120 else text[:117] + "…"

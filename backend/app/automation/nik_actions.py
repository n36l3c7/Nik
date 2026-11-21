"""The "Nik" nodes: what a playbook does inside Nik.

They call the functions the API's routers call, never the API itself: a
playbook is not an HTTP client of its own server. Everything they change is
signed ``nik-automation`` (a system account that cannot sign in), written to
the audit log with the run and with who approved it, and marked as made by
automation where an analyst will read it. In a dry run nothing is changed:
the step shows what would have been.

The values they return carry classes (payloads.py), so what a later node
sends out is judged by where it came from.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm.attributes import flag_modified

from .. import ioc_library as lib
from ..core import audit
from ..core.locking import lock_incident
from ..core.models import Incident, IocList, IocListItem, UrlScan, User
from ..core.permissions import SYSTEM_USER
from ..core.security import now_iso
from ..iocs import TYPES, normalize
from . import payloads, triggers
from .actions import ActionError, Call, Result, action

ACTOR = SYSTEM_USER
ADHOC_PLAYBOOK = "adhoc"  # the playbook the commands of the War Room run under (commands.ADHOC_ID)
SEVERITIES = ("low", "medium", "high", "critical", "")
STATUSES = ("open", "in_progress", "closed")
FIELDS = ("ticketId", "title", "host", "username", "os", "severity", "status", "assignee")


def system_user(db: OrmSession) -> User:
    """The account the engine acts as: it exists so that its name means one thing, and cannot sign in."""
    found = db.scalars(select(User).where(User.username == ACTOR)).first()
    if found is None:
        found = User(
            id=str(uuid.uuid4()),
            username=ACTOR,
            password_hash="!",  # noqa: S106 - not a hash: no password matches it
            roles=["automation"],
            created_at=now_iso(),
            created_by=None,
            disabled=True,
        )
        db.add(found)
        db.flush()
    return found


def signature(call: Call) -> str:
    """Who did it, for the audit log: the playbook, the run, and who approved."""
    playbook = (call.run.trigger or {}).get("playbook", "")
    who = f", approved by {call.approved_by}" if call.approved_by else ""
    return f' (playbook "{playbook}", run {call.run.id}{who})'


def _wanted(call: Call, given: Any) -> str:
    """The id of the incident a node names: an id, or the incident another node gave (its ``id``
    is read, so ``{{ create_incident.incident }}`` works as well as ``….incident.id``). The
    incident of the run when nothing is given."""
    if isinstance(given, dict):
        given = given.get("id")
    return str(given or call.run.incident_id or "")


def _incident(call: Call, incident_id: Any) -> Incident:
    wanted = _wanted(call, incident_id)
    row = lock_incident(call.db, wanted) if wanted else None
    if row is None:
        raise ActionError("The incident does not exist" if wanted else "No incident was given", retry=False)
    return row


def _save(call: Call, row: Incident, doc: dict, changed: list[str]) -> None:
    from ..routers.incidents import _sync_columns  # the columns the lists read

    doc["updatedAt"] = now_iso()
    row.doc = doc
    flag_modified(row, "doc")
    _sync_columns(row)
    triggers.incident_changed(call.db, row, "incident.updated", changed)


def _incident_result(row: Incident) -> Result:
    return Result(output={"incident": payloads.incident_data(row)}, classes=payloads.incident_classes())


INCIDENT_ARG = {
    "name": "incident",
    "type": "text",
    "description": "The incident's id, or the incident a node gave; the incident of the run when left empty",
}
INCIDENT_OUT = [
    {
        "name": "incident",
        "type": "object",
        "description": "The incident: id, name, status, severity, assignee, url…",
        "shape": "incident",
    }
]


# --------------------------------------------------------------------------- #
# Incidents                                                                   #
# --------------------------------------------------------------------------- #
@action(
    "nik.get-incident",
    group="Nik",
    name="Get an incident",
    description="Read an incident as it is now: what every incident has, and each of its fields that has a value.",
    arguments=[INCIDENT_ARG],
    outputs=[
        *INCIDENT_OUT,
        {
            "name": "fields",
            "type": "object",
            "description": "Its fields that have a value, by their names in the registry: your own fields too",
            "shape": "fields",
        },
    ],
)
def get_incident(call: Call) -> Result:
    from .. import fields as registry
    from .. import incident_tags

    wanted = _wanted(call, call.args.get("incident"))
    row = call.db.get(Incident, wanted) if wanted else None
    if row is None:
        raise ActionError("The incident does not exist" if wanted else "No incident was given", retry=False)
    # The fields carry the classes ``{{ incident.… }}`` gives them: a custom one has none of its own.
    held = {f"fields.{name}": classes for name, classes in payloads.registry_classes().items()}
    fields = incident_tags.named(call.db, registry.read(call.db, row))
    return Result(
        output={"incident": payloads.incident_data(row), "fields": fields},
        classes={**payloads.incident_classes(), **held},
    )


@action(
    "nik.add-note",
    group="Nik",
    name="Add a note",
    description="Write a note on an incident, marked as written by automation.",
    arguments=[INCIDENT_ARG, {"name": "text", "type": "text", "required": True, "description": "The note"}],
    outputs=[{"name": "note", "type": "text", "description": "The id of the note"}],
)
def add_note(call: Call) -> Result:
    text = str(call.args.get("text") or "").strip()
    if not text:
        raise ActionError("The note is empty", retry=False)
    if call.dry_run:
        return Result(output={"note": "dry-run"}, request={"would": "add a note", "text": text[:2000]})
    row = _incident(call, call.args.get("incident"))
    doc = dict(row.doc or {})
    now = now_iso()
    note = {
        "id": str(uuid.uuid4()),
        "text": text[:20_000],
        "createdAt": now,
        "updatedAt": now,
        "author": ACTOR,
        "automation": {"run": call.run.id, "playbook": (call.run.trigger or {}).get("playbook", "")},
    }
    notes = doc.get("notes") if isinstance(doc.get("notes"), list) else []
    doc["notes"] = [*notes, note]
    _save(call, row, doc, ["notes"])
    audit.record(call.db, ACTOR, "note.add", "Added a note" + signature(call), row)
    return Result(output={"note": note["id"]}, classes={"note": ["nik_id"]})


def _set_field(call: Call, name: str, value: str) -> Result:
    if name not in FIELDS:
        raise ActionError("This field cannot be set: " + ", ".join(FIELDS), retry=False)
    if name == "severity" and value not in SEVERITIES:
        raise ActionError("The severity is low, medium, high or critical", retry=False)
    if name == "status" and value not in STATUSES:
        raise ActionError("The status is open, in_progress or closed", retry=False)
    if name == "assignee" and value:
        known = call.db.scalars(select(User).where(User.username == value, User.disabled.is_(False))).first()
        if known is None:
            raise ActionError("There is no account with this name to assign the incident to", retry=False)
    if call.dry_run:
        # Nothing is changed; later steps read the incident as it would have been.
        wanted = _wanted(call, call.args.get("incident"))
        current = call.db.get(Incident, wanted) if wanted else None
        if current is None:
            raise ActionError("The incident does not exist" if wanted else "No incident was given", retry=False)
        data = payloads.incident_data(current)
        if name in data:
            data[name] = value
        would = {"would": f"set {name}", "value": value}
        return Result(output={"incident": data}, classes=payloads.incident_classes(), request=would)
    row = _incident(call, call.args.get("incident"))
    doc = dict(row.doc or {})
    before = doc.get(name) or ("open" if name == "status" else "")
    if before == value:
        return _incident_result(row)
    doc[name] = value
    _save(call, row, doc, [name])
    audit.record(
        call.db,
        ACTOR,
        "incident.update",
        f"Set {name}: {before or 'empty'} → {value or 'empty'}" + signature(call),
        row,
    )
    return _incident_result(row)


@action(
    "nik.set-status",
    group="Nik",
    name="Set the status",
    description="Mark an incident open, in progress or closed.",
    arguments=[
        INCIDENT_ARG,
        {"name": "status", "type": "choice", "choices": list(STATUSES), "required": True, "description": "The status"},
    ],
    outputs=INCIDENT_OUT,
)
def set_status(call: Call) -> Result:
    return _set_field(call, "status", str(call.args.get("status") or ""))


@action(
    "nik.set-assignee",
    group="Nik",
    name="Assign the incident",
    description="Give an incident to an analyst; empty takes it from whoever has it.",
    arguments=[INCIDENT_ARG, {"name": "assignee", "type": "text", "description": "A user name, or empty"}],
    outputs=INCIDENT_OUT,
)
def set_assignee(call: Call) -> Result:
    return _set_field(call, "assignee", str(call.args.get("assignee") or "").strip())


@action(
    "nik.set-incident-field",
    group="Nik",
    name="Set a field of the incident",
    description="Set the ticket, the title, the host, the user, the OS or the severity of an incident.",
    arguments=[
        INCIDENT_ARG,
        {"name": "field", "type": "choice", "choices": list(FIELDS), "required": True, "description": "Which field"},
        {"name": "value", "type": "text", "description": "Its new value"},
    ],
    outputs=INCIDENT_OUT,
)
def set_incident_field(call: Call) -> Result:
    return _set_field(call, str(call.args.get("field") or ""), str(call.args.get("value") or "").strip())


INCIDENT_TAGS_ARG = {
    "name": "tags",
    "type": "list",
    "required": True,
    "description": "The tags: a list, or words separated by commas",
}
INCIDENT_TAGS_OUT = [
    {"name": "tags", "type": "list", "description": "The tags of the incident afterwards"},
    {"name": "changed", "type": "bool", "description": "Whether its tags are not what they were"},
]


def _tag_incident(call: Call, change, would: str) -> Result:
    """Put tags on an incident or take them off (``change`` is which). Doing it twice changes
    nothing the second time: the incident has the tags already, or no longer has them."""
    from .. import fields as registry
    from .. import incident_tags

    wanted = incident_tags.given(call.args.get("tags"))
    if not wanted:
        raise ActionError("At least one tag is needed", retry=False)
    found = _wanted(call, call.args.get("incident"))
    # A dry run reads the incident and changes nothing, so it does not lock it.
    row = (call.db.get(Incident, found) if found else None) if call.dry_run else _incident(call, found)
    if row is None:
        raise ActionError("The incident does not exist" if found else "No incident was given", retry=False)
    held = incident_tags.of(row)
    try:
        after = change(held, wanted)
        if after != held and not call.dry_run:
            registry.update(
                call.db,
                row,
                {incident_tags.FIELD: after or None},
                ACTOR,
                f"run:{call.run.id}",
                signature=signature(call),
            )
    except registry.FieldError as error:
        raise ActionError(error.message, retry=False) from None
    request = {"would": would, "tags": [str(tag) for tag in wanted][:50]} if call.dry_run else None
    return Result(output={"tags": after, "changed": after != held}, request=request)


@action(
    "nik.add-incident-tags",
    group="Nik",
    name="Tag the incident",
    description="Add tags to an incident. The tags it has already stay as they are.",
    arguments=[INCIDENT_ARG, INCIDENT_TAGS_ARG],
    outputs=INCIDENT_TAGS_OUT,
)
def add_incident_tags(call: Call) -> Result:
    from .. import incident_tags

    return _tag_incident(call, incident_tags.added, "tag the incident")


@action(
    "nik.remove-incident-tags",
    group="Nik",
    name="Take tags off the incident",
    description="Remove tags from an incident. A tag it does not have changes nothing.",
    arguments=[INCIDENT_ARG, INCIDENT_TAGS_ARG],
    outputs=INCIDENT_TAGS_OUT,
)
def remove_incident_tags(call: Call) -> Result:
    from .. import incident_tags

    return _tag_incident(call, incident_tags.removed, "take tags off the incident")


@action(
    "nik.create-incident",
    group="Nik",
    name="Create an incident",
    description="Open a new incident.",
    arguments=[
        {"name": "title", "type": "text", "required": True, "description": "A short title"},
        {"name": "ticketId", "type": "text", "description": "The ticket of your tracker"},
        {"name": "host", "type": "text", "description": "The host it is about"},
        {"name": "username", "type": "text", "description": "The account it is about"},
        {"name": "severity", "type": "choice", "choices": ["", "low", "medium", "high", "critical"], "default": ""},
    ],
    outputs=INCIDENT_OUT,
)
def create_incident(call: Call) -> Result:
    from ..routers.incidents import _sync_columns

    title = str(call.args.get("title") or "").strip()[:200]
    if not title:
        raise ActionError("A title is required", retry=False)
    severity = str(call.args.get("severity") or "")
    if severity not in SEVERITIES:
        raise ActionError("The severity is low, medium, high or critical", retry=False)
    now = now_iso()
    ticket = str(call.args.get("ticketId") or "").strip()[:80]
    host = str(call.args.get("host") or "").strip()[:200]
    username = str(call.args.get("username") or "").strip()[:200]
    name = " · ".join(part for part in (ticket, title) if part)
    if call.dry_run:
        # Nothing is made; the steps after read the incident as it would have been.
        would = {
            "id": "dry-run",
            "url": "",
            "name": name,
            "ticket": ticket,
            "status": "open",
            "severity": severity,
            "assignee": "",
            "host": host,
            "username": username,
            "os": "",
            "created": now,
            "modified": now,
        }
        return Result(
            output={"incident": would},
            classes=payloads.incident_classes(),
            request={"would": "create an incident", "title": title},
        )
    doc = {
        "id": str(uuid.uuid4()),
        "ticketId": ticket,
        "title": title,
        "host": host,
        "username": username,
        "os": "",
        "severity": severity,
        "status": "open",
        "assignee": "",
        "name": name,
        "createdAt": now,
        "updatedAt": now,
        "createdBy": ACTOR,
        "automation": {"run": call.run.id, "playbook": (call.run.trigger or {}).get("playbook", "")},
        "data": {},
        "flags": [],
        "notes": [],
    }
    row = Incident(id=doc["id"], doc=doc)
    _sync_columns(row)
    call.db.add(row)
    call.db.flush()
    audit.record(call.db, ACTOR, "incident.create", f'Created incident "{row.name}"' + signature(call), row)
    triggers.incident_changed(call.db, row, "incident.created")
    # The incident is whole: its fields are read for indicators (indicators_found.py).
    from .. import indicators_found

    indicators_found.scan(call.db, row, "playbook")
    return _incident_result(row)


# --------------------------------------------------------------------------- #
# Indicators                                                                  #
# --------------------------------------------------------------------------- #
def _pairs(values: Any, kind: str = "") -> list[tuple[str, str]]:
    """Indicators from a list of values, of ``{type, value}`` objects, or a text of them."""
    if isinstance(values, str):
        return [(item["type"], item["value"]) for item in lib.parse(values)["items"]]
    out: list[tuple[str, str]] = []
    for item in values if isinstance(values, (list, tuple)) else [values]:
        if isinstance(item, dict):
            found_kind, raw = str(item.get("type") or kind), item.get("value")
        else:
            found_kind, raw = kind, item
        if found_kind in TYPES:
            value = normalize(found_kind, str(raw or ""))
            if value:
                out.append((found_kind, value))
        elif raw:
            detected = lib.detect(str(raw))
            if detected:
                out.append(detected)
    return list(dict.fromkeys(out))[: lib.MAX_BATCH]


INDICATORS_ARG = {
    "name": "indicators",
    "type": "any",
    "required": True,
    "description": "A list of values, of {type, value} objects, or a text that holds them",
}
TAGS_ARG = {"name": "tags", "type": "list", "description": "Tags to put on them"}


@action(
    "nik.add-indicators",
    group="Nik",
    name="Add indicators",
    description="Keep indicators in the Indicators page, with tags and a note.",
    arguments=[INDICATORS_ARG, TAGS_ARG, {"name": "note", "type": "text", "description": "A note on each"}],
    outputs=[
        {"name": "added", "type": "number", "description": "How many were new"},
        {"name": "known", "type": "number", "description": "How many the library already had"},
    ],
)
def add_indicators(call: Call) -> Result:
    pairs = _pairs(call.args.get("indicators"))
    if not pairs:
        raise ActionError("No indicator was found in what was given", retry=False)
    tags = call.args.get("tags") if isinstance(call.args.get("tags"), list) else []
    if call.dry_run:
        return Result(output={"added": 0, "known": 0}, request={"would": "add indicators", "count": len(pairs)})
    items = [{"type": kind, "value": value} for kind, value in pairs]
    done = lib.save_items(
        call.db, items, ACTOR, now_iso(), origin="import", tags=tags, note=str(call.args.get("note") or "")
    )
    audit.record(call.db, ACTOR, "ioc.add", f"Added {len(pairs)} indicators to the library" + signature(call))
    return Result(output={"added": done.get("added", 0), "known": len(pairs) - done.get("added", 0)})


MAKE_MAX = 500  # values of one call
MAKE_TEXT = 200  # characters of a value that was not recognised, as the output shows it


def _texts(given: Any) -> list[tuple[str, str]]:
    """What a node gave to make indicators of, as ``(text, type or "")``: a text, a list of texts,
    or ``{type, value}`` objects."""
    out: list[tuple[str, str]] = []
    for item in given if isinstance(given, (list, tuple)) else [given]:
        if isinstance(item, dict):
            out.append((str(item.get("value") or ""), str(item.get("type") or "")))
        elif item not in (None, ""):
            out.append((str(item), ""))
    return [(text, kind) for text, kind in out if text.strip()][:MAKE_MAX]


@action(
    "nik.make-indicators",
    group="Nik",
    name="Make indicators of a text",
    description=(
        "Reads a value, a list of values or a longer text, works out what each indicator in it is (an "
        "address, a domain, a URL, an e-mail address, a hash) and makes it one: of the incident when the "
        "run has one, of the Indicators page otherwise. Defanged values are read as meant, and a URL gives "
        "two: the URL and its host. An indicator that is there already is linked, not made twice."
    ),
    arguments=[
        {
            "name": "text",
            "type": "any",
            "required": True,
            "description": "A value, a list of values, or a text that holds them",
        },
        {
            "name": "type",
            "type": "choice",
            "choices": ["", *TYPES],
            "default": "",
            "description": "What they are, when you know; worked out for each one when left empty",
        },
        TAGS_ARG,
        {"name": "note", "type": "text", "description": "A note on each"},
        {
            "name": "leave_out_harmless",
            "type": "bool",
            "default": False,
            "description": (
                "Leave out private and reserved addresses, names kept for documentation, the organisation's "
                "own domains and the IOC allowlist, as the finding of indicators in a new incident does"
            ),
        },
        INCIDENT_ARG,
    ],
    outputs=[
        {
            "name": "indicators",
            "type": "list",
            "description": "Each indicator: {type, value, new, marks}",
            "shape": [
                {"name": "[0].type", "type": "text", "description": "ip, domain, url, email, md5, sha1 or sha256"},
                {"name": "[0].value", "type": "text", "description": "The first indicator, as Nik writes it"},
                {"name": "[0].new", "type": "bool", "description": "Whether Nik did not know it before"},
                {"name": "[0].marks", "type": "list", "description": "private, benign, own, allowlisted"},
            ],
        },
        {"name": "created", "type": "number", "description": "How many Nik did not know before"},
        {"name": "linked", "type": "number", "description": "How many the incident did not hold before"},
        {
            "name": "not_recognised",
            "type": "list",
            "description": "What was not made an indicator, and why: {text, reason}",
            "shape": [
                {"name": "[0].text", "type": "text", "description": "The first value that was not recognised"},
                {"name": "[0].reason", "type": "text", "description": "Why"},
            ],
        },
    ],
)
def make_indicators(call: Call) -> Result:
    from .. import indicators_found, iocs, recognise

    forced = str(call.args.get("type") or "")
    if forced and forced not in TYPES:
        raise ActionError("The type is one of: " + ", ".join(TYPES), retry=False)
    texts = _texts(call.args.get("text"))
    if not texts:
        raise ActionError("No text was given", retry=False)
    known = indicators_found.known_of(call.db)
    leave_out = _truthy(call.args.get("leave_out_harmless"))
    found: dict[tuple[str, str], recognise.Found] = {}
    refused: list[dict[str, str]] = []
    for text, kind in texts:
        items, why = recognise.identify(text, known, force=forced or (kind if kind in TYPES else ""))
        if not items:
            refused.append({"text": text[:MAKE_TEXT], "reason": why})
        for item in items:
            if leave_out and item.marks:
                refused.append({"text": item.value[:MAKE_TEXT], "reason": "left out: " + ", ".join(item.marks)})
            else:
                found.setdefault((item.type, item.value), item)
    pairs = list(found)
    library = lib.known_pairs(call.db, pairs)
    incident_id = _wanted(call, call.args.get("incident"))
    tags = call.args.get("tags") if isinstance(call.args.get("tags"), list) else []
    note = str(call.args.get("note") or "")
    output = {
        "indicators": [
            {"type": item.type, "value": item.value, "new": key not in library, "marks": list(item.marks)}
            for key, item in found.items()
        ],
        "created": sum(1 for key in pairs if key not in library),
        "linked": 0,
        "not_recognised": refused,
    }
    # What comes out is made of what went in: it carries the same classes, so nothing is laundered.
    classes = {"indicators": sorted(call.classes), "not_recognised": sorted(call.classes)}
    if call.dry_run:
        return Result(output=output, classes=classes, request={"would": "make indicators", "count": len(pairs)})
    if not pairs:
        return Result(output=output, classes=classes, log="No indicator was recognised")
    if incident_id:
        row = _incident(call, incident_id)
        source = "warroom" if call.run.playbook_id == ADHOC_PLAYBOOK else "playbook"
        output["linked"] = len(iocs.add_manual_many(call.db, row, pairs, source, ACTOR))
    if not incident_id or tags or note:
        # With no incident the Indicators page keeps them; tags and a note live there too.
        items = [{"type": kind, "value": value} for kind, value in pairs]
        lib.save_items(call.db, items, ACTOR, now_iso(), origin="import", tags=tags, note=note)
    if output["created"] or output["linked"]:
        audit.record(
            call.db,
            ACTOR,
            "ioc.add",
            f"Made {len(pairs)} indicators of a text ({output['created']} new)" + signature(call),
            call.db.get(Incident, incident_id) if incident_id else None,
        )
    return Result(output=output, classes=classes)


@action(
    "nik.add-tags",
    group="Nik",
    name="Tag indicators",
    description="Add tags to indicators of the library (those not in it yet are added).",
    arguments=[INDICATORS_ARG, {**TAGS_ARG, "required": True}],
    outputs=[{"name": "tagged", "type": "number", "description": "How many indicators"}],
)
def add_tags(call: Call) -> Result:
    pairs = _pairs(call.args.get("indicators"))
    tags = lib.clean_tags(call.args.get("tags") if isinstance(call.args.get("tags"), list) else [])
    if not pairs or not tags:
        raise ActionError("Indicators and at least one tag are needed", retry=False)
    if call.dry_run:
        return Result(output={"tagged": len(pairs)}, request={"would": "tag indicators", "tags": tags})
    lib.save_items(call.db, [{"type": k, "value": v} for k, v in pairs], ACTOR, now_iso(), origin="import", tags=tags)
    audit.record(call.db, ACTOR, "ioc.tag", f"Tagged {len(pairs)} indicators: {', '.join(tags)}" + signature(call))
    return Result(output={"tagged": len(pairs)})


LIST_ARG = {"name": "list", "type": "text", "required": True, "description": "The name of the watch list"}


@action(
    "nik.add-to-ioc-list",
    group="Nik",
    name="Add to a list",
    description="Put indicators in a watch list (made if there is none with that name).",
    arguments=[LIST_ARG, INDICATORS_ARG],
    outputs=[{"name": "added", "type": "number", "description": "How many were not in the list yet"}],
)
def add_to_list(call: Call) -> Result:
    pairs = _pairs(call.args.get("indicators"))
    name = str(call.args.get("list") or "").strip()
    if not pairs or not name:
        raise ActionError("A list and at least one indicator are needed", retry=False)
    if call.dry_run:
        return Result(output={"added": 0}, request={"would": f'add to the list "{name}"', "count": len(pairs)})
    now = now_iso()
    target = lib.list_named(call.db, name, ACTOR, now)
    lib.save_items(call.db, [{"type": k, "value": v} for k, v in pairs], ACTOR, now, origin="import")
    added = lib.add_to_list(call.db, target, pairs, ACTOR, now)
    audit.record(call.db, ACTOR, "ioc.list", f'Added {added} indicators to the list "{target.name}"' + signature(call))
    return Result(output={"added": added, "list": target.id}, classes={"list": ["nik_id"]})


@action(
    "nik.remove-from-ioc-list",
    group="Nik",
    name="Remove from a list",
    description="Take indicators out of a watch list. They stay in the library.",
    arguments=[LIST_ARG, INDICATORS_ARG],
    outputs=[{"name": "removed", "type": "number", "description": "How many were in the list"}],
)
def remove_from_list(call: Call) -> Result:
    pairs = _pairs(call.args.get("indicators"))
    name = str(call.args.get("list") or "").strip()
    target = call.db.scalars(select(IocList).where(IocList.name == name)).first()
    if target is None:
        raise ActionError("There is no list with this name", retry=False)
    if call.dry_run:
        return Result(output={"removed": 0}, request={"would": f'remove from the list "{name}"', "count": len(pairs)})
    removed = 0
    for kind, value in pairs:
        removed += call.db.execute(
            delete(IocListItem).where(
                IocListItem.list_id == target.id, IocListItem.type == kind, IocListItem.value == value
            )
        ).rowcount
    target.updated_at = now_iso()
    audit.record(
        call.db, ACTOR, "ioc.list", f'Removed {removed} indicators from the list "{target.name}"' + signature(call)
    )
    return Result(output={"removed": removed})


@action(
    "nik.get-ioc-lists",
    group="Nik",
    name="Get the lists",
    description="The lists of indicators of the library: all of them, or those that are watched.",
    arguments=[
        {"name": "watched", "type": "bool", "default": False, "description": "Only the lists that are watched"},
    ],
    outputs=[
        {
            "name": "lists",
            "type": "list",
            "description": "Each list: {id, name, description, watched, tlp, count}",
            "shape": [
                {"name": "[0].id", "type": "text", "description": "The id of the first list"},
                {"name": "[0].name", "type": "text", "description": "Its name"},
                {"name": "[0].description", "type": "text", "description": "What it is for"},
                {"name": "[0].watched", "type": "bool", "description": "Whether it is watched"},
                {"name": "[0].tlp", "type": "text", "description": "Its TLP"},
                {"name": "[0].count", "type": "number", "description": "How many indicators it holds"},
            ],
        },
        {"name": "names", "type": "list", "description": "Their names"},
        {"name": "count", "type": "number", "description": "How many lists"},
    ],
)
def get_lists(call: Call) -> Result:
    query = select(IocList).order_by(IocList.name)
    if _truthy(call.args.get("watched")):
        query = query.where(IocList.watch.is_(True))
    counts = dict(call.db.execute(select(IocListItem.list_id, func.count()).group_by(IocListItem.list_id)).all())
    lists = [
        {
            "id": row.id,
            "name": row.name,
            "description": row.description,
            "watched": bool(row.watch),
            "tlp": row.tlp,
            "count": counts.get(row.id, 0),
        }
        for row in call.db.scalars(query)
    ]
    # The name of a list has no class of its own (it is not the name of an incident): like any text
    # with none, the guard reads it for internal names and addresses where it would leave.
    return Result(
        output={"lists": lists, "names": [item["name"] for item in lists], "count": len(lists)},
        classes={"lists.id": ["nik_id"]},
    )


RECHECK_EVERY = 30
RECHECK_ITEMS = 2000
# One indicator with its verdict, as "Check a list again" gives it before and after.
VERDICT_ITEM = [
    {"name": "[0].type", "type": "text", "description": "The type of the first indicator"},
    {"name": "[0].value", "type": "text", "description": "The indicator"},
    {"name": "[0].verdict", "type": "text", "description": "Its verdict"},
]


def _truthy(value: Any) -> bool:
    return value is True or str(value).strip().lower() in ("true", "yes", "1", "on")


def _verdicts(db: OrmSession, pairs: list[tuple[str, str]]) -> list[dict[str, Any]]:
    from ..enrichment import service

    found = service.summaries(db, pairs)
    return [
        {"type": kind, "value": value, "verdict": (found.get((kind, value)) or {}).get("verdict") or ""}
        for kind, value in pairs
    ]


@action(
    "nik.recheck-list",
    group="Nik",
    name="Check a list again",
    description=(
        "Ask the reputation sources again about every indicator of a list, and wait for the answers. "
        "Gives the verdicts as they were and as they are, for a script to compare. The check is the same "
        "as the library's bulk check: it keeps to the quota of each source."
    ),
    arguments=[
        LIST_ARG,
        {
            "name": "force",
            "type": "bool",
            "default": True,
            "description": "Ask also about what was checked lately (off: only what is due)",
        },
        {
            "name": "wait_minutes",
            "type": "number",
            "default": 120,
            "description": "How long to wait for the answers before going on with what is there",
        },
    ],
    outputs=[
        {"name": "list", "type": "text", "description": "The name of the list"},
        {
            "name": "before",
            "type": "list",
            "description": "The indicators as they were: [{type, value, verdict}]",
            "shape": VERDICT_ITEM,
        },
        {"name": "after", "type": "list", "description": "The same indicators as they are now", "shape": VERDICT_ITEM},
        {"name": "total", "type": "number", "description": "How many indicators the list has"},
        {"name": "asked", "type": "number", "description": "About how many the sources were asked"},
        {"name": "finished", "type": "bool", "description": "Every answer came in the time given"},
        {"name": "check", "type": "text", "description": "The id of the bulk check"},
    ],
)
def recheck_list(call: Call) -> Result:
    from ..core.models import IocCheck
    from ..enrichment import service
    from ..routers.settings import read_settings

    name = str(call.args.get("list") or "").strip()
    target = call.db.scalars(select(IocList).where(IocList.name == name)).first()
    if target is None:
        raise ActionError("There is no list with this name", retry=False)
    every = [
        (kind, value)
        for kind, value in call.db.execute(
            select(IocListItem.type, IocListItem.value)
            .where(IocListItem.list_id == target.id)
            .order_by(IocListItem.type, IocListItem.value)
        )
    ]
    shown = every[:RECHECK_ITEMS]
    held: set[str] = set()
    for kind, value in shown[:200]:
        held.update(payloads.indicator_data(call.db, kind, value)[1])
    # Beyond the first, the guard's scan of what leaves decides.
    value_classes = sorted(held - {"public_indicator"}) or (["public_indicator"] if len(shown) <= 200 else [])
    classes = {
        "check": ["nik_id"],
        "before.value": value_classes,
        "after.value": value_classes,
        "before.verdict": ["verdict"],
        "after.verdict": ["verdict"],
        "before.type": ["verdict"],
        "after.type": ["verdict"],
    }

    def done(before: list, asked: int, finished: bool, check_id: str) -> Result:
        return Result(
            output={
                "list": target.name,
                "before": before,
                "after": _verdicts(call.db, shown),
                "total": len(every),
                "asked": asked,
                "finished": finished,
                "check": check_id,
            },
            classes=classes,
        )

    state = call.state or {}
    if not state:
        before = _verdicts(call.db, shown)
        plan = service.plan_check(call.db, every, read_settings(call.db), force=_truthy(call.args.get("force")))
        if call.dry_run:
            would = {"would": f'check the list "{target.name}" again', "count": plan["toAsk"]}
            result = done(before, 0, True, "")
            result.request = would
            return result
        check = service.start_check(call.db, plan, target.name, ACTOR, of_list=target)
        audit.record(
            call.db,
            ACTOR,
            "ioc.check",
            f"Bulk check of {plan['toAsk']} indicator(s)" + signature(call),
            target=target.name,
        )
        if check.status == "done":
            return done(before, 0, True, check.id)
        try:
            minutes = max(1.0, min(float(call.args.get("wait_minutes") or 120), 24 * 60))
        except (TypeError, ValueError):
            minutes = 120.0
        return Result(
            again_at=call.now + RECHECK_EVERY,
            state={"check": check.id, "before": before, "until": call.now + minutes * 60, "asked": plan["toAsk"]},
            log=f"Asking the sources about {plan['toAsk']} indicator(s)",
        )
    check = call.db.get(IocCheck, str(state.get("check") or ""))
    before = state.get("before") or []
    asked = int(state.get("asked") or 0)
    if check is None:
        return done(before, asked, False, "")
    if check.status in ("running", "waiting") and call.now < float(state.get("until") or 0):
        return Result(
            again_at=call.now + RECHECK_EVERY, state=state, log=f"{check.done} of {check.total} asked ({check.status})"
        )
    return done(before, asked, check.status == "done", check.id)


@action(
    "nik.get-indicator",
    group="Nik",
    name="Get an indicator",
    description="What Nik knows of an indicator: its verdict, score, tags, lists and the incidents it was seen in.",
    arguments=[
        {"name": "value", "type": "text", "required": True, "description": "The indicator"},
        {
            "name": "type",
            "type": "choice",
            "choices": ["", *TYPES],
            "default": "",
            "description": "Its type; guessed when empty",
        },
    ],
    outputs=[
        {"name": "found", "type": "bool", "description": "It is in the library"},
        {"name": "type", "type": "text", "description": "Its type, as it was given or guessed"},
        {"name": "value", "type": "text", "description": "The indicator, as Nik writes it"},
        {"name": "verdict", "type": "text", "description": "malicious, suspicious, harmless, unknown or empty"},
        {"name": "score", "type": "number", "description": "The reputation score"},
        {"name": "tags", "type": "list", "description": "Its tags"},
        {"name": "lists", "type": "list", "description": "The names of its lists"},
        {"name": "incidents", "type": "number", "description": "In how many incidents it was seen"},
        {"name": "allowlisted", "type": "bool", "description": "It is in the allowlist"},
    ],
)
def get_indicator(call: Call) -> Result:
    from ..routers.settings import read_settings

    pairs = _pairs([call.args.get("value")], str(call.args.get("type") or ""))
    if not pairs:
        raise ActionError("That is not an indicator Nik can read", retry=False)
    rows = lib.library(call.db, read_settings(call.db), only={pairs[0]})
    row = rows[0] if rows else None
    output = {
        "found": row is not None,
        "type": pairs[0][0],
        "value": pairs[0][1],
        "verdict": (row or {}).get("verdict") or "",
        "score": (row or {}).get("score"),
        "tags": (row or {}).get("tags") or [],
        "lists": [entry["name"] for entry in (row or {}).get("lists") or []],
        "incidents": (row or {}).get("incidents") or 0,
        "allowlisted": bool((row or {}).get("allowlisted")),
    }
    # The value keeps the classes it came in with; what Nik says of it is a verdict.
    return Result(output=output, classes={"value": sorted(call.classes), "verdict": ["verdict"], "score": ["verdict"]})


VERDICTS = ("malicious", "suspicious", "harmless", "unknown")
_ENTITY = {"ip": ("IP", "Address"), "domain": ("Domain", "Name"), "url": ("URL", "Data")}
_HASH = {32: "md5", 40: "sha1", 64: "sha256"}


@action(
    "nik.reputation",
    group="Nik",
    name="Reputation of an indicator",
    description=(
        "What is known of an address, a domain, a URL, a file hash or an e-mail address: the reputation "
        "command of every source that is on (a connector with an instance), in one verdict. The same "
        "look-up as Check now on the page of an indicator: answers that still stand are not asked again."
    ),
    arguments=[
        {"name": "kind", "type": "choice", "choices": ["ip", "domain", "url", "file", "email"], "required": True},
        {"name": "value", "type": "text", "required": True, "description": "The indicator"},
    ],
    outputs=[
        {"name": "verdict", "type": "text", "description": "malicious, suspicious, harmless, unknown or empty"},
        {"name": "score", "type": "number", "description": "0 to 100"},
        {"name": "kind", "type": "text", "description": "What it was looked up as: ip, domain, url, email, md5…"},
        {"name": "value", "type": "text", "description": "The indicator, as Nik writes it"},
        {
            "name": "sources",
            "type": "list",
            "description": "Each source that answered: {source, verdict, summary}",
            "shape": [
                {"name": "[0].source", "type": "text", "description": "The first source that answered"},
                {"name": "[0].verdict", "type": "text", "description": "What it says"},
                {"name": "[0].summary", "type": "text", "description": "Its answer in a line"},
            ],
        },
        {
            "name": "skipped",
            "type": "list",
            "description": "The sources that were not asked, and why",
            "shape": [
                {"name": "[0].source", "type": "text", "description": "The first source that was not asked"},
                {"name": "[0].reason", "type": "text", "description": "Why"},
            ],
        },
    ],
    timeout=120,
)
def reputation(call: Call) -> Result:
    from ..enrichment import service
    from ..enrichment import sources as lookup_sources
    from ..iocs import Allowlist
    from ..routers.settings import read_settings
    from . import outbound

    wanted = str(call.args.get("kind") or "")
    raw = str(call.args.get("value") or "").strip()
    kind = _HASH.get(len(raw), "") if wanted == "file" else wanted
    value = normalize(kind, raw) if kind in TYPES else ""
    if not value:
        what = {"file": "a file hash (MD5, SHA-1 or SHA-256)", "ip": "an IP address", "email": "an e-mail address"}
        raise ActionError("That is not " + what.get(wanted, f"a {wanted}"), retry=False)
    shared = read_settings(call.db)
    skipped: list[dict[str, str]] = []
    answers: list[tuple[str, str]] = []
    sources: list[dict[str, Any]] = []
    # Two rules, each asked once for all the sources: what a look-up never sends, which no playbook
    # loosens, then the data guard of this playbook.
    looked_up = kind in service.LOOKUP_TYPES
    why = service.blocked(call.db, kind, value, Allowlist(shared.get("iocAllowlist") or [])) if looked_up else None
    if not why and not call.dry_run:
        try:
            said, _decided = outbound.guarded(call, {"value": value})
            if said.get("value") != value:  # the node drops what is held, and the value is what is held
                why = "the data guard of the playbook holds the value back"
        except ActionError as error:
            why = error.message
    if why:
        skipped.append({"source": "reputation sources", "reason": why})
    elif looked_up:
        if not call.dry_run:
            skipped += [
                {"source": item["label"], "reason": item["reason"]}
                for item in service.check_now(call.db, kind, value, shared, playbook=call.playbook)["skipped"]
            ]
        for item in service.results(call.db, kind, value, service.config(shared)):
            if item.get("status") == "done":
                answers.append((item["provider"], item.get("verdict") or "unknown"))
                sources.append(
                    {
                        "source": item.get("label") or item["provider"],
                        "verdict": item.get("verdict") or "unknown",
                        "summary": item.get("summary") or "",
                    }
                )
            elif item.get("status") == "error":
                skipped.append({"source": item.get("label") or item["provider"], "reason": item.get("error") or ""})
    elif not call.dry_run:
        # An e-mail address has no page of its own and nothing is stored of it: the sources that judge
        # one are asked, and what they say is given to the playbook only.
        for source in lookup_sources.sources(call.db):
            if not source.on or not source.supports(kind):
                continue
            try:
                outputs = lookup_sources.ask(call.db, source, kind, value, playbook=call.playbook)
            except (lookup_sources.Unavailable, lookup_sources.Failed) as error:
                skipped.append({"source": source.label, "reason": error.message[:300]})
                continue
            verdict = lookup_sources.verdict_of(outputs)
            answers.append((source.id, verdict))
            sources.append(
                {"source": source.label, "verdict": verdict, "summary": str(outputs.get("summary") or "")[:500]}
            )
    summary = service.overall(answers, lookup_sources.weights(call.db)) or {}
    output = {
        "kind": kind,
        "value": value,
        "verdict": summary.get("verdict") or "",
        "score": summary.get("score"),
        "sources": sources,
        "skipped": skipped,
    }
    context: list[tuple[str, Any]] = []
    held = payloads.indicator_data(call.db, kind, value)[1]
    if summary:
        if kind in _ENTITY:
            entity, key = _ENTITY[kind]
            context.append((entity, {key: value, "Verdict": output["verdict"], "Score": output["score"]}))
        elif kind in ("md5", "sha1", "sha256"):
            context.append(("File", {kind.upper(): value, "Verdict": output["verdict"], "Score": output["score"]}))
    return Result(
        output=output,
        classes={"value": held, "verdict": ["verdict"], "score": ["verdict"], "kind": ["verdict"]},
        context=context,
        request={"would": f"look up {value}"} if call.dry_run else None,
    )


# --------------------------------------------------------------------------- #
# SLA timers                                                                  #
# --------------------------------------------------------------------------- #
TIMER_ARG = {
    "name": "timer",
    "type": "text",
    "required": True,
    "description": "The timer: time_to_assign, time_to_contain, time_to_close, or a timer field of your own",
}
TIMER_OUTPUTS = [
    {"name": "state", "type": "text", "description": "running, paused or stopped"},
    {"name": "elapsed_minutes", "type": "number", "description": "What it has counted so far"},
    {"name": "due_minutes", "type": "number", "description": "The time allowed, when there is one"},
    {"name": "breached", "type": "bool", "description": "Whether it is past its time"},
]


def _timer(call: Call, what: str) -> Result:
    from .. import timers

    name = str(call.args.get("timer") or "").strip()
    row = _incident(call, call.args.get("incident"))
    minutes = call.args.get("minutes")
    try:
        if call.dry_run:
            timers._known(call.db, name)
            return Result(output={"state": "dry-run"}, request={"would": f"{what} the timer {name}"})
        if what == "start":
            due = int(float(minutes)) * 60 if minutes not in (None, "") else None
            if due is not None and not 60 <= due <= timers.MINUTES_MAX * 60:
                raise ActionError("The time allowed is in minutes, from 1 to a year", retry=False)
            timers.start(
                call.db,
                row,
                name,
                call.now,
                due_s=due,
                business=bool(call.args.get("business_hours")) if call.args.get("business_hours") is not None else None,
                restart=bool(call.args.get("restart")),
            )
        else:
            timers.halt(call.db, row, name, call.now, state="paused" if what == "pause" else "stopped")
    except timers.TimerError as error:
        raise ActionError(error.message, retry=False) from None
    except (TypeError, ValueError):
        raise ActionError("The time allowed is a number of minutes", retry=False) from None
    shown = next((item for item in timers.of(call.db, row, call.now) if item["field"] == name), None)
    audit.record(call.db, ACTOR, f"timer.{what}", f"Timer {name}: {what}" + signature(call), row)
    if shown is None:
        return Result(output={"state": "idle", "elapsed_minutes": 0, "due_minutes": None, "breached": False})
    return Result(
        output={
            "state": shown["state"],
            "elapsed_minutes": shown["elapsedS"] // 60,
            "due_minutes": (shown["dueS"] // 60) if shown["dueS"] else None,
            "breached": shown["breached"],
        }
    )


@action(
    "timer.start",
    group="Nik",
    name="Start a timer",
    description="Start an SLA timer of an incident, or let it go on from where it was paused or stopped.",
    arguments=[
        INCIDENT_ARG,
        TIMER_ARG,
        {"name": "minutes", "type": "number", "description": "The time allowed; empty keeps what it has"},
        {"name": "business_hours", "type": "bool", "description": "Count only inside business hours"},
        {"name": "restart", "type": "bool", "description": "Count again from nothing"},
    ],
    outputs=TIMER_OUTPUTS,
)
def timer_start(call: Call) -> Result:
    return _timer(call, "start")


@action(
    "timer.pause",
    group="Nik",
    name="Pause a timer",
    description="Pause an SLA timer of an incident: it counts nothing until it is started again.",
    arguments=[INCIDENT_ARG, TIMER_ARG],
    outputs=TIMER_OUTPUTS,
)
def timer_pause(call: Call) -> Result:
    return _timer(call, "pause")


@action(
    "timer.stop",
    group="Nik",
    name="Stop a timer",
    description="Stop an SLA timer of an incident: what it timed is over.",
    arguments=[INCIDENT_ARG, TIMER_ARG],
    outputs=TIMER_OUTPUTS,
)
def timer_stop(call: Call) -> Result:
    return _timer(call, "stop")


# --------------------------------------------------------------------------- #
# Lists                                                                       #
# --------------------------------------------------------------------------- #
LIST_ARG = {"name": "list", "type": "text", "required": True, "description": "The name of the list"}


def _list_for_writing(call: Call, name: str):
    from .. import lists

    row = lists.find(call.db, name)
    if row is None:
        if lists.watch_list(call.db, name) is not None:
            raise ActionError("A list of the Indicators page is changed with the indicator nodes", retry=False)
        raise ActionError(f'There is no list called "{name}"', retry=False)
    if not row.writable_by_automation:
        raise ActionError(
            f'Playbooks may not write to the list "{name}": whoever manages lists can allow it', retry=False
        )
    return row


@action(
    "list.get",
    group="Nik",
    name="Read a list",
    description="What a list holds: its values, its keys with their values, or its document.",
    arguments=[LIST_ARG],
    outputs=[
        {"name": "items", "type": "any", "description": "A list of values, an object of key → value, or the document"},
        {"name": "count", "type": "number", "description": "How many items it holds"},
    ],
)
def list_get(call: Call) -> Result:
    from .. import lists

    name = str(call.args.get("list") or "").strip()
    try:
        held = lists.get(call.db, name)
    except lists.ListError as error:
        raise ActionError(error.message, retry=False) from None
    return Result(output={"items": held, "count": len(held) if isinstance(held, (list, dict)) else 1})


@action(
    "list.contains",
    group="Nik",
    name="Is it in a list?",
    description="Whether a value is in a list. A list of networks holds the addresses inside them.",
    arguments=[LIST_ARG, {"name": "value", "type": "text", "required": True, "description": "What to look for"}],
    outputs=[{"name": "found", "type": "bool", "description": "Whether the list holds it"}],
)
def list_contains(call: Call) -> Result:
    from .. import lists

    name = str(call.args.get("list") or "").strip()
    if lists.find(call.db, name) is None and lists.watch_list(call.db, name) is None:
        raise ActionError(f'There is no list called "{name}"', retry=False)
    return Result(output={"found": lists.contains(call.db, name, call.args.get("value"))})


@action(
    "list.add",
    group="Nik",
    name="Add to a list",
    description="Add a value to a list that playbooks may write to, or change the value of a key.",
    arguments=[
        LIST_ARG,
        {
            "name": "value",
            "type": "text",
            "required": True,
            "description": "The value to add (the key, in a key → value list)",
        },
        {"name": "data", "type": "any", "description": "What the key holds, in a key → value list"},
        {"name": "note", "type": "text", "description": "Why it is there"},
        {"name": "expires_minutes", "type": "number", "description": "Dropped after so long; empty to keep it"},
    ],
    outputs=[
        {"name": "added", "type": "bool", "description": "False when the list held it already"},
        {"name": "count", "type": "number", "description": "How many items the list holds now"},
    ],
)
def list_add(call: Call) -> Result:
    from .. import lists

    name = str(call.args.get("list") or "").strip()
    row = _list_for_writing(call, name)
    value = str(call.args.get("value") or "").strip()
    minutes = call.args.get("expires_minutes")
    try:
        expires = call.now + float(minutes) * 60 if minutes not in (None, "") else None
    except (TypeError, ValueError):
        raise ActionError("The time after which it is dropped is a number of minutes", retry=False) from None
    if call.dry_run:
        return Result(output={"added": False, "count": 0}, request={"would": f"add to the list {name}", "value": value})
    try:
        added = lists.add_item(
            call.db, row, value, call.args.get("data"), ACTOR, note=str(call.args.get("note") or ""), expires_at=expires
        )
    except lists.ListError as error:
        raise ActionError(error.message, retry=False) from None
    audit.record(
        call.db, ACTOR, "list.add", f'Added "{value[:80]}" to the list "{name}"' + signature(call), target=name
    )
    call.db.flush()
    return Result(output={"added": added, "count": len(lists.items(call.db, name))})


@action(
    "list.remove",
    group="Nik",
    name="Remove from a list",
    description="Remove a value from a list that playbooks may write to.",
    arguments=[LIST_ARG, {"name": "value", "type": "text", "required": True, "description": "The value (or the key)"}],
    outputs=[{"name": "removed", "type": "bool", "description": "False when the list did not hold it"}],
)
def list_remove(call: Call) -> Result:
    from .. import lists

    name = str(call.args.get("list") or "").strip()
    row = _list_for_writing(call, name)
    value = str(call.args.get("value") or "").strip()
    if call.dry_run:
        return Result(output={"removed": False}, request={"would": f"remove from the list {name}", "value": value})
    removed = lists.remove_item(call.db, row, value, ACTOR)
    if removed:
        audit.record(
            call.db,
            ACTOR,
            "list.remove",
            f'Removed "{value[:80]}" from the list "{name}"' + signature(call),
            target=name,
        )
    return Result(output={"removed": removed})


@action(
    "list.set",
    group="Nik",
    name="Set a list",
    description="Replace everything a list holds, when playbooks may write to it.",
    arguments=[
        LIST_ARG,
        {
            "name": "items",
            "type": "any",
            "required": True,
            "description": "The values, an object of key → value, or the document of a list that is one",
        },
    ],
    outputs=[{"name": "count", "type": "number", "description": "How many items the list holds now"}],
)
def list_set(call: Call) -> Result:
    from .. import lists

    name = str(call.args.get("list") or "").strip()
    row = _list_for_writing(call, name)
    wanted = call.args.get("items")
    if call.dry_run:
        return Result(output={"count": 0}, request={"would": f"set the list {name}"})
    try:
        count = lists.set_items(call.db, row, wanted, ACTOR)
    except lists.ListError as error:
        raise ActionError(error.message, retry=False) from None
    audit.record(call.db, ACTOR, "list.set", f'Set the list "{name}": {count} items' + signature(call), target=name)
    return Result(output={"count": count})


# --------------------------------------------------------------------------- #
# Scanning an address                                                         #
# --------------------------------------------------------------------------- #
SCAN_EVERY = 5  # seconds between two looks at a scan that is not finished
SCAN_WAIT = 300  # the five minutes after which the interface too calls a scan interrupted
SCAN_INDICATORS = 100


def _scan_output(row: UrlScan, scanned: bool, summary: str = "") -> dict[str, Any]:
    """What the node gives of a scan. Not scanned (a dry run, an address held back), every
    output is there all the same, empty, with ``summary`` saying why."""
    from .. import urlscan

    result = (row.result or {}) if scanned else {}
    final = str(result.get("finalUrl") or row.url)
    chain = result.get("chain") or []
    hops = max(0, len(chain) - 1)
    findings = [str(finding.get("text") or "") for finding in result.get("findings") or []]
    password = bool(result.get("passwordFields"))
    if scanned:
        parts = [f"{row.verdict or 'clean'} (score {row.score or 0}): {urlscan.display(final)}"]
        if final != row.url:
            through = f" through {hops} redirects" if hops > 1 else ""
            parts.append(f"reached from {urlscan.display(row.url)}{through}")
        if password:
            parts.append("asks for a password")
        if findings:
            parts.append(findings[0])
        summary = "; ".join(parts)[:500]
    indicators = [{"type": kind, "value": value} for kind, value in (urlscan.url_iocs(row) if scanned else [])]
    return {
        "scanned": scanned,
        "verdict": (row.verdict or "clean") if scanned else "",
        "score": int(row.score or 0) if scanned else 0,
        "url": row.url,
        "final_url": final,
        "redirected": final != row.url,
        "redirects": hops,
        "title": str(result.get("title") or ""),
        "password_form": password,
        "findings": findings,
        "indicators": indicators[:SCAN_INDICATORS],
        "scan": row.id,
        "artifact": f"url-{row.id}",
        "page": f"/artifact/url-{row.id}",
        "summary": summary,
    }


_SCAN_IDS = {"scan": ["nik_id"], "artifact": ["nik_id"], "page": ["nik_id"], "scanned": ["verdict"]}


def _scan_result(call: Call, row: UrlScan) -> Result:
    output = _scan_output(row, True)
    # The address keeps the classes it came in with, and the line that repeats it too; what the
    # scan says of it is a verdict.
    came_in = sorted(call.classes)
    return Result(
        output=output,
        classes={**_SCAN_IDS, "verdict": ["verdict"], "score": ["verdict"], "url": came_in, "summary": came_in},
        context=[("URL", {"Data": row.url, "Verdict": output["verdict"], "Score": output["score"]})],
        log=output["summary"],
    )


def _not_scanned(call: Call, url: str, why: str, request: dict) -> Result:
    from .. import urlscan

    row = call.db.get(UrlScan, urlscan.scan_id(url)) or UrlScan(id=urlscan.scan_id(url), url=url, result={})
    classes = {**_SCAN_IDS, "url": sorted(call.classes), "summary": ["verdict"]}
    return Result(output=_scan_output(row, False, why), classes=classes, request=request)


def _scan_started(row: UrlScan) -> float:
    from datetime import datetime

    try:
        started = str((row.result or {}).get("startedAt") or row.created_at)
        return datetime.fromisoformat(started.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 0.0


@action(
    "nik.scan-url",
    group="Nik",
    name="Scan an address",
    description=(
        "Visit an address with the isolated browser, as URL Analysis does, and wait for the verdict. "
        "Nothing is typed, clicked or submitted. The scan is kept as an artifact and put in the incident."
    ),
    arguments=[
        {
            "name": "url",
            "type": "text",
            "required": True,
            "description": "The address, http or https (defanged text is understood)",
        },
        INCIDENT_ARG,
        {
            "name": "again",
            "type": "bool",
            "default": False,
            "description": "Visit it again even when Nik holds a scan of it (off: the scan it holds is given)",
        },
    ],
    outputs=[
        {"name": "scanned", "type": "bool", "description": "The address was visited (false in a dry run)"},
        {"name": "verdict", "type": "text", "description": "phishing, suspicious or clean"},
        {"name": "score", "type": "number", "description": "0 to 100"},
        {"name": "url", "type": "text", "description": "The address, as Nik writes it"},
        {"name": "final_url", "type": "text", "description": "Where the browser ended"},
        {"name": "redirected", "type": "bool", "description": "It ended somewhere else than the address given"},
        {"name": "redirects", "type": "number", "description": "How many redirects led there"},
        {"name": "title", "type": "text", "description": "The title of the page"},
        {"name": "password_form", "type": "bool", "description": "The page asks for a password"},
        {"name": "findings", "type": "list", "description": "The reasons behind the verdict, the strongest first"},
        {"name": "indicators", "type": "list", "description": "What the scan found: [{type, value}], 100 at most"},
        {"name": "scan", "type": "text", "description": "The id of the scan"},
        {"name": "artifact", "type": "text", "description": "The scan as an artifact (url-…)"},
        {"name": "page", "type": "text", "description": "Its address in Nik"},
        {"name": "summary", "type": "text", "description": "The verdict and where the address led, in a line"},
    ],
)
def scan_url(call: Call) -> Result:
    import dataclasses

    from .. import urlscan, urlscan_queue
    from . import outbound

    state = call.state or {}
    if state:
        # Called again. The API process runs the scan (urlscan_queue.py): here it is only looked at.
        row = call.db.get(UrlScan, str(state.get("scan") or ""))
        if row is None:
            raise ActionError("The scan was deleted before it ended", retry=False)
        if row.status == "done":
            return _scan_result(call, row)
        if row.status == "error":
            message = row.error or "The scan failed"
            # Without the isolated browser trying again cannot help; a visit that failed may pass.
            raise ActionError(message, retry="BROWSER_URL" not in message)
        if call.now < float(state.get("until") or 0):
            return Result(again_at=call.now + SCAN_EVERY, state=state, log=f"The scan is {row.status}")
        raise ActionError(
            f"The scan did not end in {SCAN_WAIT // 60} minutes: see whether the server and the isolated "
            "browser answer (Settings → System → Workers)",
            retry=False,
        )

    try:
        url = urlscan.normalise(str(call.args.get("url") or ""))
    except urlscan.UrlError as error:
        raise ActionError(str(error), retry=False) from None
    # The address leaves Nik when the browser visits it, so the data guard decides: on the classes
    # the value came in with, on what it looks like, and on what Nik holds of it as an indicator
    # (allowlisted, TLP:RED). The hosts a playbook may reach are not asked: the visit is made by the
    # isolated browser, from its own network, and an address nobody listed is what the node is for.
    held = set(payloads.indicator_data(call.db, "url", url)[1]) - {"public_indicator"}
    judged = dataclasses.replace(call, classes=frozenset(call.classes) | frozenset(held))
    payload, decided = outbound.guarded(judged, {"url": url})
    if not payload.get("url"):
        # The node sends without what is held: nothing is left to visit.
        return _not_scanned(judged, url, "Not scanned: the data guard held the address back", {"held": decided})
    if call.dry_run:
        would = {"would": "scan the address", "url": urlscan.display(url), "held": decided}
        return _not_scanned(call, url, "Dry run: the address was not visited", would)

    incident = _incident(call, call.args.get("incident")) if _wanted(call, call.args.get("incident")) else None
    known = call.db.get(UrlScan, urlscan.scan_id(url)) is not None
    row = urlscan.register(call.db, url, ACTOR)
    if incident is not None:
        urlscan.attach(call.db, incident, row, ACTOR)
        triggers.incident_changed(call.db, incident, "incident.updated", ["data"])
    if row.status == "done" and not _truthy(call.args.get("again")):
        details = f"Scan of {urlscan.display(url)} (already known)" + signature(call)
        audit.record(call.db, ACTOR, "url.scan", details, incident, target=urlscan.display(url))
        return _scan_result(call, row)
    in_progress = known and row.status in ("queued", "running") and call.now - _scan_started(row) < SCAN_WAIT
    if not in_progress:
        # Not being scanned now (or left so by a restart): the API process is asked for a visit.
        cause = triggers.current_run.get()
        urlscan_queue.ask(call.db, row, ACTOR, call.run.id, cause[1] if cause else 0)
    details = f"Scan of {urlscan.display(url)}" + signature(call)
    audit.record(call.db, ACTOR, "url.scan", details, incident, target=urlscan.display(url))
    return Result(
        again_at=call.now + SCAN_EVERY,
        state={"scan": row.id, "until": call.now + SCAN_WAIT},
        request={"held": decided},
        log=f"Scanning {urlscan.display(url)}",
    )

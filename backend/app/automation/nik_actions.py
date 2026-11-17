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
from ..core.models import Artifact, Incident, IocList, IocListItem, Mail, Sample, UrlScan, User
from ..core.permissions import SYSTEM_USER
from ..core.security import now_iso
from ..iocs import TYPES, normalize
from . import egress, payloads, triggers
from .actions import ActionError, Call, Result, action

ACTOR = SYSTEM_USER
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
            role="analyst",
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


def _incident(call: Call, incident_id: Any) -> Incident:
    wanted = str(incident_id or call.run.incident_id or "")
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
    "description": "The incident's id; the incident of the run when left empty",
}
INCIDENT_OUT = [
    {"name": "incident", "type": "object", "description": "The incident: id, name, status, severity, assignee, url"}
]


# --------------------------------------------------------------------------- #
# Incidents                                                                   #
# --------------------------------------------------------------------------- #
@action(
    "nik.get-incident",
    group="Nik",
    name="Get an incident",
    description="Read an incident as it is now.",
    arguments=[INCIDENT_ARG],
    outputs=INCIDENT_OUT,
)
def get_incident(call: Call) -> Result:
    wanted = str(call.args.get("incident") or call.run.incident_id or "")
    row = call.db.get(Incident, wanted) if wanted else None
    if row is None:
        raise ActionError("The incident does not exist" if wanted else "No incident was given", retry=False)
    return _incident_result(row)


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
        wanted = str(call.args.get("incident") or call.run.incident_id or "")
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
    if call.dry_run:
        return Result(
            output={"incident": {"id": "dry-run", "name": title}},
            request={"would": "create an incident", "title": title},
        )
    now = now_iso()
    ticket = str(call.args.get("ticketId") or "").strip()[:80]
    doc = {
        "id": str(uuid.uuid4()),
        "ticketId": ticket,
        "title": title,
        "host": str(call.args.get("host") or "").strip()[:200],
        "username": str(call.args.get("username") or "").strip()[:200],
        "os": "",
        "severity": severity,
        "status": "open",
        "assignee": "",
        "name": " · ".join(part for part in (ticket, title) if part),
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
    description="Keep indicators in the IoC library, with tags and a note.",
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
        {"name": "lists", "type": "list", "description": "Each list: {id, name, description, watched, tlp, count}"},
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
        {"name": "before", "type": "list", "description": "The indicators as they were: [{type, value, verdict}]"},
        {"name": "after", "type": "list", "description": "The same indicators as they are now"},
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
        check = service.start_check(call.db, plan, target.name, ACTOR)
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
        "What is known of an address, a domain, a URL, a file hash or an e-mail address: Nik's own "
        "reputation sources and every connector command that looks that kind up, in one verdict."
    ),
    arguments=[
        {"name": "kind", "type": "choice", "choices": ["ip", "domain", "url", "file", "email"], "required": True},
        {"name": "value", "type": "text", "required": True, "description": "The indicator"},
    ],
    outputs=[
        {"name": "verdict", "type": "text", "description": "malicious, suspicious, harmless, unknown or empty"},
        {"name": "score", "type": "number", "description": "0 to 100"},
        {"name": "sources", "type": "list", "description": "Each source that answered: {source, verdict, summary}"},
        {"name": "skipped", "type": "list", "description": "The sources that were not asked, and why"},
    ],
    timeout=120,
)
def reputation(call: Call) -> Result:
    from ..core.models import Connector
    from ..enrichment import service
    from ..iocs import Allowlist
    from ..routers.settings import read_settings
    from . import connector_actions, outbound

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
    # Nik's own sources, under the rules that say what is never sent to them.
    why = service.blocked(call.db, kind, value, Allowlist(shared.get("iocAllowlist") or []))
    if why:
        skipped.append({"source": "reputation sources", "reason": why})
    elif not call.dry_run:
        skipped += [
            {"source": item["label"], "reason": item["reason"]}
            for item in service.check_now(call.db, kind, value, shared)["skipped"]
        ]
    for item in service.results(call.db, kind, value, service.config(shared)) if not why else []:
        if item.get("status") == "done":
            answers.append((item["provider"], item.get("verdict") or "unknown"))
            sources.append(
                {
                    "source": item.get("label") or item["provider"],
                    "verdict": item.get("verdict") or "unknown",
                    "summary": item.get("summary") or "",
                }
            )
    # The connectors that look this kind up, each on each of its connections.
    if not call.dry_run:
        for row in call.db.scalars(select(Connector).order_by(Connector.name)):
            connector = connector_actions.parsed(row)
            for command in connector.commands if connector is not None else []:
                if command.reputation != wanted or not command.arguments:
                    continue
                for connection in connector_actions.connections_of(call.db, row.id):
                    name = f"{connector.name} ({connection.name})"
                    try:
                        outbound.guarded(call, {"value": value})
                        runtime = connector_actions.runtime_for(call.db, connector, connection, call.playbook, call.now)
                        answer = runtime.run(command.name, {command.arguments[0].name: value})
                    except (ActionError, connector_actions.CommandError, egress.EgressError) as error:
                        skipped.append({"source": name, "reason": getattr(error, "message", str(error))[:300]})
                        continue
                    outputs = answer.outputs or {}
                    verdict = str(outputs.get("verdict") or "unknown").lower()
                    verdict = verdict if verdict in VERDICTS else "unknown"
                    answers.append((f"connector:{row.id}", verdict))
                    sources.append(
                        {"source": name, "verdict": verdict, "summary": str(outputs.get("summary") or "")[:500]}
                    )
    summary = service.overall(answers) or {}
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
# Artifacts                                                                   #
# --------------------------------------------------------------------------- #
@action(
    "nik.link-artifact",
    group="Nik",
    name="Link an artifact",
    description="Put an analysed file, e-mail or address in an incident.",
    arguments=[
        {
            "name": "artifact",
            "type": "text",
            "required": True,
            "description": "The artifact's id (file-…, mail-…, url-…)",
        },
        INCIDENT_ARG,
    ],
    outputs=[{"name": "linked", "type": "bool", "description": "It is in the incident"}],
)
def link_artifact(call: Call) -> Result:
    from .. import urlscan
    from ..routers import mails as mail_routes
    from ..routers import samples as sample_routes

    row = call.db.get(Artifact, str(call.args.get("artifact") or ""))
    if row is None:
        raise ActionError("The artifact does not exist", retry=False)
    if row.kind not in ("file", "mail", "url"):
        raise ActionError("Only a file, an e-mail or an address can be linked by a playbook", retry=False)
    if call.dry_run:
        return Result(output={"linked": False}, request={"would": "link the artifact", "artifact": row.id})
    incident = _incident(call, call.args.get("incident"))
    if row.kind == "file":
        sample_routes.attach_sample(call.db, incident, call.db.get(Sample, row.ref), row.name, ACTOR)
    elif row.kind == "mail":
        mail_routes.attach_mail(call.db, incident, call.db.get(Mail, row.ref), row.name, ACTOR)
    else:
        urlscan.attach(call.db, incident, call.db.get(UrlScan, row.ref), ACTOR)
    audit.record(
        call.db,
        ACTOR,
        "artifact.link",
        f"Linked {row.kind} {row.name or row.ref[:12]} to the incident" + signature(call),
        incident,
    )
    triggers.incident_changed(call.db, incident, "incident.updated", ["data"])
    return Result(output={"linked": True})

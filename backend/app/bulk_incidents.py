"""What can be done to many incidents at once (``bulk.py`` runs it).

Every action here is the single action, called once for each incident: the
field registry writes the fields (``fields.update``: its checks, the audit
entry, the event, the timers, who set the field last, the mirror), the route
of the delete deletes, a run is started as "Run a playbook…" starts it.

**Which fields can be set on many.** Any field the registry lets a person
write, except:

- ``name`` and ``ticket``: each incident has its own, and one value for many
  is a mistake, not a change;
- the tags (``labels``): setting them would replace what each incident holds;
  they have their own action, which adds and removes;
- fields of the types ``tags``, ``indicator``, ``list`` and ``json``: a value
  made of parts, edited part by part on the incident;
- timers, and what Nik writes itself (the registry refuses them anyway).

A field that is not of the type of an incident is refused for that incident,
with the sentence the registry gives; the others are set.
"""

from __future__ import annotations

import time
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from . import bulk, incident_tags, indicators_found, mirror
from . import fields as registry
from .core import audit
from .core.locking import lock_incident
from .core.models import Incident, Playbook, Run
from .core.permissions import AUTOMATION_RUN, WRITE
from .core.security import Principal
from .events import emit_detached

NOT_IN_BULK = ("name", "ticket", incident_tags.FIELD)
PARTS = ("tags", "indicator", "list", "json", "timer")
DIRECTIONS = ("in", "out", "both", "none")


def settable(db: OrmSession) -> list[dict[str, Any]]:
    """The fields a bulk action may set, as the screens list them."""
    out = []
    for name, field in registry.registry(db).items():
        spec = registry.SYSTEM_FIELDS.get(name) if field.system else None
        if field.applies_to != "incident" or name in NOT_IN_BULK or field.type in PARTS:
            continue
        if spec is not None and not spec.writable:
            continue
        out.append({"name": name, "label": field.label or name, "type": field.type, "options": field.options or {}})
    return out


def _resolve(db: OrmSession, caller: Principal, ids: list[str] | None, query: dict[str, Any] | None):
    from .routers.incidents import matching

    wanted = select(Incident.id, Incident.name, Incident.number)
    if ids is not None:
        found = {}
        for start in range(0, len(ids), 500):
            for row in db.execute(wanted.where(Incident.id.in_(ids[start : start + 500]))):
                found[row.id] = row
        # An id that names nothing stays an item: its result says that it was not found.
        return [(item, _called(found.get(item))) for item in ids]
    conditions = matching(db, caller, str((query or {}).get("q") or ""))
    rows = db.execute(wanted.where(*conditions).order_by(Incident.updated_at.desc())).all()
    return [(row.id, _called(row)) for row in rows]


def _called(row: Any) -> str:
    if row is None:
        return ""
    return f"#{row.number} {row.name}" if row.number else str(row.name or "")


def _locked(db: OrmSession, ref: str) -> Incident:
    row = lock_incident(db, ref)
    if row is None:
        raise bulk.Refused("There is no such incident any more")
    return row


def _told(db: OrmSession, row: Incident) -> None:
    """The webhooks hear of the change once it is committed, as after a single change."""
    emit_detached(db, "incident.updated", {"id": row.id, "name": row.name})


# --------------------------------------------------------------------------- #
# Fields                                                                      #
# --------------------------------------------------------------------------- #
def _clean_set(db: OrmSession, params: dict[str, Any], _caller: Principal) -> dict[str, Any]:
    changes = params.get("changes")
    if not isinstance(changes, dict) or not changes:
        raise bulk.BulkError("Say what to set: changes is a value for each field", 422)
    allowed = {item["name"] for item in settable(db)}
    for name in changes:
        if name in NOT_IN_BULK:
            raise bulk.BulkError(f'"{name}" is not set on many incidents at once', 422)
        if name not in allowed and name not in ("close_reason", "close_notes"):
            raise bulk.BulkError(f'"{name}" is not a field that can be set on many incidents at once', 422)
    return {"changes": changes}


def _said(value: Any) -> str:
    return "empty" if value in (None, "", []) else str(value)[:60]


def _describe_set(params: dict[str, Any]) -> str:
    changes = params.get("changes") or {}
    if changes.get("status") == "closed":
        return "Close"
    shown = [f"{name} to {_said(value)}" for name, value in changes.items()]
    return "Set " + ", ".join(shown)


def _set(db: OrmSession, ref: str, params: dict[str, Any], caller: Principal) -> str:
    row = _locked(db, ref)
    try:
        changed = registry.update(db, row, params["changes"], caller.actor, f"user:{caller.actor}")
    except registry.FieldError as error:
        raise bulk.Refused(error.message) from None
    if not changed:
        raise bulk.Skipped("It was so already")
    _told(db, row)
    return ""


def mirrored_out(db: OrmSession, refs: list[str]) -> int:
    """How many of these incidents are mirrored towards another system."""
    count = 0
    for start in range(0, len(refs), 500):
        for held in db.scalars(select(Incident.mirror).where(Incident.id.in_(refs[start : start + 500]))):
            if isinstance(held, dict) and held.get("connection") and held.get("direction") in ("out", "both"):
                count += 1
    return count


def _plan_set(db: OrmSession, refs: list[str], params: dict[str, Any], _caller: Principal) -> dict[str, Any]:
    notes = []
    out = mirrored_out(db, refs)
    if out:
        are = "is mirrored" if out == 1 else "are mirrored"
        notes.append(f"{out} of these {are} Out: their tickets will be updated, one update for each")
    if params["changes"].get("status") == "closed":
        notes.append(
            "An incident whose type wants a field filled to close, or another reason, is refused and stays open"
        )
    return {"notes": notes}


# --------------------------------------------------------------------------- #
# Tags                                                                        #
# --------------------------------------------------------------------------- #
def clean_tags(params: dict[str, Any], rule=incident_tags.clean_tag) -> dict[str, Any]:
    """``{add, remove}`` of a tags action, each tag as its list writes it. Raises ``BulkError``."""
    out: dict[str, list[str]] = {}
    for key in ("add", "remove"):
        given = params.get(key) or []
        if not isinstance(given, list) or len(given) > incident_tags.TAGS_MAX:
            raise bulk.BulkError(f"{key} is a list of at most {incident_tags.TAGS_MAX} tags", 422)
        tags = []
        for raw in given:
            try:
                tag = rule(raw)
            except registry.FieldError:
                tag = ""
            if not tag:
                raise bulk.BulkError(f'"{str(raw)[:40]}" is not a tag. {incident_tags.RULE}', 422)
            if tag not in tags:
                tags.append(tag)
        out[key] = tags
    if not out["add"] and not out["remove"]:
        raise bulk.BulkError("Say which tags to add or to remove", 422)
    return out


def describe_tags(params: dict[str, Any]) -> str:
    said = []
    if params.get("add"):
        said.append("Add the tags " + ", ".join(params["add"]))
    if params.get("remove"):
        said.append(("remove " if said else "Remove the tags ") + ", ".join(params["remove"]))
    return ", ".join(said)


def _tags(db: OrmSession, ref: str, params: dict[str, Any], caller: Principal) -> str:
    row = _locked(db, ref)
    held = incident_tags.of(row)
    gone = {tag.lower() for tag in params["remove"]}
    wanted = [tag for tag in held if tag.lower() not in gone]
    wanted += [tag for tag in params["add"] if tag.lower() not in {kept.lower() for kept in wanted}]
    if wanted == held:
        raise bulk.Skipped("It was so already")
    if len(wanted) > incident_tags.TAGS_MAX:
        raise bulk.Refused(f"An incident holds {incident_tags.TAGS_MAX} tags at most")
    try:
        registry.update(db, row, {incident_tags.FIELD: wanted}, caller.actor, f"user:{caller.actor}")
    except registry.FieldError as error:
        raise bulk.Refused(error.message) from None
    _told(db, row)
    return ""


# --------------------------------------------------------------------------- #
# Delete                                                                      #
# --------------------------------------------------------------------------- #
def _delete(db: OrmSession, ref: str, _params: dict[str, Any], caller: Principal) -> str:
    from .routers.incidents import remove_incident

    row = lock_incident(db, ref)
    if row is None:
        raise bulk.Skipped("It was deleted already")
    name = remove_incident(db, row, caller.actor)
    emit_detached(db, "incident.deleted", {"id": ref, "name": name})
    return ""


# --------------------------------------------------------------------------- #
# A playbook on each                                                          #
# --------------------------------------------------------------------------- #
def _clean_playbook(db: OrmSession, params: dict[str, Any], _caller: Principal) -> dict[str, Any]:
    from .automation import triggers

    row = db.get(Playbook, str(params.get("playbook") or ""))
    if row is None:
        raise bulk.BulkError("There is no such playbook", 404)
    config = triggers.trigger_config(db, row) if row.current_version else {}
    if not config.get("manual"):
        raise bulk.BulkError("This playbook is not meant to be run by hand", 400)
    wrong = triggers.manual_problem(config, "incident")
    if wrong:
        raise bulk.BulkError(wrong, 400)
    return {"playbook": row.id, "name": row.name}


def _unfinished(db: OrmSession) -> int:
    from .automation import engine

    started = db.info.get("bulk_runs") or []
    if not started:
        return 0
    finished = set(db.scalars(select(Run.id).where(Run.id.in_(started), Run.status.in_(engine.FINISHED))))
    started[:] = [run for run in started if run not in finished]
    return len(started)


def runs_ahead(db: OrmSession) -> bool:
    """Whether the job has as many runs unfinished as it may have at a time."""
    return _unfinished(db) >= bulk.RUNS_AHEAD


def _playbook(db: OrmSession, ref: str, params: dict[str, Any], caller: Principal) -> str:
    from .routers.automation import start_by_hand

    row = db.get(Playbook, params["playbook"])
    if row is None:
        raise bulk.Refused("The playbook is not there any more")
    run = start_by_hand(db, row, "incident", ref, caller.actor)
    db.info.setdefault("bulk_runs", []).append(run.id)
    return f"Run {run.id} started"


def _plan_playbook(db: OrmSession, refs: list[str], params: dict[str, Any], _caller: Principal) -> dict[str, Any]:
    row = db.get(Playbook, params["playbook"])
    hourly = (row.max_runs_per_hour or 60) if row is not None else 60
    notes = [f"The runs are started {bulk.RUNS_AHEAD} at a time at most: the next ones wait for those to end"]
    if len(refs) > hourly:
        notes.append(
            f"This playbook starts {hourly} runs an hour at most: the incidents past that are refused, and can be "
            "tried again later"
        )
    return {"notes": notes}


# --------------------------------------------------------------------------- #
# Mirroring                                                                   #
# --------------------------------------------------------------------------- #
def _clean_mirror(_db: OrmSession, params: dict[str, Any], caller: Principal) -> dict[str, Any]:
    direction = str(params.get("direction") or "")
    if direction not in DIRECTIONS:
        raise bulk.BulkError("The direction is one of: " + ", ".join(DIRECTIONS), 422)
    if direction in ("out", "both") and not caller.has(AUTOMATION_RUN):
        raise bulk.BulkError("Sending to another system needs the permission to run playbooks", 403)
    return {"direction": direction}


def _describe_mirror(params: dict[str, Any]) -> str:
    words = {"in": "In", "out": "Out", "both": "In-out", "none": "None (stop mirroring)"}
    return f"Set mirroring to {words[params['direction']]}"


def _mirror(db: OrmSession, ref: str, params: dict[str, Any], caller: Principal) -> str:
    row = _locked(db, ref)
    state = mirror.state_of(row)
    if state is None:
        raise bulk.Skipped("It is not mirrored")
    direction = params["direction"]
    if direction == "none":
        mirror.stop(db, row, caller.actor)
        return ""
    if state.get("direction") == direction:
        raise bulk.Skipped("It was so already")
    if direction != "in" and not caller.has(AUTOMATION_RUN):
        raise bulk.Refused("Sending to another system needs the permission to run playbooks")
    try:
        mirror.redirect(db, row, direction, caller.actor, time.time())
    except mirror.MirrorError as error:
        raise bulk.Refused(error.message) from None
    return ""


def _plan_mirror(db: OrmSession, refs: list[str], _params: dict[str, Any], _caller: Principal) -> dict[str, Any]:
    count = 0
    for start in range(0, len(refs), 500):
        for held in db.scalars(select(Incident.mirror).where(Incident.id.in_(refs[start : start + 500]))):
            count += bool(isinstance(held, dict) and held.get("connection") and held.get("id"))
    return {"applies": count}


# --------------------------------------------------------------------------- #
# Indicators                                                                  #
# --------------------------------------------------------------------------- #
def _find(db: OrmSession, ref: str, _params: dict[str, Any], caller: Principal) -> str:
    row = _locked(db, ref)
    summary = indicators_found.scan(db, row, "asked", asked=True) or {}
    audit.record(db, caller.actor, "ioc.found_scan", "Asked for the incident to be read for indicators", row)
    if summary.get("new"):
        _told(db, row)
    return f"{summary.get('new', 0)} new"


LIST = bulk.register(bulk.Listing("incidents", ("incident", "incidents"), _resolve))
LIST.add(
    bulk.Action(
        "set",
        "Set fields",
        WRITE,
        apply=_set,
        clean=_clean_set,
        describe=_describe_set,
        plan=_plan_set,
        grave=lambda params: params.get("changes", {}).get("status") == "closed",
        events=True,
        verb="close",
    )
)
LIST.add(
    bulk.Action(
        "tags", "Change the tags", WRITE, apply=_tags, clean=lambda _db, p, _c: clean_tags(p), describe=describe_tags,
        events=True,
    )
)  # fmt: skip
LIST.add(bulk.Action("delete", "Delete", WRITE, apply=_delete, destructive=True, verb="delete"))
LIST.add(
    bulk.Action(
        "playbook",
        "Run a playbook on each",
        AUTOMATION_RUN,
        apply=_playbook,
        clean=_clean_playbook,
        describe=lambda params: f'Run the playbook "{params.get("name", "")}" on each',
        plan=_plan_playbook,
        events=True,
        crowded=runs_ahead,
    )
)
LIST.add(
    bulk.Action(
        "mirror", "Change mirroring", WRITE, apply=_mirror, clean=_clean_mirror, describe=_describe_mirror,
        plan=_plan_mirror,
    )
)  # fmt: skip
LIST.add(bulk.Action("find_indicators", "Find indicators now", WRITE, apply=_find, events=True))

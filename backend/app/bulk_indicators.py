"""What can be done to many indicators at once (``bulk.py`` runs it).

An indicator is named ``type:value`` (``domain:evil.example``), as it is
where a playbook runs on one. A selection is the indicators named, or what
the Indicators page shows for a filter, a list or an incident.

Each action is the single action, called once for each indicator: what the
dialog of an indicator saves (its tags, its TLP), its place in a list, the ×
of an indicator found by itself in an incident (remembered, so it is not
found again), its removal from the library, the allowlist.

**Checking** is the exception that is not one: a check of many indicators was
always one queue, worked through by the look-ups within the quota of each
source and behind the data guard (``enrichment/service.py``). A bulk check
puts the selection in that queue, once; the plan says how many requests it
costs each source before anything is asked.

Nothing here watches an indicator: a watch is of a list. Indicators are
watched by adding them to a list that is.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session as OrmSession

from . import bulk, indicators_found, lists
from . import ioc_library as lib
from .bulk_incidents import clean_tags, describe_tags
from .core import audit
from .core.clock import now_iso
from .core.locking import lock_incident
from .core.models import Incident, IocEntry, IocList, IocListItem, IocRecord
from .core.permissions import WRITE
from .core.security import Principal
from .iocs import TYPES, Allowlist, normalize

FILTER_KEYS = ("q", "type", "verdict", "origin", "analysis", "list", "expired")


def ref_of(kind: str, value: str) -> str:
    return f"{kind}:{value}"


def pair_of(ref: str) -> tuple[str, str]:
    """The indicator a ref names. Raises ``Refused`` for what is not one."""
    kind, _, value = str(ref).partition(":")
    clean = normalize(kind, value) if kind in TYPES else None
    if clean is None:
        raise bulk.Refused("This is not an indicator")
    return kind, clean


def _resolve(db: OrmSession, _caller: Principal, ids: list[str] | None, query: dict[str, Any] | None):
    from .routers.settings import read_settings

    if ids is not None:
        return [(item, "") for item in ids]
    query = query or {}
    shared = read_settings(db)
    incident = str(query.get("incident") or "")
    if incident:
        if db.get(Incident, incident) is None:
            raise bulk.BulkError("There is no such incident", 404)
        pairs = set(db.execute(select(IocEntry.type, IocEntry.value).where(IocEntry.incident_id == incident)).tuples())
        rows = lib.library(db, shared, only=pairs)
    else:
        rows = lib.library(db, shared)
    filters = {key: query.get(key) for key in FILTER_KEYS if query.get(key) not in (None, "")}
    return [(ref_of(row["type"], row["value"]), "") for row in lib.select_rows(rows, filters)]


def _known(db: OrmSession, pair: tuple[str, str]) -> None:
    if not lib.known_pairs(db, [pair]):
        raise bulk.Refused("It is not in the library any more")


# --------------------------------------------------------------------------- #
# What an analyst says of an indicator                                        #
# --------------------------------------------------------------------------- #
def _edit(db: OrmSession, pair: tuple[str, str], caller: Principal, **values: Any) -> None:
    from .routers.ioc_library import EditIn, edit

    edit(db, EditIn(type=pair[0], value=pair[1], **values), caller)


def _tags(db: OrmSession, ref: str, params: dict[str, Any], caller: Principal) -> str:
    pair = pair_of(ref)
    record = db.get(IocRecord, pair)
    held = list(record.tags or []) if record is not None else []
    wanted = [tag for tag in held if tag not in params["remove"]]
    wanted += [tag for tag in params["add"] if tag not in wanted]
    if wanted == held:
        raise bulk.Skipped("It was so already")
    if len(wanted) > lib.TAGS_MAX:
        raise bulk.Refused(f"An indicator holds {lib.TAGS_MAX} tags at most")
    _edit(db, pair, caller, tags=wanted)
    return ""


def _clean_tlp(_db: OrmSession, params: dict[str, Any], _caller: Principal) -> dict[str, Any]:
    tlp = str(params.get("tlp") or "")
    if tlp not in lib.TLPS:
        raise bulk.BulkError("The TLP is one of: " + ", ".join(lib.TLPS), 422)
    return {"tlp": tlp}


def _tlp(db: OrmSession, ref: str, params: dict[str, Any], caller: Principal) -> str:
    pair = pair_of(ref)
    record = db.get(IocRecord, pair)
    if record is not None and record.tlp == params["tlp"]:
        raise bulk.Skipped("It was so already")
    _edit(db, pair, caller, tlp=params["tlp"])
    return ""


# --------------------------------------------------------------------------- #
# Lists                                                                       #
# --------------------------------------------------------------------------- #
def _clean_list(db: OrmSession, params: dict[str, Any], _caller: Principal) -> dict[str, Any]:
    row = db.get(IocList, str(params.get("list") or ""))
    if row is None:
        raise bulk.BulkError("There is no such list", 404)
    return {"list": row.id, "name": row.name}


def _target(db: OrmSession, params: dict[str, Any]) -> IocList:
    row = db.get(IocList, params["list"])
    if row is None:
        raise bulk.Refused("The list is not there any more")
    return row


def _list_add(db: OrmSession, ref: str, params: dict[str, Any], caller: Principal) -> str:
    pair = pair_of(ref)
    target = _target(db, params)
    if not lib.add_to_list(db, target, [pair], caller.actor, now_iso()):
        raise bulk.Skipped("It was in the list already")
    audit.record(
        db,
        caller.actor,
        "ioc.list_add",
        f'Added {pair[0]} {pair[1][:200]} to the list "{target.name}"',
        target=target.name,
    )
    return ""


def _list_remove(db: OrmSession, ref: str, params: dict[str, Any], caller: Principal) -> str:
    pair = pair_of(ref)
    target = _target(db, params)
    gone = db.execute(
        delete(IocListItem).where(
            IocListItem.list_id == target.id, IocListItem.type == pair[0], IocListItem.value == pair[1]
        )
    ).rowcount
    if not gone:
        raise bulk.Skipped("It is not in the list")
    target.updated_at = now_iso()
    audit.record(
        db,
        caller.actor,
        "ioc.list_remove",
        f'Took {pair[0]} {pair[1][:200]} out of the list "{target.name}"',
        target=target.name,
    )
    return ""


# --------------------------------------------------------------------------- #
# The allowlist                                                               #
# --------------------------------------------------------------------------- #
def _allowlist(db: OrmSession, ref: str, _params: dict[str, Any], caller: Principal) -> str:
    from .routers.settings import read_settings

    kind, value = pair_of(ref)
    held = read_settings(db).get("iocAllowlist") or []
    if Allowlist(held).matches(kind, value):
        raise bulk.Skipped("The allowlist holds it already")
    row = lists.find(db, lists.pointers_of(db)["iocAllowlist"])
    try:
        if row is None:
            # The list is not there yet (a database older than the lists): made as saving the setting makes it.
            lists.apply_setting(db, "iocAllowlist", [*held, value], caller.actor)
        else:
            lists.add_item(db, row, value, actor=caller.actor, note=f"added in bulk by {caller.actor}")
    except lists.ListError as error:
        raise bulk.Refused(error.message) from None
    audit.record(db, caller.actor, "ioc.allowlist", f"Added {kind} {value[:200]} to the allowlist", target=value[:200])
    return ""


# --------------------------------------------------------------------------- #
# Out of an incident, out of the library                                      #
# --------------------------------------------------------------------------- #
def _clean_incident(db: OrmSession, params: dict[str, Any], _caller: Principal) -> dict[str, Any]:
    row = db.get(Incident, str(params.get("incident") or ""))
    if row is None:
        raise bulk.BulkError("There is no such incident", 404)
    return {"incident": row.id, "name": row.name}


def _incident_remove(db: OrmSession, ref: str, params: dict[str, Any], caller: Principal) -> str:
    kind, value = pair_of(ref)
    incident = lock_incident(db, params["incident"])
    if incident is None:
        raise bulk.Refused("The incident is not there any more")
    entry = db.get(IocEntry, (incident.id, kind, value))
    if entry is None:
        raise bulk.Skipped("The incident does not hold it")
    if not indicators_found.only_found(entry.sources):
        raise bulk.Skipped("It is in the evidence of the incident: only one found by itself can be removed")
    if not indicators_found.remove(db, incident, kind, value, caller.actor):
        raise bulk.Skipped("It was removed already")
    return ""


def _plan_incident_remove(
    db: OrmSession, refs: list[str], params: dict[str, Any], _caller: Principal
) -> dict[str, Any]:
    wanted = set(refs)
    rows = db.execute(
        select(IocEntry.type, IocEntry.value, IocEntry.sources).where(IocEntry.incident_id == params["incident"])
    )
    count = sum(
        1 for kind, value, sources in rows if ref_of(kind, value) in wanted and indicators_found.only_found(sources)
    )
    return {
        "applies": count,
        "notes": ["Only what was found by itself is removed, and it is not found again in this incident"],
    }


def _delete(db: OrmSession, ref: str, _params: dict[str, Any], caller: Principal) -> str:
    from . import analysis_links
    from .routers.ioc_library import forget

    kind, value = pair_of(ref)
    in_incidents = (
        db.scalar(select(func.count()).select_from(IocEntry).where(IocEntry.type == kind, IocEntry.value == value)) or 0
    )
    in_lists = db.scalar(
        select(func.count()).select_from(IocListItem).where(IocListItem.type == kind, IocListItem.value == value)
    )
    if db.get(IocRecord, (kind, value)) is None and not in_lists:
        raise bulk.Skipped(
            "An incident holds it: it stays, as part of that incident" if in_incidents else "It was removed already"
        )
    row = {
        "type": kind,
        "value": value,
        "incidents": in_incidents,
        "artifacts": analysis_links.standalone(db).get((kind, value)) or [],
    }
    gone = forget(db, row)
    audit.record(db, caller.actor, "ioc.remove", f"Removed the indicator {kind} {value[:200]}", target=value[:200])
    return "" if gone else "Its record and its lists are gone; an incident or an artifact still holds it"


# --------------------------------------------------------------------------- #
# Checking: one queue for the whole selection                                 #
# --------------------------------------------------------------------------- #
def _check_plan(
    db: OrmSession, refs: list[str], params: dict[str, Any]
) -> tuple[dict[str, Any], list[tuple[str, str]]]:
    from .enrichment import service
    from .routers.settings import read_settings

    pairs = []
    for ref in refs:
        try:
            pairs.append(pair_of(ref))
        except bulk.Refused:
            continue
    return service.plan_check(db, pairs, read_settings(db), force=bool(params.get("force"))), pairs


def _plan_check(db: OrmSession, refs: list[str], params: dict[str, Any], _caller: Principal) -> dict[str, Any]:
    from .enrichment import service

    if len(refs) > service.MAX_CHECK_ITEMS:
        return {"applies": 0, "notes": [f"At most {service.MAX_CHECK_ITEMS} indicators in one check"]}
    plan, _pairs = _check_plan(db, refs, params)
    notes = []
    for source in plan["sources"]:
        line = f"{source['label']}: {source['needed']} request{'' if source['needed'] == 1 else 's'}"
        if source["leftToday"] is not None:
            line += f", {source['leftToday']} left today"
        if source["later"]:
            line += f" ({source['later']} wait for tomorrow's quota)"
        notes.append(line)
    if plan["reused"]:
        notes.append(f"{plan['reused']} have a fresh answer already: not asked again")
    if plan["neverSent"]:
        notes.append(f"{plan['neverSent']} are never sent to the sources")
    if plan["held"]:
        notes.append(service.held_note(plan["held"]))
    return {"applies": plan["toAsk"], "notes": notes}


def _check(db: OrmSession, job: Any, refs: list[str], caller: Principal) -> dict[str, tuple[str, str]]:
    from .enrichment import service

    if len(refs) > service.MAX_CHECK_ITEMS:
        return dict.fromkeys(refs, ("refused", f"At most {service.MAX_CHECK_ITEMS} indicators in one check"))
    plan, _pairs = _check_plan(db, refs, job.params or {})
    asked = {ref_of(kind, value) for kind, value, _sources in plan["pending"]}
    check = service.start_check(db, plan, job.label, caller.actor)
    audit.record(db, caller.actor, "ioc.check", f"Bulk check of {plan['toAsk']} indicator(s)", target=job.label[:200])
    queued = f"In the queue of the check {check.id}"
    results: dict[str, tuple[str, str]] = {}
    for ref in refs:
        try:
            clean = ref_of(*pair_of(ref))
        except bulk.Refused as said:
            results[ref] = ("refused", str(said))
            continue
        results[ref] = (
            ("done", queued)
            if clean in asked
            else ("skipped", "Not asked: a fresh answer is there, or it is never sent, or the data guard holds it")
        )
    return results


LIST = bulk.register(bulk.Listing("indicators", ("indicator", "indicators"), _resolve))
LIST.add(
    bulk.Action(
        "check",
        "Check now",
        WRITE,
        whole=_check,
        clean=lambda _db, params, _caller: {"force": bool(params.get("force"))},
        plan=_plan_check,
    )
)
LIST.add(
    bulk.Action(
        "tags",
        "Change the tags",
        WRITE,
        apply=_tags,
        clean=lambda _db, params, _caller: clean_tags(params, lambda raw: (lib.clean_tags([raw]) or [""])[0]),
        describe=describe_tags,
    )
)
LIST.add(
    bulk.Action(
        "tlp",
        "Set the TLP",
        WRITE,
        apply=_tlp,
        clean=_clean_tlp,
        describe=lambda params: f"Set the TLP to {params['tlp']}",
    )
)
LIST.add(
    bulk.Action(
        "list_add",
        "Add to a list",
        WRITE,
        apply=_list_add,
        clean=_clean_list,
        describe=lambda params: f'Add to the list "{params.get("name", "")}"',
    )
)
LIST.add(
    bulk.Action(
        "list_remove",
        "Take out of a list",
        WRITE,
        apply=_list_remove,
        clean=_clean_list,
        describe=lambda params: f'Take out of the list "{params.get("name", "")}"',
    )
)
LIST.add(bulk.Action("allowlist", "Add to the allowlist", WRITE, apply=_allowlist))
LIST.add(
    bulk.Action(
        "incident_remove",
        "Remove from the incident",
        WRITE,
        apply=_incident_remove,
        clean=_clean_incident,
        describe=lambda params: f'Remove from the incident "{params.get("name", "")}"',
        plan=_plan_incident_remove,
    )
)
LIST.add(bulk.Action("delete", "Remove from the library", WRITE, apply=_delete, destructive=True, verb="remove"))

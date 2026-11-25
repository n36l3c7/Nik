"""Sigma rules: the detection rules host evidence is read against (7.0).

A rule is one YAML document. Nik ships a few (the pack ``nik``), a content pack may carry thousands
(SigmaHQ's), and rules can be written here. **The forensics worker judges every text**: it says whether it
is a rule, whether Nik can run it and why not, and with which version of its evaluator; a text it
refuses is not saved, and the answer says which line is wrong. A rule is run on a file when it is enabled
and supported, at the time the file is read; the detections of a file already read change only when the
file is read again ("Analyse again").

Readers list; changing rules needs ``rules.manage``. Switching a rule on or off, in bulk or one at a time,
is a change too. A rule of a pack is switched off, not deleted; written over, it keeps the text of the pack
for Reset. The level of a rule is 1 (informational) to 5 (critical).
"""

from __future__ import annotations

import threading
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as OrmSession

from ..core import audit
from ..core.db import get_db
from ..core.permissions import READ
from ..core.security import Principal, rules_principal, rules_reader_principal
from ..sigma import manage, recheck, rules, trying, worker

router = APIRouter(prefix="/sigma/rules", tags=["sigma-rules"])

LIMIT_MAX = 500
IDS_MAX = 20_000


class RuleIn(BaseModel):
    """The YAML of a rule. ``enabled`` left out: on when Nik can run it."""

    source: str = Field(max_length=manage.SOURCE_MAX)
    enabled: bool | None = None


class TextIn(BaseModel):
    """The YAML of a rule, to be read and not saved."""

    source: str = Field(max_length=manage.SOURCE_MAX)


class TryIn(BaseModel):
    """The YAML of a rule and the incident to run it on. ``kind`` (a section: eventlog, endpoint, browser,
    commands) or ``sourceId`` (one file) narrow the records."""

    source: str = Field(max_length=manage.SOURCE_MAX)
    incidentId: str = Field(min_length=1, max_length=200)
    kind: str = Field(default="", max_length=16)
    sourceId: str = Field(default="", max_length=32)


class EnabledIn(BaseModel):
    enabled: bool


class FiltersIn(BaseModel):
    """The filters of the list of rules, as ``GET /sigma/rules`` takes them."""

    q: str = Field(default="", max_length=200)
    pack: str = Field(default="", max_length=80)
    level: int | None = Field(default=None, ge=1, le=5)
    status: str = Field(default="", max_length=14)
    enabled: bool | None = None
    supported: bool | None = None
    product: str = Field(default="", max_length=40)
    category: str = Field(default="", max_length=60)
    service: str = Field(default="", max_length=60)
    kind: str = Field(default="", max_length=12)


class BulkIn(BaseModel):
    """Switch many rules on or off: those of ``ids``, or those a filter keeps (one of the two). Switching
    on leaves out the rules Nik cannot run."""

    enabled: bool
    ids: list[str] | None = Field(default=None, max_length=IDS_MAX)
    filters: FiltersIn | None = None


def _filters(
    q: str = Query(
        default="",
        max_length=200,
        description="Words of the title, the id, the name or the author.",
    ),
    pack: str = Query(
        default="",
        max_length=80,
        description="A pack id, ``nik``, or ``-`` for the rules written here.",
    ),
    level: int | None = Query(default=None, ge=1, le=5, description="The lowest level."),
    status: str = Query(default="", max_length=14, description="stable, test, experimental, deprecated…"),
    enabled: bool | None = None,
    supported: bool | None = None,
    product: str = Query(default="", max_length=40),
    category: str = Query(default="", max_length=60),
    service: str = Query(default="", max_length=60),
    kind: str = Query(default="", max_length=12, description="rule or correlation."),
) -> dict[str, Any]:
    return {
        "q": q,
        "pack": pack,
        "level": level,
        "status": status,
        "enabled": enabled,
        "supported": supported,
        "product": product,
        "category": category,
        "service": service,
        "kind": kind,
    }


def _shown(row: Any) -> dict[str, Any]:
    return rules.out(row, whole=True)


@router.get("")
def list_rules(
    f: dict[str, Any] = Depends(_filters),
    limit: int = Query(default=100, ge=1, le=LIMIT_MAX),
    offset: int = Query(default=0, ge=0),
    order: str = Query(default="title", max_length=10, description="title, level, -level or -updated."),
    _caller: Principal = Depends(rules_reader_principal),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    """The rules, without their text: ``{rules, total, limit, offset}``. Each has ``id``, ``name``, ``title``,
    ``author``, ``kind``, ``level`` (1 to 5) and ``levelName``, ``status``, ``product``, ``category``, ``service``,
    ``tags``, ``enabled``, ``supported`` with its ``reason``, ``checked`` (false: the worker has not read it yet),
    ``pack`` (empty: written here), ``edited`` (a rule of a pack that was changed) and who wrote it when."""
    return rules.listing(db, f, limit, offset, order)


@router.get("/summary")
def get_summary(
    _caller: Principal = Depends(rules_reader_principal),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    """What the screen shows above the list: ``total``, ``enabled``, ``supported``, ``unchecked``, ``byLevel``,
    ``products``, the ``packs`` the rules come from (with their counts) and whether the worker is there
    (``workerConfigured``, ``engine``: the version of its evaluator)."""
    answer = rules.summary(db)
    answer["workerConfigured"] = worker.configured()
    return answer


@router.post("/validate")
def validate_rule(
    body: TextIn,
    _caller: Principal = Depends(rules_principal),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    """Have the worker read a text without saving it: ``{ok, engine, errors, rules}``. ``errors`` are
    ``{line, column, message}``; each of ``rules`` says what the worker made of it (``supported``, ``reason``,
    ``line`` where the document begins) and whether a rule with this id is here already (``exists``)."""
    return manage.validate(db, body.source)


@router.post("/try")
def try_rule(
    body: TryIn,
    caller: Principal = Depends(rules_principal),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    """Run a text of rules over the records of an incident, saving nothing. The records are taken in time
    order, 20,000 at a time, up to 200,000 records or 60 seconds: ``cut`` says the run stopped before the
    end (``cutReason``: ``records`` or ``time``). Answers ``scanned``, ``matchCount`` and ``matches`` (at most
    1,000: the rule, the record's id, key, time and summary, and for a correlation the keys of its records),
    the rules that were not run (``notEvaluated``, ``rules[].supported``) and ``notes``. Needs the permission
    to read incidents."""
    if not caller.has(READ):
        raise HTTPException(
            status_code=403,
            detail="Trying a rule reads an incident: it needs the permission to read",
        )
    return trying.run(db, body.incidentId, body.source, {"kind": body.kind, "sourceId": body.sourceId})


@router.post("/bulk")
def switch_rules(
    body: BulkIn,
    caller: Principal = Depends(rules_principal),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    """Switch on or off the rules of ``ids``, or those the ``filters`` keep: ``{matched, changed}``."""
    if (body.ids is None) == (body.filters is None):
        raise HTTPException(
            status_code=400,
            detail="Give the rules by ids, or by filters, not both and not neither",
        )
    f = body.filters.model_dump() if body.filters is not None else None
    result = rules.switch(db, body.enabled, body.ids, f)
    what = f"{len(body.ids)} chosen rules" if body.ids is not None else rules.describe(f or {})
    audit.record(
        db,
        caller.actor,
        "sigma.bulk",
        f"{'Switched on' if body.enabled else 'Switched off'} {result['changed']} Sigma rules ({what})",
    )
    db.commit()
    return result


@router.post("/recheck", status_code=status.HTTP_202_ACCEPTED)
def recheck_rules(_caller: Principal = Depends(rules_principal)) -> dict[str, Any]:
    """Have the worker read the rules again that it did not read with its present version (and the ones it
    never read): done in the background."""
    if not worker.configured():
        raise HTTPException(
            status_code=503,
            detail="The forensics worker is not configured (FORENSICS_URL)",
        )
    threading.Thread(target=recheck.run_once, name="nik-sigma", daemon=True).start()
    return {"started": True}


@router.post("", status_code=status.HTTP_201_CREATED)
def create_rule(
    body: RuleIn,
    caller: Principal = Depends(rules_principal),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    """Save the rules of a text (one or several YAML documents, each a rule with an ``id``). All or none:
    a text with a document that is not a rule saves nothing, and ``errors`` says where. A rule whose id is
    here is refused (change it with PUT). Answers ``{rules}``, each with its text."""
    made = manage.create(db, body.source, caller.actor, body.enabled)
    for row in made:
        audit.record(
            db,
            caller.actor,
            "sigma.add",
            f"Added the Sigma rule {row.title or row.id}",
            target=row.id,
        )
    db.commit()
    return {"rules": [_shown(row) for row in made]}


@router.get("/{rule_id}")
def get_rule(
    rule_id: str,
    _caller: Principal = Depends(rules_reader_principal),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    """One rule with its text (``source``) and, for a rule of a pack that was changed, the text of the pack
    (``original``)."""
    return _shown(rules.get(db, rule_id))


@router.put("/{rule_id}")
def update_rule(
    rule_id: str,
    body: RuleIn,
    caller: Principal = Depends(rules_principal),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    """Put a new text in a rule: the text holds that rule alone and its id does not change. A rule of a
    pack is now the person's (it is not overwritten when the pack is updated), and Reset gives the pack's
    text back."""
    row = manage.change(db, rules.get(db, rule_id), body.source, caller.actor, body.enabled)
    audit.record(
        db,
        caller.actor,
        "sigma.update",
        f"Changed the Sigma rule {row.title or row.id}",
        target=row.id,
    )
    db.commit()
    return _shown(row)


@router.patch("/{rule_id}")
def switch_rule(
    rule_id: str,
    body: EnabledIn,
    caller: Principal = Depends(rules_principal),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    """Switch a rule on or off. One Nik cannot run is refused (409) when switched on."""
    row = rules.get(db, rule_id)
    rules.set_enabled(row, body.enabled)
    rules.bump(db)
    audit.record(
        db,
        caller.actor,
        "sigma.enable" if body.enabled else "sigma.disable",
        f"{'Switched on' if body.enabled else 'Switched off'} the Sigma rule {row.title or row.id}",
        target=row.id,
    )
    db.commit()
    return _shown(row)


@router.post("/{rule_id}/reset")
def reset_rule(
    rule_id: str,
    caller: Principal = Depends(rules_principal),
    db: OrmSession = Depends(get_db),
) -> dict[str, Any]:
    """Put back the text a pack gave a rule that was changed here (409 for a rule that was not)."""
    row = manage.reset(db, rules.get(db, rule_id), caller.actor)
    audit.record(
        db,
        caller.actor,
        "sigma.reset",
        f"Reset the Sigma rule {row.title or row.id} to its pack",
        target=row.id,
    )
    db.commit()
    return _shown(row)


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_rule(
    rule_id: str,
    caller: Principal = Depends(rules_principal),
    db: OrmSession = Depends(get_db),
) -> Response:
    """Delete a rule written here. A rule of a pack is switched off, not deleted (409)."""
    row = rules.get(db, rule_id)
    rules.remove(db, row)
    audit.record(
        db,
        caller.actor,
        "sigma.delete",
        f"Deleted the Sigma rule {row.title or row.id}",
        target=row.id,
    )
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)

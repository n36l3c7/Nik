"""Threat intelligence: the sources (the connectors that judge indicators), look-ups and stored answers.

A source is asked through an instance of its connector, with the keys of that
instance: this router holds no key and returns none. Look-ups refuse private
addresses, internal names, allowlisted values and values of TLP:RED incidents
(``enrichment/service.py``).
"""

from __future__ import annotations

import json
import uuid
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as OrmSession

from .. import analysis_links
from ..automation import connector_actions, instance_keys
from ..core.db import get_db
from ..core.models import AuditEntry, Connector, Enrichment, IntegrationKey, UrlScan
from ..core.security import Principal, admin_principal, now_iso, reader_principal, writer_principal
from ..enrichment import old_keys, service
from ..enrichment import sources as src
from ..iocs import Allowlist
from .settings import read_settings

router = APIRouter(prefix="/enrichment", tags=["threat intelligence"])

LookupType = Literal["ip", "domain", "url", "md5", "sha1", "sha256"]


def _audit(db: OrmSession, caller: Principal, action: str, details: str) -> None:
    db.add(
        AuditEntry(
            id=str(uuid.uuid4()),
            at=now_iso(),
            actor=caller.actor,
            action=action,
            target=None,
            details=details,
            incident_id=None,
            incident_name=None,
        )
    )


def _value_or_400(kind: str, value: str) -> str:
    cleaned = service.normalized(kind, value)
    if cleaned is None:
        raise HTTPException(status_code=400, detail=f"Not a valid {kind}.")
    return cleaned


def _source_out(db: OrmSession, source: src.Source) -> dict:
    """A source as Settings lists it: what it judges, whether it is on, and through which instance."""
    asks_for = [param for param in source.connector.configuration if param.required and param.default in (None, "")]
    policy = instance_keys.policy_of(source.instance) if source.instance is not None else None
    return {
        "id": source.id,
        "label": source.label,
        "types": source.types,
        "commands": {kind: f"{source.id}.{name}" for kind, name in source.commands.items() if kind in src.KINDS},
        "weight": source.weight,
        "informational": source.informational,
        "on": source.on,
        # The instance the look-ups go through (the oldest that is on), and how many the connector has.
        "instance": source.instance.name if source.instance is not None else None,
        "instances": source.instances,
        "keys": src.keys_count(source),
        "limits": ({key: policy[key] for key in ("perMinute", "perDay", "cacheHours")} if policy is not None else None),
        # Nothing has to be typed to make an instance: it can be turned on from here.
        "needsNothing": not asks_for,
        "logo": connector_actions.logo_path(db.get(Connector, source.id)),
    }


@router.get("/sources")
def list_sources(_caller: Principal = Depends(reader_principal), db: OrmSession = Depends(get_db)) -> dict:
    """The sources of threat intelligence: every installed connector with a command that judges an
    indicator (`reputation` in its file), whether it is on (an instance of it is), which instance the
    look-ups go through and its limits. `oldKeys`: the API keys kept before 6.5 that have no instance
    yet (never the keys: their last four characters), each with the connectors it waits for."""
    shared = read_settings(db)
    return {
        "sources": [_source_out(db, source) for source in src.sources(db)],
        "settings": service.config(shared),
        "oldKeys": old_keys.left(db),
    }


@router.delete("/old-keys/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_old_key(
    key_id: str, caller: Principal = Depends(admin_principal), db: OrmSession = Depends(get_db)
) -> Response:
    """Delete an API key kept from before 6.5 that was not moved to an instance (**admin**)."""
    row = db.get(IntegrationKey, key_id)
    if row is None:
        raise HTTPException(status_code=404, detail="No such key")
    label = old_keys.OLD.get(row.provider, {}).get("label", row.provider)
    _audit(db, caller, "enrichment.key", f"Removed a {label} API key kept from before 6.5 (…{row.hint})")
    db.delete(row)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


def _analysis(db: OrmSession, row) -> dict:
    """An artifact as the indicator's page shows it: its verdict, and for a
    scanned address what was found."""
    out = analysis_links.brief(row)
    if row.kind == "url":
        scan = db.get(UrlScan, row.ref)
        result = (scan.result or {}) if scan is not None else {}
        scripts = result.get("scripts") or []
        out.update(
            status=scan.status if scan is not None else "",
            url=scan.url if scan is not None else "",
            scannedAt=scan.scanned_at if scan is not None else None,
            finalUrl=result.get("finalUrl"),
            findings=[str(f.get("text")) for f in (result.get("findings") or [])[:4]],
            scripts=len(scripts),
            scriptsFlagged=sum(1 for s in scripts if s.get("findings")),
            screenshot=bool(result.get("screenshot")),
        )
    return out


def _detail(db: OrmSession, kind: str, value: str, shared: dict, reason: str | None) -> dict:
    """What the indicator's page shows: each source's answer with its
    history, the weighted verdict, and what could still be asked."""
    cfg = service.config(shared)
    judging = [source for source in src.sources(db) if source.supports(kind)]
    names = {source.id: source.label for source in judging}
    available = [source.id for source in judging if source.on]
    results = service.results(db, kind, value, cfg)
    answered = {r["provider"] for r in results}
    analyses = analysis_links.analyses_for(db, [(kind, value)]).get((kind, value), [])
    flagged = analysis_links.verdicts(db, [(kind, value)]).get((kind, value))
    answers = [(r["provider"], r["verdict"]) for r in results if r["status"] == "done"]
    if flagged:
        answers.append((service.NIK, flagged))
    stale = [r["provider"] for r in results if r["expired"] and r["provider"] in available]
    return {
        "type": kind,
        "value": value,
        "blocked": reason,
        "providers": available,
        "notAsked": [{"provider": p, "label": names[p]} for p in available if p not in answered],
        # Installed, but no instance of the connector is on: not asked until one is (Settings, Connectors).
        "off": [{"provider": source.id, "label": source.label} for source in judging if not source.on],
        "results": results,
        "summary": service.overall(answers, src.weights(db)),
        # What Nik saw when it analysed this value itself (an artifact), next
        # to what the sources say. ``verdict`` is the analysis in the words of
        # a reputation when it flags the value: it counts among the sources.
        "analysis": {
            "label": analysis_links.LABEL,
            "weight": service.NIK_WEIGHT,
            "verdict": flagged,
            "canAnalyse": kind in ("url", "domain") and analysis_links.scan_id_of(value) is not None,
            "artifacts": [_analysis(db, row) for row in analyses[:5]],
        },
        "retentionDays": cfg["retentionDays"][service.retention_group(kind)],
        # Expired answers the app should ask again now (Settings: refresh expired answers).
        "refresh": stale if cfg["refreshExpired"] and not reason else [],
    }


@router.get("")
def cached(
    type: LookupType = Query(...),
    value: str = Query(..., min_length=1, max_length=1024),
    _caller: Principal = Depends(reader_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """What is known about an indicator: each source's stored answer
    (`provider`: the id of the source's connector; `data`: the outputs of its
    reputation command, with `_command` naming it; `history` of its earlier
    verdicts; `expired` past the retention of the type), the weighted `summary`
    (`verdict`, `score` 0-100, `counts`), `providers`: the sources that can be
    asked now, `off`: those whose connector has no instance that is on, and
    `blocked`: why it is never sent, or null."""
    value = _value_or_400(type, value)
    shared = read_settings(db)
    reason = service.blocked(db, type, value, Allowlist(shared.get("iocAllowlist") or []))
    return _detail(db, type, value, shared, reason)


@router.get("/raw")
def raw_answer(
    type: LookupType = Query(...),
    value: str = Query(..., min_length=1, max_length=1024),
    provider: str = Query(..., max_length=40),
    _caller: Principal = Depends(reader_principal),
    db: OrmSession = Depends(get_db),
) -> Response:
    """A source's whole answer about the indicator (every output of its command), as a JSON file."""
    value = _value_or_400(type, value)
    row = db.get(Enrichment, (type, value, provider))
    if row is None or row.raw is None:
        raise HTTPException(status_code=404, detail="No stored answer from this source")
    body = {"provider": provider, "type": type, "value": value, "checkedAt": row.checked_at, "response": row.raw}
    return Response(
        json.dumps(body, indent=2, ensure_ascii=False),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="nik-{provider}-{type}.json"'},
    )


class CheckIn(BaseModel):
    type: LookupType
    value: str = Field(min_length=1, max_length=1024)
    force: bool = False


@router.post("/check")
async def check(body: CheckIn, caller: Principal = Depends(writer_principal), db: OrmSession = Depends(get_db)) -> dict:
    """Ask every source that is on about the indicator now ("Check now"); answers that
    still stand are reused unless ``force``. ``422`` when the value must not be sent."""
    value = _value_or_400(body.type, body.value)
    shared = read_settings(db)
    reason = service.blocked(db, body.type, value, Allowlist(shared.get("iocAllowlist") or []))
    if reason:
        raise HTTPException(status_code=422, detail=f"Not sent: {reason}.")
    outcome = await run_in_threadpool(service.check_now, db, body.type, value, shared, body.force)
    _audit(db, caller, "enrichment.check", f"Checked {body.type} {value[:200]} with the threat-intelligence sources")
    db.commit()
    return {**_detail(db, body.type, value, shared, None), "skipped": outcome["skipped"]}

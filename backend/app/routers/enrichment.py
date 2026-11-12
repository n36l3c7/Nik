"""Threat intelligence: provider keys (admin), lookups and cached answers.

The keys are stored encrypted (``vault.py``) and never returned; the
providers list says only whether each one is configured and the key's last
four characters. Lookups refuse private addresses, internal names,
allowlisted values and values of TLP:RED incidents (``enrichment/service.py``).
"""

from __future__ import annotations

import json
import uuid
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from .. import analysis_links
from ..core import vault
from ..core.db import get_db
from ..core.models import AuditEntry, Enrichment, IntegrationKey, UrlScan
from ..core.security import Principal, admin_principal, now_iso, principal, writer_principal
from ..enrichment import service
from ..enrichment.providers import BY_ID, PROVIDERS
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


MAX_KEYS = 10


def _key_out(row: IntegrationKey) -> dict:
    readable = vault.decrypt(row.secret) is not None
    return {
        "id": row.id,
        "hint": row.hint,
        "label": row.label,
        # ok | rejected (the provider refused it) | unreadable (SECRET_KEY changed)
        "status": row.status if readable else "unreadable",
        "error": row.error,
        "updatedAt": row.updated_at,
        "updatedBy": row.updated_by,
    }


@router.get("/providers")
def list_providers(_caller: Principal = Depends(principal), db: OrmSession = Depends(get_db)) -> dict:
    """Every provider: types, key requirement, its keys' state (never the keys), free-tier limits."""
    shared = read_settings(db)
    cfg = service.config(shared)
    stored: dict[str, list[IntegrationKey]] = {}
    for row in db.scalars(select(IntegrationKey).order_by(IntegrationKey.updated_at, IntegrationKey.id)):
        stored.setdefault(row.provider, []).append(row)
    all_keys = service.keys(db)
    out = []
    for p in PROVIDERS:
        key_rows = [_key_out(row) for row in stored.get(p.id, [])]
        working = [k for k in key_rows if k["status"] == "ok"]
        out.append(
            {
                "id": p.id,
                "label": p.label,
                "types": list(p.types),
                "key": p.key,
                "keys": key_rows,
                "configured": bool(working),
                # The first working key, as before several keys existed.
                "keyHint": working[0]["hint"] if working else "",
                "keyUnreadable": any(k["status"] == "unreadable" for k in key_rows),
                "enabled": cfg["providers"].get(p.id, True),
                "usable": service.usable(p, cfg, all_keys),
                "maxKeys": MAX_KEYS,
                "signup": p.signup,
                "note": p.note,
            }
        )
    return {"providers": out, "settings": cfg}


class KeyIn(BaseModel):
    key: str = Field(min_length=8, max_length=512, pattern=r"^[\x21-\x7e]+$")
    label: str = Field(default="", max_length=60)


def _provider_with_keys(provider_id: str):
    provider = BY_ID.get(provider_id)
    if provider is None or provider.key == "none":
        raise HTTPException(status_code=404, detail="No such provider, or it takes no key")
    return provider


def _store_key(db: OrmSession, provider_id: str, body: KeyIn, actor: str) -> IntegrationKey:
    row = IntegrationKey(
        id=uuid.uuid4().hex,
        provider=provider_id,
        secret=vault.encrypt(body.key),
        hint=body.key[-4:],
        label=" ".join(body.label.split()),
        status="ok",
        updated_at=now_iso(),
        updated_by=actor,
    )
    db.add(row)
    return row


@router.post("/providers/{provider_id}/keys", status_code=status.HTTP_201_CREATED)
def add_key(
    provider_id: str,
    body: KeyIn,
    caller: Principal = Depends(admin_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Add an API key to a provider (**admin**), stored encrypted and never
    shown again. Lookups rotate over a provider's keys; `409` for a key
    already stored or past the limit of 10 keys."""
    provider = _provider_with_keys(provider_id)
    existing = db.scalars(select(IntegrationKey).where(IntegrationKey.provider == provider_id)).all()
    if len(existing) >= MAX_KEYS:
        raise HTTPException(status_code=409, detail=f"A provider takes at most {MAX_KEYS} keys.")
    if any(vault.decrypt(row.secret) == body.key for row in existing):
        raise HTTPException(status_code=409, detail="This key is already stored for the provider.")
    row = _store_key(db, provider_id, body, caller.actor)
    _audit(db, caller, "enrichment.key", f"Added a {provider.label} API key (…{row.hint})")
    db.commit()
    return _key_out(row)


@router.delete("/providers/{provider_id}/keys/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_one_key(
    provider_id: str, key_id: str, caller: Principal = Depends(admin_principal), db: OrmSession = Depends(get_db)
) -> Response:
    """Remove one API key of a provider (**admin**)."""
    row = db.get(IntegrationKey, key_id)
    if row is None or row.provider != provider_id:
        raise HTTPException(status_code=404, detail="No such key for this provider")
    label = BY_ID[provider_id].label if provider_id in BY_ID else provider_id
    _audit(db, caller, "enrichment.key", f"Removed a {label} API key (…{row.hint})")
    db.delete(row)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.put("/providers/{provider_id}/key", status_code=status.HTTP_204_NO_CONTENT)
def set_key(
    provider_id: str,
    body: KeyIn,
    caller: Principal = Depends(admin_principal),
    db: OrmSession = Depends(get_db),
) -> Response:
    """Replace every key of the provider with this one (**admin**). Kept for
    clients written for one key per provider; use `POST …/keys` to add one."""
    provider = _provider_with_keys(provider_id)
    for row in db.scalars(select(IntegrationKey).where(IntegrationKey.provider == provider_id)):
        db.delete(row)
    _store_key(db, provider_id, body, caller.actor)
    _audit(db, caller, "enrichment.key", f"Set the {provider.label} API key")
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.delete("/providers/{provider_id}/key", status_code=status.HTTP_204_NO_CONTENT)
def delete_key(
    provider_id: str, caller: Principal = Depends(admin_principal), db: OrmSession = Depends(get_db)
) -> Response:
    """Remove every API key of a provider (**admin**)."""
    rows = db.scalars(select(IntegrationKey).where(IntegrationKey.provider == provider_id)).all()
    if not rows:
        raise HTTPException(status_code=404, detail="No key stored for this provider")
    for row in rows:
        db.delete(row)
    label = BY_ID[provider_id].label if provider_id in BY_ID else provider_id
    _audit(db, caller, "enrichment.key", f"Removed the {label} API key{'s' if len(rows) > 1 else ''}")
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
    """What the indicator's page shows: each provider's answer with its
    history, the weighted verdict, and what could still be asked."""
    cfg, all_keys = service.config(shared), service.keys(db)
    available = [p.id for p in PROVIDERS if p.supports(kind) and service.usable(p, cfg, all_keys)]
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
        "notAsked": [{"provider": p, "label": BY_ID[p].label} for p in available if p not in answered],
        "results": results,
        "summary": service.overall(answers),
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
    _caller: Principal = Depends(principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """What is known about an indicator: each provider's cached answer
    (`data` in the provider's shape, `history` of its earlier verdicts,
    `expired` past the retention of the type), the weighted `summary`
    (`verdict`, `score` 0-100, `counts`), and `blocked`: why it is never
    sent, or null."""
    value = _value_or_400(type, value)
    shared = read_settings(db)
    reason = service.blocked(db, type, value, Allowlist(shared.get("iocAllowlist") or []))
    return _detail(db, type, value, shared, reason)


@router.get("/raw")
def raw_answer(
    type: LookupType = Query(...),
    value: str = Query(..., min_length=1, max_length=1024),
    provider: str = Query(..., max_length=40),
    _caller: Principal = Depends(principal),
    db: OrmSession = Depends(get_db),
) -> Response:
    """A provider's own answer about the indicator, as a JSON file."""
    value = _value_or_400(type, value)
    row = db.get(Enrichment, (type, value, provider))
    if row is None or row.raw is None:
        raise HTTPException(status_code=404, detail="No stored answer from this provider")
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
    """Ask every usable provider about the indicator now ("Check now"); fresh
    answers are reused unless ``force``. ``422`` when the value must not be sent."""
    value = _value_or_400(body.type, body.value)
    shared = read_settings(db)
    reason = service.blocked(db, body.type, value, Allowlist(shared.get("iocAllowlist") or []))
    if reason:
        raise HTTPException(status_code=422, detail=f"Not sent: {reason}.")
    outcome = await run_in_threadpool(service.check_now, db, body.type, value, shared, body.force)
    _audit(db, caller, "enrichment.check", f"Checked {body.type} {value[:200]} with threat-intelligence providers")
    db.commit()
    return {**_detail(db, body.type, value, shared, None), "skipped": outcome["skipped"]}

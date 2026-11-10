"""Threat intelligence: provider keys (admin), lookups and cached answers.

The keys are stored encrypted (``vault.py``) and never returned; the
providers list says only whether each one is configured and the key's last
four characters. Lookups refuse private addresses, internal names,
allowlisted values and values of TLP:RED incidents (``enrichment/service.py``).
"""

from __future__ import annotations

import uuid
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from .. import vault
from ..db import get_db
from ..enrichment import service
from ..enrichment.providers import BY_ID, PROVIDERS
from ..iocs import Allowlist
from ..models import AuditEntry, IntegrationKey
from ..security import Principal, admin_principal, now_iso, principal, writer_principal
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


@router.get("/providers")
def list_providers(_caller: Principal = Depends(principal), db: OrmSession = Depends(get_db)) -> dict:
    """Every provider: types, key requirement and state, free-tier limits. Never the keys."""
    shared = read_settings(db)
    cfg = service.config(shared)
    stored = {row.provider: row for row in db.scalars(select(IntegrationKey))}
    out = []
    for p in PROVIDERS:
        row = stored.get(p.id)
        readable = row is not None and vault.decrypt(row.secret) is not None
        out.append(
            {
                "id": p.id,
                "label": p.label,
                "types": list(p.types),
                "key": p.key,
                "configured": readable,
                "keyHint": row.hint if readable else "",
                "keyUnreadable": row is not None and not readable,
                "keyUpdatedAt": row.updated_at if row is not None else None,
                "keyUpdatedBy": row.updated_by if row is not None else None,
                "enabled": cfg["providers"].get(p.id, True),
                "usable": service.usable(p, cfg, {p.id: "x" if readable else None}),
                "signup": p.signup,
                "note": p.note,
            }
        )
    return {"providers": out, "settings": cfg}


class KeyIn(BaseModel):
    key: str = Field(min_length=8, max_length=512, pattern=r"^[\x21-\x7e]+$")


@router.put("/providers/{provider_id}/key", status_code=status.HTTP_204_NO_CONTENT)
def set_key(
    provider_id: str,
    body: KeyIn,
    caller: Principal = Depends(admin_principal),
    db: OrmSession = Depends(get_db),
) -> Response:
    """Store a provider's API key, encrypted (**admin**). It is never shown again."""
    provider = BY_ID.get(provider_id)
    if provider is None or provider.key == "none":
        raise HTTPException(status_code=404, detail="No such provider, or it takes no key")
    row = db.get(IntegrationKey, provider_id)
    if row is None:
        row = IntegrationKey(provider=provider_id, secret="", updated_at=now_iso())
        db.add(row)
    row.secret, row.hint = vault.encrypt(body.key), body.key[-4:]
    row.updated_at, row.updated_by = now_iso(), caller.actor
    _audit(db, caller, "enrichment.key", f"Set the {provider.label} API key")
    db.commit()
    service.limiter.reset()  # a new key: forget an auth back-off
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.delete("/providers/{provider_id}/key", status_code=status.HTTP_204_NO_CONTENT)
def delete_key(
    provider_id: str, caller: Principal = Depends(admin_principal), db: OrmSession = Depends(get_db)
) -> Response:
    """Remove a provider's API key (**admin**)."""
    row = db.get(IntegrationKey, provider_id)
    if row is None:
        raise HTTPException(status_code=404, detail="No key stored for this provider")
    db.delete(row)
    _audit(
        db,
        caller,
        "enrichment.key",
        f"Removed the {BY_ID[provider_id].label if provider_id in BY_ID else provider_id} API key",
    )
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("")
def cached(
    type: LookupType = Query(...),
    value: str = Query(..., min_length=1, max_length=1024),
    _caller: Principal = Depends(principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """The cached answers about an indicator, and whether it may be sent at all."""
    value = _value_or_400(type, value)
    shared = read_settings(db)
    reason = service.blocked(db, type, value, Allowlist(shared.get("iocAllowlist") or []))
    cfg, all_keys = service.config(shared), service.keys(db)
    available = [p.id for p in PROVIDERS if p.supports(type) and service.usable(p, cfg, all_keys)]
    return {
        "type": type,
        "value": value,
        "blocked": reason,
        "providers": available,
        "results": service.results(db, type, value),
    }


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
    return {"type": body.type, "value": value, "blocked": None, **outcome}

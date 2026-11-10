"""Admin-managed capa rules.

Admins add capa rules (YAML, one rule each) that the capa worker matches with
its bundled rule set. Every rule is checked by the worker before it is saved
(syntax, features, a unique name, the rules it ``match``es), so a broken rule
never stops capa; a rule that another enabled rule depends on cannot be
disabled or deleted.
"""

from __future__ import annotations

import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from .. import capa, capa_rules
from ..analyzer import AnalyzerError
from ..db import get_db
from ..models import AuditEntry, CapaRule
from ..security import Principal, admin_principal, now_iso, principal

router = APIRouter(prefix="/capa-rules", tags=["capa-rules"])


class CapaRuleIn(BaseModel):
    """A capa rule's YAML source and whether it is matched."""

    source: str
    enabled: bool = True


class CapaRuleCheck(BaseModel):
    """A source to validate; ``id`` when it replaces an existing rule."""

    source: str
    id: Optional[str] = None


def _to_dict(row: CapaRule) -> dict:
    return {
        "id": row.id,
        "name": row.name,
        "namespace": row.namespace,
        "scope": row.scope,
        "source": row.source,
        "enabled": row.enabled,
        "createdAt": row.created_at,
        "createdBy": row.created_by,
        "updatedAt": row.updated_at,
    }


def _audit(db: OrmSession, caller: Principal, action: str, details: str) -> None:
    db.add(AuditEntry(id=str(uuid.uuid4()), at=now_iso(), actor=caller.actor, action=action, details=details))


def _row_or_404(db: OrmSession, rule_id: str) -> CapaRule:
    row = db.get(CapaRule, rule_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    return row


def _check(db: OrmSession, source: str, exclude_id: str | None) -> dict:
    """The worker's verdict, plus a unique name among all admin rules (disabled ones too)."""
    if not capa.configured():
        raise HTTPException(
            status_code=503, detail="The capa worker is not configured (CAPA_URL): it checks the rules."
        )
    if not source.strip() or len(source) > capa_rules.MAX_SOURCE_CHARS:
        raise HTTPException(status_code=400, detail=f"A rule is 1 to {capa_rules.MAX_SOURCE_CHARS} characters.")
    try:
        verdict = capa_rules.validate(db, source, exclude_id)
    except AnalyzerError as exc:
        raise HTTPException(status_code=502, detail=f"The capa worker could not check the rule: {exc}") from exc
    if verdict.get("ok"):
        clash = db.scalar(select(CapaRule).where(CapaRule.name == verdict["name"], CapaRule.id != (exclude_id or "")))
        if clash is not None:
            verdict = {**verdict, "ok": False, "errors": [f"An admin rule is already named {verdict['name']!r}."]}
    return verdict


def _validated(db: OrmSession, source: str, exclude_id: str | None) -> dict:
    verdict = _check(db, source, exclude_id)
    if not verdict.get("ok"):
        raise HTTPException(status_code=400, detail=f"The rule is not valid: {'; '.join(verdict['errors'])}")
    return verdict


def _refuse_if_used(db: OrmSession, row: CapaRule, action: str) -> None:
    users = capa_rules.dependents(db, row)
    if users:
        raise HTTPException(status_code=409, detail=f"Cannot {action} {row.name!r}: {', '.join(users)} match it.")


@router.get("")
def list_rules(_caller: Principal = Depends(principal), db: OrmSession = Depends(get_db)) -> dict:
    """Admin rules, oldest first."""
    rows = db.scalars(select(CapaRule).order_by(CapaRule.created_at)).all()
    return {"rules": [_to_dict(row) for row in rows]}


@router.post("/validate")
def validate_rule(
    body: CapaRuleCheck, _caller: Principal = Depends(admin_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Check a source without saving it: `{ ok, errors, name, namespace, scope }`."""
    return _check(db, body.source, body.id)


@router.post("", status_code=status.HTTP_201_CREATED)
def create_rule(
    body: CapaRuleIn, caller: Principal = Depends(admin_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Add a rule; the capa worker must accept it."""
    verdict = _validated(db, body.source, None)
    now = now_iso()
    row = CapaRule(
        id=uuid.uuid4().hex,
        name=verdict["name"],
        namespace=verdict.get("namespace") or "",
        scope=verdict.get("scope") or "",
        source=body.source,
        enabled=body.enabled,
        created_at=now,
        created_by=caller.actor,
        updated_at=now,
    )
    capa_rules.write_file(row)
    db.add(row)
    _audit(db, caller, "capa.add", f"Added capa rule {row.name}")
    db.commit()
    return _to_dict(row)


@router.put("/{rule_id}")
def update_rule(
    rule_id: str, body: CapaRuleIn, caller: Principal = Depends(admin_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Replace a rule's source or switch it on/off."""
    row = _row_or_404(db, rule_id)
    verdict = _validated(db, body.source, row.id)
    if not body.enabled or verdict["name"] != row.name:  # the rules that match it would break
        _refuse_if_used(db, row, "disable" if not body.enabled else "rename")
    row.name, row.namespace, row.scope = verdict["name"], verdict.get("namespace") or "", verdict.get("scope") or ""
    row.source, row.enabled, row.updated_at = body.source, body.enabled, now_iso()
    capa_rules.write_file(row)
    _audit(db, caller, "capa.update", f"Updated capa rule {row.name} ({'enabled' if row.enabled else 'disabled'})")
    db.commit()
    return _to_dict(row)


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_rule(
    rule_id: str, caller: Principal = Depends(admin_principal), db: OrmSession = Depends(get_db)
) -> Response:
    row = _row_or_404(db, rule_id)
    _refuse_if_used(db, row, "delete")
    capa_rules.delete_file(row)
    db.delete(row)
    _audit(db, caller, "capa.delete", f"Deleted capa rule {row.name}")
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)

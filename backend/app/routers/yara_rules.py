"""Admin-managed YARA rules.

Admins add rule sources that are compiled with Nik's built-in set and run on
every sample upload or re-analysis. A rule is validated (compiled on its own)
before it is saved, so a typo can never break the shared scan.
"""

from __future__ import annotations

import re
import uuid

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from ..core.db import get_db
from ..core.models import AuditEntry, YaraRule
from ..core.schemas import YaraRuleIn, YaraRulesEnvelope
from ..core.security import Principal, admin_principal, now_iso, principal
from ..malware import yara_rules

router = APIRouter(prefix="/yara-rules", tags=["yara-rules"])

_RULE_NAME_RE = re.compile(r"^\s*(?:private\s+|global\s+)*rule\s+([A-Za-z_][A-Za-z0-9_]*)", re.MULTILINE)


def _rule_names(source: str) -> list[str]:
    return _RULE_NAME_RE.findall(source)


def _to_dict(row: YaraRule) -> dict:
    return {
        "id": row.id,
        "name": row.name,
        "source": row.source,
        "enabled": row.enabled,
        "createdAt": row.created_at,
        "createdBy": row.created_by,
        "updatedAt": row.updated_at,
        "ruleNames": _rule_names(row.source),
    }


def _audit(db: OrmSession, caller: Principal, action: str, details: str) -> None:
    db.add(AuditEntry(id=str(uuid.uuid4()), at=now_iso(), actor=caller.actor, action=action, details=details))


def _validated(body: YaraRuleIn) -> None:
    if not body.name.strip():
        raise HTTPException(status_code=400, detail="The rule needs a name.")
    errors = yara_rules.validate(body.source)
    if errors:
        raise HTTPException(status_code=400, detail=f"The rule does not compile: {errors[0]}")
    if not _rule_names(body.source):
        raise HTTPException(status_code=400, detail="The source contains no `rule` declaration.")


@router.get("", response_model=YaraRulesEnvelope)
def list_rules(_caller: Principal = Depends(principal), db: OrmSession = Depends(get_db)) -> dict:
    """Admin rules with their source, plus the names of the built-in rule files."""
    rows = db.scalars(select(YaraRule).order_by(YaraRule.created_at)).all()
    builtin = [
        {"namespace": namespace, "ruleNames": _rule_names(source)}
        for namespace, source in yara_rules.builtin_sources().items()
    ]
    return {"rules": [_to_dict(r) for r in rows], "builtin": builtin}


@router.post("", status_code=status.HTTP_201_CREATED)
def create_rule(
    body: YaraRuleIn, caller: Principal = Depends(admin_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Add a rule set; it must compile on its own."""
    _validated(body)
    now = now_iso()
    row = YaraRule(
        id=str(uuid.uuid4()),
        name=body.name.strip(),
        source=body.source,
        enabled=bool(body.enabled),
        created_at=now,
        created_by=caller.actor,
        updated_at=now,
    )
    db.add(row)
    _audit(db, caller, "yara.add", f"Added YARA rule set {row.name}")
    db.commit()
    yara_rules.invalidate()
    return _to_dict(row)


@router.put("/{rule_id}")
def update_rule(
    rule_id: str, body: YaraRuleIn, caller: Principal = Depends(admin_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Replace a rule set's name, source or enabled flag."""
    row = db.get(YaraRule, rule_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    _validated(body)
    row.name = body.name.strip()
    row.source = body.source
    row.enabled = bool(body.enabled)
    row.updated_at = now_iso()
    _audit(db, caller, "yara.update", f"Updated YARA rule set {row.name} ({'enabled' if row.enabled else 'disabled'})")
    db.commit()
    yara_rules.invalidate()
    return _to_dict(row)


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_rule(
    rule_id: str, caller: Principal = Depends(admin_principal), db: OrmSession = Depends(get_db)
) -> Response:
    row = db.get(YaraRule, rule_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    db.delete(row)
    _audit(db, caller, "yara.delete", f"Deleted YARA rule set {row.name}")
    db.commit()
    yara_rules.invalidate()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/validate")
def validate_rule(body: YaraRuleIn, _caller: Principal = Depends(admin_principal)) -> dict:
    """Compile a source without saving it: `{ ok, errors, ruleNames }`."""
    errors = yara_rules.validate(body.source)
    return {"ok": not errors, "errors": errors, "ruleNames": _rule_names(body.source)}

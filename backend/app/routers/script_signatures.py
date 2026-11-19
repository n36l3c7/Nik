"""The signatures the Scripts tab of URL Analysis checks, managed like YARA and capa rules.

Nik ships a set; whoever manages rules (``rules.manage``) turns one off,
changes it, puts it back as it shipped, and adds their own. A pattern is
tried against long hostile texts before it is saved, so that no signature can
stall the analysis of a page. Changes apply to the scans made from then on:
*Analyse again* on a scanned address reads it with the signatures of now.
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session as OrmSession

from .. import jsanalysis
from ..core import audit
from ..core.db import get_db
from ..core.models import ScriptSignature
from ..core.security import Principal, now_iso, rules_principal, rules_reader_principal

router = APIRouter(prefix="/script-signatures", tags=["script signatures"])


class SignatureIn(BaseModel):
    key: str = Field(default="", max_length=61)
    title: str = Field(default="", max_length=200)
    severity: str = Field(default="medium", max_length=10)
    points: int = Field(default=10, ge=0, le=100)
    pattern: str = Field(default="", max_length=jsanalysis.PATTERN_MAX)
    # A second pattern that must match somewhere in the script too ("…and the script sends data out").
    also: str = Field(default="", max_length=jsanalysis.PATTERN_MAX)
    enabled: bool = True


class TryIn(SignatureIn):
    # A piece of code to try the signature on, without saving it.
    code: str = Field(default="", max_length=jsanalysis.MAX_CODE)


def _refused(error: jsanalysis.SignatureError) -> HTTPException:
    return HTTPException(status_code=400, detail={"message": error.message, "field": error.field})


def _get(db: OrmSession, signature_id: str) -> ScriptSignature:
    row = db.get(ScriptSignature, signature_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Signature not found")
    return row


def _all(db: OrmSession) -> list[ScriptSignature]:
    if jsanalysis.seed(db, now_iso()):
        db.commit()  # the first time they are asked for, on a database that was never started with them
    rows = db.scalars(select(ScriptSignature)).all()
    order = {name: index for index, name in enumerate(jsanalysis.SEVERITIES)}
    return sorted(rows, key=lambda row: (order.get(row.severity, 9), -row.points, row.key))


@router.get("")
def list_signatures(_caller: Principal = Depends(rules_reader_principal), db: OrmSession = Depends(get_db)) -> dict:
    """Every signature, the worst first: Nik's own (``builtin``, ``changed`` when it differs from what
    ships) and the ones added here."""
    return {"signatures": [jsanalysis.out(row) for row in _all(db)], "severities": list(jsanalysis.SEVERITIES)}


@router.post("", status_code=status.HTTP_201_CREATED)
def create_signature(
    body: SignatureIn, caller: Principal = Depends(rules_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Add a signature of your own: ``{key, title, severity, points, pattern, also, enabled}``."""
    _all(db)
    try:
        cleaned = jsanalysis.clean(body.model_dump())
    except jsanalysis.SignatureError as error:
        raise _refused(error) from None
    taken = db.scalar(select(ScriptSignature.id).where(func.lower(ScriptSignature.key) == cleaned["key"]))
    if taken is not None or cleaned["key"] == "obf.heavy":
        raise HTTPException(
            status_code=409, detail={"message": "There is a signature with this key already", "field": "key"}
        )
    row = ScriptSignature(id=uuid.uuid4().hex, builtin=False, updated_at=now_iso(), updated_by=caller.actor, **cleaned)
    db.add(row)
    audit.record(db, caller.actor, "signature.add", f"Added the script signature {row.key}", target=row.key)
    db.commit()
    jsanalysis.clear_cache()
    return jsanalysis.out(row)


@router.put("/{signature_id}")
def update_signature(
    signature_id: str,
    body: SignatureIn,
    caller: Principal = Depends(rules_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Change a signature. One of Nik's own keeps its key; everything else of it can be changed, and
    it can be turned off."""
    row = _get(db, signature_id)
    try:
        cleaned = jsanalysis.clean({**body.model_dump(), "key": row.key})
    except jsanalysis.SignatureError as error:
        raise _refused(error) from None
    for name, value in cleaned.items():
        setattr(row, name, value)
    row.updated_at, row.updated_by = now_iso(), caller.actor
    word = "on" if row.enabled else "off"
    audit.record(
        db, caller.actor, "signature.update", f"Changed the script signature {row.key} ({word})", target=row.key
    )
    db.commit()
    jsanalysis.clear_cache()
    return jsanalysis.out(row)


@router.post("/{signature_id}/restore")
def restore_signature(
    signature_id: str, caller: Principal = Depends(rules_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Put a signature of Nik's own back as it ships, and on."""
    row = _get(db, signature_id)
    shipped = jsanalysis.builtin_definition(row.key) if row.builtin else None
    if shipped is None:
        raise HTTPException(status_code=409, detail="Only a signature Nik ships can be put back as it shipped")
    for name in ("title", "severity", "points", "pattern", "also", "enabled"):
        setattr(row, name, shipped[name])
    # "nik": nobody's change is in it any more, so it follows the releases again.
    row.updated_at, row.updated_by = now_iso(), "nik"
    audit.record(db, caller.actor, "signature.restore", f"Restored the script signature {row.key}", target=row.key)
    db.commit()
    jsanalysis.clear_cache()
    return jsanalysis.out(row)


@router.delete("/{signature_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_signature(
    signature_id: str, caller: Principal = Depends(rules_principal), db: OrmSession = Depends(get_db)
) -> Response:
    """Delete a signature of your own. One of Nik's is turned off instead."""
    row = _get(db, signature_id)
    if row.builtin:
        raise HTTPException(status_code=409, detail="A signature Nik ships is not deleted: turn it off instead")
    db.delete(row)
    audit.record(db, caller.actor, "signature.delete", f"Deleted the script signature {row.key}", target=row.key)
    db.commit()
    jsanalysis.clear_cache()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/validate")
def validate_signature(body: TryIn, _caller: Principal = Depends(rules_principal)) -> dict[str, Any]:
    """Check a signature without saving it, and try it on a piece of code:
    ``{ok, problem?, field?, matches?, finding?, timedOut?}``."""
    try:
        cleaned = jsanalysis.clean({**body.model_dump(exclude={"code"}), "key": body.key or "try.it"})
    except jsanalysis.SignatureError as error:
        return {"ok": False, "problem": error.message, "field": error.field}
    if not body.code:
        return {"ok": True}
    return {"ok": True, **jsanalysis.try_on(cleaned, body.code)}

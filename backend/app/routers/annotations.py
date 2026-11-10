"""Analysts' names and comments for the functions of a sample.

An annotation is keyed by the sample's SHA-256 and the function address, so
it is shared by every incident that holds the same file and survives a new
disassembly (addresses do not move). Saving both fields empty removes it.
"""

from __future__ import annotations

import re
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from ..core.db import get_db
from ..core.models import AuditEntry, FunctionAnnotation, Sample, SampleCode
from ..core.security import Principal, now_iso, principal, writer_principal
from ..malware.samples import is_sha256

router = APIRouter(tags=["samples"])

MAX_NAME = 128
MAX_COMMENT = 2000
# A name is shown in place of rizin's: one line, no control characters.
_NAME_RE = re.compile(r"^[^\x00-\x1f\x7f]+$")


class AnnotationIn(BaseModel):
    """The new name and comment; an empty or missing field clears it."""

    name: Optional[str] = None
    comment: Optional[str] = None


def _to_dict(row: FunctionAnnotation) -> dict:
    return {
        "addr": row.addr,
        "name": row.name,
        "comment": row.comment,
        "updatedAt": row.updated_at,
        "updatedBy": row.updated_by,
    }


def _known_functions(db: OrmSession, sha256: str) -> dict[int, str]:
    if not is_sha256(sha256) or db.get(Sample, sha256) is None:
        raise HTTPException(status_code=404, detail="Sample not found")
    code = db.get(SampleCode, sha256)
    if code is None or code.status != "done":
        raise HTTPException(status_code=409, detail="Disassemble the sample before annotating its functions.")
    return {fn.get("addr"): fn.get("name", "") for fn in (code.summary or {}).get("functions", [])}


def _clean(body: AnnotationIn) -> tuple[str | None, str | None]:
    name = (body.name or "").strip() or None
    comment = (body.comment or "").strip() or None
    if name is not None and (len(name) > MAX_NAME or not _NAME_RE.match(name)):
        raise HTTPException(status_code=400, detail=f"A name is one line of at most {MAX_NAME} characters.")
    if comment is not None and len(comment) > MAX_COMMENT:
        raise HTTPException(status_code=400, detail=f"A comment is at most {MAX_COMMENT} characters.")
    return name, comment


def delete_for_sample(db: OrmSession, sha256: str) -> None:
    """Remove a sample's annotations (called when the sample itself is deleted)."""
    for row in db.scalars(select(FunctionAnnotation).where(FunctionAnnotation.sha256 == sha256)).all():
        db.delete(row)


@router.get("/samples/{sha256}/annotations")
def list_annotations(sha256: str, _caller: Principal = Depends(principal), db: OrmSession = Depends(get_db)) -> dict:
    if not is_sha256(sha256) or db.get(Sample, sha256) is None:
        raise HTTPException(status_code=404, detail="Sample not found")
    rows = db.scalars(
        select(FunctionAnnotation).where(FunctionAnnotation.sha256 == sha256).order_by(FunctionAnnotation.addr)
    ).all()
    return {"annotations": [_to_dict(row) for row in rows]}


@router.put("/samples/{sha256}/annotations/{addr}")
def save_annotation(
    sha256: str,
    addr: int,
    body: AnnotationIn,
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
) -> dict | None:
    """Set a function's name and comment; null when both are empty (the annotation is removed)."""
    functions = _known_functions(db, sha256)
    if addr not in functions:
        raise HTTPException(status_code=404, detail="No function of this sample starts at this address")
    name, comment = _clean(body)
    row = db.get(FunctionAnnotation, (sha256, addr))
    label = name or functions[addr] or hex(addr)
    if name is None and comment is None:
        if row is None:
            return None
        db.delete(row)
        details = f"Cleared the annotation of {functions[addr] or hex(addr)} in sample {sha256[:12]}…"
        result = None
    else:
        if row is None:
            row = FunctionAnnotation(sha256=sha256, addr=addr)
            db.add(row)
        row.name, row.comment = name, comment
        row.updated_at, row.updated_by = now_iso(), caller.actor
        details = f"Annotated {functions[addr] or hex(addr)} as {label} in sample {sha256[:12]}…"
        result = row
    db.add(
        AuditEntry(id=str(uuid.uuid4()), at=now_iso(), actor=caller.actor, action="sample.annotate", details=details)
    )
    db.commit()
    return _to_dict(result) if result is not None else None

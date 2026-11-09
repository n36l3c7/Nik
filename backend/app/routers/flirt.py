"""Admin-managed FLIRT signatures for the analyzer worker.

Admins upload compiled signatures (.sig) or patterns (.pat) for the libraries
their samples link (a toolchain's runtime, a crate set); the worker applies
the enabled ones on top of rizin's bundled set at the next disassembly, so the
functions they match are recognised as library code and named.
"""

from __future__ import annotations

import hashlib
import uuid

from fastapi import APIRouter, Depends, File, Form, HTTPException, Response, UploadFile, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from .. import flirt
from ..db import get_db
from ..models import AuditEntry, FlirtSignature
from ..security import Principal, admin_principal, now_iso, principal

router = APIRouter(prefix="/flirt-signatures", tags=["flirt-signatures"])

MAX_NAME = 120


class FlirtSignatureUpdate(BaseModel):
    """Rename a signature or switch it on/off."""

    name: str
    enabled: bool = True


def _to_dict(row: FlirtSignature) -> dict:
    return {
        "id": row.id,
        "name": row.name,
        "fileName": row.file_name,
        "kind": row.kind,
        "size": row.size,
        "sha256": row.sha256,
        "enabled": row.enabled,
        "createdAt": row.created_at,
        "createdBy": row.created_by,
        "updatedAt": row.updated_at,
    }


def _audit(db: OrmSession, caller: Principal, action: str, details: str) -> None:
    db.add(AuditEntry(id=str(uuid.uuid4()), at=now_iso(), actor=caller.actor, action=action, details=details))


def _clean_name(name: str) -> str:
    cleaned = " ".join((name or "").split())
    if not cleaned:
        raise HTTPException(status_code=400, detail="The signature needs a name.")
    return cleaned[:MAX_NAME]


def _row_or_404(db: OrmSession, signature_id: str) -> FlirtSignature:
    row = db.get(FlirtSignature, signature_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Signature not found")
    return row


@router.get("")
def list_signatures(_caller: Principal = Depends(principal), db: OrmSession = Depends(get_db)) -> dict:
    """Uploaded signatures, oldest first (the order the worker applies them in)."""
    rows = db.scalars(select(FlirtSignature).order_by(FlirtSignature.created_at)).all()
    return {"signatures": [_to_dict(row) for row in rows]}


@router.post("", status_code=status.HTTP_201_CREATED)
async def upload_signature(
    name: str = Form(..., description="Display name, e.g. the library and version it covers."),
    file: UploadFile = File(..., description="A compiled FLIRT signature (.sig) or a pattern file (.pat)."),
    caller: Principal = Depends(admin_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Store a signature file; it applies from the next disassembly of each sample."""
    clean = _clean_name(name)
    data = await file.read(flirt.MAX_BYTES + 1)
    try:
        kind = flirt.kind_of(file.filename or "", data)
    except flirt.SignatureError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    now = now_iso()
    row = FlirtSignature(
        id=uuid.uuid4().hex,
        name=clean,
        file_name=(file.filename or f"signature.{kind}")[:255],
        kind=kind,
        size=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        enabled=True,
        created_at=now,
        created_by=caller.actor,
        updated_at=now,
    )
    flirt.write_file(row.id, kind, data)
    db.add(row)
    _audit(db, caller, "flirt.add", f"Added FLIRT signature {row.name} ({row.file_name})")
    db.commit()
    return _to_dict(row)


@router.put("/{signature_id}")
def update_signature(
    signature_id: str,
    body: FlirtSignatureUpdate,
    caller: Principal = Depends(admin_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    row = _row_or_404(db, signature_id)
    row.name = _clean_name(body.name)
    row.enabled = bool(body.enabled)
    row.updated_at = now_iso()
    state = "enabled" if row.enabled else "disabled"
    _audit(db, caller, "flirt.update", f"Updated FLIRT signature {row.name} ({state})")
    db.commit()
    return _to_dict(row)


@router.delete("/{signature_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_signature(
    signature_id: str, caller: Principal = Depends(admin_principal), db: OrmSession = Depends(get_db)
) -> Response:
    row = _row_or_404(db, signature_id)
    flirt.delete_file(row)
    db.delete(row)
    _audit(db, caller, "flirt.delete", f"Deleted FLIRT signature {row.name}")
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)

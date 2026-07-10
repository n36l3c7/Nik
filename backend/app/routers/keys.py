"""API-key management routes (admin session only).

API keys let external clients drive the platform without the browser (see the
``principal`` dependency in ``security.py``). Keys are created and revoked here
by an admin; the plaintext key is returned exactly once, at creation.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from ..db import get_db
from ..models import ApiKey, User
from ..schemas import ApiKeyCreate, ApiKeyCreated, ApiKeyOut, ApiKeysEnvelope
from ..security import generate_api_key, hash_api_key, now_iso, require_admin

router = APIRouter(prefix="/keys", tags=["api-keys"])


def _to_dict(key: ApiKey) -> dict:
    return {
        "id": key.id,
        "label": key.label,
        "prefix": key.prefix,
        "createdAt": key.created_at,
        "createdBy": key.created_by,
        "lastUsedAt": key.last_used_at,
    }


@router.get("", response_model=ApiKeysEnvelope)
def list_keys(
    _admin: User = Depends(require_admin), db: OrmSession = Depends(get_db)
) -> dict:
    """List every non-revoked API key (admin only). Secrets are never returned."""
    rows = db.scalars(
        select(ApiKey).where(ApiKey.revoked_at.is_(None)).order_by(ApiKey.created_at.desc())
    ).all()
    return {"keys": [_to_dict(k) for k in rows]}


@router.post("", response_model=ApiKeyCreated, status_code=status.HTTP_201_CREATED)
def create_key(
    body: ApiKeyCreate,
    admin: User = Depends(require_admin),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Create an API key (admin only).

    The response contains the plaintext ``key`` — shown only here. Store it
    securely; it cannot be retrieved again.
    """
    label = body.label.strip()
    if not label:
        raise HTTPException(status_code=400, detail="A label is required")

    token, prefix = generate_api_key()
    row = ApiKey(
        id=str(uuid.uuid4()),
        label=label,
        prefix=prefix,
        key_hash=hash_api_key(token),
        created_at=now_iso(),
        created_by=admin.username,
    )
    db.add(row)
    db.commit()
    return {"key": token, "apiKey": _to_dict(row)}


@router.delete("/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_key(
    key_id: str,
    _admin: User = Depends(require_admin),
    db: OrmSession = Depends(get_db),
):
    """Revoke an API key (admin only). Idempotent-ish: 404 only if unknown."""
    row = db.get(ApiKey, key_id)
    if row is None or row.revoked_at is not None:
        raise HTTPException(status_code=404, detail="API key not found")
    row.revoked_at = now_iso()
    db.commit()
    # 204 No Content

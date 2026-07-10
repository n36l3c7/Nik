"""API-key management routes (admin only).

API keys let external clients drive the platform without the browser (see the
``principal`` dependency in ``security.py``). An admin — whether signed in via
the browser or authenticating with an **admin API key** — creates and revokes
keys here and sets each key's permissions (role + scopes + optional expiry).
The plaintext key is returned exactly once, at creation.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from ..db import get_db
from ..models import ApiKey
from ..schemas import ApiKeyCreate, ApiKeyCreated, ApiKeyOut, ApiKeysEnvelope
from ..security import (
    SCOPE_READ,
    SCOPE_WRITE,
    Principal,
    admin_principal,
    generate_api_key,
    hash_api_key,
    normalize_scopes,
    now_iso,
)

router = APIRouter(prefix="/keys", tags=["api-keys"])


def _to_dict(key: ApiKey) -> dict:
    return {
        "id": key.id,
        "label": key.label,
        "prefix": key.prefix,
        "role": key.role,
        "scopes": (key.scopes or "").split(",") if key.scopes else [],
        "createdAt": key.created_at,
        "createdBy": key.created_by,
        "expiresAt": key.expires_at,
        "lastUsedAt": key.last_used_at,
    }


@router.get("", response_model=ApiKeysEnvelope)
def list_keys(
    _admin: Principal = Depends(admin_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """List every non-revoked API key (admin only). Secrets are never returned."""
    rows = db.scalars(
        select(ApiKey).where(ApiKey.revoked_at.is_(None)).order_by(ApiKey.created_at.desc())
    ).all()
    return {"keys": [_to_dict(k) for k in rows]}


@router.post("", response_model=ApiKeyCreated, status_code=status.HTTP_201_CREATED)
def create_key(
    body: ApiKeyCreate,
    admin: Principal = Depends(admin_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Create an API key (admin only).

    The permissions are set here and bound to the key: ``role`` decides whether
    the key can reach the admin-data endpoints, ``scopes`` restricts read/write.
    The response contains the plaintext ``key`` — shown only here.
    """
    label = body.label.strip()
    if not label:
        raise HTTPException(status_code=400, detail="A label is required")

    role = body.role if body.role in {"admin", "analyst"} else "analyst"
    # Default an analyst key to read+write when scopes are not specified.
    requested = body.scopes if body.scopes is not None else [SCOPE_READ, SCOPE_WRITE]
    scopes = normalize_scopes(requested, role)

    expires_at = None
    if body.expiresInDays is not None:
        if body.expiresInDays <= 0:
            raise HTTPException(status_code=400, detail="expiresInDays must be positive")
        expires_at = (
            datetime.now(timezone.utc) + timedelta(days=body.expiresInDays)
        ).isoformat()

    token, prefix = generate_api_key()
    row = ApiKey(
        id=str(uuid.uuid4()),
        label=label,
        prefix=prefix,
        key_hash=hash_api_key(token),
        role=role,
        scopes=",".join(scopes),
        created_at=now_iso(),
        created_by=admin.actor,
        expires_at=expires_at,
    )
    db.add(row)
    db.commit()
    return {"key": token, "apiKey": _to_dict(row)}


@router.delete("/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_key(
    key_id: str,
    _admin: Principal = Depends(admin_principal),
    db: OrmSession = Depends(get_db),
):
    """Revoke an API key (admin only). Idempotent-ish: 404 only if unknown."""
    row = db.get(ApiKey, key_id)
    if row is None or row.revoked_at is not None:
        raise HTTPException(status_code=404, detail="API key not found")
    row.revoked_at = now_iso()
    db.commit()
    # 204 No Content

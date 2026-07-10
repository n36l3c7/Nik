"""Webhook subscription management (admin only).

Register URLs that receive HMAC-signed POSTs when incident/note/upload events
happen (see ``app/events.py``). The signing secret is returned once, at
creation.
"""

from __future__ import annotations

import secrets
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from ..db import get_db
from ..events import KNOWN_EVENTS
from ..models import Webhook
from ..schemas import WebhookCreate, WebhookCreated, WebhookOut, WebhooksEnvelope
from ..security import Principal, admin_principal, now_iso

router = APIRouter(prefix="/webhooks", tags=["webhooks"])


def _to_dict(w: Webhook) -> dict:
    return {
        "id": w.id,
        "url": w.url,
        "events": (w.events or "").split(",") if w.events else [],
        "active": w.active,
        "createdAt": w.created_at,
        "createdBy": w.created_by,
    }


@router.get("", response_model=WebhooksEnvelope)
def list_webhooks(
    _admin: Principal = Depends(admin_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """List webhook subscriptions (admin only). Secrets are never returned."""
    rows = db.scalars(select(Webhook).order_by(Webhook.created_at.desc())).all()
    return {"webhooks": [_to_dict(w) for w in rows]}


@router.post("", response_model=WebhookCreated, status_code=status.HTTP_201_CREATED)
def create_webhook(
    body: WebhookCreate,
    admin: Principal = Depends(admin_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Register a webhook (admin only). Returns the signing secret once.

    Valid events: incident.created, incident.updated, incident.deleted,
    note.added, upload.completed.
    """
    url = body.url.strip()
    if not url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="url must be an http(s) URL")
    events = [e for e in body.events if e in KNOWN_EVENTS]
    if not events:
        raise HTTPException(status_code=400, detail=f"Provide at least one known event: {', '.join(KNOWN_EVENTS)}")

    secret = "whsec_" + secrets.token_urlsafe(24)
    row = Webhook(
        id=str(uuid.uuid4()),
        url=url,
        secret=secret,
        events=",".join(events),
        active=True,
        created_at=now_iso(),
        created_by=admin.actor,
    )
    db.add(row)
    db.commit()
    return {"webhook": _to_dict(row), "secret": secret}


@router.delete("/{webhook_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_webhook(
    webhook_id: str,
    _admin: Principal = Depends(admin_principal),
    db: OrmSession = Depends(get_db),
):
    """Delete a webhook subscription (admin only)."""
    row = db.get(Webhook, webhook_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Webhook not found")
    db.delete(row)
    db.commit()
    # 204 No Content

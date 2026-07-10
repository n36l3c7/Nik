"""Outbound webhook events.

Handlers call ``emit(...)`` with a BackgroundTasks so delivery happens after the
response is sent (fire-and-forget, short timeout). Each POST is signed with the
subscription's secret so the receiver can verify it:

    HMAC-SHA256(secret, raw_body)  →  header ``X-Nik-Signature: sha256=<hex>``
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import urllib.request
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from .models import Webhook

logger = logging.getLogger("nik.webhooks")

# Event names a webhook may subscribe to.
KNOWN_EVENTS = (
    "incident.created",
    "incident.updated",
    "incident.deleted",
    "note.added",
    "upload.completed",
)


def sign(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def _deliver(url: str, secret: str, event: str, data: dict) -> None:
    body = json.dumps(
        {"event": event, "at": datetime.now(timezone.utc).isoformat(), "data": data}
    ).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "User-Agent": "nik-webhooks/1.0",
            "X-Nik-Event": event,
            "X-Nik-Signature": sign(secret, body),
        },
    )
    try:
        urllib.request.urlopen(req, timeout=5).read()  # noqa: S310 (operator-configured URL)
    except Exception as exc:  # pragma: no cover - network best-effort
        logger.warning("webhook delivery to %s failed: %s", url, exc)


def emit(db: OrmSession, background_tasks, event: str, data: dict) -> None:
    """Schedule delivery of ``event`` to every active subscribed webhook."""
    if background_tasks is None:
        return
    for hook in _subscribers(db, event):
        background_tasks.add_task(_deliver, hook.url, hook.secret, event, data)


def emit_now(db: OrmSession, event: str, data: dict) -> None:
    """Deliver synchronously (used from a background job that has no request)."""
    for hook in _subscribers(db, event):
        _deliver(hook.url, hook.secret, event, data)


def _subscribers(db: OrmSession, event: str):
    hooks = db.scalars(select(Webhook).where(Webhook.active.is_(True))).all()
    return [h for h in hooks if event in (h.events or "").split(",")]

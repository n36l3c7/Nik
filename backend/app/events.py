"""Outbound webhook events.

Handlers call ``emit(...)`` with a BackgroundTasks so delivery happens after the
response is sent (fire-and-forget, short timeout). Each POST is signed with the
subscription's secret so the receiver can verify it:

    HMAC-SHA256(secret, raw_body)  →  header ``X-Nik-Signature: sha256=<hex>``

**When.** A webhook is told of a change only once the change is committed:
``emit`` runs after the response of the request that made it, and
``emit_detached``, for callers that are not a request, waits for the commit
of the session it is given and is dropped when that transaction is rolled
back. So a webhook never hears of something that did not happen. Delivery is
then tried once: a server that stops between the commit and the request has
not told the webhook, and does not tell it later (at most once; what must
not be missed is a playbook's work, which reads the outbox of
``automation/triggers.py`` exactly once).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import urllib.request

from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from .core.clock import now_iso
from .core.models import Webhook

logger = logging.getLogger("nik.webhooks")

# Event names a webhook may subscribe to.
KNOWN_EVENTS = (
    "incident.created",
    "incident.updated",
    "incident.deleted",
    "note.added",
    "upload.completed",
    "ioc.watch_hit",
    "mail.analysed",
    "file.analysed",
    "code.analysed",
    "capabilities.analysed",
    "capture.analysed",
    "url.analysed",
    "ioc.verdict_changed",
    "storage.low",
    "sla.breached",
    "artifact.expiring",
    "artifact.expired",
)


def sign(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def _deliver(url: str, secret: str, event: str, data: dict) -> None:
    from .core import copy

    if copy.is_copy():
        logger.info("Webhook %s to %s not sent: this server is a copy", event, url)
        return
    body = json.dumps({"event": event, "at": now_iso(), "data": data}).encode("utf-8")
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
    except Exception as exc:  # noqa: BLE001 - a receiver that does not answer must not fail what happened
        logger.warning("Webhook delivery to %s failed: %s", url, exc)


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


_PENDING = "nik_webhooks_pending"


def _send_pending(session) -> None:
    import threading

    for url, secret, event, data in session.info.pop(_PENDING, []):
        threading.Thread(target=_deliver, args=(url, secret, event, data), daemon=True).start()


def _drop_pending(session) -> None:
    session.info.pop(_PENDING, None)


def emit_detached(db: OrmSession, event: str, data: dict) -> None:
    """Deliver from a thread of its own, for callers with no BackgroundTasks: once the transaction
    of ``db`` is committed, and not at all when it is rolled back."""
    from sqlalchemy import event as sa_event

    hooks = [(hook.url, hook.secret, event, data) for hook in _subscribers(db, event)]
    if not hooks:
        return
    if _PENDING not in db.info and not db.info.get(_PENDING + "_listening"):
        db.info[_PENDING + "_listening"] = True
        sa_event.listen(db, "after_commit", _send_pending)
        sa_event.listen(db, "after_rollback", _drop_pending)
    db.info.setdefault(_PENDING, []).extend(hooks)


def _subscribers(db: OrmSession, event: str):
    hooks = db.scalars(select(Webhook).where(Webhook.active.is_(True))).all()
    return [h for h in hooks if event in (h.events or "").split(",")]

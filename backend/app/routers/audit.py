"""Audit-log routes.

The log is written by the server: each handler records what it does (see
``core/audit.py``). The only entries a browser may add are the actions that
happen in the browser alone, with no request the server could record
(``CLIENT_ACTIONS``); the id, timestamp and actor are always the server's.

The log is a chain (``app/auditlog``): the routes under ``/audit/chain`` say
where it stands and walk it, those under ``/audit/forwarding`` set where it
is sent as it is written. Reading the chain and walking it is open to
whoever reads the log. The forwarding is the administrators'; changing it,
testing it and removing old entries need a signed-in administrator
(``admin_session``): whoever holds a key alone must not be able to point the
log elsewhere, turn its forwarding off, or remove entries.
"""

from __future__ import annotations

import re
import time
import uuid
from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Response, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session as OrmSession

from .. import query
from ..auditlog import chain, forward
from ..core import audit
from ..core.config import settings as app_settings
from ..core.db import get_db
from ..core.models import AuditEntry
from ..core.schemas import AuditEnvelope, AuditIn, AuditOut
from ..core.security import (
    Principal,
    admin_principal,
    admin_session,
    audit_principal,
    now_iso,
    reader_principal,
)

router = APIRouter(prefix="/audit", tags=["audit"])

# Maximum number of entries returned by the list endpoint.
MAX_ENTRIES = 5000
# Done in the browser only (a file built and downloaded there): reported by it.
CLIENT_ACTIONS = {"incident.export"}


def _entry_to_dict(entry: AuditEntry) -> dict:
    """Convert an AuditEntry ORM object into the API representation."""
    return {
        "id": entry.id,
        "at": entry.at,
        "actor": entry.actor,
        "action": entry.action,
        "target": entry.target,
        "details": entry.details,
        "incidentId": entry.incident_id,
        "incidentName": entry.incident_name,
        # Its place in the chain: nothing until the transaction that wrote it committed.
        "seq": entry.seq,
        "prev": entry.prev_hash,
        "hash": entry.hash,
        # "import" for an entry that came in a file of content from another server.
        "origin": entry.origin,
        "mac": entry.mac,
        "keyId": entry.key_id,
    }


@router.get("", response_model=AuditEnvelope)
def list_audit(
    response: Response,
    caller: Principal = Depends(audit_principal),
    db: OrmSession = Depends(get_db),
    limit: int | None = Query(None, ge=1, le=MAX_ENTRIES, description="Page size (default: up to MAX_ENTRIES)."),
    offset: int = Query(0, ge=0),
    q: str | None = Query(
        None,
        max_length=2000,
        description="A query: `action:user.* at:>=yesterday`; plain words match actor, action, details, incident.",
    ),
    actor: str | None = Query(None),
    incident_id: str | None = Query(None, alias="incidentId"),
) -> dict:
    """Return audit entries newest-first, filterable and paginated.

    Backward compatible: with no params it returns up to ``MAX_ENTRIES`` entries.
    The total matching count is in the ``X-Total-Count`` header.
    """
    conditions = query.sql("audit", q, caller) if q and q.strip() else []
    if conditions:
        query.statement_timeout(db)
    if actor:
        conditions.append(AuditEntry.actor.ilike(f"%{actor}%"))
    if incident_id:
        conditions.append(AuditEntry.incident_id == incident_id)

    total = db.scalar(select(func.count()).select_from(AuditEntry).where(*conditions)) or 0
    response.headers["X-Total-Count"] = str(total)

    stmt = select(AuditEntry).where(*conditions).order_by(AuditEntry.at.desc())
    stmt = stmt.offset(offset).limit(limit if limit is not None else MAX_ENTRIES)
    rows = db.scalars(stmt).all()
    return {"entries": [_entry_to_dict(r) for r in rows]}


@router.post("", response_model=AuditOut, status_code=status.HTTP_201_CREATED)
def create_audit(
    body: AuditIn,
    caller: Principal = Depends(reader_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Record an action that happened in the browser only (``incident.export``).

    Everything else is recorded by the server when it happens, so any other
    action is refused: the log cannot be written by hand.
    """
    if body.action not in CLIENT_ACTIONS:
        raise HTTPException(status_code=400, detail="This action is recorded by the server")
    entry = AuditEntry(
        id=str(uuid.uuid4()),
        at=now_iso(),
        actor=caller.actor,  # server-authoritative
        action=body.action,
        target=body.target,
        details=body.details or "",
        incident_id=body.incidentId,
        incident_name=body.incidentName,
    )
    db.add(entry)
    db.commit()
    return _entry_to_dict(entry)


@router.delete("")
def clear_audit(
    older_than_days: int | None = Query(None, alias="olderThanDays", ge=1, le=36500),
    admin: Principal = Depends(admin_session),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Remove old entries (a signed-in administrator): all of them, or with ``olderThanDays``
    those from the start of the log that are older. The chain keeps an ``audit.trim`` entry
    that says how many went, their numbers and the hash of the last, so it still verifies.
    While the log is forwarded, an entry that was not sent yet stays."""
    removed = chain.trim(db, admin.actor, older_than_days=older_than_days)
    db.commit()
    return {"removed": removed, "entries": db.scalar(select(func.count()).select_from(AuditEntry)) or 0}


# --------------------------------------------------------------------------- #
# The chain                                                                   #
# --------------------------------------------------------------------------- #
_HASH = re.compile(r"^[0-9a-f]{64}$")


@router.get("/chain")
def read_chain(_: Principal = Depends(audit_principal), db: OrmSession = Depends(get_db)) -> dict:
    """Where the chain of the log stands: its head, how far it was verified and when, the
    problem the last walk found (``kind``, ``seq``, ``text``) or none."""
    return chain.out(db)


@router.post("/chain/verify")
def verify_chain(
    body: dict[str, Any] = Body(default={}),
    caller: Principal = Depends(audit_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Walk the chain now. ``full`` reads every entry (otherwise only what was added since the
    last good walk); ``head`` (``{"seq": …, "hash": "…"}``) is a head noted outside the server,
    such as the last checkpoint the syslog receiver got: the end of the log is held against it."""
    outside = None
    given = body.get("head")
    if given:
        seq = given.get("seq") if isinstance(given, dict) else None
        held = str(given.get("hash") or "").strip().lower() if isinstance(given, dict) else ""
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1 or not _HASH.match(held):
            raise HTTPException(
                status_code=422, detail="A head is the number of an entry and its hash (64 hexadecimal digits)."
            )
        outside = (seq, held)
    chain.link_strays()
    state = chain.verify(db, full=bool(body.get("full")), outside=outside)
    problem = state.get("problem")
    audit.record(
        db,
        caller.actor,
        "audit.verify",
        f"Verified the audit log: {problem['text']}"
        if problem
        else f"Verified the audit log: it holds up to entry {(state.get('verified') or {}).get('seq')}",
        target="audit log",
    )
    db.commit()
    return chain.out(db)


# --------------------------------------------------------------------------- #
# Forwarding to syslog                                                        #
# --------------------------------------------------------------------------- #
@router.get("/forwarding")
def read_forwarding(_: Principal = Depends(admin_principal), db: OrmSession = Depends(get_db)) -> dict:
    """Where the log is sent as it is written, and how that stands: the receiver in force, the
    backlog, the last error. The key of a client certificate is never returned."""
    return forward.out(db)


@router.put("/forwarding")
def write_forwarding(
    body: dict[str, Any] = Body(...), caller: Principal = Depends(admin_session), db: OrmSession = Depends(get_db)
) -> dict:
    """Change the forwarding (only the keys that are sent change). The change is an audit entry,
    and takes effect once the receiver that was set before took that entry: turning the
    forwarding off, or pointing it elsewhere, is the last thing the old receiver hears."""
    try:
        forward.write(db, body, caller.actor)
    except forward.ConfigError as error:
        raise HTTPException(status_code=422, detail=str(error)) from None
    db.commit()
    return forward.out(db)


@router.post("/forwarding/test")
def test_forwarding(caller: Principal = Depends(admin_session), db: OrmSession = Depends(get_db)) -> dict:
    """Send a marked test message to the receiver that is saved, over a connection of its own,
    and say what the socket said. The process that forwards does it (the backend has no way
    out), so the answer can take a few seconds."""
    if not forward.ready(forward.read(db)):
        raise HTTPException(status_code=409, detail="Save a receiver first.")
    if app_settings.AUTOMATION_WORKER == "off":
        raise HTTPException(
            status_code=409,
            detail="The log is sent by the automation worker, and AUTOMATION_WORKER is off on this server.",
        )
    request = forward.ask_test(db)
    audit.record(
        db,
        caller.actor,
        "audit.forward.test",
        f"Tested the syslog receiver {forward.destination(forward.read(db))}",
        target="audit log forwarding",
    )
    db.commit()
    deadline = time.time() + forward.TEST_ANSWER_WITHIN
    while time.time() < deadline:
        db.rollback()  # a new look at the row, and no transaction held while waiting
        answer = forward.test_answer(db, request)
        if answer is not None:
            return answer
        time.sleep(0.5)
    return {
        "ok": False,
        "message": "The automation worker, which sends the log, did not answer. "
        "Its state is in Settings → System → Workers.",
    }

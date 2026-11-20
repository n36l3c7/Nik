"""Moving content from one Nik to another, as one file (admin only).

``GET /backup/export`` returns a single JSON envelope with the incidents (full
documents, imported artifacts included), the accounts (with their bcrypt
password hashes), the audit log and the detection settings.
``POST /backup/import`` **adds** what such a file holds to this server.

This was the "Full backup" of releases before 6.7, and its import then
replaced everything: it deleted every account, every incident and every row
of ``settings`` and made them again from the file. A file that carries four
things cannot stand for a server that holds many more (second factors,
sessions, stored credentials, instances, the backup passphrase, whatever a
later release adds): whatever it did not carry was lost without a word. So
the import no longer deletes or changes anything:

- an **incident** whose id is not here is added, with the number it had when
  that number is free; one that is here already is left as it is;
- an **account** whose name is not here is added, with the roles and the
  password hash of the file; one that is here is left as it is, password,
  roles and everything else;
- an **audit entry** whose id is not here is added;
- the **detection settings** are taken only by a server that has none yet;
- nothing else is read from the file, and no table is emptied.

Bringing a server back is the job of the backups Nik takes by itself
(``app/backups``): they hold the whole database and every file.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session as OrmSession

from ..browser_profiles import normalize_browser_data
from ..core.db import get_db
from ..core.models import AuditEntry, Incident, Setting, User
from ..core.permissions import RoleError, clean_roles, stored_roles
from ..core.security import Principal, admin_principal, now_iso
from ..iocs import reindex_incident
from .incidents import _sync_columns
from .settings import SETTINGS_ID

router = APIRouter(prefix="/backup", tags=["backup"])

logger = logging.getLogger("nik.backup")

BACKUP_TYPE = "backup"
BACKUP_VERSION = 1


def _log(db: OrmSession, actor: str, action: str, details: str) -> None:
    """Append an audit entry (id/at stamped here, actor from the session)."""
    db.add(
        AuditEntry(
            id=str(uuid.uuid4()),
            at=now_iso(),
            actor=actor,
            action=action,
            target=None,
            details=details,
        )
    )


def _backup_roles(user: dict) -> list[str]:
    """The roles of an account in a backup: its ``roles``, or what the single
    ``role`` of a backup taken before 4.0 stands for. Such a file can still be
    restored, and every account in it must come out able to do what it could."""
    try:
        return clean_roles(user.get("roles"))
    except RoleError:
        role = user.get("role")
        return [role] if role in ("admin", "viewer") else ["analyst"]


@router.get("/export")
def export_backup(caller: Principal = Depends(admin_principal), db: OrmSession = Depends(get_db)) -> dict:
    """Return the incidents, the accounts, the audit log and the detection settings as one
    envelope (admin session or admin key), to add them to another Nik.

    The envelope contains password hashes: treat the downloaded file as a
    secret. It is not a backup of the server: see the module docstring.
    """
    # The system account of the automation engine is made again where it is needed.
    users = [
        u for u in db.scalars(select(User).order_by(User.created_at)).all() if stored_roles(u.roles) != ["automation"]
    ]
    incidents = db.scalars(select(Incident).order_by(Incident.updated_at.desc())).all()
    audit = db.scalars(select(AuditEntry).order_by(AuditEntry.at.desc())).all()
    setting_row = db.get(Setting, SETTINGS_ID)

    _log(db, caller.actor, "backup.export", "Exported incidents, accounts, the audit log and the detection settings")
    db.commit()

    return {
        "app": "Nik",
        "type": BACKUP_TYPE,
        "version": BACKUP_VERSION,
        "exportedAt": now_iso(),
        "users": [
            {
                "id": u.id,
                "username": u.username,
                "passwordHash": u.password_hash,
                "roles": stored_roles(u.roles),
                "createdAt": u.created_at,
                "createdBy": u.created_by,
            }
            for u in users
        ],
        # With its number: a restore gives every incident the number it had.
        "incidents": [{**(row.doc or {}), "number": row.number} for row in incidents],
        "audit": [
            {
                "id": e.id,
                "at": e.at,
                "actor": e.actor,
                "action": e.action,
                "target": e.target,
                "details": e.details,
                "incidentId": e.incident_id,
                "incidentName": e.incident_name,
            }
            for e in audit
        ],
        "settings": (setting_row.doc or None) if setting_row is not None else None,
    }


def _validate_envelope(body: dict[str, Any]) -> tuple[list, list, list, dict | None]:
    """Validate the backup envelope shape; raise 400 with a clear message."""

    def bad(message: str) -> HTTPException:
        return HTTPException(status_code=400, detail=message)

    if not isinstance(body, dict) or body.get("type") != BACKUP_TYPE:
        raise bad("Not a file exported by Nik: the export of Settings → Backup is expected.")

    users = body.get("users")
    incidents = body.get("incidents", [])
    audit = body.get("audit", [])
    settings_doc = body.get("settings")

    if not isinstance(users, list) or len(users) == 0:
        raise bad("Invalid backup: the 'users' list is missing or empty.")
    if not isinstance(incidents, list) or not isinstance(audit, list):
        raise bad("Invalid backup: 'incidents' and 'audit' must be lists.")
    if settings_doc is not None and not isinstance(settings_doc, dict):
        raise bad("Invalid backup: 'settings' must be an object or null.")

    seen_ids: set[str] = set()
    seen_names: set[str] = set()
    for u in users:
        if not isinstance(u, dict):
            raise bad("Invalid backup: every user must be an object.")
        if not (u.get("id") and u.get("username") and u.get("passwordHash")):
            raise bad("Invalid backup: users need id, username and passwordHash.")
        uid, uname = str(u["id"]), str(u["username"]).lower()
        if uid in seen_ids or uname in seen_names:
            raise bad(f"Invalid backup: duplicate user '{u['username']}'.")
        seen_ids.add(uid)
        seen_names.add(uname)

    for doc in incidents:
        if not isinstance(doc, dict) or not doc.get("id"):
            raise bad("Invalid backup: every incident needs an id.")

    return users, incidents, audit, settings_doc


@router.post("/import")
def import_backup(
    body: dict[str, Any] = Body(...),
    caller: Principal = Depends(admin_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Add the content of an exported file to this server (admin session or key).

    Nothing that is here is changed or deleted: what the file holds and the
    server does not is added, the rest is counted as skipped. All or nothing.
    """
    users, incidents, audit, settings_doc = _validate_envelope(body)
    added = {"users": 0, "incidents": 0, "audit": 0}
    try:
        names = {str(name).lower() for name in db.scalars(select(User.username))}
        ids = set(db.scalars(select(User.id)))
        for u in users:
            if str(u["username"]).lower() in names:
                continue
            names.add(str(u["username"]).lower())
            user_id = str(u["id"]) if str(u["id"]) not in ids else str(uuid.uuid4())
            ids.add(user_id)
            db.add(
                User(
                    id=user_id,
                    username=str(u["username"]),
                    password_hash=str(u["passwordHash"]),
                    roles=_backup_roles(u),
                    created_at=str(u.get("createdAt") or now_iso()),
                    created_by=u.get("createdBy"),
                )
            )
            added["users"] += 1

        here = set(db.scalars(select(Incident.id)))
        numbered = {number for number in db.scalars(select(Incident.number)) if number is not None}
        fresh: list[Incident] = []
        # The ones with a number first, so that those without get numbers after them.
        for doc in sorted(incidents, key=lambda doc: not isinstance(doc.get("number"), int)):
            if str(doc["id"]) in here:
                continue
            here.add(str(doc["id"]))
            doc = dict(doc)
            normalize_browser_data(doc)  # files written before 2.0.0
            # The number it had, when the file holds one that is still free; a new one otherwise.
            number = doc.pop("number", None)
            doc.pop("uuid", None)
            if not isinstance(number, int) or isinstance(number, bool) or number <= 0 or number in numbered:
                number = None
            else:
                numbered.add(number)
            row = Incident(id=str(doc["id"]), doc=doc, number=number)
            _sync_columns(row)
            db.add(row)
            fresh.append(row)
            added["incidents"] += 1

        seen = set(db.scalars(select(AuditEntry.id)))
        for e in audit:
            if not isinstance(e, dict):
                continue
            entry_id = str(e.get("id") or uuid.uuid4())
            if entry_id in seen:
                continue
            seen.add(entry_id)
            db.add(
                AuditEntry(
                    id=entry_id,
                    at=str(e.get("at") or now_iso()),
                    actor=str(e.get("actor") or "unknown"),
                    action=str(e.get("action") or "unknown"),
                    target=e.get("target"),
                    details=str(e.get("details") or ""),
                    incident_id=e.get("incidentId"),
                    incident_name=e.get("incidentName"),
                )
            )
            added["audit"] += 1

        # The indicators of the incidents that arrived.
        db.flush()
        for row in fresh:
            reindex_incident(db, row, alerts=False)

        settings_taken = False
        if settings_doc is not None and db.get(Setting, SETTINGS_ID) is None:
            db.add(Setting(id=SETTINGS_ID, doc=settings_doc))
            settings_taken = True

        _log(
            db,
            caller.actor,
            "backup.import",
            f"Imported a file of content: added {added['users']} of {len(users)} accounts, "
            f"{added['incidents']} of {len(incidents)} incidents, {added['audit']} of {len(audit)} audit entries "
            "(they join the chain of this server here, with the time and the author the file gives them); "
            "nothing that was here was changed",
        )
        db.commit()
    except HTTPException:
        db.rollback()
        raise
    except SQLAlchemyError as exc:
        db.rollback()
        logger.exception("The import of a file of content failed")
        raise HTTPException(
            status_code=400, detail="Import failed: the file is inconsistent. Nothing was changed."
        ) from exc

    return {
        "users": added["users"],
        "incidents": added["incidents"],
        "audit": added["audit"],
        "skipped": {
            "users": len(users) - added["users"],
            "incidents": len(incidents) - added["incidents"],
            "audit": len(audit) - added["audit"],
        },
        "settingsRestored": settings_taken,
    }

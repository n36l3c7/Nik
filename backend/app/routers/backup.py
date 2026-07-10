"""Full-platform backup routes (admin only).

``GET /backup/export`` returns a single JSON envelope with EVERYTHING the
platform stores — users (including their bcrypt password hashes), incidents
(full documents, imported artifacts included), the audit log and the shared
settings. ``POST /backup/import`` restores such an envelope, replacing the
current database content wholesale.

Restore semantics (single transaction — all-or-nothing):

- All existing rows are deleted (sessions, audit log, incidents, settings,
  users) and replaced by the imported ones.
- The importing admin is never locked out: if their username exists in the
  backup, their session is re-attached to that account (whose password becomes
  the one from the backup); otherwise their current account is re-inserted
  unchanged alongside the imported users.
- The session cookie keeps working across the restore (same token, fresh
  expiry), so the client only needs to reload its data.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Body, Cookie, Depends, HTTPException
from sqlalchemy import delete as sa_delete
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session as OrmSession

from ..config import settings as app_settings
from ..db import get_db
from ..models import AuditEntry, Incident, Setting, User
from ..models import Session as SessionModel
from ..security import Principal, admin_principal, now_iso
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


@router.get("/export")
def export_backup(
    caller: Principal = Depends(admin_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Return a full backup envelope of the platform (admin session or admin key).

    The envelope contains password hashes: treat the downloaded file as a
    secret, like any database dump.
    """
    users = db.scalars(select(User).order_by(User.created_at)).all()
    incidents = db.scalars(select(Incident).order_by(Incident.updated_at.desc())).all()
    audit = db.scalars(select(AuditEntry).order_by(AuditEntry.at.desc())).all()
    setting_row = db.get(Setting, SETTINGS_ID)

    _log(db, caller.actor, "backup.export", "Exported a full platform backup")
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
                "role": u.role,
                "createdAt": u.created_at,
                "createdBy": u.created_by,
            }
            for u in users
        ],
        "incidents": [row.doc for row in incidents],
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
        raise bad("Not a Nik backup file: a full-backup export is expected.")

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
    nik_session: str | None = Cookie(default=None),
) -> dict:
    """Restore a full backup, replacing ALL current data (admin session or key).

    A signed-in admin is preserved and kept logged in across the restore. An
    admin **API key** has no user account to preserve — the restore simply
    replaces the users from the backup; the key itself (in a separate table) is
    untouched, so it keeps working afterwards.
    """
    users, incidents, audit, settings_doc = _validate_envelope(body)

    # Snapshot the importing admin (session callers only) before wiping.
    session_admin = caller.user
    keep_admin = (
        {
            "id": session_admin.id,
            "username": session_admin.username,
            "password_hash": session_admin.password_hash,
            "role": session_admin.role,
            "created_at": session_admin.created_at,
            "created_by": session_admin.created_by,
        }
        if session_admin is not None
        else None
    )

    try:
        # 1. Wipe everything. Sessions first (FK on users). The Core deletes
        #    bypass the ORM identity map, so detach every tracked object (e.g.
        #    the `admin` row loaded by require_admin) or re-inserting the same
        #    primary keys would conflict at flush time.
        db.execute(sa_delete(SessionModel))
        db.execute(sa_delete(AuditEntry))
        db.execute(sa_delete(Incident))
        db.execute(sa_delete(Setting))
        db.execute(sa_delete(User))
        db.expunge_all()

        # 2. Insert the imported users.
        imported_by_name: dict[str, User] = {}
        for u in users:
            row = User(
                id=str(u["id"]),
                username=str(u["username"]),
                password_hash=str(u["passwordHash"]),
                role=u.get("role") if u.get("role") in {"admin", "analyst"} else "analyst",
                created_at=str(u.get("createdAt") or now_iso()),
                created_by=u.get("createdBy"),
            )
            db.add(row)
            imported_by_name[row.username.lower()] = row

        # 3. Keep the importing admin signed in and never locked out — but only
        #    for a session caller. An admin API key has no account to preserve;
        #    the key itself lives in a separate table and survives the wipe.
        if keep_admin is not None:
            session_user = imported_by_name.get(keep_admin["username"].lower())
            if session_user is None:
                # Their account is not in the backup: re-insert it unchanged
                # (with a fresh id if an imported user already took theirs).
                admin_id = keep_admin["id"]
                if any(str(u["id"]) == admin_id for u in users):
                    admin_id = str(uuid.uuid4())
                session_user = User(
                    id=admin_id,
                    username=keep_admin["username"],
                    password_hash=keep_admin["password_hash"],
                    role="admin",
                    created_at=keep_admin["created_at"],
                    created_by=keep_admin["created_by"],
                )
                db.add(session_user)

            # 4. Re-attach the current session token to the surviving account so
            #    the cookie keeps working after the restore (fresh expiry). Flush
            #    the users first: sessions.user_id has a FK on users.id.
            db.flush()
            if nik_session:
                created = datetime.now(timezone.utc)
                expires = created + timedelta(hours=app_settings.SESSION_TTL_HOURS)
                db.add(
                    SessionModel(
                        token=nik_session,
                        user_id=session_user.id,
                        created_at=created.isoformat(),
                        expires_at=expires.isoformat(),
                    )
                )

        # 5. Incidents (mirror the scalar columns used for listing/sorting).
        for doc in incidents:
            row = Incident(id=str(doc["id"]), doc=doc)
            _sync_columns(row)
            db.add(row)

        # 6. Audit log (dedupe ids defensively so one bad file can't 500 us).
        seen_audit: set[str] = set()
        for e in audit:
            if not isinstance(e, dict):
                continue
            entry_id = str(e.get("id") or uuid.uuid4())
            if entry_id in seen_audit:
                continue
            seen_audit.add(entry_id)
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

        # 7. Shared settings.
        if settings_doc is not None:
            db.add(Setting(id=SETTINGS_ID, doc=settings_doc))

        # 8. Record the restore itself in the (restored) audit log.
        _log(
            db,
            caller.actor,
            "backup.import",
            f"Restored a full backup: {len(users)} users, "
            f"{len(incidents)} incidents, {len(seen_audit)} audit entries",
        )

        db.commit()
    except HTTPException:
        db.rollback()
        raise
    except SQLAlchemyError:
        db.rollback()
        logger.exception("Backup restore failed")
        raise HTTPException(
            status_code=400, detail="Restore failed: the backup file is inconsistent."
        )

    return {
        "users": len(users),
        "incidents": len(incidents),
        "audit": len(seen_audit),
        "settingsRestored": settings_doc is not None,
    }

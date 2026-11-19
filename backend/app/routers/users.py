"""User management routes.

First-run rule: when there are zero users, ``POST /users`` is allowed WITHOUT
authentication and the created user is forced to the admin role. Afterwards
accounts are created, changed and deleted by an admin (session or admin key);
every signed-in user can change their own password.

An account holds one or more roles (``core/permissions.py``); only an admin
gives them. Rules that keep the platform reachable: there is always at least
one admin that can sign in, and an admin cannot disable, demote or delete
themselves.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, status
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm.attributes import flag_modified

from .. import saved_filters
from ..core import audit
from ..core.db import get_db
from ..core.locking import lock_incident
from ..core.models import Incident, User
from ..core.models import Session as SessionModel
from ..core.permissions import ADMIN, SYSTEM_ROLE, SYSTEM_USER, RoleError, clean_roles, legacy_role, stored_roles
from ..core.schemas import PasswordChange, UserCreate, UserEnvelope, UsersEnvelope, UserUpdate
from ..core.security import (
    Principal,
    admin_principal,
    current_user,
    hash_password,
    now_iso,
    optional_principal,
    principal,
    user_to_dict,
    verify_password,
)

router = APIRouter(prefix="/users", tags=["users"])

# Minimum password length enforced server-side.
MIN_PASSWORD_LENGTH = 8


def _wanted_roles(roles: list[str] | None, role: str | None) -> list[str] | None:
    """The roles a request asks for: ``roles``, or the single ``role`` of
    releases before 4.0; None when it names neither."""
    if roles is None and role is None:
        return None
    try:
        return clean_roles(roles if roles is not None else [role])
    except RoleError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None


def _is_admin(user: User) -> bool:
    return "admin" in stored_roles(user.roles)


def _check_password(password: str) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise HTTPException(
            status_code=400,
            detail=f"Password must be at least {MIN_PASSWORD_LENGTH} characters",
        )


def _name_taken(db: OrmSession, username: str, except_id: str | None = None) -> bool:
    """Case-insensitive duplicate check."""
    existing = db.scalar(select(User).where(func.lower(User.username) == username.lower()))
    return existing is not None and existing.id != except_id


def _active_admins(db: OrmSession, except_id: str | None = None) -> int:
    """Admins that can sign in, not counting ``except_id``."""
    # Counted in Python: a JSON list has no portable "contains" (SQLite, PostgreSQL).
    rows = db.execute(select(User.id, User.roles).where(User.disabled.is_(False))).all()
    return sum(1 for user_id, roles in rows if user_id != except_id and "admin" in stored_roles(roles))


def _people(db: OrmSession) -> int:
    """How many accounts there are, not counting the automation engine's own."""
    return db.scalar(select(func.count()).select_from(User).where(User.username != SYSTEM_USER)) or 0


def revoke_sessions(db: OrmSession, user_id: str, keep: str | None = None) -> None:
    """Sign the user out everywhere (except the session ``keep``)."""
    stmt = delete(SessionModel).where(SessionModel.user_id == user_id)
    if keep:
        stmt = stmt.where(SessionModel.token != keep)
    db.execute(stmt)


def _rename_assignee(db: OrmSession, old: str, new: str) -> int:
    """Incidents assigned to ``old`` follow the account to its new name."""
    ids = db.scalars(select(Incident.id).where(func.lower(Incident.assignee) == old.lower())).all()
    for incident_id in ids:
        incident = lock_incident(db, incident_id)
        if incident is None:
            continue
        incident.doc = {**(incident.doc or {}), "assignee": new}
        incident.assignee = new
        flag_modified(incident, "doc")
    return len(ids)


@router.post("", response_model=UserEnvelope, status_code=status.HTTP_201_CREATED)
def create_user(body: UserCreate, request: Request, db: OrmSession = Depends(get_db)) -> dict:
    """Create a user.

    - Zero users exist  → allowed without auth; role forced to 'admin'.
    - Otherwise         → requires admin permissions (admin session OR admin key).
    """
    username = body.username.strip()
    if not username:
        raise HTTPException(status_code=400, detail="Username is required")
    _check_password(body.password)

    if username.lower() == SYSTEM_USER:
        raise HTTPException(status_code=400, detail="This name is the automation engine's: choose another")
    user_count = _people(db)
    is_first_run = user_count == 0

    if is_first_run:
        # First user always becomes an admin, no auth needed.
        roles = ["admin"]
        created_by = None
    else:
        caller = optional_principal(request, db)
        if caller is None:
            raise HTTPException(status_code=401, detail="Not authenticated")
        if not caller.has(ADMIN):
            raise HTTPException(status_code=403, detail="Admin privileges required")
        roles = _wanted_roles(body.roles, body.role) or ["analyst"]
        created_by = caller.actor

    if _name_taken(db, username):
        raise HTTPException(status_code=400, detail="Username already exists")

    user = User(
        id=str(uuid.uuid4()),
        username=username,
        password_hash=hash_password(body.password),
        roles=roles,
        role=legacy_role(roles),
        created_at=now_iso(),
        created_by=created_by,
    )
    db.add(user)
    audit.record(
        db,
        created_by or username,
        "user.create",
        f'Created the account "{username}" with the roles {", ".join(roles)}' + ("" if created_by else " (first run)"),
        target=username,
    )
    db.commit()
    return {"user": user_to_dict(user)}


@router.get("", response_model=UsersEnvelope)
def list_users(_admin: Principal = Depends(admin_principal), db: OrmSession = Depends(get_db)) -> dict:
    """List all users (admin session or admin key)."""
    users = db.scalars(select(User).order_by(User.created_at.asc())).all()
    # The system account of the automation engine is not one people manage.
    return {"users": [user_to_dict(u) for u in users if stored_roles(u.roles) != [SYSTEM_ROLE]]}


@router.get("/names")
def list_user_names(_caller: Principal = Depends(principal), db: OrmSession = Depends(get_db)) -> dict:
    """The usernames an incident can be assigned to (any signed-in user or key)."""
    names = db.scalars(select(User.username).where(User.disabled.is_(False)).order_by(func.lower(User.username))).all()
    return {"names": list(names)}


@router.put("/me/password", status_code=status.HTTP_204_NO_CONTENT)
def change_own_password(
    body: PasswordChange,
    user: User = Depends(current_user),
    db: OrmSession = Depends(get_db),
    nik_session: str | None = Cookie(default=None),
):
    """Change the signed-in user's password; the other sessions of the account end."""
    if not verify_password(body.currentPassword, user.password_hash):
        raise HTTPException(status_code=400, detail="The current password is not correct")
    _check_password(body.newPassword)
    user.password_hash = hash_password(body.newPassword)
    revoke_sessions(db, user.id, keep=nik_session)
    audit.record(db, user.username, "user.password", "Changed their own password", target=user.username)
    db.commit()
    # 204 No Content


@router.patch("/{user_id}", response_model=UserEnvelope)
def update_user(
    user_id: str,
    body: UserUpdate,
    admin: Principal = Depends(admin_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Change an account (admin session or admin key): any of its name, roles,
    password and whether it is disabled. Fields left out are kept.

    - A new **name** is carried to the incidents assigned to the account. What
      the account already wrote (notes, flags, the audit log) keeps the name it
      had then.
    - A new **password** or **disabling** the account ends its sessions. A
      change of its **roles** takes effect at its next request, with no need
      to sign in again.
    - The last admin that can sign in cannot be demoted or disabled, and an
      admin cannot demote or disable themselves.
    """
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="User not found")
    is_self = admin.user is not None and admin.user.id == target.id
    changes: list[str] = []

    current_roles = stored_roles(target.roles)
    roles = _wanted_roles(body.roles, body.role) or current_roles
    disabled = target.disabled if body.disabled is None else body.disabled
    loses_admin = _is_admin(target) and not target.disabled and ("admin" not in roles or disabled)
    if loses_admin and is_self:
        raise HTTPException(status_code=400, detail="You cannot demote or disable your own account")
    if loses_admin and _active_admins(db, except_id=target.id) == 0:
        raise HTTPException(status_code=400, detail="There must be at least one admin that can sign in")

    if body.username is not None:
        username = body.username.strip()
        if not username:
            raise HTTPException(status_code=400, detail="Username is required")
        if username.lower() == SYSTEM_USER:
            raise HTTPException(status_code=400, detail="This name is the automation engine's: choose another")
        if _name_taken(db, username, except_id=target.id):
            raise HTTPException(status_code=400, detail="Username already exists")
        if username != target.username:
            moved = _rename_assignee(db, target.username, username)
            saved_filters.renamed(db, target.username, username)
            changes.append(
                f'renamed from "{target.username}"' + (f" ({moved} assigned incidents follow)" if moved else "")
            )
            target.username = username

    if roles != current_roles:
        changes.append(f"roles {', '.join(current_roles) or 'none'} → {', '.join(roles)}")
        target.roles = roles
        target.role = legacy_role(roles)
        target.session_epoch = (target.session_epoch or 0) + 1

    if body.password is not None:
        _check_password(body.password)
        target.password_hash = hash_password(body.password)
        target.failed_logins = 0
        target.locked_until = None
        revoke_sessions(db, target.id)
        changes.append("password reset")

    if disabled != target.disabled:
        target.disabled = disabled
        if disabled:
            revoke_sessions(db, target.id)
        else:
            target.failed_logins = 0
            target.locked_until = None
        changes.append("disabled" if disabled else "enabled")

    if changes:
        audit.record(
            db,
            admin.actor,
            "user.update",
            f'Changed the account "{target.username}": {", ".join(changes)}',
            target=target.username,
        )
    db.commit()
    return {"user": user_to_dict(target)}


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    user_id: str,
    admin: Principal = Depends(admin_principal),
    db: OrmSession = Depends(get_db),
):
    """Delete a user (admin session or admin key).

    Refuses to delete the caller's own account, the last remaining user and
    the last admin that can sign in.
    """
    target = db.get(User, user_id)
    if target is None:
        # Idempotent-ish: nothing to delete.
        raise HTTPException(status_code=404, detail="User not found")

    # A signed-in admin can't delete their own account; an API key has no
    # "own account", so this only applies to session callers.
    if admin.user is not None and target.id == admin.user.id:
        raise HTTPException(status_code=400, detail="You cannot delete yourself")

    total = _people(db)
    if total <= 1:
        raise HTTPException(status_code=400, detail="Cannot delete the last user")
    if _is_admin(target) and not target.disabled and _active_admins(db, except_id=target.id) == 0:
        raise HTTPException(status_code=400, detail="There must be at least one admin that can sign in")

    audit.record(db, admin.actor, "user.delete", f'Deleted the account "{target.username}"', target=target.username)
    db.delete(target)
    db.commit()
    # 204 No Content

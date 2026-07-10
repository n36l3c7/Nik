"""User management routes.

First-run rule: when there are zero users, ``POST /users`` is allowed WITHOUT
authentication and the created user is forced to the admin role. Afterwards user
creation and deletion require an admin session.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session as OrmSession

from ..db import get_db
from ..models import User
from ..schemas import UserCreate, UserEnvelope, UsersEnvelope
from ..security import (
    Principal,
    admin_principal,
    hash_password,
    now_iso,
    optional_principal,
    user_to_dict,
)

router = APIRouter(prefix="/users", tags=["users"])

# Minimum password length enforced server-side.
MIN_PASSWORD_LENGTH = 8


@router.post("", response_model=UserEnvelope, status_code=status.HTTP_201_CREATED)
def create_user(
    body: UserCreate, request: Request, db: OrmSession = Depends(get_db)
) -> dict:
    """Create a user.

    - Zero users exist  → allowed without auth; role forced to 'admin'.
    - Otherwise         → requires admin permissions (admin session OR admin key).
    """
    username = body.username.strip()
    if not username:
        raise HTTPException(status_code=400, detail="Username is required")
    if len(body.password) < MIN_PASSWORD_LENGTH:
        raise HTTPException(
            status_code=400,
            detail=f"Password must be at least {MIN_PASSWORD_LENGTH} characters",
        )

    user_count = db.scalar(select(func.count()).select_from(User)) or 0
    is_first_run = user_count == 0

    if is_first_run:
        # First user always becomes an admin, no auth needed.
        role = "admin"
        created_by = None
    else:
        caller = optional_principal(request, db)
        if caller is None:
            raise HTTPException(status_code=401, detail="Not authenticated")
        if caller.role != "admin" or "admin" not in caller.scopes:
            raise HTTPException(status_code=403, detail="Admin privileges required")
        role = body.role if body.role in {"admin", "analyst"} else "analyst"
        created_by = caller.actor

    # Case-insensitive duplicate check.
    existing = db.scalar(
        select(User).where(func.lower(User.username) == username.lower())
    )
    if existing is not None:
        raise HTTPException(status_code=400, detail="Username already exists")

    user = User(
        id=str(uuid.uuid4()),
        username=username,
        password_hash=hash_password(body.password),
        role=role,
        created_at=now_iso(),
        created_by=created_by,
    )
    db.add(user)
    db.commit()
    return {"user": user_to_dict(user)}


@router.get("", response_model=UsersEnvelope)
def list_users(
    _admin: Principal = Depends(admin_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """List all users (admin session or admin key)."""
    users = db.scalars(select(User).order_by(User.created_at.asc())).all()
    return {"users": [user_to_dict(u) for u in users]}


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    user_id: str,
    admin: Principal = Depends(admin_principal),
    db: OrmSession = Depends(get_db),
):
    """Delete a user (admin session or admin key).

    Refuses to delete the last remaining user or the caller's own account.
    """
    target = db.get(User, user_id)
    if target is None:
        # Idempotent-ish: nothing to delete.
        raise HTTPException(status_code=404, detail="User not found")

    # A signed-in admin can't delete their own account; an API key has no
    # "own account", so this only applies to session callers.
    if admin.user is not None and target.id == admin.user.id:
        raise HTTPException(status_code=400, detail="You cannot delete yourself")

    total = db.scalar(select(func.count()).select_from(User)) or 0
    if total <= 1:
        raise HTTPException(status_code=400, detail="Cannot delete the last user")

    db.delete(target)
    db.commit()
    # 204 No Content

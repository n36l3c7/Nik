"""Security helpers: password hashing, sessions, and auth dependencies.

- Passwords are hashed with bcrypt via passlib.
- Sessions are server-side rows keyed by a random hex token delivered in the
  ``csap_session`` httpOnly cookie.
- ``current_user`` and ``require_admin`` are FastAPI dependencies that resolve
  the cookie to a live (non-expired) user, raising 401/403 as appropriate.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone

from fastapi import Cookie, Depends, HTTPException, Response, status
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from .config import settings
from .db import get_db
from .models import Session as SessionModel
from .models import User

# bcrypt password hashing context.
_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# ---------------------------------------------------------------------------
# Time helpers (all timestamps stored as ISO-8601 UTC strings)
# ---------------------------------------------------------------------------
def now_iso() -> str:
    """Current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


def _parse_iso(value: str) -> datetime:
    """Parse an ISO-8601 string into an aware datetime (assume UTC if naive)."""
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------
def hash_password(password: str) -> str:
    """Return a bcrypt hash of the given plaintext password."""
    return _pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a plaintext password against a stored bcrypt hash."""
    try:
        return _pwd_context.verify(password, password_hash)
    except ValueError:
        # Malformed/unknown hash format.
        return False


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------
def create_session(db: OrmSession, user: User) -> SessionModel:
    """Create and persist a new session row for a user."""
    token = secrets.token_hex(32)  # 64 hex chars, 32 bytes of entropy
    created = datetime.now(timezone.utc)
    expires = created + timedelta(hours=settings.SESSION_TTL_HOURS)
    session = SessionModel(
        token=token,
        user_id=user.id,
        created_at=created.isoformat(),
        expires_at=expires.isoformat(),
    )
    db.add(session)
    db.commit()
    return session


def delete_session(db: OrmSession, token: str) -> None:
    """Delete a session row by token (no-op if absent)."""
    row = db.get(SessionModel, token)
    if row is not None:
        db.delete(row)
        db.commit()


def set_session_cookie(response: Response, token: str) -> None:
    """Attach the session cookie to a response (httpOnly, SameSite=Lax)."""
    response.set_cookie(
        key=settings.SESSION_COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="lax",
        secure=settings.COOKIE_SECURE,
        path="/",
        max_age=settings.SESSION_TTL_HOURS * 3600,
    )


def clear_session_cookie(response: Response) -> None:
    """Remove the session cookie from the client."""
    response.delete_cookie(
        key=settings.SESSION_COOKIE_NAME,
        path="/",
        samesite="lax",
        secure=settings.COOKIE_SECURE,
        httponly=True,
    )


# ---------------------------------------------------------------------------
# Auth dependencies
# ---------------------------------------------------------------------------
def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated"
    )


def current_user(
    db: OrmSession = Depends(get_db),
    csap_session: str | None = Cookie(default=None),
) -> User:
    """Resolve the session cookie to the authenticated user.

    Raises 401 when the cookie is missing, unknown, or the session has expired.
    Expired sessions are proactively deleted.
    """
    if not csap_session:
        raise _unauthorized()

    session = db.get(SessionModel, csap_session)
    if session is None:
        raise _unauthorized()

    # Reject and clean up expired sessions.
    if _parse_iso(session.expires_at) <= datetime.now(timezone.utc):
        db.delete(session)
        db.commit()
        raise _unauthorized()

    user = db.get(User, session.user_id)
    if user is None:
        raise _unauthorized()

    return user


def require_admin(user: User = Depends(current_user)) -> User:
    """Dependency that requires the current user to have the admin role."""
    if user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required"
        )
    return user


# ---------------------------------------------------------------------------
# Serialization helper
# ---------------------------------------------------------------------------
def user_to_dict(user: User) -> dict:
    """Convert a User ORM object into the public API representation."""
    return {
        "id": user.id,
        "username": user.username,
        "role": user.role,
        "createdAt": user.created_at,
        "createdBy": user.created_by,
    }

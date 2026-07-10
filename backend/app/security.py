"""Security helpers: password hashing, sessions, and auth dependencies.

- Passwords and API keys are hashed with bcrypt via passlib.
- Sessions are server-side rows keyed by a random hex token delivered in the
  ``nik_session`` httpOnly cookie.
- ``current_user`` and ``require_admin`` resolve the session cookie to a live
  user. ``principal`` additionally accepts an ``X-API-Key`` header, so the same
  endpoints can be driven by the browser (cookie) or by external API clients
  (key). Raises 401/403 as appropriate.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from fastapi import Cookie, Depends, HTTPException, Response, Security, status
from fastapi.security import APIKeyHeader
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from .config import settings
from .db import get_db
from .models import ApiKey
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
    nik_session: str | None = Cookie(default=None),
) -> User:
    """Resolve the session cookie to the authenticated user.

    Raises 401 when the cookie is missing, unknown, or the session has expired.
    Expired sessions are proactively deleted.
    """
    if not nik_session:
        raise _unauthorized()

    session = db.get(SessionModel, nik_session)
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
# API keys
# ---------------------------------------------------------------------------
# API keys are 256-bit random tokens (high entropy), so a fast digest with an
# exact-match lookup is both safe and O(1) — unlike passwords, they don't need
# a slow bcrypt hash. Only the digest is stored; the plaintext is shown once.
API_KEY_PREFIX = "nik_"


def generate_api_key() -> tuple[str, str]:
    """Return a new (plaintext_key, prefix). Store only ``hash_api_key(key)``."""
    token = API_KEY_PREFIX + secrets.token_urlsafe(32)
    return token, token[: len(API_KEY_PREFIX) + 8]


def hash_api_key(key: str) -> str:
    """SHA-256 hex digest of an API key (used for storage and lookup)."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


# Documented in OpenAPI so Swagger UI shows an "Authorize" box for the header.
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


@dataclass
class Principal:
    """The authenticated caller: a logged-in user or an API key."""

    kind: str  # 'user' | 'apikey'
    actor: str  # username, or 'api:<label>'
    role: str  # 'admin' | 'analyst'
    user: User | None = None


def principal(
    db: OrmSession = Depends(get_db),
    nik_session: str | None = Cookie(default=None),
    api_key: str | None = Security(api_key_header),
) -> Principal:
    """Resolve the caller from an API key header OR the session cookie.

    Endpoints usable both from the browser and by external clients depend on
    this instead of ``current_user``. An API key grants analyst-level access.
    """
    # 1. API key (external clients): exact digest match against a live key.
    if api_key:
        row = db.scalar(
            select(ApiKey).where(
                ApiKey.key_hash == hash_api_key(api_key),
                ApiKey.revoked_at.is_(None),
            )
        )
        if row is None:
            raise _unauthorized()
        row.last_used_at = now_iso()
        db.commit()
        return Principal(kind="apikey", actor=f"api:{row.label}", role="analyst")

    # 2. Session cookie (browser): reuse the same validation as current_user.
    if nik_session:
        session = db.get(SessionModel, nik_session)
        if session is not None and _parse_iso(session.expires_at) > datetime.now(
            timezone.utc
        ):
            user = db.get(User, session.user_id)
            if user is not None:
                return Principal(
                    kind="user", actor=user.username, role=user.role, user=user
                )

    raise _unauthorized()


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

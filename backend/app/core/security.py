"""Security helpers: password hashing, sessions, and auth dependencies.

- Passwords are hashed with bcrypt; API keys (high-entropy tokens) with SHA-256.
- Sessions are server-side rows keyed by a random hex token delivered in the
  ``nik_session`` httpOnly cookie.
- ``current_user`` resolves the session cookie to a live user. ``principal``
  additionally accepts an ``X-API-Key`` header, so the same endpoints can be
  driven by the browser (cookie) or by external API clients (key).
- What a caller may do comes from its roles (``core/permissions.py``): a route
  depends on ``require("<permission>")``. Raises 401/403 as appropriate.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import bcrypt
from fastapi import Cookie, Depends, HTTPException, Request, Response, Security, status
from fastapi.security import APIKeyHeader
from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from .config import settings
from .db import get_db
from .models import ApiKey, User
from .models import Session as SessionModel
from .permissions import (
    ADMIN,
    AUDIT_READ,
    PERMISSIONS,
    READ,
    RULES_MANAGE,
    WRITE,
    legacy_role,
    permissions_of,
    stored_roles,
)

# bcrypt cost factor (2^12 rounds, the value the existing hashes use) and the
# password length bcrypt reads.
BCRYPT_ROUNDS = 12
BCRYPT_MAX_BYTES = 72
_BCRYPT_HASH = re.compile(r"^\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}$")


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
def _password_bytes(password: str) -> bytes:
    """UTF-8 bytes bcrypt reads: it uses the first 72 bytes only, so they are cut there
    (as passlib, which created the existing hashes, did)."""
    return password.encode("utf-8")[:BCRYPT_MAX_BYTES]


def hash_password(password: str) -> str:
    """Return a bcrypt (``$2b$``) hash of the given plaintext password."""
    return bcrypt.hashpw(_password_bytes(password), bcrypt.gensalt(rounds=BCRYPT_ROUNDS)).decode("ascii")


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a plaintext password against a stored bcrypt hash (False for a malformed hash)."""
    # Checked up front: some bcrypt releases abort (Rust panic) on a truncated hash.
    if not _BCRYPT_HASH.match(password_hash or ""):
        return False
    return bcrypt.checkpw(_password_bytes(password), password_hash.encode("ascii"))


# Checked when a sign-in names an account that does not exist, so that answer
# takes as long as a wrong password for one that does.
DUMMY_PASSWORD_HASH = hash_password(secrets.token_hex(16))

parse_iso = _parse_iso


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
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")


def _forbidden(detail: str = "You do not have the permission this needs") -> HTTPException:
    return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=detail)


def _session_user(db: OrmSession, token: str | None) -> User | None:
    """The live user of a session token, or None.

    An expired session is deleted. The roles are read from the account on
    every request, so a role given or taken away takes effect at once.
    """
    if not token:
        return None
    session = db.get(SessionModel, token)
    if session is None:
        return None
    if _parse_iso(session.expires_at) <= datetime.now(timezone.utc):
        db.delete(session)
        db.commit()
        return None
    user = db.get(User, session.user_id)
    if user is None or user.disabled:
        return None
    return user


def current_user(
    db: OrmSession = Depends(get_db),
    nik_session: str | None = Cookie(default=None),
) -> User:
    """Resolve the session cookie to the authenticated user (401 otherwise)."""
    user = _session_user(db, nik_session)
    if user is None:
        raise _unauthorized()
    return user


# ---------------------------------------------------------------------------
# API keys
# ---------------------------------------------------------------------------
# API keys are 256-bit random tokens (high entropy), so a fast digest with an
# exact-match lookup is both safe and O(1): unlike passwords, they need no
# slow bcrypt hash. Only the digest is stored; the plaintext is shown once.
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
    """The authenticated caller: a signed-in user or an API key.

    ``roles`` are the role tags of the account; ``permissions`` is everything
    they grant together. Code asks ``has(permission)``, never for a role.
    """

    kind: str  # 'user' | 'apikey'
    actor: str  # username, or 'api:<label>'
    roles: list[str] = field(default_factory=list)
    user: User | None = None
    permissions: frozenset[str] = field(init=False)

    def __post_init__(self) -> None:
        self.permissions = permissions_of(self.roles)

    def has(self, *wanted: str) -> bool:
        """True when the caller holds at least one of the permissions."""
        return any(permission in self.permissions for permission in wanted)

    @property
    def role(self) -> str:
        """The single role of releases before 4.0 (for messages and old clients)."""
        return legacy_role(self.roles)


def _key_expired(row: ApiKey) -> bool:
    if not row.expires_at:
        return False
    try:
        return _parse_iso(row.expires_at) <= datetime.now(timezone.utc)
    except ValueError:
        return False


def key_principal(db: OrmSession, key: str | None, touch: bool = True) -> Principal | None:
    """The caller behind an API key, or None when the key is unknown, revoked or expired."""
    if not key:
        return None
    row = db.scalar(select(ApiKey).where(ApiKey.key_hash == hash_api_key(key), ApiKey.revoked_at.is_(None)))
    if row is None or _key_expired(row):
        return None
    if touch:
        row.last_used_at = now_iso()
        db.commit()
    return Principal(kind="apikey", actor=f"api:{row.label}", roles=stored_roles(row.roles))


def _user_principal(user: User) -> Principal:
    return Principal(kind="user", actor=user.username, roles=stored_roles(user.roles), user=user)


def principal(
    db: OrmSession = Depends(get_db),
    nik_session: str | None = Cookie(default=None),
    api_key: str | None = Security(api_key_header),
) -> Principal:
    """Resolve the caller from an API key header OR the session cookie.

    Any signed-in caller passes, whatever its roles: routes that need a
    permission depend on ``require(...)`` (or on one of the wrappers below).
    """
    # 1. API key (external clients): exact digest match against a live key.
    if api_key:
        caller = key_principal(db, api_key)
        if caller is None:
            raise _unauthorized()
        return caller
    # 2. Session cookie (browser).
    user = _session_user(db, nik_session)
    if user is None:
        raise _unauthorized()
    return _user_principal(user)


def optional_principal(request: Request, db: OrmSession) -> Principal | None:
    """Resolve the caller (API key or session) WITHOUT raising when absent.

    Used by endpoints that must handle both an unauthenticated case (first-run
    user creation) and an authenticated, admin-gated case.
    """
    api_key = request.headers.get("X-API-Key")
    if api_key:
        return key_principal(db, api_key, touch=False)
    user = _session_user(db, request.cookies.get(settings.SESSION_COOKIE_NAME))
    return _user_principal(user) if user is not None else None


_REQUIRE_CACHE: dict[tuple[str, ...], object] = {}


def require(*wanted: str):
    """A dependency that lets a caller through when it holds **one of** the
    permissions (any signed-in caller when none is named), and returns it.

    The same permissions give the same dependency object, and the object
    carries them as ``permissions``: the route matrix test reads them there.
    """
    for permission in wanted:
        if permission not in PERMISSIONS:
            raise ValueError(f"unknown permission {permission!r}")
    key = tuple(wanted)
    cached = _REQUIRE_CACHE.get(key)
    if cached is not None:
        return cached

    def dependency(caller: Principal = Depends(principal)) -> Principal:
        if wanted and not caller.has(*wanted):
            raise _forbidden()
        return caller

    dependency.permissions = key
    _REQUIRE_CACHE[key] = dependency
    return dependency


# The gates the routes use (module-level, so a route names one instead of
# calling require() in its signature).
reader_principal = require(READ)
writer_principal = require(WRITE)
admin_principal = require(ADMIN)
audit_principal = require(AUDIT_READ)
rules_principal = require(RULES_MANAGE)
# Rule sets are listed by whoever reads the analyses they produce or manages them.
rules_reader_principal = require(READ, RULES_MANAGE)


# ---------------------------------------------------------------------------
# Serialization helper
# ---------------------------------------------------------------------------
def user_to_dict(user: User) -> dict:
    """Convert a User ORM object into the public API representation."""
    roles = stored_roles(user.roles)
    return {
        "id": user.id,
        "username": user.username,
        "roles": roles,
        # The single role of releases before 4.0, for clients that still read it.
        "role": legacy_role(roles),
        "permissions": sorted(permissions_of(roles)),
        "createdAt": user.created_at,
        "createdBy": user.created_by,
        "disabled": bool(user.disabled),
    }

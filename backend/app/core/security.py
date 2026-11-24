"""Security helpers: password hashing, sessions, and auth dependencies.

- Passwords are hashed with bcrypt; API keys (high-entropy tokens) with SHA-256.
- Sessions are server-side rows keyed by a random hex token delivered in the
  ``nik_session`` httpOnly cookie. A session ends when it was not used for a
  while, and in any case some hours after the sign-in (core/signin_policy.py);
  "used" is a request the person caused, not one the page sends by itself
  (those carry ``X-Nik-Background``).
- An account whose role must have a second factor and has none is let
  through to the routes of the enrolment only; an account that holds the
  administrator's permission is accepted only from the administrators'
  networks, when some are listed. Both refusals are a 403 with a ``code``.
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
from sqlalchemy import select, update
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm.attributes import set_committed_value

from . import client_address, signin_policy
from .clock import now_iso
from .config import settings
from .db import get_db
from .models import ApiKey, User, UserFactor
from .models import Session as SessionModel
from .permissions import (
    ADMIN,
    AUDIT_READ,
    AUTOMATION_EDIT,
    AUTOMATION_RUN,
    CONNECTORS_MANAGE,
    INCIDENTS_ARCHIVE,
    INCIDENTS_CONFIGURE,
    PERMISSIONS,
    READ,
    RULES_MANAGE,
    WRITE,
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
def utcnow() -> datetime:
    """The time, for everything that decides when a session or a wait ends (a test puts its own clock here)."""
    return datetime.now(timezone.utc)


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
# A request the page sends by itself (a list that refreshes, the count of
# notifications) says so with this header: it is answered, and does not count
# as the person using the session.
BACKGROUND_HEADER = "x-nik-background"
# The last use of a session is written down at most this often (more often when the idle time is short).
TOUCH_SECONDS = 30
# The person is warned this long before a session ends for not being used
# (half the idle time when that is shorter than two minutes).
WARN_SECONDS = 60


def create_session(db: OrmSession, user: User, request: Request | None = None) -> SessionModel:
    """Create and persist a new session row for a user."""
    token = secrets.token_hex(32)  # 64 hex chars, 32 bytes of entropy
    created = utcnow()
    expires = created + timedelta(seconds=signin_policy.lifetime_seconds(signin_policy.load(db)))
    session = SessionModel(
        token=token,
        user_id=user.id,
        created_at=created.isoformat(),
        expires_at=expires.isoformat(),
        public_id=secrets.token_hex(8),
        last_used_at=created.isoformat(),
        address=client_address.client_address(request)[:64] if request is not None else None,
        user_agent=(request.headers.get("user-agent", "")[:400] or None) if request is not None else None,
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


def set_session_cookie(response: Response, token: str, max_age: int | None = None) -> None:
    """Attach the session cookie to a response (httpOnly, SameSite=Lax)."""
    response.set_cookie(
        key=settings.SESSION_COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="lax",
        secure=settings.COOKIE_SECURE,
        path="/",
        max_age=max_age if max_age is not None else settings.SESSION_TTL_HOURS * 3600,
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


def session_times(session: SessionModel, policy: dict, roles: list[str]) -> tuple[datetime, datetime | None]:
    """When a session ends whatever happens, and when it ends if it is not used before (None: no such limit).

    Both follow the policy of this moment: a lifetime or an idle time made
    shorter applies to the sessions that are open.
    """
    created = _parse_iso(session.created_at)
    ends = min(_parse_iso(session.expires_at), created + timedelta(seconds=signin_policy.lifetime_seconds(policy)))
    idle = signin_policy.idle_seconds(policy, roles)
    if not idle:
        return ends, None
    return ends, _parse_iso(session.last_used_at or session.created_at) + timedelta(seconds=idle)


def session_alive(session: SessionModel, policy: dict, roles: list[str], now: datetime | None = None) -> bool:
    now = now or utcnow()
    ends, idle_ends = session_times(session, policy, roles)
    return now < ends and (idle_ends is None or now < idle_ends)


def warn_seconds(policy: dict, roles: list[str]) -> int:
    """How long before the end for lack of use the person is warned."""
    idle = signin_policy.idle_seconds(policy, roles)
    return min(WARN_SECONDS, idle // 2) if idle else 0


# ---------------------------------------------------------------------------
# Auth dependencies
# ---------------------------------------------------------------------------
SECOND_FACTOR_REQUIRED = "second_factor_required"
ADMIN_NETWORK = "admin_network"

# What an account that must set up its second factor may still call: who it
# is, the state of its session, and the enrolment itself.
ENROLMENT_ROUTES = frozenset(
    {
        ("GET", "/api/auth/me"),
        ("GET", "/api/auth/session"),
        ("POST", "/api/auth/session/stay"),
        ("GET", "/api/auth/second-factor"),
        ("POST", "/api/auth/second-factor/totp"),
        ("POST", "/api/auth/second-factor/totp/confirm"),
    }
)


class Refused(HTTPException):
    """A refusal the interface recognises by its ``code``, answered as ``{detail, code}``."""

    def __init__(self, code: str, detail: str, status_code: int = status.HTTP_403_FORBIDDEN) -> None:
        super().__init__(status_code=status_code, detail=detail)
        self.code = code


def _unauthorized() -> HTTPException:
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")


def _forbidden(detail: str = "You do not have the permission this needs") -> HTTPException:
    return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=detail)


def has_factor(db: OrmSession, user_id: str) -> bool:
    """Whether the account has a second factor that is on."""
    found = db.scalar(
        select(UserFactor.id).where(UserFactor.user_id == user_id, UserFactor.confirmed_at.is_not(None)).limit(1)
    )
    return found is not None


def must_enrol(db: OrmSession, user: User, policy: dict | None = None) -> bool:
    """Whether the account has to set up a second factor before anything else."""
    policy = policy if policy is not None else signin_policy.load(db)
    return signin_policy.must_have_factor(policy, stored_roles(user.roles)) and not has_factor(db, user.id)


def check_admin_network(request: Request | None, policy: dict, roles: list[str]) -> None:
    """Refuse an administrator who is not on one of the administrators' networks, when some are listed."""
    networks = signin_policy.admin_networks(policy)
    if not networks or request is None or not signin_policy.is_admin(roles):
        return
    address = client_address.client_address(request)
    if not client_address.inside(address, networks):
        raise Refused(
            ADMIN_NETWORK,
            "Administrators can use Nik only from the networks listed in its sign-in policy, "
            f"and this address ({address or 'unknown'}) is not in one of them.",
        )


def _session_user(db: OrmSession, token: str | None, request: Request | None = None) -> User | None:
    """The live user of a session token, or None.

    A session that ended (its lifetime, or too long without use) is deleted.
    The roles are read from the account on every request, so a role given or
    taken away takes effect at once. With the request at hand the session's
    last use is written down, unless the page sent the request by itself.
    """
    if not token:
        return None
    session = db.get(SessionModel, token)
    if session is None:
        return None
    user = db.get(User, session.user_id)
    roles = stored_roles(user.roles) if user is not None else []
    policy = signin_policy.load(db)
    now = utcnow()
    if not session_alive(session, policy, roles, now):
        db.delete(session)
        db.commit()
        return None
    if user is None or user.disabled:
        return None
    if request is None:
        return user
    check_admin_network(request, policy, roles)
    route = (request.method.upper(), request.url.path.rstrip("/") or "/")
    if route not in ENROLMENT_ROUTES and must_enrol(db, user, policy):
        raise Refused(
            SECOND_FACTOR_REQUIRED,
            "Your account must have a second factor: set it up to go on.",
        )
    background = request.headers.get(BACKGROUND_HEADER) is not None or route == ("GET", "/api/auth/session")
    last_used = _parse_iso(session.last_used_at or session.created_at)
    changes: dict[str, str] = {}
    if not session.public_id:
        # A session made by something older than the lists of sessions (a restore) gets its name here.
        changes["public_id"] = secrets.token_hex(8)
    # Not at every request: often enough for the shortest idle time to be exact within a twentieth.
    idle = signin_policy.idle_seconds(policy, roles)
    every = min(TOUCH_SECONDS, idle / 20) if idle else TOUCH_SECONDS
    if not background and (now - last_used).total_seconds() >= every:
        changes["last_used_at"] = now.isoformat()
    if changes:
        touch_session(db, session, **changes)
    request.state.nik_session = session
    return user


def touch_session(db: OrmSession, session: SessionModel, **values: str) -> None:
    """Write something down about a session, and commit. As a plain UPDATE: a session that was ended
    at the same instant by somebody else is simply not there any more, which is no error."""
    db.execute(update(SessionModel).where(SessionModel.token == session.token).values(**values))
    db.commit()
    for name, value in values.items():
        set_committed_value(session, name, value)


def current_user(
    request: Request,
    db: OrmSession = Depends(get_db),
    nik_session: str | None = Cookie(default=None),
) -> User:
    """Resolve the session cookie to the authenticated user (401 otherwise)."""
    user = _session_user(db, nik_session, request)
    if user is None:
        raise _unauthorized()
    return user


def current_session(request: Request) -> SessionModel:
    """The session of this request (after ``current_user``)."""
    session = getattr(request.state, "nik_session", None)
    if session is None:
        raise _unauthorized()
    return session


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


def token_digest(token: str) -> str:
    """What is kept of a token Nik gave out (an API key, a ticket of the sign-in, the token of the
    metrics, the key of a hook): its SHA-256, in hexadecimal. The token itself is never stored."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def hash_api_key(key: str) -> str:
    """SHA-256 hex digest of an API key (used for storage and lookup)."""
    return token_digest(key)


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
    request: Request,
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
        # A key is not asked for a second factor; an administrator's key is
        # held to the administrators' networks like the administrator.
        check_admin_network(request, signin_policy.load(db), caller.roles)
        return caller
    # 2. Session cookie (browser).
    user = _session_user(db, nik_session, request)
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
        caller = key_principal(db, api_key, touch=False)
        if caller is not None:
            check_admin_network(request, signin_policy.load(db), caller.roles)
        return caller
    user = _session_user(db, request.cookies.get(settings.SESSION_COOKIE_NAME), request)
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


def admin_session(user: User = Depends(current_user)) -> Principal:
    """A signed-in administrator: the session of a person, never an API key.

    For what must not be done with a key alone: taking away somebody's second
    factor would let whoever holds an administrator's key sign in as them.
    """
    caller = _user_principal(user)
    if not caller.has(ADMIN):
        raise _forbidden()
    return caller


# The gates the routes use (module-level, so a route names one instead of
# calling require() in its signature).
reader_principal = require(READ)
writer_principal = require(WRITE)
admin_principal = require(ADMIN)
audit_principal = require(AUDIT_READ)
rules_principal = require(RULES_MANAGE)
# Rule sets are listed by whoever reads the analyses they produce or manages them.
rules_reader_principal = require(READ, RULES_MANAGE)
# Automation: run a playbook and read runs; build playbooks and scripts.
runner_principal = require(AUTOMATION_RUN)
editor_principal = require(AUTOMATION_EDIT)
# Connectors with their instances, credentials and mappers; the fields, the types and the
# pre-processing of incidents.
manager_principal = require(CONNECTORS_MANAGE)
configure_principal = require(INCIDENTS_CONFIGURE)
# Archiving a closed incident and taking it out of the archive (7.0).
archive_principal = require(INCIDENTS_ARCHIVE)


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
        "permissions": sorted(permissions_of(roles)),
        "createdAt": user.created_at,
        "createdBy": user.created_by,
        "disabled": bool(user.disabled),
    }

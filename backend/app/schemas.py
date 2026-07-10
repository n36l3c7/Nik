"""Pydantic request/response schemas.

Incident bodies are treated as opaque documents (the backend is a document
store), so they are typed as ``dict``/``Any`` rather than fully modeled.
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Auth / users
# ---------------------------------------------------------------------------
class LoginIn(BaseModel):
    """Login request body."""

    username: str
    password: str


class UserCreate(BaseModel):
    """User creation request body. ``role`` is optional and may be ignored on
    first-run (forced to 'admin')."""

    username: str
    password: str
    role: Optional[str] = None


class UserOut(BaseModel):
    """Public user representation. Never includes the password hash."""

    id: str
    username: str
    role: str
    createdAt: str
    createdBy: Optional[str] = None


class BootstrapOut(BaseModel):
    """Response for GET /api/auth/bootstrap."""

    hasUsers: bool


class UserEnvelope(BaseModel):
    """Wrapper for a single user response: {user}."""

    user: UserOut


class UsersEnvelope(BaseModel):
    """Wrapper for a list of users: {users}."""

    users: list[UserOut]


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------
class AuditIn(BaseModel):
    """Audit creation request body. Actor and timestamp are set server-side."""

    action: str
    target: Optional[str] = None
    details: Optional[str] = None
    incidentId: Optional[str] = None
    incidentName: Optional[str] = None


class AuditOut(BaseModel):
    """Audit entry as returned to the client."""

    id: str
    at: str
    actor: str
    action: str
    target: Optional[str] = None
    details: str
    incidentId: Optional[str] = None
    incidentName: Optional[str] = None


class AuditEnvelope(BaseModel):
    """Wrapper for a list of audit entries: {entries}."""

    entries: list[AuditOut]


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------
class SettingsIn(BaseModel):
    """Shared settings request body."""

    keywords: list[dict[str, Any]] = Field(default_factory=list)
    businessHours: dict[str, Any] = Field(default_factory=dict)


class SettingsOut(BaseModel):
    """Shared settings response body."""

    keywords: list[dict[str, Any]]
    businessHours: dict[str, Any]


# ---------------------------------------------------------------------------
# API keys
# ---------------------------------------------------------------------------
class ApiKeyCreate(BaseModel):
    """Request body to create an API key.

    The admin creating the key sets its permissions: ``role`` ('admin' or
    'analyst') and ``scopes`` (subset of read/write). An admin key can reach the
    admin-data endpoints; scopes further restrict an analyst key (e.g. a
    read-only key with ``scopes: ["read"]``). ``expiresInDays`` optionally sets
    an expiry.
    """

    label: str
    role: Optional[str] = "analyst"
    scopes: Optional[list[str]] = None
    expiresInDays: Optional[int] = None


class ApiKeyOut(BaseModel):
    """Public API-key representation. Never includes the secret."""

    id: str
    label: str
    prefix: str
    role: str
    scopes: list[str]
    createdAt: str
    createdBy: Optional[str] = None
    expiresAt: Optional[str] = None
    lastUsedAt: Optional[str] = None


class ApiKeysEnvelope(BaseModel):
    """Wrapper for a list of API keys: {keys}."""

    keys: list[ApiKeyOut]


class ApiKeyCreated(BaseModel):
    """Create response: the plaintext key (shown ONCE) plus its record."""

    key: str
    apiKey: ApiKeyOut


# ---------------------------------------------------------------------------
# Incident notes (dedicated API endpoints)
# ---------------------------------------------------------------------------
class NoteIn(BaseModel):
    """Request body to add or edit an incident note."""

    text: str

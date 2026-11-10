"""Pydantic request/response schemas.

Incident bodies are treated as opaque documents (the backend is a document
store), so they are typed as ``dict``/``Any`` rather than fully modeled.
"""

from __future__ import annotations

from typing import Annotated, Any, Optional

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
class ReportBrandingIn(BaseModel):
    """Organisation shown on incident reports."""

    orgName: str = Field(default="", max_length=200)
    # A data: URI (PNG, JPEG or SVG), at most ~256 KB of base64.
    logo: str = Field(
        default="", max_length=350_000, pattern=r"^(|data:image/(png|jpeg|svg\+xml);base64,[A-Za-z0-9+/=]+)$"
    )


_DOMAIN = r"^[A-Za-z0-9.-]{1,253}$"


class MailSettingsIn(BaseModel):
    """Mail Analysis: the organisation's own domains (impersonation checks)
    and the servers whose Authentication-Results headers can be believed."""

    orgDomains: list[Annotated[str, Field(pattern=_DOMAIN)]] = Field(default_factory=list, max_length=200)
    trustedAuthServers: list[Annotated[str, Field(pattern=_DOMAIN)]] = Field(default_factory=list, max_length=200)


class SettingsIn(BaseModel):
    """Shared settings request body."""

    keywords: list[dict[str, Any]] = Field(default_factory=list)
    businessHours: dict[str, Any] = Field(default_factory=dict)
    # Omitted (older clients): the stored allowlist is kept.
    iocAllowlist: Optional[list[str]] = Field(default=None, max_length=5000)
    # Omitted: the stored report header is kept.
    report: Optional[ReportBrandingIn] = None
    # Omitted: the stored mail settings are kept.
    mail: Optional[MailSettingsIn] = None


class SettingsOut(BaseModel):
    """Shared settings response body."""

    keywords: list[dict[str, Any]]
    businessHours: dict[str, Any]
    iocAllowlist: list[str]
    report: dict[str, Any]
    mail: dict[str, Any]
    # The factory allowlist, for the Settings "restore defaults" button.
    iocAllowlistDefault: list[str]


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
# YARA rules (admin)
# ---------------------------------------------------------------------------
class YaraRuleIn(BaseModel):
    """Create or replace an admin YARA rule: a display name and the rule source."""

    name: str
    source: str
    enabled: Optional[bool] = True


class YaraRuleOut(BaseModel):
    id: str
    name: str
    source: str
    enabled: bool
    createdAt: str
    createdBy: str
    updatedAt: str
    ruleNames: list[str]


class YaraRulesEnvelope(BaseModel):
    rules: list[YaraRuleOut]
    builtin: list[dict]


# ---------------------------------------------------------------------------
# Incident notes (dedicated API endpoints)
# ---------------------------------------------------------------------------
class NoteIn(BaseModel):
    """Request body to add or edit an incident note."""

    text: str


# ---------------------------------------------------------------------------
# Webhooks
# ---------------------------------------------------------------------------
class WebhookCreate(BaseModel):
    """Request body to register a webhook."""

    url: str
    events: list[str] = Field(default_factory=list)


class WebhookOut(BaseModel):
    """Public webhook representation. Never includes the secret."""

    id: str
    url: str
    events: list[str]
    active: bool
    createdAt: str
    createdBy: Optional[str] = None


class WebhooksEnvelope(BaseModel):
    """Wrapper for a list of webhooks: {webhooks}."""

    webhooks: list[WebhookOut]


class WebhookCreated(BaseModel):
    """Create response: the webhook plus its signing secret (shown ONCE)."""

    webhook: WebhookOut
    secret: str


# ---------------------------------------------------------------------------
# Async jobs
# ---------------------------------------------------------------------------
class JobOut(BaseModel):
    """Async job status."""

    id: str
    kind: str
    status: str
    incidentId: Optional[str] = None
    createdAt: str
    updatedAt: str
    result: Optional[dict[str, Any]] = None
    error: Optional[str] = None

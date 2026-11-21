"""Pydantic request/response schemas.

Incident bodies are treated as opaque documents (the backend is a document
store), so they are typed as ``dict``/``Any`` rather than fully modeled.
"""

from __future__ import annotations

from typing import Annotated, Any, Optional

from fastapi import HTTPException
from pydantic import BaseModel, Field, model_validator


# ---------------------------------------------------------------------------
# Auth / users
# ---------------------------------------------------------------------------
class RolesBody(BaseModel):
    """A request body that says what an account or a key may do with ``roles``.

    Releases before 4.0 took one ``role``, and ``scopes`` on a key. A body that
    still sends one is refused rather than read without it: a client asking for
    a key with ``scopes: ["read"]`` would otherwise be handed a key that writes.
    """

    @model_validator(mode="before")
    @classmethod
    def _refuse_what_roles_replaced(cls, data: Any) -> Any:
        if isinstance(data, dict):
            for name in ("role", "scopes"):
                if name in data:
                    raise HTTPException(
                        status_code=400,
                        detail=f'"{name}" is no longer accepted: send "roles", a list of role names '
                        '(for example ["viewer"] for an account or a key that only reads)',
                    )
        return data


class LoginIn(BaseModel):
    """Login request body."""

    username: str
    password: str


class UserCreate(RolesBody):
    """User creation request body.

    ``roles`` is the list of role names of the account (``analyst`` when left
    out); on first run it is ignored and the account is an admin.
    """

    username: str
    password: str
    roles: Optional[list[str]] = Field(default=None, max_length=16)


class UserUpdate(RolesBody):
    """Changes to an account, made by an admin. A field left out is kept."""

    username: Optional[str] = None
    roles: Optional[list[str]] = Field(default=None, max_length=16)
    password: Optional[str] = None
    disabled: Optional[bool] = None


class PasswordChange(BaseModel):
    """A user changing their own password; with a second factor, a current code of it
    (or a recovery code) is asked too."""

    currentPassword: str
    newPassword: str
    code: Optional[str] = None
    recoveryCode: Optional[str] = None


class CodeIn(BaseModel):
    """The second step of a sign-in: a code of the second factor, or a recovery code."""

    code: Optional[str] = None
    recoveryCode: Optional[str] = None


class IdentityIn(BaseModel):
    """The password again, and a current code when the account has a second factor."""

    password: str = ""
    code: Optional[str] = None
    recoveryCode: Optional[str] = None


class UserOut(BaseModel):
    """Public user representation. Never includes the password hash."""

    id: str
    username: str
    roles: list[str] = []
    # Everything the roles grant together.
    permissions: list[str] = []
    createdAt: str
    createdBy: Optional[str] = None
    disabled: bool = False
    # Whether the account has a second factor, and whether its roles ask for one.
    secondFactor: bool = False
    secondFactorRequired: bool = False


class SessionState(BaseModel):
    """How long the caller's session has left. ``idleSeconds`` is the limit (0: none),
    ``idleLeft`` what is left of it, ``warnSeconds`` how long before the end the page warns."""

    idleSeconds: int = 0
    idleLeft: Optional[int] = None
    lifetimeLeft: int = 0
    warnSeconds: int = 0


class BootstrapOut(BaseModel):
    """Response for GET /api/auth/bootstrap."""

    hasUsers: bool


class UserEnvelope(BaseModel):
    """Wrapper for a single user response: {user}."""

    user: UserOut


class SignedIn(UserEnvelope):
    """A signed-in person: the account, the state of the session and, right after a
    sign-in, what the person is told once (``notice``) and how many recovery codes are
    left when one was just used."""

    session: Optional[SessionState] = None
    notice: Optional[str] = None
    recoveryCodesLeft: Optional[int] = None


class LoginOut(BaseModel):
    """The answer to a right password: the signed-in person, or ``secondFactor`` when a
    second step is asked first (nothing else is said, and no session exists yet)."""

    user: Optional[UserOut] = None
    session: Optional[SessionState] = None
    notice: Optional[str] = None
    secondFactor: Optional[dict] = None


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
    # The place of the entry in the chain (app/auditlog): its number, the hash of the entry before, its own.
    seq: Optional[int] = None
    prev: Optional[str] = None
    hash: Optional[str] = None
    # "import": it came in a file of content from another server; its time and author are that file's.
    # "outside": it was found in the table, not written by the server's own transactions.
    origin: Optional[str] = None
    # The signature of the entry and the id of the key that made it.
    mac: Optional[str] = None
    keyId: Optional[str] = None


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


class EnrichmentAutoIn(BaseModel):
    ip: bool = False
    url: bool = False
    hash: bool = False


class EnrichmentRetentionIn(BaseModel):
    """Days an answer stands, per type (url covers domains, hash the three digests)."""

    ip: int = Field(default=30, ge=1, le=730)
    url: int = Field(default=30, ge=1, le=730)
    hash: int = Field(default=180, ge=1, le=730)


class EnrichmentSettingsIn(BaseModel):
    """Threat intelligence: automatic lookups per type (IP addresses, URLs and
    domains, file hashes), how long answers stand and whether expired ones are
    asked again. Which sources are asked is not set here: a source is on when an
    instance of its connector is (a client that still sends ``virustotal`` or
    ``providers``, the settings of before 6.5, is not refused: they are ignored)."""

    auto: EnrichmentAutoIn = Field(default_factory=EnrichmentAutoIn)
    retentionDays: EnrichmentRetentionIn = Field(default_factory=EnrichmentRetentionIn)
    refreshExpired: bool = True


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
    # Omitted: the stored threat-intelligence settings are kept.
    enrichment: Optional[EnrichmentSettingsIn] = None


class SettingsOut(BaseModel):
    """Shared settings response body."""

    keywords: list[dict[str, Any]]
    businessHours: dict[str, Any]
    iocAllowlist: list[str]
    report: dict[str, Any]
    mail: dict[str, Any]
    enrichment: dict[str, Any]
    # The factory allowlist, for the Settings "restore defaults" button.
    iocAllowlistDefault: list[str]


# ---------------------------------------------------------------------------
# API keys
# ---------------------------------------------------------------------------
class ApiKeyCreate(RolesBody):
    """Request body to create an API key.

    The admin creating the key sets what it may do with ``roles``, the same
    role names an account takes (``["viewer"]`` for a read-only key,
    ``["analyst"]`` when left out). ``expiresInDays`` optionally sets an expiry.
    """

    label: str
    roles: Optional[list[str]] = Field(default=None, max_length=16)
    expiresInDays: Optional[int] = None


class ApiKeyOut(BaseModel):
    """Public API-key representation. Never includes the secret."""

    id: str
    label: str
    prefix: str
    roles: list[str] = []
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

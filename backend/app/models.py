"""SQLAlchemy ORM models.

Mirrors the DB tables described in the spec. The portable ``JSON`` column type
maps to ``JSONB`` on PostgreSQL and to a TEXT-backed JSON on SQLite, so the same
models run in dev and prod. Timestamps are stored as ISO-8601 strings to match
the frontend data shape exactly.
"""

from __future__ import annotations

from typing import Any, Optional

from sqlalchemy import ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import JSON

from .db import Base


class User(Base):
    """Application user (analyst or admin)."""

    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    # Stored as provided; case-insensitive matching is done at query time.
    username: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String, nullable=False)
    role: Mapped[str] = mapped_column(String, nullable=False, default="analyst")
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    created_by: Mapped[Optional[str]] = mapped_column(String, nullable=True)


class Session(Base):
    """Server-side session, referenced by the httpOnly cookie token."""

    __tablename__ = "sessions"

    token: Mapped[str] = mapped_column(String, primary_key=True)
    user_id: Mapped[str] = mapped_column(
        String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    expires_at: Mapped[str] = mapped_column(String, nullable=False)


class Incident(Base):
    """Incident document store.

    The full frontend incident object lives in ``doc``; a handful of scalar
    fields are duplicated into columns purely for listing/sorting.
    """

    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    name: Mapped[str] = mapped_column(String, nullable=False, default="")
    host: Mapped[str] = mapped_column(String, nullable=False, default="")
    username: Mapped[str] = mapped_column(String, nullable=False, default="")
    updated_at: Mapped[str] = mapped_column(String, nullable=False, default="")
    created_at: Mapped[str] = mapped_column(String, nullable=False, default="")
    doc: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)


class AuditEntry(Base):
    """Immutable audit-log entry; actor is stamped server-side from the session."""

    __tablename__ = "audit_log"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    at: Mapped[str] = mapped_column(String, nullable=False)
    actor: Mapped[str] = mapped_column(String, nullable=False)
    action: Mapped[str] = mapped_column(String, nullable=False)
    target: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    details: Mapped[str] = mapped_column(String, nullable=False, default="")
    incident_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    incident_name: Mapped[Optional[str]] = mapped_column(String, nullable=True)


class Setting(Base):
    """Global shared settings (keywords + business hours). Single row, id=1."""

    __tablename__ = "settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    doc: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)


class ApiKey(Base):
    """An API key for external, browser-less access.

    Only the SHA-256 ``key_hash`` is stored; the plaintext key is shown to the
    admin exactly once at creation. ``prefix`` is the first few characters
    (safe to display) so a key can be recognised in listings.

    Permissions are set by the admin at creation and tied to the key:
    - ``role``   'admin' | 'analyst' — an admin key can reach the admin-data
      endpoints (users, backup, keys); an analyst key cannot.
    - ``scopes`` comma-separated subset of read/write/admin controlling which
      operations the key may perform.
    - ``expires_at`` optional ISO timestamp after which the key is rejected.

    A revoked key has a non-null ``revoked_at`` and is rejected.
    """

    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    label: Mapped[str] = mapped_column(String, nullable=False)
    prefix: Mapped[str] = mapped_column(String, nullable=False)
    key_hash: Mapped[str] = mapped_column(String, nullable=False)
    role: Mapped[str] = mapped_column(String, nullable=False, default="analyst")
    scopes: Mapped[str] = mapped_column(String, nullable=False, default="read,write")
    created_at: Mapped[str] = mapped_column(String, nullable=False)
    created_by: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    expires_at: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    last_used_at: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    revoked_at: Mapped[Optional[str]] = mapped_column(String, nullable=True)

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

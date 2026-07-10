"""baseline schema

Creates the full v1 schema (users, sessions, incidents, audit_log, settings,
api_keys, idempotency_keys) from the ORM metadata. ``create_all`` is
checkfirst, so this is safe to stamp onto a database whose tables already exist
(e.g. one bootstrapped by the startup create_all).

Revision ID: 0001_baseline
Revises:
Create Date: 2026-07-11
"""
from __future__ import annotations

from alembic import op

from app.db import Base
from app import models  # noqa: F401 — register all tables on Base.metadata

revision = "0001_baseline"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    Base.metadata.create_all(bind=op.get_bind())


def downgrade() -> None:
    Base.metadata.drop_all(bind=op.get_bind())

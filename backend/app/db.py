"""Database engine, session factory and declarative base.

Uses SQLAlchemy 2.0. The engine is configured from ``settings.DATABASE_URL``.
When the URL points at SQLite, the connection is tuned for a threaded ASGI
server (``check_same_thread=False``) and foreign-key enforcement is enabled via
a PRAGMA on every new connection so the SQLite dev database behaves like the
PostgreSQL production database.
"""

from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import settings


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""


# Build engine-specific connect args. SQLite needs check_same_thread disabled
# because FastAPI may access the connection from different threads.
_connect_args: dict = {}
if settings.is_sqlite:
    _connect_args["check_same_thread"] = False

engine: Engine = create_engine(
    settings.DATABASE_URL,
    connect_args=_connect_args,
    future=True,
    # A modest pool_pre_ping guards against stale PostgreSQL connections.
    pool_pre_ping=True,
)


if settings.is_sqlite:

    @event.listens_for(engine, "connect")
    def _enable_sqlite_fk(dbapi_connection, connection_record):  # noqa: ANN001
        """Enable foreign-key constraint enforcement on SQLite connections."""
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


# Session factory. expire_on_commit=False keeps attributes usable after commit
# (handy when returning ORM objects from request handlers).
SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
    class_=Session,
)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency that yields a DB session and always closes it."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

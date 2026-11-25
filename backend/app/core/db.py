"""Database engine, session factory and declarative base.

Uses SQLAlchemy 2.0. The engine is configured from ``settings.DATABASE_URL``.
When the URL points at SQLite, the connection is tuned for a threaded ASGI
server (``check_same_thread=False``) and foreign-key enforcement is enabled via
a PRAGMA on every new connection so the SQLite dev database behaves like the
PostgreSQL production database.
"""

from __future__ import annotations

import contextlib
import logging
from collections.abc import Generator, Iterator

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import settings

logger = logging.getLogger("nik.db")


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""


def without_statement_limit(db: Session) -> None:
    """Let the rest of this transaction take as long as it needs (PostgreSQL; SQLite has no such limit). For the
    few things that remove millions of rows in one go (an incident, a file read again): the limit on one statement
    (``DB_STATEMENT_TIMEOUT_MS``) is for the requests of people, and this is a delete of a million rows, which with
    the rows that hang on them takes about a minute."""
    if db.get_bind().dialect.name == "postgresql":
        db.execute(text("SET LOCAL statement_timeout = 0"))


# Build engine-specific connect args. SQLite needs check_same_thread disabled
# because FastAPI may access the connection from different threads.
_connect_args: dict = {}
_engine_kwargs: dict = {"future": True, "pool_pre_ping": True}
if settings.is_sqlite:
    _connect_args["check_same_thread"] = False
else:
    # PostgreSQL: size the pool and apply a server-side statement timeout so a
    # runaway query can't pin a worker forever.
    _engine_kwargs.update(
        pool_size=settings.DB_POOL_SIZE,
        max_overflow=settings.DB_MAX_OVERFLOW,
        pool_recycle=settings.DB_POOL_RECYCLE,
    )
    _connect_args["options"] = f"-c statement_timeout={settings.DB_STATEMENT_TIMEOUT_MS}"

engine: Engine = create_engine(
    settings.DATABASE_URL,
    connect_args=_connect_args,
    **_engine_kwargs,
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


# Held by the process that is adding what Nik ships when the server starts (main.py). Two numbers:
# the form with one number is how the connection of a dump is told apart (health/checks.py).
SEEDING_LOCK = (0x4E494B, 1)


@contextlib.contextmanager
def one_process(lock: tuple[int, int]) -> Iterator[None]:
    """What is done inside is done by one process of the server at a time: another that comes to
    the same point waits until the first is through, and then goes through it in its turn.

    On PostgreSQL this is an advisory lock taken in a transaction of a connection of its own, so
    that the work inside may commit as often as it needs; the lock goes with that transaction, or
    with the connection if the process dies. It is not a lease (core/leases.py): it has no holder
    and no expiry, and a standby takes it like anybody else. On SQLite there is one process, and
    nothing to take. Should the lock not be had (the database refused, or went away), the work is
    done all the same: what is written inside must stay correct without it.
    """
    if engine.dialect.name != "postgresql":
        yield
        return
    conn = None
    try:
        conn = engine.connect()
        # The wait is for as long as the other process works: the limit on one statement is not for it.
        conn.execute(text("SET LOCAL statement_timeout = 0"))
        conn.execute(text("SELECT pg_advisory_xact_lock(:high, :low)"), {"high": lock[0], "low": lock[1]})
    except SQLAlchemyError:
        logger.warning("The lock of what one process does at a time was not had: going on without it")
    try:
        yield
    finally:
        if conn is not None:
            try:
                conn.close()  # ends the transaction, and the lock with it
            except SQLAlchemyError:
                logger.warning("The connection of a lock did not close cleanly")


def connection_lost(error: BaseException) -> bool:
    """Whether an error is the database going away under a transaction (it was restarted, killed,
    or the network to it dropped), and not something the work in hand did wrong. Work that meets
    one is not failed for it: nothing can be written at that moment, so it is left as it is, held
    by who held it, and taken back as work whose holder stopped."""
    from sqlalchemy.exc import DBAPIError, InterfaceError, OperationalError, PendingRollbackError

    if isinstance(error, (OperationalError, InterfaceError, PendingRollbackError)):
        return True
    return isinstance(error, DBAPIError) and bool(error.connection_invalidated)


def after_commit(db: Session, action) -> None:
    """Run ``action()`` once this session's transaction is committed.

    For what cannot be rolled back (deleting a file): done only when the
    rows that pointed at it are gone for good.
    """
    event.listen(db, "after_commit", lambda _session: action(), once=True)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency that yields a DB session and always closes it."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

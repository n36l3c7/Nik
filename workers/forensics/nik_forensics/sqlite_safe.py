"""Reading a SQLite database that comes from a host that may be compromised.

The file can be built to hurt whoever opens it: a view over an endless recursive query in place of a
table, a schema that calls functions with side effects, a value of gigabytes. So a database is opened
here, and only here:

* read-only and ``immutable=1``: no ``-wal``, ``-shm`` or journal is looked for or created, nothing is
  written next to the file (a database in WAL mode is read as the file stands: what is still in the
  ``-wal`` file is not in it);
* ``query_only`` on and ``trusted_schema`` off: nothing in the schema of the file can call functions
  with side effects;
* views and triggers are turned off for the connection: a name a parser takes for a table cannot be a
  view built to loop, and nothing of the file's own runs when it is read. Defensive mode is on;
* ``cell_size_check`` on and no memory mapping, as SQLite asks for a file that may be damaged on
  purpose: a bad page is an error, not a read outside the page;
* a bound on the time one connection may run queries (``MAX_SECONDS``), whatever the caller asks:
  the worker bounds the CPU of a job too, but hours later;
* an authorizer that allows SELECT, READ, RECURSIVE and the functions (but ``load_extension``) and
  denies everything else: ATTACH, PRAGMA, writes, ``CREATE``;
* ``setlimit`` on the size of a value, of a statement and of a row;
* text read as UTF-8 with replacement characters: a bad byte is never an exception.

The API is small:

    open_ro(path, stop=None) -> sqlite3.Connection   (``NotSqlite`` when the header is not SQLite's)
    wal_mode(path) -> bool                           the header says WAL: rows may be in a ``-wal`` file
    tables(conn) -> set[str]                         real tables only (no views, no virtual tables)
    columns(conn, table) -> set[str]                 the column names of a table
    scalar(conn, sql, params=()) -> Any | None       the first value of the first row, None on an error
    count(conn, table) -> int | None                 ``count(*)`` of a table, None when it cannot be read
    rows(conn, sql, params=()) -> Iterator[dict]     the rows, one dict each, fetched in batches

``rows`` and ``count`` raise ``sqlite3.DatabaseError`` (``count`` and ``scalar`` return None instead)
when a page is damaged: a caller that goes on reads the next table. Standard library only.
"""

from __future__ import annotations

import re
import sqlite3
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

SQLITE_MAGIC = b"SQLite format 3\x00"
# The largest value (a text, a blob, a row) and statement the library will build.
MAX_LENGTH = 64 * 1024 * 1024
MAX_SQL_LENGTH = 100_000
MAX_COLUMNS = 2000
# How many rows come from the library in one call.
BATCH = 1000
# How many VM steps pass between two calls of ``stop``.
STOP_EVERY = 20_000
# How long the queries of one connection may run in all. A browser history of millions of rows is
# read in a minute or two: half an hour is a query that will not end.
MAX_SECONDS = 1800

_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_ALLOWED = {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_RECURSIVE}
_DENIED_FUNCTIONS = {"load_extension"}


class NotSqlite(sqlite3.DatabaseError):
    """The file does not start with the SQLite header."""


def _authorizer(action: int, arg1: Any, arg2: Any, _db: Any, _source: Any) -> int:
    if action in _ALLOWED:
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_FUNCTION and str(arg2).lower() not in _DENIED_FUNCTIONS:
        return sqlite3.SQLITE_OK
    return sqlite3.SQLITE_DENY


def _text(raw: bytes) -> str:
    return raw.decode("utf-8", "replace")


def _header(path: str) -> bytes:
    with open(path, "rb") as handle:
        return handle.read(100)


def wal_mode(path: str) -> bool:
    """True when the file header says the database is in WAL mode (file format version 2)."""
    try:
        head = _header(path)
    except OSError:
        return False
    return len(head) >= 20 and head.startswith(SQLITE_MAGIC) and (head[18] == 2 or head[19] == 2)


def open_ro(path: str, stop: Callable[[], bool] | None = None) -> sqlite3.Connection:
    """Open ``path`` read-only and locked down as the module says.

    ``stop``, when given, is called now and then while a query runs: when it returns true the query is
    interrupted (``sqlite3.OperationalError: interrupted``). So it is when the queries of the connection
    have run for ``MAX_SECONDS`` in all.
    """
    if not _header(path).startswith(SQLITE_MAGIC):
        raise NotSqlite("file is not a SQLite database")
    uri = Path(path).resolve().as_uri() + "?mode=ro&immutable=1"
    conn = sqlite3.connect(uri, uri=True, check_same_thread=False)
    try:
        conn.text_factory = _text
        if hasattr(conn, "enable_load_extension"):
            conn.enable_load_extension(False)
        # Nothing of the file's own runs: no view is expanded, no trigger fires. A parser that asks
        # for a table that is in truth a view gets "no such table", which it reports.
        conn.setconfig(sqlite3.SQLITE_DBCONFIG_ENABLE_VIEW, False)
        conn.setconfig(sqlite3.SQLITE_DBCONFIG_ENABLE_TRIGGER, False)
        conn.setconfig(sqlite3.SQLITE_DBCONFIG_DEFENSIVE, True)
        conn.setconfig(sqlite3.SQLITE_DBCONFIG_TRUSTED_SCHEMA, False)
        conn.execute("PRAGMA query_only = ON")
        conn.execute("PRAGMA trusted_schema = OFF")
        conn.execute("PRAGMA cell_size_check = ON")
        conn.execute("PRAGMA mmap_size = 0")
        conn.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, MAX_LENGTH)
        conn.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH, MAX_SQL_LENGTH)
        conn.setlimit(sqlite3.SQLITE_LIMIT_COLUMN, MAX_COLUMNS)
        conn.setlimit(sqlite3.SQLITE_LIMIT_ATTACHED, 0)
        conn.setlimit(sqlite3.SQLITE_LIMIT_WORKER_THREADS, 0)
        deadline = time.monotonic() + MAX_SECONDS
        conn.set_progress_handler(
            lambda: 1 if time.monotonic() > deadline or (stop is not None and stop()) else 0, STOP_EVERY
        )
        # Last: from here on PRAGMA and the rest are refused.
        conn.set_authorizer(_authorizer)
    except BaseException:
        conn.close()
        raise
    return conn


def tables(conn: sqlite3.Connection) -> set[str]:
    """The names of the real tables: a view or a virtual table is not one (a view can hide a loop)."""
    found = conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND sql NOT LIKE 'CREATE VIRTUAL%'"
    ).fetchall()
    return {str(row[0]) for row in found}


def columns(conn: sqlite3.Connection, table: str) -> set[str]:
    """The column names of ``table`` (empty when it cannot be read)."""
    if not _NAME.match(table):
        raise ValueError(f"not a table name: {table!r}")
    try:
        return {str(name[0]) for name in conn.execute(f'SELECT * FROM "{table}" LIMIT 0').description}
    except sqlite3.DatabaseError:
        return set()


def scalar(conn: sqlite3.Connection, sql: str, params: tuple | list = ()) -> Any | None:
    try:
        row = conn.execute(sql, params).fetchone()
    except sqlite3.DatabaseError:
        return None
    return row[0] if row else None


def count(conn: sqlite3.Connection, table: str) -> int | None:
    """The rows the table says it holds, None when a damaged page stops the count."""
    if not _NAME.match(table):
        raise ValueError(f"not a table name: {table!r}")
    value = scalar(conn, f'SELECT count(*) FROM "{table}"')
    return int(value) if isinstance(value, int) else None


def rows(conn: sqlite3.Connection, sql: str, params: tuple | list = ()) -> Iterator[dict[str, Any]]:
    """The rows of a query as dicts, in batches. Raises ``sqlite3.DatabaseError`` on a damaged page."""
    cursor = conn.execute(sql, params)
    names = [str(column[0]) for column in cursor.description or ()]
    while True:
        batch = cursor.fetchmany(BATCH)
        if not batch:
            return
        for row in batch:
            yield dict(zip(names, row, strict=False))

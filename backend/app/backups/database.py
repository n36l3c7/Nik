"""The database inside a backup: taking it out, and putting it into another one.

**PostgreSQL.** The dump is read through one connection, in one transaction
that sees one moment of the database (``REPEATABLE READ``, read only). It
holds a description of the ``public`` schema read from the catalogs of the
server (extensions, enumerated types, sequences, tables and their columns,
constraints, indexes: ``db/schema.json``) and then the rows of every table in
the text format of ``COPY``, one part of the backup for each table. The image
holds no ``pg_dump`` and needs none, so a backup never depends on a client
program being as recent as the server.

Putting it back makes the types, the sequences and the tables from the
description, fills the tables, and only then adds the constraints and the
indexes (rows go in faster without them, and in any order). The sequences
are set to where they were. Then the schema that came out is read from the
catalogs again and compared with the description, and the number of rows of
each table with what was counted when it was read: a backup that does not
give back the database it was taken from fails there.

What a description cannot carry stops the backup when it is taken, with its
name, instead of being left out in silence: views, triggers, functions that
are not an extension's, tables outside ``public``, partitions. Nik makes
none of these. Privileges and owners are not carried either: everything
belongs to the role that restores.

**SQLite** (a development server): the database file, copied with SQLite's
own backup call so that it is consistent, as the single part ``db/sqlite``.

**A scratch database** is where a backup is tried: made for one test under a
name of its own (``nik_scratch_…``, ``nik_rehearsal_…``), owned where the
server allows it by a role made for it that owns nothing else, and dropped
when the test ends, however it ends. ``Scratch`` refuses any other name and
the name of the database Nik runs on, and nothing here writes to a database
it was not handed as a ``Scratch`` or, for the restore from the command
line, as an explicit target.
"""

from __future__ import annotations

import json
import logging
import os
import re
import secrets as random
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from sqlalchemy.engine import URL, make_url

from .container import CHUNK, BackupError, Part, Writer

logger = logging.getLogger("nik.backups")

BACKEND = Path(__file__).resolve().parents[2]
ALEMBIC_INI = BACKEND / "alembic.ini"
SCHEMA_PART = "db/schema.json"
SQLITE_PART = "db/sqlite"
TABLE_PART = re.compile(r"^db/([A-Za-z_][A-Za-z0-9_]{0,62})\.copy$")
SCRATCH_NAME = re.compile(r"^nik_(scratch|rehearsal)_[0-9a-f]{12}$")
# Held (shared) by a dump and (alone) by the migrations: neither starts while the other runs.
MIGRATION_LOCK = 0x4E494B4D4947
ALEMBIC_TIMEOUT = 6 * 3600


class Busy(BackupError):
    """Something else holds the database: a migration, or another backup."""


class MigrationFailed(BackupError):
    """The migrations did not run to their end; ``output`` is what they printed last."""

    def __init__(self, message: str, output: str = "") -> None:
        super().__init__(message)
        self.output = output


def live_url() -> URL:
    from ..core.config import settings

    return make_url(settings.DATABASE_URL)


def is_postgres(url: URL) -> bool:
    return url.get_backend_name() == "postgresql"


def _text(url: URL) -> str:
    return url.render_as_string(hide_password=False)


def _pg(url: URL, *, autocommit: bool = False):
    import psycopg

    options = {key: value for key, value in url.query.items() if isinstance(value, str)}
    return psycopg.connect(
        host=url.host,
        port=url.port or 5432,
        user=url.username,
        password=url.password,
        dbname=url.database,
        autocommit=autocommit,
        connect_timeout=15,
        **options,
    )


def _ident(name: str):
    from psycopg import sql

    return sql.Identifier(name)


def _sqlite_path(url: URL) -> str:
    if not url.database or url.database == ":memory:":
        raise BackupError("A database kept in memory cannot be backed up")
    return url.database


# --------------------------------------------------------------------------- #
# Alembic                                                                     #
# --------------------------------------------------------------------------- #
def _alembic_config(config: Path | None):
    from alembic.config import Config

    path = Path(config or ALEMBIC_INI)
    cfg = Config(str(path))
    location = cfg.get_main_option("script_location") or "alembic"
    if not os.path.isabs(location):
        cfg.set_main_option("script_location", str(path.parent / location))
    return cfg


def head_revision(config: Path | None = None) -> str:
    """The revision the migrations of this version of Nik lead to."""
    from alembic.script import ScriptDirectory

    return ScriptDirectory.from_config(_alembic_config(config)).get_current_head()


def known_revision(revision: str, config: Path | None = None) -> bool:
    """Whether this version of Nik has the migration that leads to ``revision``."""
    from alembic.script import ScriptDirectory
    from alembic.util import CommandError

    try:
        return ScriptDirectory.from_config(_alembic_config(config)).get_revision(revision) is not None
    except CommandError:
        return False


def migrate(url: URL, revision: str = "head", config: Path | None = None) -> None:
    """Run the migrations on the database at ``url`` up to ``revision``.

    In a process of its own: the configuration is read once in a process, so
    what must see another database cannot run in this one.
    """
    path = Path(config or ALEMBIC_INI)
    env = {**os.environ, "DATABASE_URL": _text(url), "RUN_CREATE_ALL": "false", "PYTHONDONTWRITEBYTECODE": "1"}
    env["PYTHONPATH"] = os.pathsep.join(filter(None, [str(BACKEND), env.get("PYTHONPATH", "")]))
    try:
        done = subprocess.run(  # noqa: S603 - this interpreter, arguments Nik wrote
            [sys.executable, "-m", "alembic", "-c", str(path), "upgrade", revision],
            cwd=str(path.parent),
            env=env,
            capture_output=True,
            text=True,
            timeout=ALEMBIC_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise MigrationFailed(f"The migrations did not end in {ALEMBIC_TIMEOUT // 3600} hours") from None
    if done.returncode != 0:
        output = (done.stderr or done.stdout or "").strip()
        last = output.splitlines()[-1] if output else "no message"
        raise MigrationFailed(f"The migrations failed: {last}", output[-6000:])


# --------------------------------------------------------------------------- #
# What a database is                                                          #
# --------------------------------------------------------------------------- #
def _pg_tables(cur) -> list[str]:
    cur.execute(
        "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
        "WHERE n.nspname = 'public' AND c.relkind = 'r' ORDER BY c.relname"
    )
    return [row[0] for row in cur.fetchall()]


_UNSUPPORTED = r"""
SELECT 'the ' || CASE c.relkind WHEN 'v' THEN 'view' WHEN 'm' THEN 'materialized view'
                 WHEN 'p' THEN 'partitioned table' ELSE 'foreign table' END || ' ' || c.relname
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = 'public' AND c.relkind IN ('v', 'm', 'p', 'f')
UNION ALL
SELECT 'the trigger ' || t.tgname || ' of ' || c.relname
  FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = 'public' AND NOT t.tgisinternal
UNION ALL
SELECT 'the function ' || p.proname
  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
 WHERE n.nspname = 'public'
   AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.objid = p.oid AND d.deptype = 'e')
UNION ALL
SELECT 'the table ' || n.nspname || '.' || c.relname
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE c.relkind IN ('r', 'p') AND n.nspname NOT IN ('public', 'information_schema') AND n.nspname NOT LIKE 'pg\_%'
UNION ALL
SELECT 'the type ' || t.typname
  FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace
 WHERE n.nspname = 'public' AND t.typtype IN ('d', 'r', 'm')
   AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.objid = t.oid AND d.deptype = 'e')
UNION ALL
SELECT 'the row policy ' || p.polname FROM pg_policy p
UNION ALL
SELECT 'the table ' || c.relname || ', which inherits from another'
  FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
"""

_COLUMNS = """
SELECT c.relname, a.attname, format_type(a.atttypid, a.atttypmod), a.attnotnull,
       pg_get_expr(d.adbin, d.adrelid), a.attidentity::text, a.attgenerated::text,
       CASE WHEN a.attcollation <> t.typcollation AND a.attcollation <> 0
            THEN quote_ident(cn.nspname) || '.' || quote_ident(co.collname) END
  FROM pg_attribute a
  JOIN pg_class c ON c.oid = a.attrelid
  JOIN pg_namespace n ON n.oid = c.relnamespace
  JOIN pg_type t ON t.oid = a.atttypid
  LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
  LEFT JOIN pg_collation co ON co.oid = a.attcollation
  LEFT JOIN pg_namespace cn ON cn.oid = co.collnamespace
 WHERE n.nspname = 'public' AND c.relkind = 'r' AND a.attnum > 0 AND NOT a.attisdropped
 ORDER BY c.relname, a.attnum
"""

# Not-null is said by the column itself (PostgreSQL 18 also lists it as a constraint).
_CONSTRAINTS = """
SELECT c.relname, k.conname, k.contype::text, pg_get_constraintdef(k.oid)
  FROM pg_constraint k JOIN pg_class c ON c.oid = k.conrelid JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = 'public' AND c.relkind = 'r' AND k.contype <> 'n'
 ORDER BY c.relname, k.conname
"""

_INDEXES = """
SELECT t.relname, i.relname, pg_get_indexdef(x.indexrelid)
  FROM pg_index x JOIN pg_class i ON i.oid = x.indexrelid JOIN pg_class t ON t.oid = x.indrelid
  JOIN pg_namespace n ON n.oid = t.relnamespace
 WHERE n.nspname = 'public' AND t.relkind = 'r'
   AND NOT EXISTS (SELECT 1 FROM pg_constraint k WHERE k.conindid = x.indexrelid)
 ORDER BY t.relname, i.relname
"""

_SEQUENCES = """
SELECT s.sequencename, s.data_type::text, s.start_value, s.min_value, s.max_value, s.increment_by,
       s.cycle, s.cache_size, s.last_value, o.relname, o.attname, o.deptype
  FROM pg_sequences s
  LEFT JOIN (SELECT seq.relname AS sequence, tab.relname, a.attname, d.deptype::text
               FROM pg_depend d
               JOIN pg_class seq ON seq.oid = d.objid AND seq.relkind = 'S'
               JOIN pg_namespace n ON n.oid = seq.relnamespace AND n.nspname = 'public'
               JOIN pg_class tab ON tab.oid = d.refobjid
               JOIN pg_attribute a ON a.attrelid = d.refobjid AND a.attnum = d.refobjsubid
              WHERE d.classid = 'pg_class'::regclass AND d.refclassid = 'pg_class'::regclass
                AND d.deptype IN ('a', 'i')) o ON o.sequence = s.sequencename
 WHERE s.schemaname = 'public'
 ORDER BY s.sequencename
"""

_ENUMS = """
SELECT t.typname, array_agg(e.enumlabel::text ORDER BY e.enumsortorder)
  FROM pg_type t JOIN pg_enum e ON e.enumtypid = t.oid JOIN pg_namespace n ON n.oid = t.typnamespace
 WHERE n.nspname = 'public' GROUP BY t.typname ORDER BY t.typname
"""


def _pg_describe(cur) -> dict[str, Any]:
    """The ``public`` schema as the catalogs of the server tell it: what a backup carries of it."""
    cur.execute("SET LOCAL search_path TO public")
    cur.execute(_UNSUPPORTED)
    unsupported = [row[0] for row in cur.fetchall()]
    if unsupported:
        raise BackupError(
            "The database holds what a backup of Nik does not carry, and Nik does not make: "
            + ", ".join(unsupported[:10])
            + ". Nothing was left out in silence: the backup was not taken"
        )
    tables: dict[str, list[dict[str, Any]]] = {name: [] for name in _pg_tables(cur)}
    cur.execute(_COLUMNS)
    for table, name, kind, notnull, default, identity, generated, collation in cur.fetchall():
        tables[table].append(
            {
                "name": name,
                "type": kind,
                "notnull": bool(notnull),
                "default": default,
                "identity": identity or "",
                "generated": generated or "",
                "collation": collation,
            }
        )
    cur.execute(_CONSTRAINTS)
    constraints = [
        {"table": table, "name": name, "kind": kind, "definition": definition}
        for table, name, kind, definition in cur.fetchall()
    ]
    cur.execute(_INDEXES)
    indexes = [{"table": table, "name": name, "definition": definition} for table, name, definition in cur.fetchall()]
    cur.execute(_SEQUENCES)
    sequences = [
        {
            "name": name,
            "type": kind,
            "start": start,
            "min": low,
            "max": high,
            "increment": step,
            "cycle": bool(cycle),
            "cache": cache,
            "last": last,
            "table": table,
            "column": column,
            "identity": deptype == "i",
        }
        for name, kind, start, low, high, step, cycle, cache, last, table, column, deptype in cur.fetchall()
    ]
    cur.execute(_ENUMS)
    enums = [{"name": name, "labels": list(labels)} for name, labels in cur.fetchall()]
    cur.execute("SELECT extname FROM pg_extension WHERE extname <> 'plpgsql' ORDER BY extname")
    extensions = [row[0] for row in cur.fetchall()]
    return {
        "extensions": extensions,
        "enums": enums,
        "sequences": sequences,
        "tables": [{"name": name, "columns": columns} for name, columns in tables.items()],
        "constraints": constraints,
        "indexes": indexes,
    }


def _differing(taken: list, restored: list) -> list[str]:
    def named(entries: list) -> dict[str, Any]:
        return {(entry.get("name") if isinstance(entry, dict) else str(entry)): entry for entry in entries}

    one, other = named(taken), named(restored)
    return sorted(str(name) for name in set(one) | set(other) if one.get(name) != other.get(name))


def _same_schema(taken: dict[str, Any], restored: dict[str, Any]) -> list[str]:
    """What differs between the schema a backup describes and the one that came out of it."""

    def without_position(sequences: list[dict[str, Any]]) -> list[dict[str, Any]]:
        # An identity column names its own sequence, and where a sequence stands is set from the backup.
        return [
            {key: value for key, value in sequence.items() if key != "last"}
            for sequence in sequences
            if not sequence.get("identity")
        ]

    different = []
    for what, label in (
        ("extensions", "extensions"),
        ("enums", "enumerated types"),
        ("tables", "tables or columns"),
        ("constraints", "constraints"),
        ("indexes", "indexes"),
    ):
        if (taken.get(what) or []) != (restored.get(what) or []):
            names = _differing(taken.get(what) or [], restored.get(what) or [])
            different.append(f"{label} ({', '.join(names[:5])})")
    if without_position(taken.get("sequences") or []) != without_position(restored.get("sequences") or []):
        different.append("sequences")
    return different


def _pg_revision(cur, tables: list[str]) -> str | None:
    if "alembic_version" not in tables:
        return None
    cur.execute("SELECT version_num FROM public.alembic_version")
    rows = cur.fetchall()
    return rows[0][0] if len(rows) == 1 else None


def _sqlite_counts(path: str) -> tuple[dict[str, int], str | None]:
    db = sqlite3.connect(f"file:{Path(path).as_posix()}?mode=ro", uri=True)
    try:
        names = [row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")]
        names = [name for name in names if not name.startswith("sqlite_")]
        counts = {name: db.execute(f'SELECT count(*) FROM "{name}"').fetchone()[0] for name in names}  # noqa: S608
        revision = None
        if "alembic_version" in names:
            rows = db.execute("SELECT version_num FROM alembic_version").fetchall()
            revision = rows[0][0] if len(rows) == 1 else None
    finally:
        db.close()
    return counts, revision


def about(url: URL | None = None) -> dict[str, Any]:
    """The database Nik runs on: its engine, version, revision and size."""
    url = url or live_url()
    if not is_postgres(url):
        path = _sqlite_path(url)
        size = os.path.getsize(path) if os.path.exists(path) else 0
        counts, revision = _sqlite_counts(path) if size else ({}, None)
        return {
            "engine": "sqlite",
            "serverVersion": sqlite3.sqlite_version,
            "major": 0,
            "revision": revision,
            "bytes": size,
            "empty": not counts,
        }
    with _pg(url, autocommit=True) as conn, conn.cursor() as cur:
        tables = _pg_tables(cur)
        cur.execute("SHOW server_version")
        version = cur.fetchone()[0]
        cur.execute("SHOW server_version_num")
        number = int(cur.fetchone()[0])
        cur.execute("SELECT pg_database_size(current_database())")
        size = int(cur.fetchone()[0])
        return {
            "engine": "postgresql",
            "serverVersion": version,
            "major": number // 10000,
            "revision": _pg_revision(cur, tables),
            "bytes": size,
            "empty": not tables,
        }


# --------------------------------------------------------------------------- #
# Out of the database                                                         #
# --------------------------------------------------------------------------- #
def dump(writer: Writer, url: URL | None = None, *, migrating: bool = False) -> dict[str, Any]:
    """Write the database at ``url`` (the one Nik runs on) as parts of a backup.

    Returns what goes into the manifest: the engine, its version, the alembic
    revision and the number of rows of every table. ``migrating`` is for the
    snapshot the upgrade takes itself, while it holds the lock a dump
    otherwise stops at.
    """
    url = url or live_url()
    if not is_postgres(url):
        return _dump_sqlite(writer, url)
    from psycopg import sql

    with _pg(url) as conn, conn.cursor() as cur:
        cur.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        cur.execute("SET LOCAL statement_timeout = 0")
        if not migrating:
            cur.execute("SELECT pg_try_advisory_xact_lock_shared(%s)", (MIGRATION_LOCK,))
            if not cur.fetchone()[0]:
                raise Busy("The database is being migrated: no backup is taken meanwhile")
        described = _pg_describe(cur)
        tables = [entry["name"] for entry in described["tables"]]
        cur.execute("SHOW server_version")
        version = cur.fetchone()[0]
        schema = {
            "engine": "postgresql",
            "serverVersion": version,
            "revision": _pg_revision(cur, tables),
            **described,
        }
        with writer.part(SCHEMA_PART) as part:
            part.write(json.dumps(schema, sort_keys=True).encode("utf-8"))
        counts: dict[str, int] = {}
        for entry in described["tables"]:
            table = entry["name"]
            names = [column["name"] for column in entry["columns"] if not column["generated"]]
            statement = sql.SQL("COPY {} ({}) TO STDOUT").format(
                sql.Identifier("public", table), sql.SQL(", ").join(map(sql.Identifier, names))
            )
            rows = 0
            with writer.part(f"db/{table}.copy") as part:
                if names:
                    with cur.copy(statement) as copy:
                        for data in copy:
                            piece = bytes(data)
                            # A line break inside a value is written \n: every real one ends a row.
                            rows += piece.count(b"\n")
                            part.write(piece)
            counts[table] = rows
    return {
        "engine": "postgresql",
        "serverVersion": version,
        "revision": schema["revision"],
        "rows": counts,
        "sequences": len(described["sequences"]),
    }


def _dump_sqlite(writer: Writer, url: URL) -> dict[str, Any]:
    path = _sqlite_path(url)
    folder = tempfile.mkdtemp(prefix="nik-backup-")
    try:
        copy = os.path.join(folder, "copy.db")
        source, target = sqlite3.connect(path), sqlite3.connect(copy)
        try:
            source.backup(target)
        finally:
            source.close()
            target.close()
        counts, revision = _sqlite_counts(copy)
        schema = {"engine": "sqlite", "serverVersion": sqlite3.sqlite_version, "revision": revision}
        with writer.part(SCHEMA_PART) as part:
            part.write(json.dumps(schema, sort_keys=True).encode("utf-8"))
        with writer.part(SQLITE_PART) as part, open(copy, "rb") as handle:
            for piece in iter(lambda: handle.read(CHUNK), b""):
                part.write(piece)
    finally:
        shutil.rmtree(folder, ignore_errors=True)
    return {
        "engine": "sqlite",
        "serverVersion": sqlite3.sqlite_version,
        "revision": revision,
        "rows": counts,
        "sequences": 0,
    }


def forget_in_flight(url: URL) -> int:
    """After a restore: forget the backups that were being taken when the dump was read.

    A backup holds the table of the backups as it was while that very backup
    was being written, so its own row says "running". On the restored server
    nothing is running: left there, the row would be read as a backup that
    died. Returns how many rows went.
    """
    statement = "DELETE FROM backups WHERE state IN ('queued', 'running')"
    if not is_postgres(url):
        db = sqlite3.connect(_sqlite_path(url))
        try:
            if not db.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'backups'").fetchone():
                return 0
            gone = db.execute(statement).rowcount
            db.commit()
            return gone
        finally:
            db.close()
    with _pg(url) as conn, conn.cursor() as cur:
        if "backups" not in _pg_tables(cur):
            return 0
        cur.execute(statement)
        return cur.rowcount


# --------------------------------------------------------------------------- #
# A scratch database                                                          #
# --------------------------------------------------------------------------- #
class Scratch:
    """A database made for one test and dropped after it.

        with Scratch("scratch") as scratch:
            ...                 # scratch.url

    ``separate_role`` asks for a role of its own (the restore test); the
    rehearsal of the migrations runs as the role Nik itself uses, because it
    has to find out what the migrations will do as that role.
    """

    def __init__(
        self,
        purpose: str = "scratch",
        *,
        live: URL | None = None,
        name: str | None = None,
        separate_role: bool = True,
    ) -> None:
        self.live = live or live_url()
        self.name = name or f"nik_{purpose}_{random.token_hex(6)}"
        if not SCRATCH_NAME.match(self.name):
            raise BackupError(f"{self.name!r} is not the name of a scratch database: nothing is restored into it")
        self.postgres = is_postgres(self.live)
        if self.postgres and self.name == (self.live.database or ""):
            raise BackupError("The scratch database cannot be the database Nik runs on")
        self._separate_role = separate_role and self.postgres
        self.role: str | None = None
        self._folder: str | None = None
        self.url: URL | None = None
        self.made = False

    def create(self) -> Scratch:
        if not self.postgres:
            self._folder = tempfile.mkdtemp(prefix="nik-scratch-")
            path = Path(self._folder, f"{self.name}.db").as_posix()
            self.url = make_url(f"sqlite:///{path}")
            self.made = True
            return self
        import psycopg
        from psycopg import sql

        password = None
        with _pg(self.live, autocommit=True) as conn, conn.cursor() as cur:
            if self._separate_role:
                password = random.token_urlsafe(24)
                try:
                    cur.execute(
                        sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(_ident(self.name), sql.Literal(password))
                    )
                    self.role = self.name
                except psycopg.errors.InsufficientPrivilege:
                    # The role of Nik may not make roles here: the name alone keeps the test apart.
                    logger.info("No role of its own for the scratch database: the role of Nik may not create one")
            try:
                if self.role:
                    cur.execute(sql.SQL("CREATE DATABASE {} OWNER {}").format(_ident(self.name), _ident(self.role)))
                else:
                    cur.execute(sql.SQL("CREATE DATABASE {}").format(_ident(self.name)))
            except psycopg.errors.InsufficientPrivilege:
                cur.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(_ident(self.name)))
                raise BackupError(
                    "The role Nik connects to PostgreSQL with may not create a database, so a backup cannot be "
                    f"tried in a scratch one. Give it the right with: ALTER ROLE {self.live.username} CREATEDB"
                ) from None
            self.made = True
        self.url = self.live.set(database=self.name)
        if self.role:
            self.url = self.url.set(username=self.role, password=password)
        return self

    def drop(self) -> None:
        """Remove the database (and its role). Safe to call twice, and after a failure half-way."""
        if not self.postgres:
            if self._folder:
                shutil.rmtree(self._folder, ignore_errors=True)
                self._folder = None
            self.made = False
            return
        from psycopg import sql

        with _pg(self.live, autocommit=True) as conn, conn.cursor() as cur:
            cur.execute(sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(_ident(self.name)))
            cur.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(_ident(self.name)))
        self.made = False

    def __enter__(self) -> Scratch:
        return self.create()

    def __exit__(self, *_exc) -> None:
        try:
            self.drop()
        except Exception:  # noqa: BLE001 - what failed inside matters more; the sweep removes what is left
            logger.exception("The scratch database %s could not be dropped", self.name)


def leftovers(live: URL | None = None) -> list[str]:
    """The scratch databases (and their roles) a test that was killed left behind."""
    live = live or live_url()
    if not is_postgres(live):
        return []
    with _pg(live, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("SELECT datname FROM pg_database")
        names = {row[0] for row in cur.fetchall()}
        cur.execute("SELECT rolname FROM pg_roles")
        names |= {row[0] for row in cur.fetchall()}
    return sorted(name for name in names if SCRATCH_NAME.match(name) and name != live.database)


def sweep(purpose: str, live: URL | None = None) -> int:
    """Drop what is left of earlier tests of this kind. Returns how many were removed."""
    removed = 0
    for name in leftovers(live):
        if name.startswith(f"nik_{purpose}_"):
            Scratch(live=live, name=name).drop()
            removed += 1
    return removed


# --------------------------------------------------------------------------- #
# Into a database                                                             #
# --------------------------------------------------------------------------- #
_TYPE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_ ]*$")


def _type_name(name: str) -> str:
    if not _TYPE_NAME.match(str(name)):
        raise BackupError(f"The backup names a type of sequence Nik does not know ({name})")
    return str(name)


def _column_sql(column: dict[str, Any]):
    """One column of CREATE TABLE. The type and the expressions are the server's own words
    (``format_type``, ``pg_get_expr``), read from a file whose every byte is authenticated."""
    from psycopg import sql

    pieces = [_ident(column["name"]), sql.SQL(column["type"])]
    if column.get("collation"):
        pieces += [sql.SQL("COLLATE"), sql.SQL(column["collation"])]
    if column.get("generated"):
        pieces.append(sql.SQL("GENERATED ALWAYS AS ({}) STORED").format(sql.SQL(column["default"])))
    elif column.get("identity"):
        how = "ALWAYS" if column["identity"] == "a" else "BY DEFAULT"
        pieces.append(sql.SQL(f"GENERATED {how} AS IDENTITY"))
    elif column.get("default") is not None:
        pieces += [sql.SQL("DEFAULT"), sql.SQL(column["default"])]
    if column.get("notnull"):
        pieces.append(sql.SQL("NOT NULL"))
    return sql.SQL(" ").join(pieces)


class Loader:
    """Puts the database parts of a backup, as they go by, into the database at ``target``.

        loader = Loader(scratch.url)
        for part in reader.parts():
            loader.take(part)
        checks = loader.finish(reader.manifest)

    ``finish`` compares what arrived with the manifest and returns the checks
    it made, as sentences; it raises ``BackupError`` on the first that fails.
    Nothing is committed before every check has passed: a PostgreSQL target
    is filled in one transaction, a SQLite one beside its file.
    """

    def __init__(self, target: URL, *, replace: bool = False) -> None:
        self.target, self._replace = target, replace
        self.schema: dict[str, Any] | None = None
        self.loaded: dict[str, int] = {}
        self._conn = None
        self._sqlite_partial: str | None = None

    def take(self, part: Part) -> bool:
        """Use the part if it is one of the database. Says whether it was."""
        if part.name == SCHEMA_PART:
            try:
                self.schema = json.loads(part.read())
            except ValueError:
                raise BackupError("The backup does not say what its database is") from None
            if not isinstance(self.schema, dict) or self.schema.get("engine") not in ("postgresql", "sqlite"):
                raise BackupError("The backup does not say what its database is")
            wanted = "postgresql" if is_postgres(self.target) else "sqlite"
            if self.schema["engine"] != wanted:
                raise BackupError(
                    f"The backup holds a {self.schema['engine']} database and this server runs on {wanted}"
                )
            if wanted == "postgresql":
                self._prepare()
            return True
        if part.name == SQLITE_PART:
            self._need_schema()
            self._load_sqlite(part)
            return True
        found = TABLE_PART.match(part.name)
        if not found:
            return False
        self._need_schema()
        self._load_table(found.group(1), part)
        return True

    def _need_schema(self) -> None:
        if self.schema is None:
            raise BackupError("The backup holds rows before it says what its database is")

    # ----- PostgreSQL ----- #
    def _prepare(self) -> None:
        from psycopg import sql

        schema = self.schema
        with _pg(self.target, autocommit=True) as conn, conn.cursor() as cur:
            if _pg_tables(cur) and not self._replace:
                raise BackupError(
                    f"The database {self.target.database} is not empty: nothing was changed. "
                    "Putting a backup over it removes what it holds, and has to be asked for"
                )
        self._conn = _pg(self.target)
        with self._conn.cursor() as cur:
            cur.execute("SET LOCAL statement_timeout = 0")
            if self._replace:
                # In the same transaction as the rest: what was there stays until the backup is in.
                cur.execute("DROP SCHEMA IF EXISTS public CASCADE")
                cur.execute("CREATE SCHEMA public")
            cur.execute("SET LOCAL search_path TO public")
            for name in schema.get("extensions") or []:
                cur.execute(sql.SQL("CREATE EXTENSION IF NOT EXISTS {} WITH SCHEMA public").format(_ident(name)))
            for enum in schema.get("enums") or []:
                cur.execute(
                    sql.SQL("CREATE TYPE {} AS ENUM ({})").format(
                        sql.Identifier("public", enum["name"]), sql.SQL(", ").join(map(sql.Literal, enum["labels"]))
                    )
                )
            for sequence in schema.get("sequences") or []:
                if sequence.get("identity"):
                    continue  # made with its column
                cur.execute(
                    sql.SQL(
                        "CREATE SEQUENCE {} AS {} START WITH {} INCREMENT BY {} MINVALUE {} MAXVALUE {} CACHE {} {}"
                    ).format(
                        sql.Identifier("public", sequence["name"]),
                        sql.SQL(_type_name(sequence["type"])),
                        sql.Literal(int(sequence["start"])),
                        sql.Literal(int(sequence["increment"])),
                        sql.Literal(int(sequence["min"])),
                        sql.Literal(int(sequence["max"])),
                        sql.Literal(int(sequence["cache"])),
                        sql.SQL("CYCLE" if sequence.get("cycle") else "NO CYCLE"),
                    )
                )
            for table in schema.get("tables") or []:
                columns = [_column_sql(column) for column in table["columns"]]
                cur.execute(
                    sql.SQL("CREATE TABLE {} ({})").format(
                        sql.Identifier("public", table["name"]), sql.SQL(", ").join(columns)
                    )
                )

    def _load_table(self, table: str, part: Part) -> None:
        from psycopg import sql

        if self._conn is None:
            raise BackupError("The backup holds the rows of a table where the database file was expected")
        described = {entry["name"]: entry for entry in self.schema.get("tables") or []}
        if table not in described:
            raise BackupError(f"The backup holds rows of {table}, a table it does not describe")
        names = [column["name"] for column in described[table]["columns"] if not column.get("generated")]
        if not names:
            part.drain()
            self.loaded[table] = 0
            return
        statement = sql.SQL("COPY {} ({}) FROM STDIN").format(
            sql.Identifier("public", table), sql.SQL(", ").join(map(sql.Identifier, names))
        )
        with self._conn.cursor() as cur:
            with cur.copy(statement) as copy:
                for piece in iter(lambda: part.read(CHUNK), b""):
                    copy.write(piece)
            self.loaded[table] = cur.rowcount

    def _finish_postgres(self) -> tuple[dict[str, int], str | None]:
        from psycopg import sql

        if self._conn is None:
            raise BackupError("The backup holds no database")
        schema = self.schema
        absent = [entry["name"] for entry in schema.get("tables") or [] if entry["name"] not in self.loaded]
        if absent:
            raise BackupError("The backup does not hold the rows of: " + ", ".join(absent[:10]))
        with self._conn.cursor() as cur:
            cur.execute("SET LOCAL search_path TO public")
            # Keys and uniqueness first: a reference needs the key it points to.
            constraints = sorted(schema.get("constraints") or [], key=lambda entry: entry["kind"] == "f")
            for constraint in constraints:
                cur.execute(
                    sql.SQL("ALTER TABLE {} ADD CONSTRAINT {} {}").format(
                        sql.Identifier("public", constraint["table"]),
                        _ident(constraint["name"]),
                        sql.SQL(constraint["definition"]),
                    )
                )
            for index in schema.get("indexes") or []:
                cur.execute(sql.SQL(index["definition"]))
            for sequence in schema.get("sequences") or []:
                table, column = sequence.get("table"), sequence.get("column")
                if sequence.get("identity"):
                    cur.execute("SELECT pg_get_serial_sequence(%s, %s)", (f'public."{table}"', column))
                    target = cur.fetchone()[0]
                else:
                    target = f'public."{sequence["name"]}"'
                    if table and column:
                        cur.execute(
                            sql.SQL("ALTER SEQUENCE {} OWNED BY {}").format(
                                sql.Identifier("public", sequence["name"]), sql.Identifier("public", table, column)
                            )
                        )
                if target and sequence.get("last") is not None:
                    cur.execute("SELECT setval(%s::regclass, %s, true)", (target, int(sequence["last"])))
            different = _same_schema(schema, _pg_describe(cur))
            if different:
                raise BackupError(
                    "The schema that came out of the backup is not the one it was taken from: " + "; ".join(different)
                )
            tables = _pg_tables(cur)
            counts = {}
            for table in tables:
                cur.execute(sql.SQL("SELECT count(*) FROM {}").format(sql.Identifier("public", table)))
                counts[table] = cur.fetchone()[0]
            return counts, _pg_revision(cur, tables)

    # ----- SQLite ----- #
    def _load_sqlite(self, part: Part) -> None:
        if is_postgres(self.target):
            raise BackupError("The backup holds a database file where the rows of tables were expected")
        path = _sqlite_path(self.target)
        if os.path.exists(path) and os.path.getsize(path) and not self._replace:
            raise BackupError(
                f"The database {path} is not empty: nothing was changed. "
                "Putting a backup over it removes what it holds, and has to be asked for"
            )
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self._sqlite_partial = f"{path}.restoring"
        with open(self._sqlite_partial, "wb") as out:
            for piece in iter(lambda: part.read(CHUNK), b""):
                out.write(piece)

    # ----- The end ----- #
    def finish(self, manifest: dict[str, Any]) -> list[str]:
        try:
            checks = self._finish(manifest)
        except BaseException:
            self.close()
            raise
        self.close(commit=True)
        return checks

    def _finish(self, manifest: dict[str, Any]) -> list[str]:
        self._need_schema()
        database = manifest.get("database") if isinstance(manifest.get("database"), dict) else {}
        expected = database.get("rows") if isinstance(database.get("rows"), dict) else {}
        revision = database.get("revision")
        if revision != self.schema.get("revision"):
            raise BackupError("The manifest and the database of the backup do not name the same revision")
        if is_postgres(self.target):
            counts, found = self._finish_postgres()
        else:
            if not self._sqlite_partial:
                raise BackupError("The backup holds no database")
            db = sqlite3.connect(self._sqlite_partial)
            try:
                state = db.execute("PRAGMA integrity_check").fetchone()[0]
            except sqlite3.DatabaseError as error:
                state = str(error)
            finally:
                db.close()
            if state != "ok":
                raise BackupError(f"The database of the backup is damaged: {state}")
            counts, found = _sqlite_counts(self._sqlite_partial)
        if found != revision:
            raise BackupError(
                f"The restored database is at the revision {found or 'none'}, the manifest says {revision or 'none'}"
            )
        different = sorted(
            f"{table} ({counts.get(table, 0)} for {expected.get(table, 0)})"
            for table in set(counts) | set(expected)
            if counts.get(table, 0) != expected.get(table, 0)
        )
        if different:
            raise BackupError("Not every row came back: " + ", ".join(different[:10]))
        checks = [
            f"the database restores at the revision {revision or 'of no migration'}",
            f"{sum(counts.values())} rows in {len(counts)} tables, as counted when the backup was taken",
        ]
        if is_postgres(self.target):
            checks.append("its tables, constraints and indexes are those it was taken from")
        return checks + self._sanity(counts)

    def _query(self, statement: str) -> list[tuple]:
        if is_postgres(self.target):
            with self._conn.cursor() as cur:
                cur.execute(statement)
                return cur.fetchall()
        db = sqlite3.connect(self._sqlite_partial)
        try:
            return db.execute(statement).fetchall()
        finally:
            db.close()

    def _sanity(self, counts: dict[str, int]) -> list[str]:
        """A handful of questions the restored database must answer as Nik would ask them."""
        checks = []

        def documents(rows: list[tuple]) -> list[Any]:
            return [json.loads(row[0]) if isinstance(row[0], str | bytes) else row[0] for row in rows]

        if counts.get("users"):
            try:
                roles = documents(self._query("SELECT roles FROM users"))
            except ValueError:
                raise BackupError("The roles of the accounts cannot be read in the restored database") from None
            if not any(isinstance(held, list) and "admin" in held for held in roles):
                raise BackupError("No account of the restored database is an administrator")
            checks.append("an administrator is among its accounts")
        if counts.get("incidents"):
            try:
                docs = documents(self._query("SELECT doc FROM incidents ORDER BY updated_at DESC LIMIT 50"))
            except ValueError:
                raise BackupError("The incidents of the restored database cannot be read") from None
            if not all(isinstance(doc, dict) and doc.get("id") for doc in docs):
                raise BackupError("An incident of the restored database is not readable")
            checks.append(f"its latest {len(docs)} incident(s) are readable")
        if counts.get("settings"):
            try:
                documents(self._query("SELECT doc FROM settings"))
            except ValueError:
                raise BackupError("The settings of the restored database cannot be read") from None
            checks.append("its settings are readable")
        return checks

    def close(self, commit: bool = False) -> None:
        if self._conn is not None:
            try:
                if commit:
                    self._conn.commit()
                else:
                    self._conn.rollback()
            finally:
                self._conn.close()
                self._conn = None
        partial, self._sqlite_partial = self._sqlite_partial, None
        if partial and os.path.exists(partial):
            if commit:
                os.replace(partial, _sqlite_path(self.target))
            else:
                os.remove(partial)

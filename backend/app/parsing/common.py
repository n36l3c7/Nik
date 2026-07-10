"""Shared parsing helpers (lenient field mapping, SQLite-from-bytes, ids)."""

from __future__ import annotations

import csv
import io
import os
import re
import sqlite3
import tempfile
import uuid
from contextlib import contextmanager

_KEY_RE = re.compile(r"[\s_-]+")


def gen_id() -> str:
    return str(uuid.uuid4())


def as_text(value) -> str:
    return "" if value is None else str(value).strip()


def as_count(value, fallback: int = 0) -> int:
    try:
        n = float(value)
    except (TypeError, ValueError):
        return fallback
    return round(n) if n == n and n >= 0 else fallback


def normalize_row(row: dict) -> dict:
    """Lower-case keys with separators stripped (matches the JS normalizer)."""
    out = {}
    for key, value in (row or {}).items():
        out[_KEY_RE.sub("", str(key).strip().lower())] = value
    return out


def pick(normalized_row: dict, aliases):
    for alias in aliases:
        key = _KEY_RE.sub("", alias.lower())
        value = normalized_row.get(key)
        if value is not None and str(value).strip() != "":
            return value
    return None


def base_name(path) -> str:
    """Last path segment (Windows or POSIX), no URL decoding."""
    parts = [p for p in re.split(r"[\\/]", str(path or "")) if p]
    return parts[-1] if parts else str(path or "")


def file_name_from_path(path) -> str:
    if not path:
        return ""
    value = str(path)
    if value.startswith("file:"):
        from urllib.parse import unquote

        value = unquote(re.sub(r"^file:/*", "", value, flags=re.I))
    value = re.split(r"[?#]", value)[0]
    parts = [p for p in re.split(r"[\\/]", value) if p]
    return parts[-1] if parts else value


def parse_csv(text: str):
    """Parse CSV text into a list of dict rows (header row required)."""
    reader = csv.DictReader(io.StringIO(text))
    return [dict(row) for row in reader]


SQLITE_MAGIC = b"SQLite format 3\x00"


def is_sqlite(data: bytes) -> bool:
    return len(data) >= 16 and data[:16] == SQLITE_MAGIC


@contextmanager
def open_sqlite(data: bytes):
    """Open raw bytes as a read-only in-memory-ish SQLite DB (via a temp file)."""
    fd, path = tempfile.mkstemp(suffix=".sqlite")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        conn = sqlite3.connect(path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def query_rows(conn, sql: str):
    try:
        return [dict(r) for r in conn.execute(sql).fetchall()]
    except sqlite3.Error:
        return []


def has_tables(conn, names) -> bool:
    placeholders = ",".join("?" for _ in names)
    row = conn.execute(
        f"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ({placeholders})",
        list(names),
    ).fetchone()
    return row[0] == len(names)

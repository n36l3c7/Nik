"""What the ``view`` of a parser is made of: the pieces that more than one format shows the same way.

``view(path, source, loc) -> dict`` of a parser (``parsers/__init__.py`` says what it returns) shows the
piece of the original file one record came from. The formats differ in where the piece is (a row of a
table, an event of a log, a few lines of a text); how it is cut, written and bounded is here:

    clip(text, budget)          a text cut at a number of bytes (UTF-8), at a character
    fit(answer, budget)         the whole answer cut to ``MAX_TEXT`` bytes of text, ``"cut": true`` when it was
    loc_int(loc, name)          a whole number of the locator, or a ``ViewError`` that says it is missing
    sqlite_row(...)             one row of a table (and the row it points to) as name/value pairs
    flatten(value)              an object, one level deep, as name/value pairs
    text_around(...)            the lines of a record of a text file, with those around it (seeks, never reads all)
    text_by_line(...)           the same for a record known by its line number only (reads on, never all at once)
    hex_dump(data, base)        bytes as lines of 16, with their offsets

Nothing here runs what the file holds: a database is opened by ``sqlite_safe`` and nothing else.
Standard library only.
"""

from __future__ import annotations

import json
import os
import sqlite3
from collections import deque
from typing import Any

from nik_forensics import sqlite_safe
from nik_forensics.parsers import BadLocator, ViewError

# Text of one answer, in bytes of UTF-8: what a screen can show, and a bound on what a hostile file can ask of us.
MAX_TEXT = 256 * 1024
# Lines shown before and after the lines of a record.
CONTEXT = 5
# A line of a text is read up to this many bytes; the rest of a longer one is not shown.
MAX_LINE = 64 * 1024
# Bytes of a blob shown, in hex.
BLOB_BYTES = 64
# Columns of a row shown.
MAX_COLUMNS = 400
# Where the table of a visit finds the row of its URL: the name of the table is the one the file has.
URL_OF_VISIT = {
    "visits": ("urls", "url"),
    "moz_historyvisits": ("moz_places", "place_id"),
    "history_visits": ("history_items", "history_item"),
}


# --------------------------------------------------------------------------- #
# Bounds                                                                      #
# --------------------------------------------------------------------------- #
def clip(text: str, budget: int) -> tuple[str, bool]:
    """``text`` cut to ``budget`` bytes of UTF-8 (never inside a character), and whether it was cut."""
    budget = max(budget, 0)
    if len(text) * 4 <= budget:  # even four bytes a character fit
        return text, False
    raw = text.encode("utf-8", "replace")
    if len(raw) <= budget:
        return text, False
    return raw[:budget].decode("utf-8", "ignore"), True


def fit(answer: dict[str, Any], budget: int = MAX_TEXT) -> dict[str, Any]:
    """The answer with every string of it cut at ``budget`` bytes in all; ``cut`` says whether any was."""
    left = budget
    cut = bool(answer.get("cut"))  # a view that cut something itself (a line too long) says so
    if "text" in answer:
        answer["text"], was = clip(str(answer["text"]), left)
        left -= len(answer["text"].encode("utf-8", "replace"))
        cut = cut or was
    if isinstance(answer.get("rows"), list):
        kept = []
        for name, value in answer["rows"]:
            if left <= 0:
                cut = True
                break
            name, was_name = clip(str(name), left)
            left -= len(name.encode("utf-8", "replace"))
            value, was_value = clip(str(value), left)
            left -= len(value.encode("utf-8", "replace"))
            cut = cut or was_name or was_value
            kept.append([name, value])
        answer["rows"] = kept
    answer["cut"] = cut
    return answer


def loc_int(loc: dict[str, Any], name: str) -> int:
    """A whole number (not a truth value) the locator must hold."""
    value = loc.get(name)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise BadLocator(f"The locator of the record has no {name}")
    return value


# --------------------------------------------------------------------------- #
# Values                                                                      #
# --------------------------------------------------------------------------- #
def _default(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray)):
        return f"{len(value)} bytes: {bytes(value[:BLOB_BYTES]).hex()}"
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)


def as_text(value: Any) -> str:
    """A value as the text a screen shows: text as it is, a blob as its size and its first bytes, the rest as JSON."""
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray)):
        return _default(value)
    if value is None:
        return "null"
    return json.dumps(value, ensure_ascii=False, default=_default)


def flatten(value: Any) -> list[list[str]]:
    """An object one level deep as name/value pairs (what is inside a value is its JSON); a list by position."""
    if isinstance(value, dict):
        return [[str(name), as_text(inner)] for name, inner in value.items()]
    if isinstance(value, list):
        return [[str(index), as_text(inner)] for index, inner in enumerate(value)]
    return [["value", as_text(value)]]


def pretty(value: Any) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False, default=_default)


# --------------------------------------------------------------------------- #
# A row of a database                                                         #
# --------------------------------------------------------------------------- #
def _cell(value: Any) -> str:
    if value is None:
        return "NULL"
    if isinstance(value, (bytes, bytearray)):
        return _default(value)
    return str(value)


def _quote(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _select(conn: sqlite3.Connection, table: str, key: str, value: Any) -> list[list[str]] | None:
    cursor = conn.execute(f"SELECT * FROM {_quote(table)} WHERE {key} = ? LIMIT 1", (value,))
    row = cursor.fetchone()
    if row is None:
        return None
    names = [str(column[0]) for column in cursor.description or ()]
    return [[name, _cell(item)] for name, item in list(zip(names, row, strict=False))[:MAX_COLUMNS]]


def sqlite_row(path: str, table: str, rowid: Any) -> dict[str, Any]:
    """The row ``rowid`` of ``table`` of the database at ``path``: every column, in the order of the schema.

    ``table`` is the real name of a table of the file. For a table of visits the row of the URL it points to
    follows, its columns prefixed ``url.``.
    """
    if isinstance(rowid, bool) or not isinstance(rowid, int):
        raise BadLocator("The locator of the record has no row number")
    try:
        conn = sqlite_safe.open_ro(path)
    except (sqlite3.DatabaseError, OSError) as error:
        raise ViewError(f"The file cannot be opened as a database: {str(error)[:200]}") from None
    try:
        try:
            names = sqlite_safe.tables(conn)
            real = table if table in names else None
            if real is None:
                raise ViewError(f"The file has no table {table}")
            rows = _select(conn, real, "rowid", rowid)
            if rows is None:
                raise ViewError(f"The file holds no row {rowid} in {real}")
            link = URL_OF_VISIT.get(real)
            if link and link[0] in names:
                pointer = next((value for name, value in rows if name == link[1]), None)
                if pointer not in (None, "NULL"):
                    joined = _select(conn, link[0], "id", int(pointer)) if str(pointer).lstrip("-").isdigit() else None
                    rows += [[f"url.{name}", value] for name, value in joined or []]
        except sqlite3.DatabaseError as error:
            raise ViewError(f"The row cannot be read from the database: {str(error)[:200]}") from None
    finally:
        conn.close()
    return {
        "kind": "fields",
        "title": f"Row {rowid} of the table {real}",
        "where": {"table": real, "rowid": rowid},
        "rows": rows,
    }


# --------------------------------------------------------------------------- #
# Lines of a text file                                                        #
# --------------------------------------------------------------------------- #
def _lines(data: bytes, clipped: list[bool]) -> list[str]:
    """The lines of a block of bytes (the last one only when it is not empty), without their line ends.
    A line longer than ``MAX_LINE`` is cut, and ``clipped`` says so."""
    pieces = data.split(b"\n")
    if pieces and pieces[-1] == b"":
        pieces.pop()
    if any(len(piece) > MAX_LINE for piece in pieces):
        clipped.append(True)
    return [piece.rstrip(b"\r")[:MAX_LINE].decode("utf-8", "replace") for piece in pieces]


def _shown(
    before: list[str], record: list[str], after: list[str], first: int, title: str, where: dict, cut: bool
) -> dict:
    lines = [*before, *record, *after]
    if first == 1 and lines and lines[0].startswith("\ufeff"):
        lines[0] = lines[0][1:]
    start = first + len(before)
    return {
        "kind": "text",
        "title": title,
        "where": where,
        "text": "\n".join(lines),
        "highlight": [start, start + max(len(record), 1) - 1],
        "first": first,
        "cut": cut,
    }


def text_around(path: str, offset: int, length: int, line: int) -> dict[str, Any]:
    """The lines of the record that starts at byte ``offset`` and is ``length`` bytes long (``line`` is the
    number of its first line), with up to ``CONTEXT`` lines before and after. The file is read around the
    offset, never whole: a block before it, the record, a block after it."""
    size = os.path.getsize(path)
    if offset >= size:
        raise ViewError(f"The file ends at byte {size}: it holds nothing at byte {offset}")
    if line < 1:
        raise BadLocator("The locator of the record has no line")
    with open(path, "rb") as handle:
        begin = max(0, offset - MAX_LINE)
        handle.seek(begin)
        head = handle.read(offset - begin)
        if begin > 0:  # begun inside a line: that one is not whole, and is not shown
            cut = head.find(b"\n")
            head = head[cut + 1 :] if cut >= 0 else b""
        clipped: list[bool] = []
        before = _lines(head, clipped)[-CONTEXT:]
        raw = handle.read(min(max(length, 1), MAX_TEXT + 1))
        record = _lines(raw, clipped)
        after: list[str] = []
        if length <= MAX_TEXT and raw.endswith(b"\n"):
            after = _lines(handle.read(MAX_LINE * 2), clipped)[:CONTEXT]
    where = {"offset": offset, "length": length, "line": line}
    last = line + max(len(record), 1) - 1
    title = (
        f"Line {line} of the file, at byte {offset}" if last == line else f"Lines {line} to {last}, at byte {offset}"
    )
    return _shown(before, record, after, line - len(before), title, where, bool(clipped) or length > MAX_TEXT)


def text_by_line(path: str, line: int, extra: int = 0) -> dict[str, Any]:
    """The line ``line`` of the file (and ``extra`` after it, which belong to the record) with those around it.
    The file is read from its start to there, a line at a time: a line is kept up to ``MAX_LINE`` bytes."""
    if line < 1:
        raise BadLocator("The locator of the record has no line")
    before: deque[str] = deque(maxlen=CONTEXT)
    record: list[str] = []
    after: list[str] = []
    number = 0
    clipped = False
    with open(path, "rb") as handle:
        while number < line + extra + CONTEXT:
            raw = handle.readline(MAX_LINE)
            if not raw:
                break
            while not raw.endswith(b"\n"):  # the rest of a longer line is not kept
                rest = handle.readline(MAX_LINE)
                clipped = clipped or bool(rest)
                if not rest or rest.endswith(b"\n"):
                    break
            number += 1
            text = raw.rstrip(b"\r\n").decode("utf-8", "replace")
            if number < line:
                before.append(text)
            elif number <= line + extra:
                record.append(text)
            else:
                after.append(text)
    if not record:
        raise ViewError(f"The file holds no line {line} (it ends at line {number})")
    where = {"line": line}
    return _shown(list(before), record, after, line - len(before), f"Line {line} of the file", where, clipped)


def hex_dump(data: bytes, base: int) -> str:
    """Bytes as lines of 16: the offset in the file (``base`` is that of the first byte), the bytes in hex, the text."""
    lines = []
    for at in range(0, len(data), 16):
        piece = data[at : at + 16]
        shown = " ".join(f"{byte:02x}" for byte in piece).ljust(47)
        text = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in piece)
        lines.append(f"{base + at:010x}  {shown}  {text}")
    return "\n".join(lines)

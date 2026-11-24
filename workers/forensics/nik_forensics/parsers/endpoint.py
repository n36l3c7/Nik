"""Endpoint artifacts: persistence, program execution, file access and USB devices of one host.

A port of Nik 6.x's ``parsing/artifact.py`` (and of its browser twin ``artifactParsers.js``). A source is
named ``<os>.<category>.<id>`` with the ids of the collection tab (``windows.persistence.runkeys``…) and
reads one of seven formats:

    CSV or JSON   what Nik's collection scripts write (and any tool export): one row, one record
    configlines   cron, authorized_keys and shell rc files: one non-comment line, one record
    xbel          GTK ``recently-used.xbel``: one ``<bookmark>``, one record
    plist         a LaunchAgent / LaunchDaemon (XML or binary): one record
    setupapi      Windows ``setupapi.dev.log``: one USB device-install section, one record
    knowledgec    macOS ``knowledgeC.db``: one ``/app/usage`` row of ``ZOBJECT``, one record

What a file holds, ``ctx.end(in_file=...)``, is counted in the file's own units: the data rows of a CSV
(the header and blank lines are not rows), the elements of a JSON array, the non-comment non-blank lines
of a line file, the ``<bookmark>`` elements of an XBEL, one for a plist, the ``[Device Install ... USB]``
sections of a setupapi log, the ``/app/usage`` rows of ``ZOBJECT``. ``read`` plus the rows said in notes
as left out (a row without content) plus ``lost`` gives it back; a file that could not be read at all
says ``in_file`` None with a skip of ``lost`` 0 that gives the reason.

A record is the category's fields as the collection tab names them (execution: name, path, runCount,
source; persistence: name, kind, command, location; fileaccess: name, target, kind; usb: device, serial,
vendor, connection) plus ``category`` and ``os``. Its key is the source, the host and a hash of the
time and the fields: a file read again gives the same keys, a row repeated in the file (same fields and
same time) gets ``:2``, ``:3``… in file order. Nothing is read for its indicators (``ioc`` is always empty).

A row that has not one field with content is a note, not a loss. Columns Nik does not know are a skip
of ``lost`` 0 with the header found. A time that cannot be read keeps the row with no ``ts``.

Every file is hostile: line files, CSV and the XBEL are streamed, a JSON file or plist is read whole up to
``MAX_WHOLE`` bytes, the XBEL parser refuses a DOCTYPE and entities, the SQLite file is opened with
``sqlite_safe`` (read-only, immutable, locked down). Standard library only.

The place of a record in its file (``loc``): ``{"row": n}`` for a row of a CSV or JSON file, counted from 1 (the
first row after the header, the first element of the array); ``{"line", "offset", "length"}`` for a line of a line
file; ``{"line"}`` for an XBEL bookmark or a setupapi section (the line it starts at); ``{"table", "rowid"}`` for a
row of a database; ``{"path"}`` for the key of a plist the command was read from. A CSV row with more cells than
the header is kept: the extra cells are in its data under ``extra``, and a note counts such rows.
"""

from __future__ import annotations

import csv
import hashlib
import json
import math
import os
import plistlib
import re
import sqlite3
from datetime import datetime, timezone
from typing import Any, NamedTuple
from urllib.parse import unquote
from xml.parsers import expat

from nik_forensics import sqlite_safe, viewing
from nik_forensics.parsers import BadLocator, ViewError

NAME = "endpoint"
VERSION = "1"
KIND = "endpoint"

MAX_WHOLE = 64 * 1024 * 1024  # a JSON file, a plist or an XBEL is read up to this size
MAX_LINE = 1024 * 1024
MAX_UNREADABLE = 10_000  # rows of one CSV that may be said one by one before the file is given up
# Unix ms of 9999-12-31: beyond it no calendar prints the date.
MAX_MS = 253402300799000
WEBKIT_EPOCH_OFFSET_MS = 11644473600000
MAC_EPOCH_OFFSET_S = 978307200
_SEPARATORS = re.compile(r"[\s_-]+")
_SQLITE_MAGIC = b"SQLite format 3\x00"


def _norm(name: Any) -> str:
    return _SEPARATORS.sub("", str(name).strip().lower())


class _Category(NamedTuple):
    primary: str
    fields: dict[str, tuple[str, ...]]  # field -> aliases, as the collection tab maps them
    times: tuple[str, ...]
    telling: tuple[str, ...]  # the fields that say most after the name, for the summary
    known: frozenset[str]  # every normalised alias


def _category(primary: str, fields: dict[str, list[str]], times: list[str], telling: tuple[str, ...]) -> _Category:
    mapped = {name: tuple(_norm(alias) for alias in aliases) for name, aliases in fields.items()}
    known = frozenset(alias for aliases in mapped.values() for alias in aliases)
    return _Category(primary, mapped, tuple(_norm(alias) for alias in times), telling, known)


CATEGORIES = {
    "execution": _category(
        "name",
        {
            "name": ["name", "program", "executable", "application", "filename", "process", "value"],
            "path": ["path", "fullpath", "full_path", "file_path", "image", "devicepath", "programpath"],
            "runCount": ["runcount", "run_count", "count", "executioncount", "timesexecuted"],
            "source": ["source", "artifact", "sourcetype", "type", "hive"],
        },
        [
            "lastrun",
            "last_run",
            "lastexecuted",
            "last_executed",
            "runtime",
            "executiontime",
            "timestamp",
            "time",
            "lastmodified",
            "date",
            "lastruntime",
        ],
        ("path",),
    ),
    "persistence": _category(
        "name",
        {
            "name": ["name", "entry", "task", "service", "key", "label", "value"],
            "kind": ["kind", "type", "mechanism", "category"],
            "command": ["command", "commandline", "command_line", "target", "path", "action", "exec", "data"],
            "location": ["location", "source", "hive", "file", "registrykey", "key_path"],
        },
        ["created", "modified", "lastmodified", "timestamp", "time", "date", "lastwrite"],
        ("command", "location"),
    ),
    "fileaccess": _category(
        "name",
        {
            "name": ["name", "item", "file", "filename", "document", "label", "value"],
            "target": ["target", "targetpath", "target_path", "path", "localpath", "href"],
            "kind": ["kind", "type", "artifact", "source"],
        },
        ["accessed", "lastaccessed", "modified", "visited", "timestamp", "time", "date"],
        ("target",),
    ),
    "usb": _category(
        "device",
        {
            "device": ["device", "friendlyname", "friendly_name", "devicename", "description", "model", "value"],
            "serial": ["serial", "serialnumber", "serial_number", "iserialnumber", "guid"],
            "vendor": ["vendor", "vendorproduct", "manufacturer", "product", "vid_pid", "vidpid"],
            "connection": ["connection", "event", "action", "kind", "type"],
        },
        [
            "firstconnected",
            "first_connected",
            "lastconnected",
            "last_connected",
            "firstinstall",
            "timestamp",
            "time",
            "date",
            "installdate",
            "connected",
        ],
        ("serial", "vendor"),
    ),
}


class _Spec(NamedTuple):
    os: str
    category: str
    id: str
    reader: str
    label: str  # the source's name in the collection tab: the ``location`` of a line file's records
    kind: str = ""  # configlines: the ``kind`` of its records
    record: str = ""  # configlines: the ``name`` of its records


_SPEC_LIST = (
    _Spec("windows", "execution", "bam", "delimited", "BAM/DAM last execution"),
    _Spec("windows", "persistence", "runkeys", "delimited", "Run / RunOnce keys"),
    _Spec("windows", "persistence", "tasks", "delimited", "Scheduled Tasks"),
    _Spec("windows", "persistence", "services", "delimited", "Services"),
    _Spec("windows", "persistence", "startup", "delimited", "Startup folder"),
    _Spec("windows", "persistence", "wmi", "delimited", "WMI subscriptions"),
    _Spec("windows", "usb", "usbstor", "delimited", "USBSTOR"),
    _Spec("windows", "usb", "setupapi", "setupapi", "setupapi log"),
    _Spec("macos", "execution", "knowledgec", "knowledgec", "KnowledgeC app usage"),
    _Spec("macos", "persistence", "launch", "plist", "LaunchAgent / LaunchDaemon"),
    _Spec("macos", "persistence", "cron", "configlines", "cron", "cron", "cron entry"),
    _Spec("linux", "persistence", "cron", "configlines", "cron", "cron", "cron entry"),
    _Spec("linux", "persistence", "sshkeys", "configlines", "SSH authorized_keys", "authorized_keys", "authorized_key"),
    _Spec("linux", "persistence", "rc", "configlines", "shell rc / profile", "shell rc", "rc line"),
    _Spec("linux", "persistence", "systemd", "delimited", "enabled systemd units"),
    _Spec("linux", "fileaccess", "recent", "xbel", "GTK recently-used"),
    _Spec("linux", "usb", "journal", "delimited", "kernel USB events"),
)
_SPECS = {f"{spec.os}.{spec.category}.{spec.id}": spec for spec in _SPEC_LIST}
SOURCES = tuple(_SPECS)


# --------------------------------------------------------------------------- #
# Recognising a file                                                          #
# --------------------------------------------------------------------------- #
_SETUPAPI_HEAD = re.compile(rb"^\s*(\[Device Install Log\]|>>>\s+\[Device Install)", re.I)


def _is_knowledgec(path: str) -> bool:
    conn = sqlite_safe.open_ro(path)
    try:
        return "ZOBJECT" in sqlite_safe.tables(conn)
    finally:
        conn.close()


def _is_launch_plist(path: str, head: bytes) -> bool:
    if head.startswith(b"bplist00"):
        if os.path.getsize(path) > 1024 * 1024:
            return False
        with open(path, "rb") as handle:
            data = plistlib.loads(handle.read())
        return isinstance(data, dict) and ("Label" in data or "ProgramArguments" in data)
    return b"<plist" in head and (b"<key>Label</key>" in head or b"<key>ProgramArguments</key>" in head)


def sniff(path: str, name: str, head: bytes) -> str | None:
    """Only what the file itself says: a CSV cannot be told apart, so it is None (the import names the source)."""
    try:
        text = head[3:] if head.startswith(b"\xef\xbb\xbf") else head
        if head.startswith(sqlite_safe.SQLITE_MAGIC):
            return "macos.execution.knowledgec" if _is_knowledgec(path) else None
        if _SETUPAPI_HEAD.match(text) or b"[BeginLog]" in head[:1024]:
            return "windows.usb.setupapi"
        if re.search(rb"<xbel[\s>]", head):
            return "linux.fileaccess.recent"
        if _is_launch_plist(path, head):
            return "macos.persistence.launch"
    except Exception:  # noqa: BLE001, S110 - a file that cannot even be looked at is not one of ours
        pass
    return None


# --------------------------------------------------------------------------- #
# Values                                                                      #
# --------------------------------------------------------------------------- #
def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace").strip()
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, default=str)
    return str(value).strip()


def _pick(row: dict[str, Any], aliases: tuple[str, ...]) -> Any:
    for alias in aliases:
        value = row.get(alias)
        if value is not None and str(value).strip() != "":
            return value
    return None


def _plausible(ms: int | None) -> int | None:
    return ms if ms is not None and -MAX_MS <= ms <= MAX_MS else None


def _number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return number if math.isfinite(number) else None


def _any_to_ms(value: Any) -> int | None:
    """A time of a CSV/JSON row as milliseconds since the epoch (UTC), None when it is no time.

    A number selects its unit by its size (Nik 6.x's rule): above 1e14 microseconds since 1601, above 1e11
    milliseconds, above 1e8 seconds, below that no time. A text is an ISO date; one with no zone is UTC."""
    if value is None or value == "":
        return None
    number = _number(value)
    if number is not None:
        if number > 1e14:
            return _plausible(round(number / 1000) - WEBKIT_EPOCH_OFFSET_MS)
        if number > 1e11:
            return _plausible(round(number))
        if number > 1e8:
            return _plausible(round(number * 1000))
        return None
    text = str(value).strip().replace(" ", "T").replace("Z", "+00:00")
    try:
        moment = datetime.fromisoformat(text)
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        return _plausible(round(moment.timestamp() * 1000))
    except (ValueError, OverflowError, OSError):
        return None


def _base_name(path: str) -> str:
    parts = [part for part in re.split(r"[\\/]", str(path or "")) if part]
    return parts[-1] if parts else str(path or "")


# --------------------------------------------------------------------------- #
# What a reader says                                                          #
# --------------------------------------------------------------------------- #
class _Out:
    """Makes the records of one file: the fields, the key (with the repeat counter) and the counts of the notes."""

    def __init__(self, ctx, source: str, spec: _Spec) -> None:
        self.ctx = ctx
        self.source = source
        self.spec = spec
        self.category = CATEGORIES[spec.category]
        self.host = str(ctx.params.get("host") or "")
        self.username = str(ctx.params.get("username") or "")
        self.seen: dict[str, int] = {}
        self.no_time = 0
        self.empty = 0
        self.timeless = False  # the format has no time at all: one note for the file, not "unusable"

    def put(self, fields: dict[str, str], ts: int | None, loc: dict[str, Any], extra: list[str] | None = None) -> None:
        whole = {"ts": ts, **fields}
        digest = hashlib.sha256(json.dumps(whole, sort_keys=True, ensure_ascii=False).encode("utf-8", "replace"))
        base = f"ep:{self.host}:{self.source}:{digest.hexdigest()[:16]}"
        number = self.seen.get(base, 0) + 1
        self.seen[base] = number
        if ts is None:
            self.no_time += 1
        category = self.category
        name = fields.get(category.primary) or next((value for value in fields.values() if value), "")
        tell = next((fields[key] for key in category.telling if fields.get(key) and fields[key] != name), "")
        self.ctx.record(
            key=base if number == 1 else f"{base}:{number}",
            type=self.spec.id,
            ts=ts,
            host=self.host,
            username=self.username,
            summary=f"{name} — {tell[:300]}" if tell else name,
            data={**fields, "category": self.spec.category, "os": self.spec.os, **({"extra": extra} if extra else {})},
            loc=loc,
        )

    def finish(self, in_file: int | None) -> None:
        if self.empty:
            self.ctx.note("row without content", count=self.empty, detail="not one field of the row has a value")
        if self.no_time:
            if self.timeless:
                self.ctx.note("no time", count=self.no_time, detail="this kind of file keeps none")
            else:
                self.ctx.note(
                    "row without a usable time",
                    count=self.no_time,
                    detail="the row has no time column, or a value that is not a time",
                )
        self.ctx.end(in_file=in_file)


def _encoding(path: str) -> str:
    with open(path, "rb") as handle:
        start = handle.read(4)
    if start.startswith((b"\xff\xfe", b"\xfe\xff")):
        return "utf-16"
    return "utf-8-sig"


def _whole(path: str, ctx) -> bytes | None:
    """The file's bytes, or None (and a skip) when it is larger than ``MAX_WHOLE``."""
    size = os.path.getsize(path)
    if size > MAX_WHOLE:
        ctx.skip("file too large to read whole", lost=0, length=size, detail=f"{size} bytes, the limit is {MAX_WHOLE}")
        return None
    with open(path, "rb") as handle:
        return handle.read(MAX_WHOLE + 1)


# -- CSV and JSON ---------------------------------------------------------------- #
class _Rows:
    """Maps the rows of a CSV or JSON file onto the category's fields."""

    def __init__(self, out: _Out) -> None:
        self.out = out
        self.matched = False  # some row had a column the category knows
        self.first_keys: list[str] | None = None
        self.undecodable = 0

    def row(self, raw: dict[Any, Any], number: int, extra: list[str] | None = None) -> None:
        out, category = self.out, self.out.category
        row: dict[str, Any] = {}
        for key, value in raw.items():
            row[_norm(key)] = value
        if self.first_keys is None:
            self.first_keys = [str(key) for key in raw]
        if category.known.intersection(row):
            self.matched = True
        fields = {name: _text(_pick(row, aliases)) for name, aliases in category.fields.items()}
        if any("�" in value for value in fields.values()):
            self.undecodable += 1
        if not any(fields.values()):
            out.empty += 1
            return
        out.put(fields, _any_to_ms(_pick(row, category.times)), {"row": number}, extra)

    def finish(self, ctx, header: str) -> None:
        if self.undecodable:
            ctx.note(
                "row with bytes that are not UTF-8", count=self.undecodable, detail="kept with replacement characters"
            )
        if not self.matched and self.first_keys is not None:
            ctx.skip("columns not recognised", lost=0, detail=header or ", ".join(self.first_keys))


def _read_delimited(path: str, ctx, out: _Out) -> int | None:
    with open(path, "rb") as handle:
        head = handle.read(4096)
    probe = head.decode(_encoding(path), "replace").lstrip("﻿ \t\r\n")
    if not probe:
        ctx.note("file is empty", count=0)
        return 0
    if probe[0] in "[{":
        return _read_json(path, ctx, out)
    return _read_csv(path, ctx, out)


def _read_json(path: str, ctx, out: _Out) -> int | None:
    data = _whole(path, ctx)
    if data is None:
        return None
    try:
        parsed = json.loads(data.decode(_encoding(path), "replace"))
    except (ValueError, RecursionError) as exc:
        ctx.skip("not valid JSON", lost=0, detail=str(exc)[:200])
        return None
    del data
    rows = parsed if isinstance(parsed, list) else None
    if rows is None and isinstance(parsed, dict):
        for name in ("records", "rows", "data"):
            if isinstance(parsed.get(name), list):
                rows = parsed[name]
                break
    if rows is None:
        keys = ", ".join(str(key) for key in parsed) if isinstance(parsed, dict) else type(parsed).__name__
        ctx.skip("no rows found", lost=0, detail=f"expected an array, or an object with records, rows or data: {keys}")
        return None
    mapper = _Rows(out)
    for number, raw in enumerate(rows, start=1):
        if isinstance(raw, dict):
            mapper.row(raw, number)
        else:
            ctx.skip("row cannot be read", lost=1, detail=f"row {number} is a {type(raw).__name__}, not an object")
    mapper.finish(ctx, "")
    return len(rows)


def _lines(handle, ctx):
    """The lines of a text file, none longer than ``MAX_LINE``: the rest of a longer one is a skip."""
    number = 0
    for line in iter(lambda: handle.readline(MAX_LINE + 1), ""):
        number += 1
        if len(line) > MAX_LINE and not line.endswith("\n"):
            ctx.skip("line longer than a megabyte", lost=1, detail=f"line {number}")
            while True:
                rest = handle.readline(MAX_LINE)
                if not rest or rest.endswith("\n"):
                    break
            continue
        yield line


def _read_csv(path: str, ctx, out: _Out) -> int | None:
    mapper = _Rows(out)
    previous = csv.field_size_limit(MAX_LINE)
    rows = blank = wide = errors = 0
    header: list[str] | None = None
    try:
        with open(path, encoding=_encoding(path), errors="replace", newline="") as handle:
            reader = csv.reader(_lines(handle, ctx))
            while True:
                try:
                    cells = next(reader)
                except StopIteration:
                    break
                except csv.Error as exc:
                    errors += 1
                    if header is None:
                        ctx.skip("header cannot be read", lost=0, detail=str(exc)[:200])
                        return None
                    rows += 1
                    ctx.skip("row cannot be read", lost=1, detail=f"line {reader.line_num}: {exc}")
                    if errors >= MAX_UNREADABLE:
                        ctx.skip("too many rows that cannot be read", lost=0, detail="the file is not given up in full")
                        return None
                    continue
                if not any(cell.strip() for cell in cells):
                    blank += 1
                    continue
                if header is None:
                    header = cells
                    mapper.first_keys = cells
                    mapper.matched = bool(out.category.known.intersection(_norm(cell) for cell in cells))
                    continue
                rows += 1
                if len(cells) > len(header):
                    wide += 1
                mapper.row(dict(zip(header, cells, strict=False)), rows, cells[len(header) :])
    finally:
        csv.field_size_limit(previous)
    if blank:
        ctx.note("blank line", count=blank)
    if wide:
        ctx.note(
            "row with more cells than the header", count=wide, detail="the extra cells are kept in its data, as extra"
        )
    mapper.finish(ctx, ",".join(header or []))
    return rows


# -- line files, XBEL, plist, setupapi ------------------------------------------ #
def _read_configlines(path: str, ctx, out: _Out) -> int | None:
    spec = out.spec
    location = str(ctx.params.get("file_name") or "") or spec.label
    out.timeless = True
    in_file = skipped = undecodable = 0
    offset = 0
    with open(path, "rb") as handle:
        number = 0
        for raw in iter(lambda: handle.readline(MAX_LINE + 1), b""):
            number += 1
            at, offset = offset, offset + len(raw)
            if len(raw) > MAX_LINE:
                in_file += 1
                ctx.skip("line longer than a megabyte", offset=at, length=len(raw), detail=f"line {number}")
                while not raw.endswith(b"\n"):
                    raw = handle.readline(MAX_LINE)
                    if not raw:
                        break
                    offset += len(raw)
                continue
            try:
                text = raw.decode("utf-8-sig" if number == 1 else "utf-8")
            except UnicodeDecodeError:
                text = raw.decode("utf-8", "replace")
                undecodable += 1
            line = text.strip()
            if not line or line.startswith("#"):
                skipped += 1
                continue
            in_file += 1
            out.put(
                {"name": spec.record, "kind": spec.kind, "command": line, "location": location},
                None,
                {"line": number, "offset": at, "length": len(raw)},
            )
    if skipped:
        ctx.note("comment or blank line", count=skipped, detail="not a row of the file")
    if undecodable:
        ctx.note("line with bytes that are not UTF-8", count=undecodable, detail="kept with replacement characters")
    return in_file


def _read_xbel(path: str, ctx, out: _Out) -> int | None:
    size = os.path.getsize(path)
    if size > MAX_WHOLE:
        ctx.skip("file too large to read whole", lost=0, length=size, detail=f"{size} bytes, the limit is {MAX_WHOLE}")
        return None
    parser = expat.ParserCreate()
    count = 0

    def refuse(*_args: Any) -> None:
        raise ValueError("a DOCTYPE or an entity declaration is not read")

    def start(name: str, attrs: dict[str, str]) -> None:
        nonlocal count
        if name != "bookmark":
            return
        count += 1
        href = attrs.get("href") or ""
        if not href:
            out.empty += 1
            return
        target = unquote(re.sub(r"^file:/*", "/", href, flags=re.I))
        when = attrs.get("modified") or attrs.get("visited") or attrs.get("added")
        out.put(
            {"name": _base_name(target), "target": target, "kind": "recently-used"},
            _any_to_ms(when),
            {"line": parser.CurrentLineNumber},
        )

    parser.StartDoctypeDeclHandler = refuse
    parser.EntityDeclHandler = refuse
    parser.StartElementHandler = start
    try:
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                parser.Parse(chunk, False)
        parser.Parse(b"", True)
    except (expat.ExpatError, ValueError) as exc:
        ctx.skip(
            "XML cannot be read further",
            lost=0,
            offset=max(parser.CurrentByteIndex, 0),
            detail=f"line {parser.CurrentLineNumber}, after {count} bookmarks: {str(exc)[:200]}",
        )
        raise ValueError(f"the XML stops being readable at line {parser.CurrentLineNumber}") from exc
    return count


def _read_plist(path: str, ctx, out: _Out) -> int | None:
    out.timeless = True
    data = _whole(path, ctx)
    if data is None:
        return None
    try:
        parsed = plistlib.loads(data)
    except Exception as exc:  # noqa: BLE001 - plistlib raises several unrelated types on bad input
        ctx.skip("not a valid plist", lost=0, detail=f"{type(exc).__name__}: {str(exc)[:200]}")
        return None
    if not isinstance(parsed, dict):
        ctx.skip("plist is not a dictionary", lost=1, detail=type(parsed).__name__)
        return 1
    label, args, program = parsed.get("Label"), parsed.get("ProgramArguments"), parsed.get("Program")
    if label is None and args is None and program is None:
        ctx.skip("plist has no Label, Program or ProgramArguments", lost=1, detail=", ".join(map(str, parsed))[:300])
        return 1
    if isinstance(args, list):
        command, where = " ".join(str(part) for part in args), "ProgramArguments"
    else:
        command, where = _text(program), ("Program" if program is not None else "Label")
    out.put(
        {
            "name": _text(label) or str(ctx.params.get("file_name") or ""),
            "kind": "LaunchAgent",
            "command": command,
            "location": out.spec.label,
        },
        None,
        {"path": where},
    )
    return 1


_SETUPAPI_HEADER = re.compile(r"\[Device Install[^\]]*-\s*(USBSTOR\\[^\]]+|USB\\VID_[^\]]+)\]", re.I)
_SETUPAPI_ANY = re.compile(r"\[Device Install\s*[(\-]", re.I)
_SETUPAPI_START = re.compile(r"Section start\s+([\d/]+\s+[\d:.]+)")
_SETUPAPI_WINDOW = 3  # lines after a header that are searched for its "Section start"


def _read_setupapi(path: str, ctx, out: _Out) -> int | None:
    sections = other = undecodable = 0
    pending: tuple[str, int] | None = None  # the device and the line of the header, waiting for its time
    since = 0

    def give(ts: int | None) -> None:
        nonlocal pending
        device, line = pending  # type: ignore[misc]
        serial = device.split("\\")[-1] if "\\" in device else ""
        out.put({"device": device, "serial": serial, "vendor": "", "connection": "setupapi"}, ts, {"line": line})
        pending = None

    with open(path, "rb") as handle:
        number = 0
        for raw in iter(lambda: handle.readline(MAX_LINE + 1), b""):
            number += 1
            if len(raw) > MAX_LINE:
                ctx.skip("line longer than a megabyte", lost=0, length=len(raw), detail=f"line {number}")
                while not raw.endswith(b"\n"):
                    raw = handle.readline(MAX_LINE)
                    if not raw:
                        break
                continue
            try:
                line = raw.decode("utf-8-sig" if number == 1 else "utf-8").rstrip("\r\n")
            except UnicodeDecodeError:
                line = raw.decode("utf-8", "replace").rstrip("\r\n")
                undecodable += 1
            header = _SETUPAPI_HEADER.search(line)
            if header or _SETUPAPI_ANY.search(line):
                if pending is not None:
                    give(None)
                if header:
                    sections += 1
                    pending, since = (header.group(1).strip(), number), 0
                else:
                    other += 1
                continue
            if pending is not None:
                since += 1
                found = _SETUPAPI_START.search(line)
                if found:
                    give(_any_to_ms(found.group(1).replace("/", "-")))
                elif since >= _SETUPAPI_WINDOW:
                    give(None)
    if pending is not None:
        give(None)
    if other:
        ctx.note(
            "device install that is not a USB device",
            count=other,
            detail="only USBSTOR and USB\\VID_ sections are read",
        )
    if undecodable:
        ctx.note("line with bytes that are not UTF-8", count=undecodable, detail="kept with replacement characters")
    if out.ctx.first_ts is not None:
        ctx.note(
            "time is the host's local time",
            count=ctx.read - out.no_time,
            detail="setupapi writes local time with no zone: read here as UTC",
        )
    return sections


# -- KnowledgeC ------------------------------------------------------------------ #
def _read_knowledgec(path: str, ctx, out: _Out) -> int | None:
    if sqlite_safe.wal_mode(path):
        ctx.note("database in WAL mode", detail="rows still in the -wal file are not in this file")
    try:
        conn = sqlite_safe.open_ro(path)
    except (sqlite3.DatabaseError, OSError) as exc:
        ctx.skip("database cannot be opened", lost=0, detail=str(exc)[:200])
        return None
    try:
        try:
            names = sqlite_safe.tables(conn)
        except sqlite3.DatabaseError as exc:  # the first read of a file that is no database
            ctx.skip("database cannot be opened", lost=0, detail=str(exc)[:200])
            return None
        if "ZOBJECT" not in names:
            ctx.skip("table missing", lost=0, detail="ZOBJECT: is this a knowledgeC.db?")
            return None
        try:
            where = "ZSTREAMNAME = '/app/usage'"
            in_file = sqlite_safe.scalar(conn, f"SELECT COUNT(*) FROM ZOBJECT WHERE {where}")
            total = sqlite_safe.count(conn, "ZOBJECT")
            read = 0
            sql = (
                "SELECT rowid AS id, ZVALUESTRING AS app, ZSTARTDATE AS start "
                f"FROM ZOBJECT WHERE {where} ORDER BY rowid"
            )
            for row in sqlite_safe.rows(conn, sql):
                read += 1
                name = _text(row["app"])
                if not name:
                    out.empty += 1
                    continue
                seconds = _number(row["start"])
                ts = _plausible(round((seconds + MAC_EPOCH_OFFSET_S) * 1000)) if seconds is not None else None
                out.put(
                    {"name": name, "path": name, "runCount": "", "source": "KnowledgeC"},
                    ts,
                    {"table": "ZOBJECT", "rowid": row["id"]},
                )
        except sqlite3.Error as exc:
            ctx.skip(
                "database cannot be read further" if "interrupted" in str(exc).lower() else "table cannot be read",
                lost=0,
                detail=str(exc)[:200],
            )
            raise ValueError(f"knowledgeC.db: {str(exc)[:200]}") from exc
        if in_file is None:
            in_file = read
        if total is not None and total > in_file:
            ctx.note("rows of other streams", count=total - in_file, detail="only the /app/usage stream is read")
        return in_file
    finally:
        conn.close()


_READERS = {
    "delimited": _read_delimited,
    "configlines": _read_configlines,
    "xbel": _read_xbel,
    "plist": _read_plist,
    "setupapi": _read_setupapi,
    "knowledgec": _read_knowledgec,
}


def parse(path: str, ctx, source: str) -> None:
    spec = _SPECS.get(source)
    if spec is None:
        raise ValueError(f"The endpoint parser has no source called {source}")
    host = str(ctx.params.get("host") or "")
    username = str(ctx.params.get("username") or "")
    ctx.source(NAME, VERSION, KIND, source, host=host, username=username)
    out = _Out(ctx, source, spec)
    in_file = _READERS[spec.reader](path, ctx, out)
    out.finish(in_file)


# --------------------------------------------------------------------------- #
# The view of a record                                                        #
# --------------------------------------------------------------------------- #
class _Quiet:
    """The context ``_lines`` wants, for a read that says nothing."""

    @staticmethod
    def skip(*_args: Any, **_kwargs: Any) -> None:
        return None


def _whole_for_view(path: str) -> bytes:
    if os.path.getsize(path) > MAX_WHOLE:
        raise ViewError(f"The file is larger than {MAX_WHOLE} bytes: it is not read for a view")
    with open(path, "rb") as handle:
        return handle.read(MAX_WHOLE + 1)


def _view_csv(path: str, number: int) -> dict[str, Any]:
    """The row ``number`` (from 1, the header not counted) of a CSV, counted as the parse counts: a row that
    cannot be read is one, a blank line is not."""
    seen: list[str] = []

    def tap():
        for line in _lines(handle, _Quiet):
            seen.append(line)
            yield line

    previous = csv.field_size_limit(MAX_LINE)
    header: list[str] | None = None
    rows = 0
    try:
        with open(path, encoding=_encoding(path), errors="replace", newline="") as handle:
            reader = csv.reader(tap())
            while True:
                seen.clear()
                try:
                    cells = next(reader)
                    broken = None
                except StopIteration:
                    raise ViewError(f"The file holds no row {number} (it holds {rows})") from None
                except csv.Error as exc:
                    cells, broken = [], exc
                if broken is None and not any(cell.strip() for cell in cells):
                    continue
                if header is None:
                    if broken is not None:
                        raise ViewError(f"The header of the CSV cannot be read: {broken}")
                    header = cells
                    continue
                rows += 1
                if rows == number:
                    break
    finally:
        csv.field_size_limit(previous)
    lines = list(seen)
    first = reader.line_num - len(lines) + 1
    raw = "".join(lines).rstrip("\r\n")
    where = {"row": number, "line": first}
    if broken is not None:
        return {
            "kind": "text",
            "title": f"Row {number} of the CSV, which cannot be read as CSV: {str(broken)[:100]}",
            "where": where,
            "text": raw,
            "highlight": [first, reader.line_num],
            "first": first,
        }
    pairs = [[name, cell] for name, cell in zip(header, cells, strict=False)]
    pairs += [[f"(cell {at + 1}, past the header)", cell] for at, cell in enumerate(cells[len(header) :], len(header))]
    return {
        "kind": "fields",
        "title": f"Row {number} of the CSV, with its header",
        "where": where,
        "rows": pairs,
        "text": raw,
        "first": first,
    }


def _view_delimited(path: str, loc: dict) -> dict[str, Any]:
    number = viewing.loc_int(loc, "row")
    with open(path, "rb") as handle:
        head = handle.read(4096)
    probe = head.decode(_encoding(path), "replace").lstrip("\ufeff \t\r\n")
    if not probe or probe[0] not in "[{":
        return _view_csv(path, number)
    try:
        parsed = json.loads(_whole_for_view(path).decode(_encoding(path), "replace"))
    except (ValueError, RecursionError) as exc:
        raise ViewError(f"The file is not JSON: {str(exc)[:200]}") from None
    rows = parsed if isinstance(parsed, list) else None
    if rows is None and isinstance(parsed, dict):
        rows = next((parsed[name] for name in ("records", "rows", "data") if isinstance(parsed.get(name), list)), None)
    if rows is None or not 1 <= number <= len(rows):
        raise ViewError(f"The file holds no row {number}" + (f" (it holds {len(rows)})" if rows is not None else ""))
    row = rows[number - 1]
    where = {"row": number}
    if not isinstance(row, dict):
        return {"kind": "json", "title": f"Row {number} of the array", "where": where, "text": viewing.pretty(row)}
    return {"kind": "fields", "title": f"Row {number} of the array", "where": where, "rows": viewing.flatten(row)}


def view(path: str, source: str, loc: dict) -> dict:
    """The piece of the file by the reader of the source: a row of a CSV or JSON file (``row``, from 1), a
    row of a database (``table`` and ``rowid``), the lines of a line file (``line``, ``offset``, ``length``),
    or the entry of a property list (``path`` names which)."""
    spec = _SPECS.get(source)
    if spec is None:
        raise ViewError(f"The endpoint parser has no source called {source}")
    if spec.reader == "delimited":
        return _view_delimited(path, loc)
    if spec.reader == "knowledgec":
        return viewing.sqlite_row(path, str(loc.get("table") or ""), loc.get("rowid"))
    if spec.reader == "configlines":
        line, offset, length = (viewing.loc_int(loc, name) for name in ("line", "offset", "length"))
        return viewing.text_around(path, offset, length, line)
    if spec.reader in ("xbel", "setupapi"):
        return viewing.text_by_line(path, viewing.loc_int(loc, "line"))
    try:
        parsed = plistlib.loads(_whole_for_view(path))
    except ViewError:
        raise
    except Exception as exc:  # noqa: BLE001 - plistlib raises several unrelated types on bad input
        raise ViewError(f"The file is not a property list: {type(exc).__name__}") from None
    if not isinstance(parsed, dict):
        raise ViewError("The property list is not a dictionary")
    key = loc.get("path")
    if not isinstance(key, str):
        raise BadLocator("The locator of the record has no key of the property list")
    if key not in parsed:
        raise ViewError(f"The property list has no key {key}")
    rows = viewing.flatten({key: parsed[key]})
    if key != "Label" and "Label" in parsed:
        rows.insert(0, ["Label", viewing.as_text(parsed["Label"])])
    return {
        "kind": "fields",
        "title": f"The key {key} of the property list",
        "where": {"path": key},
        "rows": rows,
    }

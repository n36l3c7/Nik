"""Plaso (log2timeline) exports: the output of ``psort`` as JSON lines or as a CSV.

    plaso.jsonl    ``psort.py -o json_line``: one event per line (``timestamp`` in microseconds, ``timestamp_desc``,
                   ``data_type``, ``message``, ``parser``, ``display_name``, ``hostname``, ``username`` and the
                   fields of the data type)
    plaso.csv      ``psort.py -o dynamic`` or ``-o l2tcsv``, told by the header (a CSV is never taken for one by name)

The native storage file (``.plaso``) is not read: ``triage.refusal`` says how to export it.

**One event is one record, and the section of a record is chosen by what the event is.** The file is one source
of the incident (kind ``collection``); each record says its own section and source (``ctx.record(kind=, source=)``),
and the pages that show a section find it there:

    windows:evtx:record                        eventlog / evtx, with the key of the native reader
                                               (``evtx:<computer>:<channel>:<record>``): the event read from the
                                               export and from the .evtx itself is one record
    fs:stat, fs:ntfs:*, fs:mft*                disk / ntfs.mft, ntfs.usnjrnl, plaso.filestat
    prefetch, amcache, appcompatcache,
    userassist, bam, run keys, services,
    usbstor, mounted devices, lnk, jump
    lists, recent documents, SRUM              endpoint / the sources of ``parsers/hive.py`` and its neighbours
    chrome:, firefox:, safari:, msie:          browser / <browser>.history
    bash and zsh history                       commands / bash, zsh
    syslog, auth, audit, journal, utmp,
    selinux, Apple system log                  syslog / linux.auth, linux.audit, linux.journal, macos.unifiedlog
    everything else                            endpoint / plaso.other, the data type as ``type``

**Time.** An event holds one time and says which (``timestamp_desc``); one object with several times is several
events, and each is a record of its own: its description is part of its key. ``ts`` is the time in milliseconds; an
event without a time (Plaso writes 0) keeps ``ts`` None and is counted in a note.

**Nothing is dropped in silence.** A line that is not JSON, a JSON that is not an event, a line longer than
``MAX_LINE``, a CSV row with another number of cells than the header: skips, each with its place in the file
(``in_file`` is the number of lines, or of rows, the file has). The file is read in a stream.

The place of a record (``loc``): ``{"offset", "length", "line"}``, the physical lines of its event.
"""

from __future__ import annotations

import csv
import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, NamedTuple

from nik_forensics import viewing

NAME = "plaso"
VERSION = "1"
KIND = "collection"
SOURCES = ("plaso.jsonl", "plaso.csv")

MAX_LINE = 4 * 1024 * 1024
MAX_MS = 253402300799000
MAX_UNREADABLE = 10_000  # skips said one by one before the file is given up
_EVENT_HEAD = re.compile(
    rb'^\s*\{\s*"(__container_type__"\s*:\s*"event"|__type__"\s*:\s*"AttributeContainer"|data_type")'
)
_CONTAINER = re.compile(rb'"__container_type__"\s*:\s*"event"')
_L2T = ("date", "time", "timezone", "macb", "source", "sourcetype", "type", "user", "host", "short", "desc")
_NOISE = {"__container_type__", "__type__", "date_time", "pathspec", "path_spec", "_event_data_stream_identifier"}


class Route(NamedTuple):
    kind: str
    source: str
    type: str
    channel: str = ""


# --------------------------------------------------------------------------- #
# What an event is                                                            #
# --------------------------------------------------------------------------- #
_EXACT: dict[str, Route] = {
    "windows:evtx:record": Route("eventlog", "evtx", "event"),
    "fs:ntfs:usn_change": Route("disk", "ntfs.usnjrnl", "usn"),
    "fs:stat:ntfs": Route("disk", "ntfs.mft", "file"),
    "fs:stat": Route("disk", "plaso.filestat", "file"),
    "windows:prefetch:execution": Route("endpoint", "windows.execution.prefetch", "prefetch"),
    "windows:registry:appcompatcache": Route("endpoint", "windows.execution.shimcache", "shimcache"),
    "windows:registry:userassist": Route("endpoint", "windows.execution.userassist", "userassist"),
    "windows:registry:bam": Route("endpoint", "windows.execution.bam-hive", "bam"),
    "windows:registry:service": Route("endpoint", "windows.persistence.services-hive", "service"),
    "windows:registry:usbstor": Route("endpoint", "windows.usb.usbstor-hive", "usbstor"),
    "windows:registry:mounted_devices": Route("endpoint", "windows.usb.mounteddevices", "mounteddevices"),
    "windows:registry:mrulistex": Route("endpoint", "windows.fileaccess.recentdocs", "recentdocs"),
    "windows:registry:mrulist": Route("endpoint", "windows.fileaccess.recentdocs", "recentdocs"),
    "windows:lnk:link": Route("endpoint", "windows.fileaccess.lnk", "lnk"),
    "olecf:dest_list:entry": Route("endpoint", "windows.fileaccess.jumplist", "jumplist"),
    "windows:srum:network_usage": Route("endpoint", "windows.network.srum-network", "srum-network"),
    "windows:srum:application_usage": Route("endpoint", "windows.network.srum-apps", "srum-apps"),
    "windows:setupapi:entry": Route("endpoint", "windows.usb.setupapi", "setupapi"),
    "selinux:line": Route("syslog", "linux.audit", "event", "audit"),
    "linux:utmp:event": Route("syslog", "linux.auth", "event", "auth"),
    "systemd:journal": Route("syslog", "linux.journal", "event", "journal"),
    "bash:history:command": Route("commands", "bash", "command"),
    "shell:zsh:history": Route("commands", "zsh", "command"),
    "mac:asl:event": Route("syslog", "macos.unifiedlog", "event", "unifiedlog"),
}
_PREFIX: tuple[tuple[str, Route], ...] = (
    ("windows:registry:amcache", Route("endpoint", "windows.execution.amcache", "amcache")),
    ("windows:prefetch:", Route("endpoint", "windows.execution.prefetch", "prefetch")),
    ("windows:lnk:", Route("endpoint", "windows.fileaccess.lnk", "lnk")),
    ("windows:srum:", Route("endpoint", "windows.network.srum-apps", "srum-apps")),
    ("fs:mft", Route("disk", "ntfs.mft", "file")),
    ("fs:ntfs:", Route("disk", "ntfs.mft", "file")),
    ("fs:stat:", Route("disk", "plaso.filestat", "file")),
    ("linux:audit", Route("syslog", "linux.audit", "event", "audit")),
    ("linux:", Route("syslog", "linux.auth", "event", "auth")),
    ("syslog:", Route("syslog", "linux.auth", "event", "auth")),
    ("macos:unified", Route("syslog", "macos.unifiedlog", "event", "unifiedlog")),
    ("mac:unified", Route("syslog", "macos.unifiedlog", "event", "unifiedlog")),
    ("mac:asl:", Route("syslog", "macos.unifiedlog", "event", "unifiedlog")),
    ("firefox:", Route("browser", "firefox.places", "visit")),
    ("safari:", Route("browser", "safari.history", "visit")),
    ("msie:webcache", Route("browser", "msie.webcache", "visit")),
    ("chrome:", Route("browser", "chrome.history", "visit")),
)
# The parsers of Plaso by name (the CSV has no data type): the part before the first ``/``, then the whole.
_BY_PARSER: dict[str, str] = {
    "winevtx": "windows:evtx:record",
    "winevt": "windows:evtx:record",
    "usnjrnl": "fs:ntfs:usn_change",
    "mft": "fs:stat:ntfs",
    "filestat": "fs:stat",
    "prefetch": "windows:prefetch:execution",
    "lnk": "windows:lnk:link",
    "custom_destinations": "olecf:dest_list:entry",
    "olecf_dest_list": "olecf:dest_list:entry",
    "amcache": "windows:registry:amcache",
    "appcompatcache": "windows:registry:appcompatcache",
    "userassist": "windows:registry:userassist",
    "bam": "windows:registry:bam",
    "windows_services": "windows:registry:service",
    "windows_usbstor": "windows:registry:usbstor",
    "mounted_devices": "windows:registry:mounted_devices",
    "mrulistex": "windows:registry:mrulistex",
    "srum": "windows:srum:application_usage",
    "setupapi": "windows:setupapi:entry",
    "selinux": "selinux:line",
    "utmp": "linux:utmp:event",
    "systemd_journal": "systemd:journal",
    "bash_history": "bash:history:command",
    "zsh_extended_history": "shell:zsh:history",
    "asl_log": "mac:asl:event",
    "syslog": "syslog:line",
    "chrome_27_history": "chrome:history:page_visited",
    "chrome_8_history": "chrome:history:page_visited",
    "chrome_66_cookies": "chrome:cookie",
    "firefox_history": "firefox:places:page_visited",
    "safari_history": "safari:history:visit",
    "msiecf": "msie:webcache:visits",
    "esedb": "msie:webcache:visits",
}
_RUN_KEY = re.compile(r"\\(Run|RunOnce|RunServices|RunServicesOnce|RunOnceEx)(\\|$)", re.I)
_CHROMIUM_BRANDS = (("edge", ("microsoft\\edge", "microsoft/edge", "msedge")), ("brave", ("bravesoftware", "brave"))
                    , ("opera", ("opera",)))  # fmt: skip


def route_of(data_type: str, parser: str, event: dict[str, Any]) -> Route:
    """The section, the source and the type of an event: its data type first, then the Plaso parser that made it."""
    kind = data_type.lower()
    if not kind and parser:
        kind = _BY_PARSER.get(parser.lower().split("/")[-1], _BY_PARSER.get(parser.lower().split("/")[0], ""))
    found = _EXACT.get(kind)
    if found is None:
        if kind == "windows:registry:key_value" or kind.startswith("windows:registry:"):
            key_path = str(event.get("key_path") or "")
            if _RUN_KEY.search(key_path):
                return Route("endpoint", "windows.persistence.runkeys-hive", "runkey")
        for prefix, candidate in _PREFIX:
            if kind.startswith(prefix):
                found = candidate
                break
    if found is None:
        return Route("endpoint", "plaso.other", data_type or parser or "event")
    if found.kind == "browser" and found.source == "chrome.history":
        # Chromium browsers write the same data type: the place of the file says which.
        place = (str(event.get("display_name") or "") + str(event.get("filename") or "")).lower()
        for brand, markers in _CHROMIUM_BRANDS:
            if any(marker in place for marker in markers):
                found = Route("browser", f"{brand}.history", found.type)
                break
        if kind.endswith("file_downloaded") or "download" in kind:
            found = found._replace(type="download")
    elif found.kind == "browser" and "download" in kind:
        found = found._replace(type="download")
    return found


# --------------------------------------------------------------------------- #
# Times                                                                       #
# --------------------------------------------------------------------------- #
def _ms(value: Any) -> int | None:
    """Milliseconds since the epoch of a number of seconds, milliseconds, microseconds or nanoseconds (told by its
    size: Plaso writes microseconds), or an ISO 8601 text. None for no time (Plaso writes 0) or one out of range."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, str):
        text = value.strip()
        if not text or text.startswith("0000") or text.startswith("1970-01-01T00:00:00"):
            return None
        try:
            moment = datetime.fromisoformat(text)
        except ValueError:
            try:
                value = float(text)
            except ValueError:
                return None
        else:
            if moment.tzinfo is None:
                moment = moment.replace(tzinfo=timezone.utc)
            ms = int(moment.timestamp() * 1000)
            return ms if 0 < ms <= MAX_MS else None
    if not isinstance(value, (int, float)) or value != value or value <= 0:
        return None
    magnitude = abs(value)
    if magnitude < 1e11:
        ms = value * 1000
    elif magnitude < 1e14:
        ms = value
    elif magnitude < 1e17:
        ms = value / 1000
    else:
        ms = value / 1_000_000
    ms = int(ms)
    return ms if 0 < ms <= MAX_MS else None


# --------------------------------------------------------------------------- #
# Reading                                                                     #
# --------------------------------------------------------------------------- #
def sniff(path: str, name: str, head: bytes) -> str | None:
    try:
        text = head.removeprefix(b"\xef\xbb\xbf").lstrip()
        if text.startswith(b"{"):
            line = text.split(b"\n", 1)[0]
            return (
                "plaso.jsonl"
                if _EVENT_HEAD.match(line) and (_CONTAINER.search(line) or b'"timestamp' in line)
                else None
            )
        columns = _columns(text.split(b"\n", 1)[0])
        if columns and ("datetime" in columns and "timestamp_desc" in columns):
            return "plaso.csv"
        if columns and columns[: len(_L2T)] == list(_L2T):
            return "plaso.csv"
    except Exception:  # noqa: BLE001 - a file that cannot even be looked at is not this parser's
        return None
    return None


def _columns(line: bytes) -> list[str]:
    text = line.decode("utf-8", "replace").strip().lower()
    if "," not in text or len(text) > 2000:
        return []
    try:
        return [cell.strip() for cell in next(csv.reader([text]))]
    except (csv.Error, StopIteration):
        return []


def _lines(handle):
    """(offset, length, line number, bytes or None) of each physical line; ``None`` for one longer than ``MAX_LINE``
    (said as a skip by the caller): the rest of it is read through without being kept."""
    offset = 0
    number = 0
    while True:
        raw = handle.readline(MAX_LINE + 1)
        if not raw:
            return
        number += 1
        length = len(raw)
        if len(raw) > MAX_LINE and not raw.endswith(b"\n"):
            while True:
                rest = handle.readline(MAX_LINE)
                length += len(rest)
                if not rest or rest.endswith(b"\n"):
                    break
            yield offset, length, number, None
        else:
            yield offset, length, number, raw
        offset += length


def _name(value: Any) -> str:
    return "" if value in (None, "-") else str(value)


def _clean(event: dict[str, Any]) -> dict[str, Any]:
    return {name: value for name, value in event.items() if name not in _NOISE and not str(name).startswith("__")}


def _digest(*parts: Any) -> str:
    whole = "\x1f".join("" if part is None else str(part) for part in parts)
    return hashlib.sha256(whole.encode("utf-8", "replace")).hexdigest()[:20]


class _Reader:
    """Turns events (dicts) into records, whatever file they came from."""

    def __init__(self, ctx) -> None:
        self.ctx = ctx
        self.host = str(ctx.params.get("host") or "")
        self.username = str(ctx.params.get("username") or "")
        self.seen: dict[str, int] = {}
        self.no_time = 0
        self.out_of_range = 0
        self.sections: dict[str, int] = {}

    def event(self, event: dict[str, Any], stamp: Any, desc: str, loc: dict[str, Any]) -> None:
        data_type = str(event.get("data_type") or "")
        parser = str(event.get("parser") or "")
        route = route_of(data_type, parser, event)
        ts = _ms(stamp)
        if ts is None:
            if stamp not in (None, "", 0, "0", 0.0):
                self.out_of_range += 1
            self.no_time += 1
        host = _name(event.get("hostname") or event.get("computer_name") or event.get("host")) or self.host
        username = _name(event.get("username") or event.get("user")) or self.username
        data = {
            **_clean(event),
            "timestampDesc": desc,
            "dataType": data_type,
            "plasoParser": parser,
        }
        data = {name: value for name, value in data.items() if value not in (None, "")}
        message = str(event.get("message") or event.get("short") or "")
        summary = message or str(event.get("display_name") or event.get("filename") or data_type)
        event_id: int | None = None
        channel = route.channel
        if route.source == "evtx":
            xml = str(event.get("xml_string") or "")
            channel = _evtx_channel(xml, event)
            computer = _name(event.get("computer_name")) or host
            number = event.get("record_number")
            event_id = _int(event.get("event_identifier") if event.get("event_identifier") is not None else None)
            if event_id is not None:
                event_id &= 0xFFFF
            data.update(_evtx_data(xml))
            data.setdefault("EventID", event_id)
            data["Channel"], data["Computer"] = channel, computer
            data["Provider"] = event.get("source_name") or event.get("provider_identifier") or ""
            key = (
                f"evtx:{computer}:{channel}:{number}"
                if number is not None
                else self._key(route, host, event, stamp, desc, message)
            )
            host = computer or host
        else:
            key = self._key(route, host, event, stamp, desc, message)
            if route.kind == "browser":
                data.setdefault("browser", route.source.split(".")[0])
                data.setdefault("profile", "")
        if route.kind == "endpoint":
            data.setdefault("category", route.source.split(".")[1] if route.source.count(".") >= 2 else "plaso")
            data.setdefault("os", route.source.split(".")[0] if route.source.count(".") >= 2 else "plaso")
        if route.kind == "commands":
            data["command"] = str(event.get("command") or message)
        self.sections[route.kind] = self.sections.get(route.kind, 0) + 1
        self.ctx.record(
            key=key,
            type=route.type,
            ts=ts,
            host=host,
            username=username,
            event_id=event_id,
            channel=channel,
            summary=summary,
            data=data,
            loc=loc,
            source=route.source,
            kind=route.kind,
        )

    def _key(self, route: Route, host: str, event: dict[str, Any], stamp: Any, desc: str, message: str) -> str:
        identity = _digest(
            event.get("data_type") or event.get("parser"),
            stamp,
            desc,
            event.get("display_name") or event.get("filename"),
            message,
            event.get("inode") or event.get("record_number") or event.get("offset"),
        )
        base = f"plaso:{host}:{route.source}:{identity}"
        number = self.seen.get(base, 0) + 1
        self.seen[base] = number
        return base if number == 1 else f"{base}:{number}"

    def finish(self, in_file: int | None) -> None:
        if self.no_time:
            self.ctx.note("event without a time", count=self.no_time, detail="Plaso writes 0 when an event has none")
        if self.out_of_range:
            self.ctx.note("time out of range", count=self.out_of_range, detail="read as no time")
        self.ctx.end(in_file=in_file)


def _int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


_CHANNEL = re.compile(r"<Channel>([^<]*)</Channel>")
_DATA = re.compile(r'<Data(?: Name="([^"]*)")?\s*>([^<]*)</Data>')


def _evtx_channel(xml: str, event: dict[str, Any]) -> str:
    found = _CHANNEL.search(xml)
    if found and found.group(1):
        return found.group(1)
    name = str(event.get("filename") or event.get("display_name") or "").replace("\\", "/").rsplit("/", 1)[-1]
    return name[: -len(".evtx")] if name.lower().endswith(".evtx") else name or "unknown"


def _evtx_data(xml: str) -> dict[str, Any]:
    held: dict[str, Any] = {}
    for position, (name, value) in enumerate(_DATA.findall(xml)):
        held[name or f"Data{position}"] = value
    return held


def parse(path: str, ctx, source: str) -> None:
    source = source if source in SOURCES else "plaso.jsonl"
    ctx.source(
        NAME,
        VERSION,
        KIND,
        source,
        host=str(ctx.params.get("host") or ""),
        username=str(ctx.params.get("username") or ""),
    )
    reader = _Reader(ctx)
    if source == "plaso.csv":
        in_file = _read_csv(path, ctx, reader)
    else:
        in_file = _read_json(path, ctx, reader)
    reader.finish(in_file)


def _read_json(path: str, ctx, reader: _Reader) -> int:
    lines = unreadable = blank = 0
    with open(path, "rb") as handle:
        for offset, length, number, raw in _lines(handle):
            if raw is None:
                lines += 1
                ctx.skip(
                    "line longer than the limit",
                    offset=offset,
                    length=length,
                    detail=f"line {number}: more than {MAX_LINE} bytes",
                )
                continue
            body = raw.strip()
            if number == 1:
                body = body.removeprefix(b"\xef\xbb\xbf")
            if not body:
                blank += 1
                continue
            lines += 1
            loc = {"offset": offset, "length": length, "line": number}
            try:
                event = json.loads(body)
            except ValueError as error:
                unreadable += 1
                if unreadable <= MAX_UNREADABLE:
                    ctx.skip(
                        "line is not JSON", offset=offset, length=length, detail=f"line {number}: {str(error)[:200]}"
                    )
                continue
            if not isinstance(event, dict) or not (
                event.get("data_type") or event.get("timestamp") is not None or event.get("message")
            ):
                ctx.skip("line is not a Plaso event", offset=offset, length=length, detail=f"line {number}")
                continue
            reader.event(event, event.get("timestamp"), str(event.get("timestamp_desc") or ""), loc)
    if unreadable > MAX_UNREADABLE:
        ctx.skip(
            "lines that are not JSON, not said one by one",
            lost=unreadable - MAX_UNREADABLE,
            detail=f"{unreadable} in all",
        )
    if blank:
        ctx.note("blank line", count=blank)
    return lines


def _read_csv(path: str, ctx, reader: _Reader) -> int | None:
    state = {"offset": 0, "line": 0, "bad_bytes": 0}
    handle = open(path, "rb")  # noqa: SIM115 - closed in the finally below, the generator reads from it

    def lines():
        for offset, length, number, raw in _lines(handle):
            state["offset"] = offset + length
            state["line"] = number
            yield (raw if raw is not None else b"").decode("utf-8-sig" if number == 1 else "utf-8", "replace")

    rows = 0
    wrong = 0
    csv.field_size_limit(MAX_LINE)
    try:
        table = csv.reader(lines())
        header: list[str] | None = None
        while True:
            start, first = state["offset"], state["line"] + 1
            try:
                row = next(table)
            except StopIteration:
                break
            except csv.Error as error:
                rows += 1
                ctx.skip(
                    "row cannot be read as CSV",
                    offset=start,
                    length=state["offset"] - start,
                    detail=f"line {first}: {str(error)[:200]}",
                )
                continue
            if not row:
                continue
            if header is None:
                header = [cell.strip().lower() for cell in row]
                continue
            rows += 1
            loc = {"offset": start, "length": state["offset"] - start, "line": first}
            if len(row) != len(header):
                wrong += 1
                if wrong <= MAX_UNREADABLE:
                    ctx.skip(
                        "row with another number of cells than the header",
                        offset=start,
                        length=loc["length"],
                        detail=f"line {first}: {len(row)} cells, the header has {len(header)}",
                    )
                continue
            _csv_event(dict(zip(header, row, strict=True)), reader, loc)
    finally:
        handle.close()
    if wrong > MAX_UNREADABLE:
        ctx.skip("rows of the wrong width, not said one by one", lost=wrong - MAX_UNREADABLE, detail=f"{wrong} in all")
    return rows


def _csv_event(row: dict[str, str], reader: _Reader, loc: dict[str, Any]) -> None:
    if "datetime" in row:
        stamp: Any = row.get("datetime")
        desc = row.get("timestamp_desc", "")
        event = {
            name: value
            for name, value in row.items()
            if value not in ("", "-") and name not in ("datetime", "timestamp_desc")
        }
        event["data_type"] = ""
        event["message"] = row.get("message", "")
    else:  # l2tcsv: the date and the time are two columns, the zone a third
        stamp = _l2t_time(row.get("date", ""), row.get("time", ""))
        desc = row.get("macb", "") or row.get("type", "")
        event = {
            "parser": row.get("format", ""),
            "data_type": "",
            "message": row.get("desc", "") or row.get("short", ""),
            "hostname": row.get("host", ""),
            "username": row.get("user", ""),
            "display_name": row.get("filename", ""),
            "source": row.get("source", ""),
            "source_long": row.get("sourcetype", ""),
            "inode": row.get("inode", ""),
            "notes": row.get("notes", ""),
            "extra": row.get("extra", ""),
        }
        if row.get("timezone", "UTC").upper() not in ("UTC", ""):
            reader.ctx.note(
                "time zone other than UTC", count=1, detail=f"the export is in {row.get('timezone')}: read as UTC"
            )
    reader.event(event, stamp, desc, loc)


def _l2t_time(date: str, clock: str) -> str:
    try:
        month, day, year = date.split("/")
        return f"{int(year):04d}-{int(month):02d}-{int(day):02d}T{clock or '00:00:00'}+00:00"
    except ValueError:
        return ""


def view(path: str, source: str, loc: dict) -> dict:
    """The lines of the event (``loc`` has its line, offset and length), with five lines before and after."""
    return viewing.text_around(
        path, viewing.loc_int(loc, "offset"), viewing.loc_int(loc, "length"), viewing.loc_int(loc, "line")
    )

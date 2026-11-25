"""The native logs of Linux and macOS: ``auth.log`` / ``secure``, ``journalctl -o json``, ``audit.log`` and the
unified log (``log show --style ndjson``).

One record per line, except the audit log, where the lines of one event are joined into one record. Every record has
a ``type`` (``logon``, ``logon_failed``, ``sudo``, ``account``, ``session``, ``process``, ``audit``, else ``log``) and
a ``channel`` (``auth``, ``journal``, ``audit``, ``unifiedlog``) that the Sigma log sources are placed by. The messages
of sshd, sudo, su, login, PAM, useradd and the like are decoded into ``data`` fields by ``syslog_parts/messages.py``,
the same code for the three sources that carry text messages.

``linux.auth``    classic syslog lines (``Nov  5 10:00:01 host sshd[12]: …``, no year, no zone), ISO-timestamp lines
                  (rsyslog's default on recent systems) and RFC 5424 lines. The year is ``params.year`` (the year
                  of the first line) or inferred so that the last line is not later than the file's own date
                  (``params.file_time``, epoch ms, as the browser saw it; else the file's date on the worker), with
                  a December to January turn adding a year; a note says which. The times are UTC unless ``params.tz``
                  names a zone; a note says so. A ``.gz`` is not opened: unpack it first.
``linux.journal`` one JSON object per line (``journalctl -o json``): fields may be texts, lists of texts or lists of
                  bytes. The key is the journal's own cursor.
``linux.audit``   ``type=… msg=audit(epoch.ms:serial): k=v …``: lines of one serial are one record (see
                  ``syslog_parts/audit.py``); an execve event is a ``process`` with ``CommandLine``.
``macos.unifiedlog`` ``log show --style ndjson``: one JSON object per line, with its own time zone.

``in_file`` counts what the file holds by the line, without decoding it: the lines that are not blank (for the audit
log: the events, and the lines that belong to none). A line that cannot be read is a skip with its offset; the same line
twice in one file is the same record twice (it has the same key) and is a note. Text before the first JSON record or
after the last (a header and a footer) is a note; a truncated object is a skip.

The file is read a line at a time and never whole. Standard library only.
"""

from __future__ import annotations

import calendar
import hashlib
import json
import os
import re
import time
from collections.abc import Iterator
from datetime import UTC, date, datetime, timedelta
from typing import Any

from nik_forensics import viewing
from nik_forensics.parsers import BadLocator, ViewError
from nik_forensics.parsers.syslog_parts import audit, messages

NAME = "syslog"
VERSION = "1"
KIND = "syslog"
SOURCES = ("linux.auth", "linux.journal", "linux.audit", "macos.unifiedlog")
CHANNEL = {"linux.auth": "auth", "linux.journal": "journal", "linux.audit": "audit", "macos.unifiedlog": "unifiedlog"}

MAX_LINE = 4 * 1024 * 1024
MAX_LINES = 40_000_000  # lines of one file that are read; the rest is a skip that says where it stopped
MAX_BYTES = 16 * 1024 * 1024 * 1024
MAX_LISTED = 200  # skips of one reason said one by one; the rest are said once, with their count
MAX_SEEN = 2_000_000  # keys remembered to count a line that comes twice
MAX_LOC_LINES = 40  # lines of an audit event whose place a record keeps
MAX_LOC_TEXT = 1000  # a locator holds numbers and short texts only (the worker's view check): at most 1024 characters
MAX_PENDING = 1000
MAX_VIEW_PIECE = 64 * 1024

_MONTHS = {name: number for number, name in enumerate(calendar.month_abbr) if name}
_TYPES_WITH_ADDRESS = ("logon", "logon_failed")
_FACILITIES = (
    "kern user mail daemon auth syslog lpr news uucp cron authpriv ftp ntp security console solaris-cron "
    "local0 local1 local2 local3 local4 local5 local6 local7"
).split()

_CLASSIC = re.compile(
    r"^(?:<\d{1,3}>)?(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<h>\d\d):(?P<m>\d\d):(?P<s>\d\d)(?:\.\d+)?"
    r"\s+(?P<host>\S+)\s+(?P<rest>.*)$"
)
_CLASSIC_BYTES = re.compile(rb"^(?:<\d{1,3}>)?([A-Z][a-z]{2})\s+(\d{1,2})\s+\d\d:\d\d:\d\d(?:\.\d+)?\s+\S+\s+\S")
_ISO = re.compile(
    r"^(?:<\d{1,3}>)?(?P<ts>\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:[.,]\d+)?(?:Z|[+-]\d\d:?\d\d)?)"
    r"\s+(?P<host>\S+)\s+(?P<rest>.*)$"
)
_RFC5424 = re.compile(
    r"^<\d{1,3}>1 (?P<ts>\S+) (?P<host>\S+) (?P<app>\S+) (?P<pid>\S+) (?P<msgid>\S+) "
    r"(?P<sd>-|(?:\[(?:[^\]\\]|\\.)*\])+)(?: (?P<msg>.*))?$"
)
_TAG = re.compile(r"^(?P<prog>[^\s:\[]+)(?:\[(?P<pid>[^\]]*)\])?:\s?(?P<msg>.*)$")
_ISO_PARTS = re.compile(r"^(\d{4})-(\d\d)-(\d\d)[T ](\d\d):(\d\d):(\d\d)(?:[.,](\d+))?(Z|[+-]\d\d:?\d\d)?$")
_UNIFIED_TIME = re.compile(r"^(\d{4})-(\d\d)-(\d\d)[T ](\d\d):(\d\d):(\d\d)(?:[.,](\d+))?\s*(Z|[+-]\d\d:?\d\d)?$")
_AUDIT_HEAD = re.compile(r"^(?:node=\S+ )?type=\S+ msg=audit\(\d+(?:\.\d+)?:\d+\):")


# --------------------------------------------------------------------------- #
# What the file is                                                            #
# --------------------------------------------------------------------------- #
def _gzip_source(base: str) -> str | None:
    """A compressed log is not read, but a parser says it is its file when the name says so, so that it is refused
    with the reason and not with ``no parser reads this file``."""
    if "audit" in base:
        return "linux.audit"
    if "journal" in base:
        return "linux.journal"
    if any(word in base for word in ("auth", "secure", "syslog", "messages")):
        return "linux.auth"
    return None


def _syslog_shaped(line: str) -> bool:
    return bool(_CLASSIC.match(line) or _ISO.match(line) or _RFC5424.match(line))


def sniff(path: str, name: str, head: bytes) -> str | None:
    base = os.path.basename(name.replace("\\", "/")).lower()
    if head[:2] == b"\x1f\x8b":
        return _gzip_source(base) if base.endswith((".gz", ".gzip")) else None
    if b"\x00" in head:
        return None
    text = head.decode("utf-8", "replace").lstrip("\ufeff")
    cut = len(head) >= 4096 and not text.endswith("\n")
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        return None
    # A header line before the first JSON object (``log show`` writes one) is not what the file is.
    first_json = next((line for line in lines[:4] if line.lstrip().startswith("{")), None)
    if first_json is not None:
        if '"eventMessage"' in first_json and any(
            word in first_json for word in ('"machTimestamp"', '"processImagePath"', '"traceID"')
        ):
            return "macos.unifiedlog"
        if any(word in first_json for word in ('"__REALTIME_TIMESTAMP"', '"__CURSOR"', '"_SYSTEMD_UNIT"')):
            return "linux.journal"
        return None
    whole = lines[:-1] if cut and len(lines) > 1 else lines
    if any(_AUDIT_HEAD.match(line) for line in whole[:5]):
        return "linux.audit"
    shown = whole[:8]
    if sum(1 for line in shown if _syslog_shaped(line)) * 10 >= len(shown) * 6 and _syslog_shaped(shown[0]):
        return "linux.auth"
    return None


# --------------------------------------------------------------------------- #
# Reading lines                                                               #
# --------------------------------------------------------------------------- #
class _Lines:
    """The lines of a file as ``(number, offset, raw or None, length)``: ``raw`` is None for a line longer than
    ``MAX_LINE`` (its length is whole). ``stop`` says where reading ended when a limit did (number, offset)."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.size = os.path.getsize(path)
        self.stop: tuple[int, int] | None = None

    def __iter__(self) -> Iterator[tuple[int, int, bytes | None, int]]:
        offset = number = 0
        with open(self.path, "rb") as handle:
            while True:
                if number >= MAX_LINES or offset >= MAX_BYTES:
                    if offset < self.size:
                        self.stop = (number, offset)
                    return
                raw = handle.readline(MAX_LINE + 1)
                if not raw:
                    return
                number += 1
                at = offset
                if len(raw) > MAX_LINE and not raw.endswith(b"\n"):
                    total = len(raw)
                    while True:
                        more = handle.readline(MAX_LINE)
                        total += len(more)
                        if not more or more.endswith(b"\n"):
                            break
                    offset += total
                    yield number, at, None, total
                    continue
                offset += len(raw)
                yield number, at, raw, len(raw)


class _Skips:
    """Skips of one reason are said one by one up to ``MAX_LISTED``, then once with how many there were."""

    def __init__(self, ctx: Any) -> None:
        self.ctx = ctx
        self.count: dict[str, int] = {}
        self.lost = 0

    def add(self, reason: str, offset: int | None, length: int | None, detail: str = "") -> None:
        seen = self.count[reason] = self.count.get(reason, 0) + 1
        self.lost += 1
        if seen <= MAX_LISTED:
            self.ctx.skip(reason, offset=offset, length=length, detail=detail)

    def done(self) -> None:
        for reason, seen in self.count.items():
            if seen > MAX_LISTED:
                self.ctx.skip(
                    reason, lost=seen - MAX_LISTED, detail=f"{seen - MAX_LISTED} more like it, not listed one by one"
                )


class _Out:
    """Writes the records of one file and counts the keys that come twice."""

    def __init__(self, ctx: Any, channel: str, host: str) -> None:
        self.ctx, self.channel, self.host = ctx, channel, host
        self.seen: set[int] = set()
        self.duplicates = 0
        self.tracking_stopped = False
        self.no_time = 0

    def give(
        self,
        key: str,
        rtype: str,
        ts: int | None,
        host: str,
        username: str,
        summary: str,
        data: dict[str, Any],
        loc: dict[str, Any],
        ioc: list[tuple[str, str]] | tuple = (),
    ) -> None:
        mark = hash(key)
        if mark in self.seen:
            self.duplicates += 1
        elif len(self.seen) < MAX_SEEN:
            self.seen.add(mark)
        else:
            self.tracking_stopped = True
        if ts is None:
            self.no_time += 1
        self.ctx.record(
            key=key,
            type=rtype,
            ts=ts,
            host=host or self.host,
            username=username,
            channel=self.channel,
            summary=summary,
            data=data,
            loc=loc,
            ioc=ioc,
        )

    def notes(self) -> None:
        if self.duplicates:
            self.ctx.note(
                "line that comes twice in the file",
                count=self.duplicates,
                detail="read as the same record twice (the same key): the second one is a duplicate, nothing is lost",
            )
        if self.tracking_stopped:
            self.ctx.note(
                "repeated lines counted in the first part only",
                detail=f"after {MAX_SEEN} records the keys are no longer remembered",
            )
        if self.no_time:
            self.ctx.note("record without a time", count=self.no_time, detail="kept, with no place on the timeline")


def _digest(raw: bytes | str) -> str:
    data = raw if isinstance(raw, bytes) else raw.encode("utf-8", "replace")
    return hashlib.sha256(data).hexdigest()[:16]


def _text(raw: bytes, bad: list[int]) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        bad[0] += 1
        return raw.decode("utf-8", "replace")


def _limit(ctx: Any, lines: _Lines) -> None:
    if lines.stop is not None:
        number, offset = lines.stop
        ctx.skip(
            "file over the limits of a job",
            offset=offset,
            length=lines.size - offset,
            lost=0,
            detail=f"reading stopped after {number} lines, at byte {offset}; the rest of the file "
            f"({lines.size - offset} bytes) was not read",
        )


def _typed(program: str, message: str, base: dict[str, Any]) -> tuple[str, str, dict[str, Any], list]:
    """The record type, the account and the data of a message, with the indicators it holds."""
    decoded = messages.decode(program, message)
    if decoded is None:
        return "log", "", base, []
    rtype, extra, user = decoded
    data = {**base, **{k: v for k, v in extra.items() if v not in (None, "")}}
    ioc = messages.indicators(extra) if rtype in _TYPES_WITH_ADDRESS else []
    return rtype, user, data, ioc


def _summary(program: str, message: str) -> str:
    return f"{program}: {message}" if program else message


# --------------------------------------------------------------------------- #
# Time                                                                        #
# --------------------------------------------------------------------------- #
def _zone(ctx: Any):
    """The zone ``params.tz`` names (None for UTC); a name that is not one is a note and UTC."""
    name = str(ctx.params.get("tz") or "").strip()
    if not name or name.upper() in ("UTC", "Z", "GMT"):
        return None, "UTC"
    try:
        from zoneinfo import ZoneInfo

        return ZoneInfo(name), name
    except Exception:  # noqa: BLE001 - an unknown zone or no tz database: UTC, and said
        ctx.note("time zone not understood", detail=f"{name[:60]} is not a zone this worker knows: UTC was used")
        return None, "UTC"


def _fraction_ms(text: str | None) -> int:
    return int((text + "000")[:3]) if text else 0


def _shift(offset: str) -> int:
    """``Z`` or ``+02:00`` as the seconds the zone is ahead of UTC."""
    if offset == "Z":
        return 0
    clean = offset.replace(":", "")
    return (int(clean[1:3]) * 3600 + int(clean[3:5]) * 60) * (-1 if clean[0] == "-" else 1)


def _iso_ms(text: str, zone: Any) -> tuple[int | None, bool]:
    """An ISO time as milliseconds, and whether it had a zone of its own."""
    found = _ISO_PARTS.match(text)
    if not found:
        return None, False
    year, month, day, hour, minute, second, fraction, offset = found.groups()
    try:
        moment = datetime(int(year), int(month), int(day), int(hour), int(minute), min(int(second), 59))
    except ValueError:
        return None, False
    if offset:
        return (calendar.timegm(moment.timetuple()) - _shift(offset)) * 1000 + _fraction_ms(fraction), True
    if zone is not None:
        return int(moment.replace(tzinfo=zone).timestamp()) * 1000 + _fraction_ms(fraction), False
    return calendar.timegm(moment.timetuple()) * 1000 + _fraction_ms(fraction), False


def _survey(path: str) -> tuple[int, int, tuple[int, int] | None]:
    """A first pass over the classic lines, reading the month and the day only: how many there are, how many times
    the month falls back by half a year or more (a December to January turn), and the date of the last one."""
    count = turns = 0
    previous: int | None = None
    last: tuple[int, int] | None = None
    for _number, _at, raw, _length in _Lines(path):
        if raw is None:
            continue
        found = _CLASSIC_BYTES.match(raw)
        if not found:
            continue
        month = _MONTHS.get(found.group(1).decode("ascii", "replace"))
        if not month:
            continue
        count += 1
        if previous is not None and previous - month >= 6:
            turns += 1
        previous, last = month, (month, int(found.group(2)))
    return count, turns, last


def _epoch_seconds(value: Any) -> float | None:
    """``params.file_time`` (epoch ms) in seconds, or None when it is absent or not a number."""
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        return None
    return value / 1000.0


class _Years:
    """The year of the classic lines (they have none): ``params.year`` for the first line, else counted back from the
    file's date so that the last line is not in its future; a turn from December to January adds one."""

    def __init__(self, path: str, ctx: Any) -> None:
        self.count, turns, last = _survey(path)
        self.year: int | None = None
        self.previous: int | None = None
        self.note = ""
        self.from_name = ""
        self.given = False
        if not self.count:
            return
        asked = ctx.params.get("year")
        try:
            wanted = int(asked) if asked not in (None, "") else None
        except (TypeError, ValueError):
            wanted = None
        if wanted is not None and 1970 <= wanted <= 2200:
            self.year, self.given = wanted, True
            self.note = f"the lines carry no year: {wanted} was taken for the first line (params.year)"
        else:
            now = time.time()
            # The file's own last-modified time as the browser saw it; the time the file reached the worker (its
            # mtime here) is the time of the transfer, and says nothing of the log.
            given_time = _epoch_seconds(ctx.params.get("file_time"))
            modified = given_time if given_time is not None else os.path.getmtime(path)
            reference = modified if 946684800 < modified <= now + 86400 else now
            self.from_name = "the file's own date" if given_time is not None else "the file's date on the worker"
            day = datetime.fromtimestamp(reference, UTC).date() + timedelta(days=1)
            year = day.year
            for _try in range(12):
                # 29 February (or a day that does not exist) of a year that has none is taken as the month's last day.
                if date(year, last[0], min(last[1], calendar.monthrange(year, last[0])[1])) <= day:  # type: ignore[index]
                    break
                year -= 1
            self.year = year - turns
            self.note = (
                f"the lines carry no year: {self.year} was assumed for the first line"
                + (f" and {self.year + turns} for the last" if turns else "")
                + f", so that no line is later than {self.from_name} ({day - timedelta(days=1)}); "
                "set params.year to say another"
            )
        if turns:
            self.note += f"; the month falls back {turns} time(s), each counted as a new year"

    def of(self, month: int) -> int:
        if self.previous is not None and self.previous - month >= 6:
            self.year = (self.year or 0) + 1
        self.previous = month
        return self.year or 1970


# --------------------------------------------------------------------------- #
# linux.auth                                                                  #
# --------------------------------------------------------------------------- #
def _parse_auth(path: str, ctx: Any, host: str) -> None:
    zone, zone_name = _zone(ctx)
    years = _Years(path, ctx)
    out = _Out(ctx, "auth", host)
    skips = _Skips(ctx)
    lines = _Lines(path)
    bad = [0]
    blank = in_file = no_zone = bad_date = 0
    days: dict[tuple[int, int, int], int | None] = {}
    for number, at, raw, length in lines:
        if raw is None:
            in_file += 1
            skips.add("line longer than the limit", at, length, f"line {number}, {length} bytes")
            continue
        line = _text(raw, bad).rstrip("\r\n")
        if not line.strip():
            blank += 1
            continue
        in_file += 1
        ts: int | None
        token: str
        found5424 = _RFC5424.match(line) if line.startswith("<") else None
        classic = None if found5424 else _CLASSIC.match(line)
        iso = None if found5424 or classic else _ISO.match(line)
        extra: dict[str, Any] = {}
        if found5424:
            ts, had_zone = _iso_ms(found5424.group("ts"), zone)
            no_zone += 0 if had_zone or ts is None else 1
            token = str(ts)
            line_host = "" if found5424.group("host") == "-" else found5424.group("host")
            program = "" if found5424.group("app") == "-" else found5424.group("app")
            pid = "" if found5424.group("pid") == "-" else found5424.group("pid")
            message = found5424.group("msg") or ""
            if found5424.group("sd") != "-":
                extra["structured"] = found5424.group("sd")
        elif classic and classic.group("mon") in _MONTHS:
            month = _MONTHS[classic.group("mon")]
            year = years.of(month)
            day = int(classic.group("day"))
            stamp = (year, month, day)
            if stamp not in days:
                valid = 1 <= day <= calendar.monthrange(year, month)[1] if 1970 <= year <= 2200 else False
                days[stamp] = calendar.timegm((year, month, day, 0, 0, 0)) if valid else None
            base = days[stamp]
            hour, minute, second = int(classic.group("h")), int(classic.group("m")), int(classic.group("s"))
            if base is None or hour > 23 or minute > 59 or second > 60:
                ts = None
                bad_date += 1
            elif zone is None:
                ts = (base + hour * 3600 + minute * 60 + second) * 1000
            else:
                moment = datetime(year, month, day, hour, minute, min(second, 59))
                ts = int(moment.replace(tzinfo=zone).timestamp()) * 1000
            no_zone += 1
            token = f"{classic.group('mon')}-{day}-{classic.group('h')}:{classic.group('m')}:{classic.group('s')}"
            line_host = classic.group("host")
            tagged = _TAG.match(classic.group("rest"))
            program, pid, message = (
                (tagged.group("prog"), tagged.group("pid") or "", tagged.group("msg"))
                if tagged
                else ("", "", classic.group("rest"))
            )
        elif iso:
            ts, had_zone = _iso_ms(iso.group("ts").replace(",", "."), zone)
            no_zone += 0 if had_zone or ts is None else 1
            token = str(ts)
            line_host = iso.group("host")
            tagged = _TAG.match(iso.group("rest"))
            program, pid, message = (
                (tagged.group("prog"), tagged.group("pid") or "", tagged.group("msg"))
                if tagged
                else ("", "", iso.group("rest"))
            )
        else:
            skips.add("line is not in a syslog format", at, length, f"line {number}: {line[:80]}")
            continue
        message = message.strip()
        base_data: dict[str, Any] = {"program": program, "message": message, **extra}
        if pid:
            base_data["pid"] = int(pid) if pid.isdigit() else pid
        rtype, user, data, ioc = _typed(program, message, base_data)
        out.give(
            f"auth:{line_host or host}:{token}:{_digest(raw.rstrip(b'\r\n'))}",
            rtype,
            ts,
            line_host,
            user,
            _summary(program, message),
            data,
            {"line": number, "offset": at, "length": length},
            ioc,
        )
    _limit(ctx, lines)
    skips.done()
    if blank:
        ctx.note("blank line", count=blank)
    if bad[0]:
        ctx.note("line with bytes that are not UTF-8", count=bad[0], detail="kept with replacement characters")
    if years.note:
        ctx.note("year assumed", count=years.count, detail=years.note)
    if no_zone:
        ctx.note(
            "times taken as UTC" if zone is None else f"times taken in {zone_name}",
            count=no_zone,
            detail="the lines carry no time zone"
            + ("" if zone is not None else "; set params.tz (for example Europe/Rome) to say another"),
        )
    if bad_date:
        ctx.note(
            "line with a date that does not exist in the assumed year", count=bad_date, detail="kept without a time"
        )
    out.notes()
    ctx.end(in_file=in_file)


# --------------------------------------------------------------------------- #
# JSON lines: journalctl and the unified log                                  #
# --------------------------------------------------------------------------- #
def _json_lines(path: str, ctx: Any, out: _Out, handle: Any, what: str) -> int:
    """Calls ``handle(object, number, offset, length)`` for every JSON object of the file, one a line. Text before the
    first object or after the last is a note (a header, a footer); a line that is not an object between records, or
    a cut one, is a skip. Returns the number of lines that are objects or try to be."""
    lines = _Lines(path)
    skips = _Skips(ctx)
    bad = [0]
    in_file = blank = header = 0
    started = False
    pending: list[tuple[int, int, int, str]] = []
    for number, at, raw, length in lines:
        if raw is None:
            in_file += 1
            started = True
            skips.add("line longer than the limit", at, length, f"line {number}, {length} bytes")
            continue
        stripped = raw.strip()
        if not stripped:
            blank += 1
            continue
        if stripped[:1] != b"{":
            if not started:
                header += 1
            elif len(pending) < MAX_PENDING:
                pending.append((number, at, length, _text(stripped[:80], bad)))
            else:
                in_file += 1
                skips.add("line that is not a JSON object", at, length, f"line {number}")
            continue
        in_file += 1
        started = True
        for held in pending:
            in_file += 1
            skips.add("line that is not a JSON object", held[1], held[2], f"line {held[0]}: {held[3]}")
        pending = []
        try:
            document = json.loads(stripped)
        except (ValueError, RecursionError):
            skips.add(
                "line is not valid JSON (a cut object?)", at, length, f"line {number}: {_text(stripped[:80], bad)}"
            )
            continue
        if not isinstance(document, dict):
            skips.add("line is not a JSON object", at, length, f"line {number}")
            continue
        handle(document, number, at, length)
    _limit(ctx, lines)
    skips.done()
    if header:
        ctx.note("text before the first record", count=header, detail=f"the header of the {what} export: not a record")
    if pending:
        ctx.note(
            "text after the last record", count=len(pending), detail=f"the footer of the {what} export: not a record"
        )
    if blank:
        ctx.note("blank line", count=blank)
    if bad[0]:
        ctx.note("line with bytes that are not UTF-8", count=bad[0], detail="kept with replacement characters")
    out.notes()
    return in_file


def _jtext(value: Any) -> str:
    """A journal field as text: a text, a number, a list of bytes (a field that is not UTF-8) or a list of texts."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, list):
        if value and all(isinstance(item, int) and not isinstance(item, bool) and 0 <= item < 256 for item in value):
            return bytes(value).decode("utf-8", "replace")
        return "\n".join(_jtext(item) for item in value)
    return json.dumps(value, ensure_ascii=False, default=str)


_JOURNAL_FIELDS = (
    "MESSAGE",
    "_SYSTEMD_UNIT",
    "SYSLOG_IDENTIFIER",
    "_PID",
    "_UID",
    "_COMM",
    "_EXE",
    "_CMDLINE",
    "PRIORITY",
    "_HOSTNAME",
    "_TRANSPORT",
)


def _parse_journal(path: str, ctx: Any, host: str) -> None:
    out = _Out(ctx, "journal", host)

    def one(document: dict, number: int, at: int, length: int) -> None:
        fields = {name: _jtext(document.get(name)) for name in _JOURNAL_FIELDS if document.get(name) is not None}
        message = fields.get("MESSAGE", "")
        program = fields.get("SYSLOG_IDENTIFIER") or fields.get("_COMM") or ""
        stamp = _jtext(document.get("__REALTIME_TIMESTAMP")) or _jtext(document.get("_SOURCE_REALTIME_TIMESTAMP"))
        ts = int(stamp) // 1000 if stamp.isdigit() else None
        line_host = fields.get("_HOSTNAME", "")
        facility = _jtext(document.get("SYSLOG_FACILITY"))
        base = {**fields, "program": program}
        if facility.isdigit() and int(facility) < len(_FACILITIES):
            base["facility"] = _FACILITIES[int(facility)]
        rtype, user, data, ioc = _typed(program, message, base)
        cursor = _jtext(document.get("__CURSOR"))
        where = line_host or host
        key = (
            f"journal:{where}:{cursor}"
            if cursor
            else f"journal:{where}:{stamp}:{_digest(json.dumps(document, sort_keys=True, default=str))}"
        )
        out.give(
            key,
            rtype,
            ts,
            line_host,
            user,
            _summary(program, message),
            data,
            {"line": number, "offset": at, "length": length},
            ioc,
        )

    ctx.end(in_file=_json_lines(path, ctx, out, one, "journalctl"))


def _unified_ms(text: str) -> int | None:
    found = _UNIFIED_TIME.match(text.strip())
    if not found:
        return None
    year, month, day, hour, minute, second, fraction, offset = found.groups()
    try:
        moment = datetime(int(year), int(month), int(day), int(hour), int(minute), min(int(second), 59))
    except ValueError:
        return None
    epoch = calendar.timegm(moment.timetuple()) - (_shift(offset) if offset else 0)
    return epoch * 1000 + _fraction_ms(fraction)


_UNIFIED_FIELDS = (
    "processImagePath",
    "processID",
    "senderImagePath",
    "subsystem",
    "category",
    "eventType",
    "messageType",
    "eventMessage",
    "userID",
    "traceID",
)


def _parse_unified(path: str, ctx: Any, host: str) -> None:
    out = _Out(ctx, "unifiedlog", host)

    def one(document: dict, number: int, at: int, length: int) -> None:
        fields = {name: document[name] for name in _UNIFIED_FIELDS if document.get(name) is not None}
        image = str(fields.get("processImagePath", ""))
        process = image.rsplit("/", 1)[-1]
        message = str(fields.get("eventMessage", ""))
        stamp = str(document.get("timestamp") or "")
        ts = _unified_ms(stamp)
        base = {**fields, "process": process, "program": process, "message": message}
        rtype, user, data, ioc = _typed(process, message, base)
        raw = json.dumps(document, sort_keys=True, default=str)
        out.give(
            f"unifiedlog:{host}:{ts if ts is not None else stamp}:{_digest(raw)}",
            rtype,
            ts,
            "",
            user,
            _summary(process, message),
            data,
            {"line": number, "offset": at, "length": length},
            ioc,
        )

    ctx.end(in_file=_json_lines(path, ctx, out, one, "log show"))


# --------------------------------------------------------------------------- #
# linux.audit                                                                 #
# --------------------------------------------------------------------------- #
def _event_record(out: _Out, event: audit.Event) -> None:
    data = audit.decode_event(event)
    kind = data.pop("kind")
    ok = audit.result_ok(data)
    host = event.node
    types = data["types"]
    username = ""
    ioc: list[tuple[str, str]] = []
    if kind == "process":
        rtype = "process"
        uid = str(data.get("uid", ""))
        username = str(data.get("uid_name") or ("root" if uid == "0" else uid))
        exe = str(data.get("exe", ""))
        summary = f"{exe} {data.get('CommandLine', '')}".strip()
    elif kind == "user":
        username = str(data.get("acct") or data.get("auid_name") or data.get("id") or "")
        where = str(data.get("addr", ""))
        extra: dict[str, Any] = {}
        messages.source_of(extra, "" if where == "?" else where)
        if not extra and data.get("hostname", "?") != "?":
            messages.source_of(extra, str(data["hostname"]))
        for name, value in extra.items():
            data[name] = value
        service = messages.base_name(str(data.get("exe", "")))
        data["logon_type"] = "ssh" if service in messages.SSHD else service
        failed = ok is False
        if failed:
            rtype = "logon_failed"
        elif "USER_LOGIN" in types and ok:
            rtype = "logon"
        else:
            rtype = "audit"
        if rtype in _TYPES_WITH_ADDRESS:
            ioc = messages.indicators(extra)
        summary = f"{' '.join(types)} {username} {data.get('op', '')} {'failed' if failed else 'ok'}".strip()
    else:
        rtype = "audit"
        summary = f"{' '.join(types)} " + " ".join(
            f"{name}={data[name]}" for name in ("acct", "unit", "op", "res", "exe", "name") if data.get(name)
        )
    lines = event.lines
    # The place of each line as ``number:offset:length``, joined by spaces (a locator holds numbers and short texts).
    shown: list[str] = []
    size = 0
    for line in lines[:MAX_LOC_LINES]:
        piece = f"{line.number}:{line.offset}:{line.length}"
        if size + len(piece) + 1 > MAX_LOC_TEXT:
            break
        shown.append(piece)
        size += len(piece) + 1
    loc = {"lines": " ".join(shown), "more": max(0, len(lines) - len(shown))}
    out.give(
        f"audit:{host or out.host}:{event.time}:{event.serial}",
        rtype,
        audit.time_ms(event.time),
        host,
        username,
        summary.strip(),
        data,
        loc,
        ioc,
    )


def _parse_audit(path: str, ctx: Any, host: str) -> None:
    out = _Out(ctx, "audit", host)
    skips = _Skips(ctx)
    joiner = audit.Joiner()
    lines = _Lines(path)
    bad = [0]
    blank = events = unreadable = 0
    nonlocal_unreadable = [0]

    def give(finished: list[audit.Event]) -> None:
        nonlocal events
        for event in finished:
            if not event.lines:  # only an EOE came: the event's other lines are somewhere else
                nonlocal_unreadable[0] += 1
                skips.add("end of an audit event without its lines", None, None, f"serial {event.serial}")
                continue
            events += 1
            _event_record(out, event)

    for number, at, raw, length in lines:
        if raw is None:
            unreadable += 1
            skips.add("line longer than the limit", at, length, f"line {number}, {length} bytes")
            continue
        text = _text(raw, bad)
        if not text.strip():
            blank += 1
            continue
        line = audit.parse_line(text, number, at, length)
        if line is None:
            unreadable += 1
            skips.add("line is not an audit record", at, length, f"line {number}: {text[:80].rstrip()}")
            continue
        give(joiner.add(line))
    give(joiner.flush())
    _limit(ctx, lines)
    if joiner.dropped_lines:
        ctx.skip(
            "audit event with more lines than are joined",
            lost=joiner.dropped_lines,
            detail=f"{joiner.dropped_lines} lines of long events were not joined (at most {audit.MAX_LINES} an event)",
        )
    skips.done()
    if blank:
        ctx.note("blank line", count=blank)
    if bad[0]:
        ctx.note("line with bytes that are not UTF-8", count=bad[0], detail="kept with replacement characters")
    if joiner.overflowed:
        ctx.note(
            "audit events written before their end line",
            count=joiner.overflowed,
            detail=f"more than {joiner.window} events were open at once: the oldest were given back without waiting",
        )
    out.notes()
    ctx.end(in_file=events + unreadable + nonlocal_unreadable[0])


# --------------------------------------------------------------------------- #
# Entry points                                                                #
# --------------------------------------------------------------------------- #
def parse(path: str, ctx: Any, source: str) -> None:
    host = str(ctx.params.get("host") or "")
    username = str(ctx.params.get("username") or "")
    if source not in SOURCES:
        with open(path, "rb") as handle:
            head = handle.read(4096)
        source = sniff(path, str(ctx.params.get("file_name") or ""), head) or "linux.auth"
    ctx.source(NAME, VERSION, KIND, source, host=host, username=username)
    with open(path, "rb") as handle:
        magic = handle.read(2)
    if magic == b"\x1f\x8b":
        ctx.skip(
            "compressed file: unpack it first",
            offset=0,
            length=os.path.getsize(path),
            lost=0,
            detail="a gzip file is not opened (its size when unpacked is not known): unpack it first, then import it",
        )
        ctx.end()
        return
    {
        "linux.auth": _parse_auth,
        "linux.journal": _parse_journal,
        "linux.audit": _parse_audit,
        "macos.unifiedlog": _parse_unified,
    }[source](path, ctx, host)


def _int_pair(item: Any) -> tuple[int, int, int]:
    parts = item.split(":") if isinstance(item, str) else []
    if len(parts) != 3 or not all(part.isascii() and part.isdigit() for part in parts):
        raise BadLocator("The locator of the record names lines that are not line:offset:length")
    return int(parts[0]), int(parts[1]), int(parts[2])


def view(path: str, source: str, loc: dict) -> dict:
    """The line of the record, with five before and after; for an audit event, its lines (they may be apart)."""
    if "lines" not in loc:
        return viewing.text_around(
            path, viewing.loc_int(loc, "offset"), viewing.loc_int(loc, "length"), viewing.loc_int(loc, "line")
        )
    text = loc.get("lines")
    pieces = text.split() if isinstance(text, str) else []
    if not pieces or len(pieces) > MAX_LOC_LINES:
        raise BadLocator("The locator of the record has no lines")
    size = os.path.getsize(path)
    shown: list[str] = []
    cut = False
    with open(path, "rb") as handle:
        for item in pieces:
            _line, offset, length = _int_pair(item)
            if offset >= size:
                raise ViewError(f"The file ends at byte {size}: it holds nothing at byte {offset}")
            handle.seek(offset)
            raw = handle.read(min(max(length, 1), MAX_VIEW_PIECE))
            cut = cut or length > MAX_VIEW_PIECE
            shown.append(raw.decode("utf-8", "replace").rstrip("\r\n"))
    numbers = [_int_pair(item)[0] for item in pieces]
    more = loc.get("more") if isinstance(loc.get("more"), int) else 0
    where = {"lines": numbers, "offset": _int_pair(pieces[0])[1], "length": sum(_int_pair(item)[2] for item in pieces)}
    title = f"{len(shown)} line(s) of one audit event, from line {numbers[0]}" + (
        f" ({more} more not shown)" if more else ""
    )
    return {
        "kind": "text",
        "title": title,
        "where": where,
        "text": "\n".join(shown),
        "highlight": [1, len(shown)],
        "first": 1,
        "cut": cut,
    }

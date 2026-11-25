"""The ``nik-eventlogs.json`` that Nik's event-log collection script writes (``Get-WinEvent`` as JSON).

One record per event, in the shape the ``evtx`` parser gives for the same event: the same key
(``evtx:<computer>:<channel>:<record id>``, the same for a record number that comes
twice, as in evtx.py, so an ``.evtx`` of the same log imported later counts these
events as the same), the same summary, user name and indicators (``evtx.normalise`` and its helpers are
used, not copied), the same ``data`` (``provider``, ``level``, then the event's fields) and the same ``proc``,
``proc_end`` and ``logon`` lines (``evtx.evidence``). The JSON holds less than the ``.evtx`` does: no ``task``,
``opcode``, ``keywords``, process or thread.

The file is a document ``{"format": "nik-eventlogs", "host", "logs": [...], "events": [...]}``, or just an
array of events (a plain ``Get-WinEvent | ConvertTo-Json``), or one event. An event is
``{TimeCreated, Id, LogName, ProviderName, RecordId, MachineName, Level, Data}``; the aliases the 6.x
screen read are read here too (``Channel``, ``EventID``, ``EventRecordID``, ``Provider``, ``Computer``,
``Properties``, ``TimeCreatedUtc``, ``Message``). ``Data`` is an object, or the unnamed ``Properties`` list
(``Data1``, ``Data2``…).

The file is read as a stream, one event at a time, so a big export does not take the memory of its parse
tree: only the file's size is limited (``MAX_FILE``). ``in_file`` is the number of events in the array.
``loc`` is ``{"index": position in the array}``. An element that is not an event is a skip. A file that
stops being JSON half way keeps the events before the break, says so in a skip and fails (a read in part).

The script exports the event IDs it was told to: the file is not the whole log, and a note says so (with
the totals the script wrote for each log). Standard library only.
"""

from __future__ import annotations

import codecs
import json
import os
import re
from collections.abc import Iterator
from typing import Any

from nik_forensics import viewing
from nik_forensics.parsers import ViewError, evtx

NAME = "eventlog-json"
VERSION = "2"  # 2: the lines of processes and logons
KIND = "eventlog"
SOURCES = ("nik-eventlogs.json",)

MAX_FILE = 256 * 1024 * 1024
MAX_ELEMENT = 32 * 1024 * 1024  # characters of one event that are held while it is decoded
CHUNK = 1024 * 1024
_DECODER = json.JSONDecoder()
_WHITESPACE = " \t\r\n"
_OFFSET = re.compile(r"(?:Z|([+-])(\d\d):?(\d\d))$")
_LEGACY = re.compile(r"/Date\((-?\d+)")
_SCRIPT_NOTE = "the script exports the event IDs it was told to: this is not the whole log"


def sniff(path: str, name: str, head: bytes) -> str | None:
    """Only a name: ``nik-eventlogs.json``. A JSON file that looks like an export is not told from any other."""
    return SOURCES[0] if os.path.basename(name.replace("\\", "/")).lower() == SOURCES[0] else None


# --------------------------------------------------------------------------- #
# One event                                                                   #
# --------------------------------------------------------------------------- #
def _time(value: Any) -> int | None:
    """An ISO text (with its zone, UTC when it has none), ``/Date(ms)/`` (PowerShell 5.1), a number of
    milliseconds or ``{"value"|"DateTime": ...}`` → milliseconds since the epoch."""
    if isinstance(value, dict):
        return _time(value.get("value", value.get("DateTime")))
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return int(value) if value == value and abs(value) < 253402300799000 else None
    text = str(value).strip()
    legacy = _LEGACY.search(text)
    if legacy:
        return int(legacy.group(1))
    ms = evtx.to_ms(text)
    if ms is None:
        return None
    # to_ms reads the date and time and leaves a zone to this: "+02:00" is two hours before UTC.
    zone = _OFFSET.search(text)
    if zone and zone.group(1):
        shift = (int(zone.group(2)) * 60 + int(zone.group(3))) * 60000
        ms += -shift if zone.group(1) == "+" else shift
    return ms


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return None


def _first(raw: dict, *names: str) -> Any:
    for name in names:
        value = raw.get(name)
        if value is not None and value != "":
            return value
    return None


def _field(value: Any) -> str | None:
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False, default=str)
    elif isinstance(value, bool):
        value = "true" if value else "false"
    return evtx._value(value)


def _fields(raw: dict) -> dict[str, str]:
    held: dict[str, str] = {}
    source = _first(raw, "Data", "Properties")
    if isinstance(source, dict):
        for name, value in source.items():
            text = _field(value)
            if text is not None:
                held[str(name)] = text
    elif isinstance(source, list):
        # Get-WinEvent | ConvertTo-Json keeps the unnamed Properties: [{"Value": ...}].
        for index, item in enumerate(source, start=1):
            text = _field(item.get("Value") if isinstance(item, dict) and "Value" in item else item)
            if text is not None:
                held[f"Data{index}"] = text
    elif source is not None:
        text = _field(source)
        if text is not None:
            held["Data"] = text
    if not held:
        message = _field(raw.get("Message"))
        if message is not None:
            held["Message"] = message
    return held


def normalise_event(raw: dict, host: str = "") -> dict[str, Any]:
    """One event of the export → what Nik keeps of it, in the shape of ``evtx.normalise`` (``script`` is None).

    ``record_id`` is None when the event has no record number. Raises ``TypeError`` for what is no event
    (not an object, or with neither an ID nor a channel)."""
    if not isinstance(raw, dict):
        raise TypeError(f"an event is an object, not a {type(raw).__name__}")
    channel = str(_first(raw, "LogName", "Channel") or "").strip()
    event_id = evtx._event_id(_first(raw, "Id", "EventID", "EventId"))
    if event_id is None and not channel:
        raise TypeError("the event has neither an ID nor a channel")
    provider = str(_first(raw, "ProviderName", "Provider") or "")
    computer = str(_first(raw, "MachineName", "Computer") or host or "").strip()
    fields = _fields(raw)
    data: dict[str, Any] = {"provider": provider, "level": raw.get("Level")}
    for name, text in fields.items():
        data[f"Data.{name}" if name in evtx.FIXED else name] = text
    return {
        "computer": computer,
        "channel": channel,
        "record_id": _int(_first(raw, "RecordId", "EventRecordID", "EventRecordId")),
        "ts": _time(_first(raw, "TimeCreated", "TimeCreatedUtc")),
        "event_id": event_id,
        "username": evtx._username(channel, event_id, provider, fields),
        "summary": evtx._summary(channel, event_id, provider, fields),
        "data": data,
        "ioc": evtx._indicators(channel, event_id, fields),
        "lines": evtx.evidence(channel, event_id, provider, computer, fields),
        "script": None,
    }


# --------------------------------------------------------------------------- #
# The file, as a stream                                                       #
# --------------------------------------------------------------------------- #
class _Stream:
    """JSON values one at a time out of a file, without reading the file whole."""

    def __init__(self, handle) -> None:
        start = handle.read(4)
        handle.seek(0)
        if start.startswith((b"\xff\xfe", b"\xfe\xff")):
            encoding = "utf-16"
        else:
            encoding = "utf-8-sig"
        self._handle = handle
        self._decoder = codecs.getincrementaldecoder(encoding)(errors="replace")
        self.buf = ""
        self.pos = 0
        self.dropped = 0  # characters of the file before ``buf``
        self.eof = False

    @property
    def at(self) -> int:
        return self.dropped + self.pos

    def _fill(self) -> bool:
        if self.eof:
            return False
        raw = self._handle.read(CHUNK)
        if self.pos > CHUNK:
            self.buf, self.dropped, self.pos = self.buf[self.pos :], self.dropped + self.pos, 0
        if not raw:
            self.eof = True
            self.buf += self._decoder.decode(b"", True)
            return False
        self.buf += self._decoder.decode(raw)
        return True

    def peek(self) -> str:
        """The next character that is not white space, "" at the end of the file."""
        while True:
            while self.pos < len(self.buf) and self.buf[self.pos] in _WHITESPACE:
                self.pos += 1
            if self.pos < len(self.buf):
                return self.buf[self.pos]
            if not self._fill() and self.pos >= len(self.buf):
                return ""

    def value(self) -> Any:
        self.peek()
        while True:
            try:
                found, end = _DECODER.raw_decode(self.buf, self.pos)
            except json.JSONDecodeError:
                if self.eof or len(self.buf) - self.pos > MAX_ELEMENT:
                    raise
                self._fill()
                continue
            if end >= len(self.buf) and not self.eof:  # a number or a word may go on in the next chunk
                self._fill()
                continue
            self.pos = end
            return found

    def expect(self, char: str) -> None:
        if self.peek() != char:
            raise ValueError(f"expected {char!r} at character {self.at}")
        self.pos += 1


def _array(stream: _Stream) -> Iterator[Any]:
    stream.pos += 1  # [
    while True:
        char = stream.peek()
        if char == "]":
            stream.pos += 1
            return
        if char == ",":
            stream.pos += 1
        elif char == "":
            raise ValueError("the file ends inside the array of events")
        else:
            yield stream.value()


def _elements(stream: _Stream, document: dict[str, Any]) -> Iterator[Any]:
    """The events of the file; the other members of a document (``host``, ``logs``) go to ``document``."""
    first = stream.peek()
    if first == "[":
        yield from _array(stream)
    elif first == "{":
        stream.pos += 1
        members: dict[str, Any] = {}
        saw_events = False
        while True:
            char = stream.peek()
            if char == "}":
                stream.pos += 1
                break
            if char == ",":
                stream.pos += 1
                continue
            if char == "":
                raise ValueError("the file ends inside the document")
            key = stream.value()
            if not isinstance(key, str):
                raise ValueError(f"a member name is not text at character {stream.at}")
            stream.expect(":")
            if key == "events" and stream.peek() == "[":
                saw_events = True
                yield from _array(stream)
            else:
                members[key] = document[key] = stream.value()
        if not saw_events and any(name in members for name in ("Id", "EventID", "EventId")):
            yield members  # one event on its own
    else:
        raise ValueError("not a JSON event export: it starts with neither [ nor {")
    if stream.peek():
        document["trailing"] = stream.at


def parse(path: str, ctx, source: str) -> None:
    host = str(ctx.params.get("host") or "")
    username = str(ctx.params.get("username") or "")
    ctx.source(NAME, VERSION, KIND, "nik-eventlogs.json", host=host, username=username)
    size = os.path.getsize(path)
    if size > MAX_FILE:
        ctx.skip("file too large to read", lost=0, length=size, detail=f"{size} bytes, the limit is {MAX_FILE}")
        ctx.end()
        return
    document: dict[str, Any] = {}
    count = no_time = no_number = 0
    failure: Exception | None = None
    with open(path, "rb") as handle:
        stream = _Stream(handle)
        try:
            for index, raw in enumerate(_elements(stream, document)):
                count += 1
                try:
                    event = normalise_event(raw, str(document.get("host") or host))
                except Exception as exc:  # noqa: BLE001 - an element of a hostile file may have any shape
                    ctx.skip("element is not an event", lost=1, detail=f"index {index}: {str(exc)[:200]}")
                    continue
                if event["ts"] is None:
                    no_time += 1
                number = event["record_id"]
                if number is None:
                    no_number += 1
                    number = f"pos{index + 1}"
                key = f"evtx:{event['computer']}:{event['channel']}:{number}"
                ctx.record(
                    key=key,
                    type="event",
                    ts=event["ts"],
                    host=event["computer"],
                    username=event["username"],
                    event_id=event["event_id"],
                    channel=event["channel"],
                    summary=event["summary"],
                    data=event["data"],
                    loc={"index": index},
                    ioc=event["ioc"],
                )
                evtx.say(ctx, key, event["ts"], event["computer"], event["lines"])
        except (ValueError, RecursionError) as exc:  # JSONDecodeError is a ValueError
            failure = exc
            ctx.skip("the file stops being JSON", lost=0, offset=None, detail=f"after {count} events: {str(exc)[:200]}")
    if count or failure is None:
        ctx.note("collection script export", count=count, detail=_SCRIPT_NOTE)
    logs = document.get("logs")
    if isinstance(logs, list):
        totals = [
            f"{log.get('name')} {log.get('total')}"
            for log in logs
            if isinstance(log, dict) and log.get("total") is not None
        ]
        if totals:
            ctx.note("log sizes said by the script", count=len(totals), detail="; ".join(totals))
    if no_time:
        ctx.note("event without a usable time", count=no_time)
    if no_number:
        ctx.note("event without a record number", count=no_number, detail="its key is its position in the file")
    if "trailing" in document:
        ctx.note("text after the JSON document", detail=f"from character {document['trailing']}")
    if failure is not None:
        raise ValueError(f"nik-eventlogs.json is not JSON after {count} events: {str(failure)[:200]}") from failure
    ctx.end(in_file=count)


def view(path: str, source: str, loc: dict) -> dict:
    """The element at ``loc["index"]`` of the array of events, found with the stream the parse reads with:
    the file is never held whole, only the element that is being read."""
    index = viewing.loc_int(loc, "index")
    if os.path.getsize(path) > MAX_FILE:
        raise ViewError("The file is too large to be read for a view")
    found: Any = None
    seen = 0
    with open(path, "rb") as handle:
        try:
            for seen, element in enumerate(_elements(_Stream(handle), {}), start=1):
                if seen == index + 1:
                    found = element
                    break
        except (ValueError, RecursionError) as error:
            raise ViewError(f"The file stops being JSON before the element {index}: {str(error)[:200]}") from None
    if seen < index + 1:
        raise ViewError(f"The file holds no element {index} (it holds {seen})")
    return {
        "kind": "json",
        "title": f"Element {index} of the array of events",
        "where": {"index": index},
        "text": viewing.pretty(found),
    }

"""Windows event logs (``.evtx``): every event of the file, and an account of what the file holds.

One record per event, whatever its ID (Nik 6.x kept a curated list). The
``evtx`` crate (Rust, with Python bindings) reads the BinXML; a scanner of the
file's own structure (``nik_forensics.evtxscan``: header, chunks, checksums,
record headers) says what the file holds. The two are reconciled while the
file is read, one chunk at a time:

* a record the scanner saw and the parser did not return is a skip, with its
  offset and the parser's own warning for it when there is one;
* a damaged stretch of a chunk, a chunk whose signature is destroyed and a
  file that stops short are skips too (``lost`` 0: how many records were in
  them is not known, and the detail says what the neighbours imply);
* a checksum that does not match while the records were read, a chunk past the
  header's count, a record whose size copy disagrees are notes: nothing was lost;
* records left behind in a chunk after the log was cleared or wrapped are read
  as well (``recovered``), with a key of their own.

``ctx.end(in_file=...)`` is what the file says it holds: the count the header of each readable chunk
promises (the records found in its used area when the header cannot be trusted).

The key of an event is computer, channel and record ID: a log read again gives
the same keys, and two logs of the same machine that overlap give the same keys
for the same events. PowerShell script blocks (4104) are also put together by
their ``ScriptBlockId`` into one ``script`` record each, from all its parts.

Indicators come only from fields that are declared as such (a logon's source
address, Sysmon's destination, DNS query and hashes). Standard library and the
``evtx`` package.
"""

from __future__ import annotations

import bisect
import hashlib
import io
import itertools
import json
import os
import re
import struct
import warnings
from collections.abc import Callable, Iterator
from datetime import date
from typing import Any

from nik_forensics import evtxscan, viewing
from nik_forensics.parsers import BadLocator, ViewError

NAME = "evtx"
VERSION = "1"
KIND = "eventlog"
SOURCES = ("evtx",)

MAX_PENDING_SCRIPT = 64 * 1024 * 1024  # characters of script blocks waiting for their other parts
MAX_COPIES = 32  # chunks with the ID range of one record that are tried (copies of a chunk are rare)
MAX_HELD = 200_000  # records of the survey waiting for the parser to return them
MAX_LISTED = 1000  # skips of one reason said one by one; the rest are said once, with their count
MAX_WARNINGS_KEPT = 50_000  # parser warnings kept for the detail of a skip
MAX_SLACK = 200_000  # records left in unused space that are indexed for their offsets
MAX_NAMED = 20  # chunk numbers named in the detail of a note
MAX_DONE_SCRIPTS = 200_000

# The names ``data`` has of its own. A field of the event with one of them is called ``Data.<name>``.
FIXED = frozenset({"provider", "level", "task", "opcode", "keywords", "pid", "tid", "sid", "qualifiers", "recovered"})

# Empty values and Windows placeholders ("%%1793" is "<value not set>", "%%1794" "<never>").
_DROP_VALUES = {"", "-", "%%1793", "%%1794", "{00000000-0000-0000-0000-000000000000}"}
_LOGON_IDS = frozenset({4624, 4625, 4634, 4647, 4648, 4740, 4771, 4776})
_NO_ADDRESS = {"", "-", "::1", "127.0.0.1", "::ffff:127.0.0.1"}
_HASHES = {"SHA256": ("sha256", 64), "SHA1": ("sha1", 40), "MD5": ("md5", 32)}
_HEX = re.compile(r"^[0-9a-fA-F]+$")
_TIME = re.compile(r"(\d{4})-(\d\d)-(\d\d)[T ](\d\d):(\d\d):(\d\d)(?:\.(\d+))?")
_EPOCH_ORDINAL = date(1970, 1, 1).toordinal()
MAX_FLATTEN_DEPTH = 12

_WARN_RECORD = re.compile(r"Failed to parse record number (\d+)")
_WARN_READ = re.compile(
    r"Failed to read the record at offset 0x[0-9a-fA-F]+ of chunk (\d+) \(file offset 0x([0-9a-fA-F]+)\)"
)
_WARN_CHUNK = re.compile(r"Failed to parse chunk number (\d+)")


def sniff(path: str, name: str, head: bytes) -> str | None:
    return "evtx" if head.startswith(evtxscan.FILE_MAGIC) else None


# --------------------------------------------------------------------------- #
# One event                                                                   #
# --------------------------------------------------------------------------- #
def _attr(node: Any, name: str) -> Any:
    if isinstance(node, dict):
        attrs = node.get("#attributes")
        if isinstance(attrs, dict):
            return attrs.get(name)
    return None


def _event_id(value: Any) -> int | None:
    """``EventID`` is a number, or ``{"#attributes": {"Qualifiers": ...}, "#text": n}``."""
    if isinstance(value, dict):
        value = value.get("#text")
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def to_ms(text: Any) -> int | None:
    """``2017-12-26T13:10:29.1368792Z`` (or ``... UTC``) → milliseconds since the epoch; None when it is no time.
    Computed with integers: a float loses the milliseconds."""
    found = _TIME.match(str(text or ""))
    if not found:
        return None
    year, month, day, hour, minute, second = (int(part) for part in found.groups()[:6])
    if year < 1970 or hour > 23 or minute > 59 or second > 59:
        return None
    try:
        days = date(year, month, day).toordinal() - _EPOCH_ORDINAL
    except ValueError:
        return None
    millis = int((found.group(7) or "")[:3].ljust(3, "0"))
    return (((days * 24 + hour) * 60 + minute) * 60 + second) * 1000 + millis


def _value(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, dict):
        value = value.get("#text", "")
        if isinstance(value, list):
            value = "\n".join(str(item) for item in value)
    if isinstance(value, list):
        value = ", ".join(str(item) for item in value if item is not None)
    text = str(value)
    # Kept as the log has it (the blocks of a script end where they end, in the middle of a line or after it).
    return None if text.strip() in _DROP_VALUES else text


def _flatten(node: Any, out: dict[str, str], depth: int = 0) -> None:
    """EventData/UserData → flat ``{name: text}``.

    Named fields come as keys; unnamed ``<Data>`` elements as ``Data`` (a value) or ``Data1``,
    ``Data2``… (a list); UserData wraps its fields in one more element (``LogFileCleared``…),
    which is unwrapped. Empty values and placeholders are left out.
    """
    if not isinstance(node, dict) or depth > MAX_FLATTEN_DEPTH:
        return
    for key, value in node.items():
        if key.startswith("#"):
            continue
        if isinstance(value, dict) and "#text" not in value:
            _flatten(value, out, depth + 1)
            continue
        if key == "Data" and isinstance(value, list):
            for index, item in enumerate(value, start=1):
                text = _value(item)
                if text is not None:
                    out[f"Data{index}"] = text
            continue
        text = _value(value)
        if text is not None:
            out[key] = text


# -- what the screens show: the summary of an event --------------------------- #
def _v(fields: dict, *names: str) -> str:
    for name in names:
        if fields.get(name):
            return fields[name]
    return ""


def _short(text: Any, limit: int = 160) -> str:
    one = " ".join(str(text if text is not None else "").split())
    return one if len(one) <= limit else one[: limit - 1] + "…"


def _who(fields: dict, prefix: str = "Target") -> str:
    user = _v(fields, f"{prefix}UserName")
    domain = _v(fields, f"{prefix}DomainName")
    if not user:
        return "?"
    return f"{domain}\\{user}" if domain and not user.endswith("$") else user


_LOGON_TYPES = {
    "2": "interactive",
    "3": "network",
    "4": "batch",
    "5": "service",
    "7": "unlock",
    "8": "network cleartext",
    "9": "new credentials",
    "10": "RDP",
    "11": "cached interactive",
}


def _logon_type(fields: dict) -> str:
    kind = fields.get("LogonType")
    return _LOGON_TYPES.get(kind or "", f"type {kind or '?'}")


def _from(fields: dict) -> str:
    address = _v(fields, "IpAddress")
    source = " / ".join(
        part for part in (_v(fields, "WorkstationName"), address if address not in _NO_ADDRESS else "") if part
    )
    return f" from {source}" if source else ""


def _host_application(fields: dict) -> str:
    text = _v(fields, "Data3", "Data2")
    found = re.search(r"HostApplication=([^\n]*)", text)
    return found.group(1) if found else text


def _rdp(fields: dict) -> str:
    address = _v(fields, "Address")
    return f"{_v(fields, 'User') or '?'}{f' from {address}' if address and address != 'LOCAL' else ''}"


def _base(path: str) -> str:
    return re.split(r"[\\/]", str(path or ""))[-1]


def _member(fields: dict) -> str:
    return f"{_v(fields, 'MemberName', 'MemberSid')} → {_v(fields, 'TargetUserName')}"


def _target_by_subject(fields: dict) -> str:
    return f"{_who(fields)} by {_who(fields, 'Subject')}"


def _session(fields: dict) -> str:
    return f"{_v(fields, 'AccountName')} from {_v(fields, 'ClientName')} {_v(fields, 'ClientAddress')}".strip()


def _threat(fields: dict) -> str:
    return _v(fields, "Threat Name", "ThreatName")


# The summary of the events Nik 6.x curated, by lower-case channel and ID (the same words as
# ``frontend/src/config/eventLogs.js``). Any other event gets ``_generic``.
_SUMMARIES: dict[tuple[str, int], Callable[[dict], str]] = {
    ("security", 1102): lambda f: f"cleared by {_who(f, 'Subject')}",
    ("security", 4624): lambda f: f"{_who(f)} — {_logon_type(f)}{_from(f)}",
    ("security", 4625): lambda f: f"{_who(f)} — {_logon_type(f)}{_from(f)}",
    ("security", 4634): lambda f: f"{_who(f)} — {_logon_type(f)}",
    ("security", 4647): lambda f: _who(f),
    ("security", 4648): lambda f: f"{_who(f, 'Subject')} as {_who(f)} → {_v(f, 'TargetServerName') or '?'}",
    ("security", 4672): lambda f: _who(f, "Subject"),
    ("security", 4688): lambda f: _short(_v(f, "CommandLine", "NewProcessName")),
    ("security", 4697): lambda f: f"{_v(f, 'ServiceName')} → {_short(_v(f, 'ServiceFileName'))}",
    ("security", 4698): lambda f: _v(f, "TaskName"),
    ("security", 4699): lambda f: _v(f, "TaskName"),
    ("security", 4702): lambda f: _v(f, "TaskName"),
    ("security", 4719): lambda f: f"by {_who(f, 'Subject')}",
    ("security", 4720): _target_by_subject,
    ("security", 4722): _target_by_subject,
    ("security", 4724): _target_by_subject,
    ("security", 4726): _target_by_subject,
    ("security", 4728): _member,
    ("security", 4732): _member,
    ("security", 4756): _member,
    ("security", 4740): lambda f: f"{_who(f)}{_from(f)}",
    ("security", 4771): lambda f: f"{_who(f)}{_from(f)}",
    ("security", 4776): lambda f: (
        f"{_v(f, 'TargetUserName')} from {_v(f, 'Workstation') or '?'} (status {_v(f, 'Status')})"
    ),
    ("security", 4778): _session,
    ("security", 4779): _session,
    ("system", 104): lambda f: f"{_v(f, 'Channel') or 'a log'} cleared by {_v(f, 'SubjectUserName') or '?'}",
    ("system", 1074): lambda f: _short(
        f"{_v(f, 'param5', 'Data5')} by {_v(f, 'param7', 'Data7')} ({_v(f, 'param1', 'Data1')})"
    ),
    ("system", 6005): lambda f: "boot",
    ("system", 6006): lambda f: "clean shutdown",
    ("system", 6008): lambda f: "previous shutdown was unexpected",
    ("system", 7040): lambda f: f"{_v(f, 'param1', 'Data1')}: {_v(f, 'param2', 'Data2')} → {_v(f, 'param3', 'Data3')}",
    ("system", 7045): lambda f: f"{_v(f, 'ServiceName')} → {_short(_v(f, 'ImagePath'))}",
    ("microsoft-windows-powershell/operational", 4103): lambda f: _short(_v(f, "Payload", "ContextInfo")),
    ("microsoft-windows-powershell/operational", 4104): lambda f: _short(_v(f, "ScriptBlockText")),
    ("windows powershell", 400): lambda f: _short(_host_application(f)),
    ("windows powershell", 800): lambda f: _short(_v(f, "Data1") or _host_application(f)),
    ("microsoft-windows-terminalservices-remoteconnectionmanager/operational", 1149): lambda f: (
        f"{_v(f, 'Param1')} {_v(f, 'Param2')} from {_v(f, 'Param3') or '?'}".strip()
    ),
    ("microsoft-windows-windows defender/operational", 1116): lambda f: f"{_threat(f)} — {_short(_v(f, 'Path'))}",
    ("microsoft-windows-windows defender/operational", 1117): lambda f: f"{_threat(f)}: {_v(f, 'Action Name')}",
    ("microsoft-windows-windows defender/operational", 5001): lambda f: "real-time protection off",
    ("microsoft-windows-taskscheduler/operational", 106): lambda f: _v(f, "TaskName"),
    ("microsoft-windows-taskscheduler/operational", 141): lambda f: _v(f, "TaskName"),
    ("microsoft-windows-taskscheduler/operational", 200): lambda f: (
        f"{_v(f, 'TaskName')} → {_short(_v(f, 'ActionName'))}"
    ),
    ("microsoft-windows-sysmon/operational", 1): lambda f: _short(_v(f, "CommandLine", "Image")),
    ("microsoft-windows-sysmon/operational", 3): lambda f: (
        f"{_base(_v(f, 'Image'))} → {_v(f, 'DestinationHostname') or _v(f, 'DestinationIp')}:{_v(f, 'DestinationPort')}"
    ),
    ("microsoft-windows-sysmon/operational", 22): lambda f: f"{_base(_v(f, 'Image'))} → {_v(f, 'QueryName')}",
}
for _id in (21, 22, 23, 24, 25):
    _SUMMARIES[("microsoft-windows-terminalservices-localsessionmanager/operational", _id)] = _rdp


def _summary(channel: str, event_id: int | None, provider: str, fields: dict) -> str:
    make = _SUMMARIES.get((channel.lower(), event_id)) if event_id is not None else None
    if make is not None:
        text = make(fields)
        if text:
            return text
    head = f"{provider or channel or 'event'} {event_id if event_id is not None else '?'}"
    first = [f"{name}={_short(text, 60)}" for name, text in list(fields.items())[:3]]
    return f"{head} — {', '.join(first)}" if first else head


def _username(channel: str, event_id: int | None, provider: str, fields: dict) -> str:
    """The most useful account of an event: the target of a logon, a Sysmon event's user, else the subject."""
    if provider == "Microsoft-Windows-Sysmon" or channel.lower() == "microsoft-windows-sysmon/operational":
        return _v(fields, "User")
    if event_id in _LOGON_IDS and channel.lower() == "security":
        return _v(fields, "TargetUserName", "SubjectUserName")
    return _v(fields, "SubjectUserName", "User", "UserName", "AccountName")


# -- indicators: only from fields that are declared as such ------------------- #
def _indicators(channel: str, event_id: int | None, fields: dict) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    key = channel.lower()
    if key == "security" and event_id in (4624, 4625, 4648):
        address = _v(fields, "IpAddress")
        if address not in _NO_ADDRESS:
            found.append(("ip", address))
    elif key == "microsoft-windows-sysmon/operational":
        if event_id == 3:
            address = _v(fields, "DestinationIp")
            if address not in _NO_ADDRESS:
                found.append(("ip", address))
            if _v(fields, "DestinationHostname"):
                found.append(("domain", _v(fields, "DestinationHostname")))
        elif event_id == 22 and _v(fields, "QueryName"):
            found.append(("domain", _v(fields, "QueryName")))
        elif event_id in (1, 7):
            for part in _v(fields, "Hashes").split(","):
                name, _, digest = part.strip().partition("=")
                kind = _HASHES.get(name.strip().upper())
                digest = digest.strip()
                if kind and len(digest) == kind[1] and _HEX.match(digest):
                    found.append((kind[0], digest.lower()))
    return list(dict.fromkeys(found))


def normalise(record: dict) -> dict[str, Any]:
    """One record of the parser (``{"event_record_id", "timestamp", "data": <JSON text>, "recovered"}``)
    → what Nik keeps of the event. Raises ``ValueError``/``KeyError``/``TypeError`` when it has not the
    shape of an event; the caller says so as a skip.

    ``script`` is set for a PowerShell script block (4104) that names its ``ScriptBlockId``."""
    event = json.loads(record["data"])["Event"]
    system = event["System"]
    if not isinstance(system, dict):
        raise TypeError("System is not an element")
    channel = str(system.get("Channel") or "").strip()
    computer = str(system.get("Computer") or "").strip()
    event_id = _event_id(system.get("EventID"))
    provider = str(_attr(system.get("Provider"), "Name") or "")
    record_id = record.get("event_record_id")
    if not isinstance(record_id, int):
        record_id = _event_id(system.get("EventRecordID"))
    stamp = to_ms(_attr(system.get("TimeCreated"), "SystemTime"))
    if stamp is None:
        stamp = to_ms(record.get("timestamp"))

    fields: dict[str, str] = {}
    for name, node in event.items():
        if name not in ("System", "#attributes"):
            _flatten({name: node}, fields)
    data: dict[str, Any] = {
        "provider": provider,
        "level": system.get("Level"),
        "task": system.get("Task"),
        "opcode": system.get("Opcode"),
        "keywords": system.get("Keywords"),
        "pid": _attr(system.get("Execution"), "ProcessID"),
        "tid": _attr(system.get("Execution"), "ThreadID"),
    }
    sid = _attr(system.get("Security"), "UserID")
    if sid:
        data["sid"] = sid
    qualifiers = _attr(system.get("EventID"), "Qualifiers")
    if qualifiers is not None:
        data["qualifiers"] = qualifiers
    for name, text in fields.items():
        data[f"Data.{name}" if name in FIXED else name] = text

    script = None
    if (
        event_id == 4104
        and channel.lower() == "microsoft-windows-powershell/operational"
        and fields.get("ScriptBlockId")
    ):
        try:
            number, total = int(fields.get("MessageNumber", "1")), int(fields.get("MessageTotal", "1"))
        except ValueError:
            number, total = 1, 1
        script = {
            "id": fields["ScriptBlockId"],
            "number": number,
            "total": total,
            "text": fields.get("ScriptBlockText", ""),
            "path": fields.get("Path", ""),
        }
    return {
        "computer": computer,
        "channel": channel,
        "record_id": record_id,
        "ts": stamp,
        "event_id": event_id,
        "username": _username(channel, event_id, provider, fields),
        "summary": _summary(channel, event_id, provider, fields),
        "data": data,
        "ioc": _indicators(channel, event_id, fields),
        "script": script,
    }


# --------------------------------------------------------------------------- #
# PowerShell script blocks                                                    #
# --------------------------------------------------------------------------- #
class _Scripts:
    """Puts the blocks of a script (4104: ``MessageNumber`` of ``MessageTotal``, one ``ScriptBlockId``) together.

    A script is said once all its blocks are seen, or at the end of the file with those that were. The text
    waiting is bounded (``MAX_PENDING_SCRIPT``): past it the oldest scripts are said as they are."""

    def __init__(self, ctx) -> None:
        self.ctx = ctx
        self.pending: dict[tuple[str, str], dict[str, Any]] = {}
        self.size = 0
        self.said: dict[str, int] = {}
        self.incomplete = 0
        self.evicted = 0
        self.count = 0

    def add(self, norm: dict, loc: dict) -> None:
        script = norm["script"]
        key = (norm["computer"], script["id"])
        entry = self.pending.get(key)
        if entry is None:
            entry = self.pending[key] = {"blocks": {}, "total": script["total"], "first": None, "path": ""}
        if script["number"] in entry["blocks"]:
            return
        entry["blocks"][script["number"]] = script["text"]
        self.size += len(script["text"])
        if entry["first"] is None or script["number"] < entry["first"][0]:
            entry["first"] = (script["number"], norm, loc)
        entry["path"] = entry["path"] or script["path"]
        if len(entry["blocks"]) >= entry["total"]:
            self._say(key, self.pending.pop(key), complete=True)
            return
        while self.size > MAX_PENDING_SCRIPT and self.pending:
            oldest = next(iter(self.pending))
            self.evicted += 1
            self._say(oldest, self.pending.pop(oldest), complete=False)

    def _say(self, key: tuple[str, str], entry: dict, *, complete: bool) -> None:
        text = "".join(entry["blocks"][number] for number in sorted(entry["blocks"]))
        self.size -= sum(len(part) for part in entry["blocks"].values())
        _number, norm, loc = entry["first"]
        self.count += 1
        if not complete:
            self.incomplete += 1
        base = f"ps:{key[0]}:{key[1]}"
        again = self.said.get(base, 0)
        if len(self.said) < MAX_DONE_SCRIPTS or again:
            self.said[base] = again + 1
        first_line = next((line.strip() for line in text.splitlines() if line.strip()), "")
        self.ctx.record(
            key=base if not again else f"{base}:{again}",
            type="script",
            ts=norm["ts"],
            host=norm["computer"],
            username=norm["username"],
            event_id=4104,
            channel=norm["channel"],
            summary=_short(first_line, 200),
            data={"script": text, "blocks": len(entry["blocks"]), "of": entry["total"], "path": entry["path"]},
            loc=loc,
        )

    def finish(self) -> None:
        while self.pending:
            key = next(iter(self.pending))
            self._say(key, self.pending.pop(key), complete=False)
        if self.incomplete:
            self.ctx.note(
                "script incomplete",
                count=self.incomplete,
                detail="not every block of these scripts is in the log, or the log ended first: said as seen",
            )
        if self.evicted:
            self.ctx.note(
                "script said before its end",
                count=self.evicted,
                detail=f"more than {MAX_PENDING_SCRIPT >> 20} MB of script text was waiting for its other blocks",
            )
        if self.count:
            self.ctx.note(
                "script put together",
                count=self.count,
                detail="records of type script, made from the blocks of 4104 events: they come on top of the events",
            )


# --------------------------------------------------------------------------- #
# The parser's warnings                                                       #
# --------------------------------------------------------------------------- #
class _Warnings:
    """What the ``evtx`` crate says about the records and chunks it could not read, kept for the skips they explain.

    A warning that no skip (and no chunk the scan knows to be empty) accounts for is said in a note."""

    def __init__(self, log: list) -> None:
        self.log = log
        self.total = 0
        self.explained = 0
        self.examples: list[str] = []
        self.by_record: dict[int, str] = {}
        self.by_read: dict[int, list[list]] = {}  # chunk -> [file offset, message, used]
        self.by_chunk: dict[int, str] = {}
        self.kept = 0

    def drain(self) -> None:
        if not self.log:
            return
        messages = [str(item.message) for item in self.log]
        del self.log[:]  # the list grows with every warning: it is emptied as it is read
        for message in messages:
            self.total += 1
            if len(self.examples) < 3:
                self.examples.append(message[:150])
            if self.kept >= MAX_WARNINGS_KEPT:
                continue
            found = _WARN_RECORD.search(message)
            if found:
                self.by_record[int(found.group(1))] = message
                self.kept += 1
                continue
            found = _WARN_READ.search(message)
            if found:
                self.by_read.setdefault(int(found.group(1)), []).append([int(found.group(2), 16), message, False])
                self.kept += 1
                continue
            found = _WARN_CHUNK.search(message)
            if found:
                self.by_chunk[int(found.group(1))] = message
                self.kept += 1

    def for_record(self, record_id: int, chunk: int, offset: int) -> str:
        message = self.by_record.pop(record_id, None)
        if message:
            self.explained += 1
            return message
        # A record that cannot be read ends the reading of its chunk: the records after it share the message.
        earlier = [entry for entry in self.by_read.get(chunk, ()) if entry[0] <= offset]
        if earlier:
            entry = max(earlier, key=lambda item: item[0])
            if not entry[2]:
                entry[2] = True
                self.explained += 1
            return entry[1]
        return ""

    def for_chunk(self, number: int) -> str:
        message = self.by_chunk.pop(number, "")
        self.explained += 1 if message else 0
        return message

    def for_stretch(self, offset: int, length: int) -> str:
        """The parser's message about a record it could not read in this stretch of the file."""
        for entries in self.by_read.values():
            for entry in entries:
                if offset <= entry[0] < offset + max(length, 1):
                    if not entry[2]:
                        entry[2] = True
                        self.explained += 1
                    return entry[1]
        return ""

    def unexplained(self, quiet: set[int]) -> int:
        """The warnings that no skip, and no chunk the survey knows to be unused, accounts for."""
        chunks = sum(1 for number in self.by_chunk if number in quiet)
        return max(0, self.total - self.explained - chunks)


# --------------------------------------------------------------------------- #
# The scan and the parser, reconciled                                         #
# --------------------------------------------------------------------------- #
class _Said:
    """Skips of one reason, said one by one up to ``MAX_LISTED``; the rest in one, with the count of what they lost.

    ``sink`` is where they go: a buffer for the survey (it is said at the end, with what the parser said of the
    same places), the context for the records the parser did not return."""

    def __init__(self, sink) -> None:
        self.sink = sink
        self.count: dict[str, int] = {}
        self.more: dict[str, list[int]] = {}

    def skip(
        self,
        reason: str,
        *,
        offset: int | None = None,
        length: int | None = None,
        lost: int = 0,
        detail: str = "",
        **more: Any,
    ) -> None:
        seen = self.count.get(reason, 0)
        self.count[reason] = seen + 1
        if seen < MAX_LISTED:
            self.sink.skip(reason, offset=offset, length=length, lost=lost, detail=detail, **more)
        else:
            more = self.more.setdefault(reason, [0, 0])
            more[0] += 1
            more[1] += lost

    def finish(self) -> None:
        for reason, (count, lost) in self.more.items():
            self.sink.skip(
                reason,
                lost=lost,
                detail=f"{count} more of the same kind after the first {MAX_LISTED}: not listed one by one",
            )
        self.more = {}


class _Buffer:
    """What the survey says, held until the end: the parser's own message about the same place is added to it."""

    def __init__(self) -> None:
        self.lines: list[tuple[str, dict[str, Any]]] = []

    def skip(self, reason: str, **kwargs: Any) -> None:
        self.lines.append((reason, kwargs))

    def replay(self, ctx, warned: _Warnings) -> None:
        for reason, kwargs in self.lines:
            chunk = kwargs.pop("chunk", None)
            message = ""
            if chunk is not None:
                message = warned.for_chunk(chunk)
            elif kwargs.get("offset") is not None and kwargs.get("length") and "cut short" not in reason:
                message = warned.for_stretch(kwargs["offset"], kwargs["length"])
            if message:
                kwargs["detail"] = f"{kwargs.get('detail', '')}; parser: {message}"
            ctx.skip(reason, **kwargs)
        self.lines = []


class _Survey:
    """The first pass over the file: every chunk in file order, one at a time, summed up. What it keeps is small
    (a few numbers per chunk, the records left in unused space up to ``MAX_SLACK``), never the records of the file.

    It says the damage of the structure (stretches without a record, destroyed chunks, a file cut short) and
    counts ``in_file``: the records found in the used area of the chunks."""

    def __init__(self, scanner: evtxscan.Scanner, said: _Said) -> None:
        self.scanner = scanner
        self.said = said
        self.in_file = 0
        self.gaps: list[tuple[int, int]] = []  # (first missing number, last missing number)
        self._numbered: list[tuple[int, int]] = []  # the numbers each readable chunk holds, to find the holes between
        self.spans: list[tuple[int, int, int]] = []  # (lowest ID, highest ID, chunk) of the chunks that hold records
        self.with_records: list[int] = []  # the chunks that hold records and are not copies
        self.duplicates: set[int] = set()  # stale chunks that hold only records other chunks hold
        self.crc_bad: set[int] = set()
        self.free_offset_bad: list[int] = []
        self.stale_chunks = 0
        self.quiet: set[int] = set()  # chunks the parser complains about and the survey has said what they are
        self.slack: dict[int, list[tuple[int, int, int]]] = {}
        self.slack_indexed = 0
        self.slack_dropped = 0
        self._bad_run: list[evtxscan.Chunk] = []
        self._last_id: int | None = None
        self._merged: list[tuple[int, int]] | None = None
        self._ranges: list[tuple[int, int]] = []
        for chunk in scanner.chunks():
            self._add(chunk)
        self._close_bad_run(None)
        if scanner.cut_header:
            said.skip(
                "file is cut short",
                offset=scanner.size,
                length=evtxscan.HEADER - scanner.size,
                detail="the file ends inside its 4 KiB header",
            )
        self.spans.sort()
        self.lows = [span[0] for span in self.spans]
        self._gaps_between_chunks()

    def _gaps_between_chunks(self) -> None:
        """Record numbers that no readable chunk holds, between the last number of one and the first of the next
        (not before the first of the log: a log that wrapped starts anywhere)."""
        top = None
        for low, high in sorted(self._numbered):
            if top is not None and low > top + 1:
                self.gaps.append((top + 1, low - 1))
            top = high if top is None else max(top, high)
        self.gaps.sort()

    def _add(self, chunk: evtxscan.Chunk) -> None:
        if chunk.state == "empty":
            # Space the log never used: nothing to say but its count.
            self.stale_chunks += 1 if chunk.stale else 0
            self.quiet.add(chunk.number)
            return
        if chunk.state == "bad magic":
            if chunk.slack:
                self._bad_run.append(chunk)
            else:
                # No record in it: space left from an earlier life of the file, not a chunk of this log.
                self.stale_chunks += 1
                self.quiet.add(chunk.number)
            return
        if chunk.state == "short header":
            self._cut_short(chunk, 0)
            return
        ids = list(chunk.records)
        if chunk.stale:
            if ids and all(self._seen_before(record_id) for record_id in ids):
                self.duplicates.add(chunk.number)
            if chunk.number in self.duplicates or not ids:
                self.stale_chunks += 1
        promised = chunk.last_no - chunk.first_no + 1
        trusted = 0 <= promised <= evtxscan.CHUNK // 24 and promised >= chunk.walked
        shortfall = promised - chunk.walked if trusted and chunk.number not in self.duplicates else 0
        if chunk.number not in self.duplicates:
            # What the file says it holds: the count the header of a readable chunk promises.
            self.in_file += promised if trusted else chunk.walked
        if chunk.number in self.duplicates:
            self.spans.append((min(ids), max(ids), chunk.number))
        elif ids:
            lowest, highest = min(ids), max(ids)
            self._close_bad_run(chunk.first_id if 0 < chunk.first_id <= lowest else lowest)
            self._numbered.append((lowest, highest))
            ordered = sorted(ids)
            self.gaps.extend((a + 1, b - 1) for a, b in zip(ordered, ordered[1:], strict=False) if b > a + 1)
            self.spans.append((lowest, highest, chunk.number))
            self.with_records.append(chunk.number)
            self._ranges.append((lowest, highest))
            self._merged = None
            self._last_id = max(highest, chunk.last_id) if chunk.last_id >= lowest else highest
        if chunk.header_crc_ok is False or chunk.events_crc_ok is False:
            self.crc_bad.add(chunk.number)
        if not chunk.free_offset_ok:
            self.free_offset_bad.append(chunk.number)
        unsaid = shortfall
        for region in chunk.regions:
            if chunk.cut_short and region.offset + region.length >= chunk.offset + chunk.available:
                continue  # the end of the file, said as such below
            detail = f"chunk {chunk.number}: bytes at this offset do not start a record ({region.kind} is damaged)"
            if region.record_id is not None:
                detail += f"; the size field of record {region.record_id} is larger than the chunk allows"
            if shortfall:
                detail += f"; the chunk header counts {promised} records, {chunk.walked} were found"
                detail += (
                    "; the difference is counted on this stretch"
                    if unsaid
                    else "; the difference is counted on the first damaged stretch of the chunk"
                )
            self.said.skip(
                "record cannot be read" if region.kind == "record magic" else "record size is not valid",
                offset=region.offset,
                length=region.length,
                lost=unsaid,
                detail=detail,
            )
            unsaid = 0
        if chunk.cut_short:
            self._cut_short(chunk, unsaid)
            unsaid = 0
        if unsaid:
            self.said.skip(
                "records missing from chunk",
                offset=chunk.offset,
                length=evtxscan.CHUNK,
                lost=unsaid,
                detail=f"chunk {chunk.number}: its header counts {promised} records, {chunk.walked} were found",
            )
        for offset, size, record_id in chunk.slack:
            if self.slack_indexed >= MAX_SLACK:
                self.slack_dropped += 1
                continue
            self.slack_indexed += 1
            self.slack.setdefault(record_id, []).append((offset, size, chunk.number))

    def _cut_short(self, chunk: evtxscan.Chunk, lost: int) -> None:
        missing = evtxscan.CHUNK - chunk.available
        implied = ""
        if chunk.state == "ok" and chunk.last_no >= chunk.first_no:
            promised = chunk.last_no - chunk.first_no + 1
            if promised > chunk.walked:
                implied = f"; its header counts {promised} records, {chunk.walked} were found"
        self.said.skip(
            "file is cut short",
            offset=self.scanner.size,
            length=missing,
            lost=lost,
            detail=f"the file ends {chunk.available} bytes into chunk {chunk.number}, {missing} bytes short{implied}",
        )

    def _seen_before(self, record_id: int) -> bool:
        """Is this ID in the range of a chunk that counts? (a stale chunk is then a copy of what the log holds)"""
        if self._merged is None:
            merged: list[tuple[int, int]] = []
            for low, high in sorted(self._ranges):
                if merged and low <= merged[-1][1] + 1:
                    merged[-1] = (merged[-1][0], max(merged[-1][1], high))
                else:
                    merged.append((low, high))
            self._merged = merged
        index = bisect.bisect_right(self._merged, (record_id, float("inf"))) - 1
        return index >= 0 and self._merged[index][1] >= record_id

    def _close_bad_run(self, next_first_id: int | None) -> None:
        """Chunks whose signature is destroyed, said with what the chunks around them imply was in them."""
        run, self._bad_run = self._bad_run, []
        if not run:
            return
        if next_first_id is None:
            next_first_id = self.scanner.header.next_record_id
        if self._last_id is not None and next_first_id > self._last_id:
            gap = next_first_id - self._last_id - 1
            implied = f"the chunks around {'it' if len(run) == 1 else 'them'} imply {gap} record numbers are missing"
        else:
            implied = "the number of records it held cannot be told from the chunks around it"
        for chunk in run:
            self.said.skip(
                "chunk cannot be read",
                offset=chunk.offset,
                length=evtxscan.CHUNK,
                detail=(
                    f"chunk {chunk.number}: its signature is destroyed and {len(chunk.slack)} whole record headers "
                    f"are still inside it; {implied}"
                ),
                chunk=chunk.number,
            )


class _Locator:
    """The second pass, with the parser: tells where in the file a record the parser returned is, and which records
    of the survey the parser never returned.

    The parser does not go through the chunks in file order (a log that has wrapped is read from its oldest chunk),
    so the chunk of a record is found by its ID in the survey and read again from the file (64 KiB). A chunk lives
    in memory from its first record to its last one; one the parser left unfinished stays, with the records it
    did not return, until the end (bounded by ``MAX_HELD``: the oldest are said as lost before). The memory is
    that and the survey, never the records of the file."""

    def __init__(self, survey: _Survey, warned: _Warnings, said: _Said) -> None:
        self.survey = survey
        self.warned = warned
        self.said = said
        self.held: dict[int, evtxscan.Chunk] = {}
        self.finished: set[int] = set()
        self.remaining = 0
        self.crc_read: set[int] = set()
        self.size_copy_read = 0
        self.stale_dropped = 0
        self.remnants: list[tuple[int, int, int]] = []

    def find(self, record_id: Any) -> tuple[int, int, int] | str | None:
        """``(chunk, offset, size)`` of a record the parser returned; ``"duplicate"`` for one that only a stale copy
        of a chunk holds; None when the survey has no such record."""
        if not isinstance(record_id, int):
            return None
        for number in self._candidates(record_id):
            if number in self.finished:
                continue
            chunk = self.held.get(number)
            if chunk is None:
                chunk = self.survey.scanner.read_chunk(number)
                self.held[number] = chunk
                self.remaining += len(chunk.records) + len(chunk.repeated)
                self._trim()
            hit = chunk.records.pop(record_id, None)
            if hit is None:
                continue
            self.remaining -= 1
            if not chunk.records and not chunk.repeated:
                del self.held[number]
                self.finished.add(number)
            if number in self.survey.duplicates:
                self.stale_dropped += 1
                return "duplicate"
            if number in self.survey.crc_bad:
                self.crc_read.add(number)
            if not hit[2]:
                self.size_copy_read += 1
            return number, hit[0], hit[1]
        return None

    def _candidates(self, record_id: int) -> list[int]:
        """The chunks whose ID range holds this ID, those that are copies last."""
        index = bisect.bisect_right(self.survey.lows, record_id)
        found = [
            span[2] for span in self.survey.spans[max(0, index - MAX_COPIES) : index][::-1] if span[1] >= record_id
        ]
        found.sort(key=lambda number: number in self.survey.duplicates)
        return found

    def _trim(self) -> None:
        """Past the bound, the oldest chunks held are said as they are: what the parser has not returned yet is lost."""
        while self.remaining > MAX_HELD and len(self.held) > 1:
            number = next(iter(self.held))
            self._lose(self.held.pop(number))
            self.finished.add(number)

    def _lose(self, chunk: evtxscan.Chunk) -> None:
        """The records of this chunk the parser did not return."""
        self.remaining -= len(chunk.records) + len(chunk.repeated)
        if chunk.number in self.survey.duplicates:
            return
        lost = [(record_id, hit[0], hit[1]) for record_id, hit in chunk.records.items()] + chunk.repeated
        for record_id, offset, size in sorted(lost, key=lambda item: item[1]):
            message = self.warned.for_record(record_id, chunk.number, offset)
            self.said.skip(
                "record cannot be read",
                offset=offset,
                length=size,
                lost=1,
                detail=f"record {record_id} in chunk {chunk.number}: " + (message or "not returned by the parser"),
            )
        chunk.records.clear()
        chunk.repeated.clear()

    def slack_of(self, record_id: Any) -> tuple[int, int, int] | None:
        found = self.survey.slack.get(record_id) if isinstance(record_id, int) else None
        if not found:
            return None
        hit = found.pop(0)
        if not found:
            del self.survey.slack[record_id]
        return hit

    def finish(self) -> None:
        for number in sorted(self.held):
            self._lose(self.held.pop(number))
            self.finished.add(number)
        # Chunks the parser never returned a record of.
        for number in self.survey.with_records:
            if number not in self.finished:
                self._lose(self.survey.scanner.read_chunk(number))
                self.finished.add(number)
        # Records left in unused space that the survey sees whole and the parser did not return.
        self.remnants = sorted(item for found in self.survey.slack.values() for item in found)
        self.said.finish()


# --------------------------------------------------------------------------- #
# The parse                                                                   #
# --------------------------------------------------------------------------- #
def _records(path: str, failure: list[str]) -> Iterator[dict]:
    """The parser's records. A parser that stops says why in ``failure``; the survey accounts for the rest."""
    try:
        import evtx  # imported here: the module is sniffed where the package may be missing

        parser = evtx.PyEvtxParser(path, number_of_threads=0, skip_errors=True, recover_records=True)
        yield from parser.records_json()
    except Exception as exc:  # noqa: BLE001 - whatever the library does to a hostile file, the survey goes on
        failure.append(f"{type(exc).__name__}: {exc}"[:400])


def _computer_of(record: dict) -> str:
    try:
        return str(json.loads(record["data"])["Event"]["System"].get("Computer") or "").strip()
    except Exception:  # noqa: BLE001 - the record is read properly (or skipped) later
        return ""


def _named(numbers: list[int]) -> str:
    shown = ", ".join(str(number) for number in sorted(numbers)[:MAX_NAMED])
    return f"chunks {shown}" + (f" and {len(numbers) - MAX_NAMED} more" if len(numbers) > MAX_NAMED else "")


def parse(path: str, ctx, source: str) -> None:
    host = str(ctx.params.get("host") or "")
    try:
        scanner = evtxscan.Scanner(path)
    except evtxscan.NotEvtx:
        ctx.source(NAME, VERSION, KIND, "evtx", host=host)
        ctx.skip("not an event log", lost=0, detail="the file does not start with the ElfFile signature")
        raise
    try:
        _parse(path, ctx, scanner, host)
    finally:
        scanner.close()


def _parse(path: str, ctx, scanner: evtxscan.Scanner, host: str) -> None:
    survey = _Survey(
        scanner, _Said(_Buffer())
    )  # the whole structure first: what the file holds, whatever the parser does
    stats = {"recovered": 0, "no_time": 0, "unlocated": 0}
    failure: list[str] = []
    with warnings.catch_warnings(record=True) as log:
        warnings.simplefilter("always")
        warned = _Warnings(log)
        stream = _records(path, failure)
        first = next(stream, None)
        if not host and first is not None:
            host = _computer_of(first)
        ctx.source(NAME, VERSION, KIND, "evtx", host=host)
        locator = _Locator(survey, warned, _Said(ctx))
        scripts = _Scripts(ctx)
        for record in itertools.chain([] if first is None else [first], stream):
            warned.drain()
            _give(ctx, locator, scripts, record, stats)
        warned.drain()
        if failure:
            ctx.skip(
                "the parser stopped", lost=0, detail=f"{failure[0]}; the records of the survey after it are skipped"
            )
        locator.finish()
        warned.drain()
        scripts.finish()
        survey.said.finish()
        survey.said.sink.replay(ctx, warned)
    _notes(ctx, scanner, survey, locator, warned, stats)
    ctx.end(in_file=survey.in_file)


def _give(ctx, locator: _Locator, scripts: _Scripts, record: dict, stats: dict) -> None:
    recovered = bool(record.get("recovered"))
    record_id = record.get("event_record_id")
    where = None  # (chunk, offset, size)
    if recovered:
        slack = locator.slack_of(record_id)
        if slack is not None:
            where = (slack[2], slack[0], slack[1])
    else:
        hit = locator.find(record_id)
        if hit == "duplicate":
            return
        if hit is not None:
            where = (hit[0], hit[1], hit[2])  # type: ignore[index]
    try:
        norm = normalise(record)
    except Exception as exc:  # noqa: BLE001 - a record of a hostile file may have any shape
        ctx.skip(
            "record cannot be understood",
            offset=where[1] if where else None,
            length=where[2] if where else None,
            lost=0 if recovered else 1,
            detail=f"record {record_id}: {type(exc).__name__}: {str(exc)[:200]}",
        )
        return
    number = norm["record_id"] if norm["record_id"] is not None else record_id
    key = f"evtx:{norm['computer']}:{norm['channel']}:{number}"
    data = norm["data"]
    loc: dict[str, Any] = {"record": number}
    if where is not None:
        loc = {"offset": where[1], "length": where[2], "chunk": where[0], "record": number}
    elif not recovered:
        stats["unlocated"] += 1
    if recovered:
        stats["recovered"] += 1
        data["recovered"] = True
        if where is not None:
            key += f":r{where[1]}"
        else:
            key += ":r?" + hashlib.sha256(str(record.get("data")).encode("utf-8", "replace")).hexdigest()[:12]
    if norm["ts"] is None:
        stats["no_time"] += 1
    ctx.record(
        key=key,
        type="event",
        ts=norm["ts"],
        host=norm["computer"],
        username=norm["username"],
        event_id=norm["event_id"],
        channel=norm["channel"],
        summary=norm["summary"],
        data=data,
        loc=loc,
        ioc=norm["ioc"],
    )
    if norm["script"] is not None and not recovered:
        scripts.add(norm, loc)


def _notes(ctx, scanner: evtxscan.Scanner, survey: _Survey, locator: _Locator, warned: _Warnings, stats: dict) -> None:
    header = scanner.header
    if header.flags & evtxscan.FLAG_DIRTY:
        ctx.note("log not closed", detail="the file header says the log was open when the file was taken")
    if header.crc_ok is False:
        ctx.note("file header checksum does not match", detail="the records were read all the same")
    if locator.crc_read:
        ctx.note(
            "chunk checksum does not match",
            count=len(locator.crc_read),
            detail=f"{_named(sorted(locator.crc_read))}: their records were read all the same",
        )
    if survey.free_offset_bad:
        ctx.note(
            "chunk free-space offset is not valid",
            count=len(survey.free_offset_bad),
            detail=f"{_named(survey.free_offset_bad)}: the whole chunk was searched for records",
        )
    if survey.stale_chunks:
        ctx.note(
            "stale chunk",
            count=survey.stale_chunks,
            detail=(
                "empty, or not a chunk, or a copy of chunks read already, in space the log does not use "
                f"({locator.stale_dropped} records left out as copies)"
            ),
        )
    if locator.size_copy_read:
        ctx.note("record size copy does not match", count=locator.size_copy_read, detail="records read all the same")
    if stats["unlocated"]:
        ctx.note(
            "record not found by the scan of the file",
            count=stats["unlocated"],
            detail="the parser returned them; the survey did not see them, so they have no offset",
        )
    if survey.slack_dropped:
        ctx.note(
            "recovered records not indexed",
            count=survey.slack_dropped,
            detail=f"more than {MAX_SLACK} records are left in unused space: the later ones have no offset",
        )
    if stats["no_time"]:
        ctx.note("record without a usable time", count=stats["no_time"], detail="kept, with no time")
    if stats["recovered"]:
        ctx.note("recovered record", count=stats["recovered"], detail="left in the log after it was cleared or wrapped")
    if locator.remnants:
        first = locator.remnants[0]
        ctx.note(
            "record remnant in unused space not rebuilt",
            count=len(locator.remnants),
            detail=f"whole records in unused space that the parser did not return; the first is at offset {first[0]}",
        )
    if survey.gaps:
        total = sum(high - low + 1 for low, high in survey.gaps)
        shown = ", ".join(f"{low}..{high}" for low, high in survey.gaps[:5])
        ctx.note(
            "gap in record numbers",
            count=len(survey.gaps),
            detail=f"{total} record numbers are in no chunk: {shown}" + (" and more" if len(survey.gaps) > 5 else ""),
        )
    unexplained = warned.unexplained(survey.quiet)
    if unexplained:
        ctx.note("parser warning", count=unexplained, detail="; ".join(warned.examples))


# --------------------------------------------------------------------------- #
# The view of a record                                                        #
# --------------------------------------------------------------------------- #
def _int_of(loc: dict, name: str) -> int | None:
    value = loc.get(name)
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def mini_log(path: str, chunk: int) -> tuple[bytes, int]:
    """A log of one chunk, made in memory: the 4096 bytes of the file header, then the 64 KiB chunk number
    ``chunk`` (fewer bytes when the file stops inside it). Returns it and the byte of ``path`` the chunk is at.

    A log can hold millions of records: to show one, the library is given this and not the file. Nothing in it
    is fixed. The library reads the chunks the file *holds* and not the count its header says (tried: the
    count of the original, a count of 0 and a wrong header checksum all give the same records), so the header,
    whose chunk count and numbers now say more than the copy holds, stays as the original has it: the XML
    shown is the library's reading of the bytes of the file, not of bytes changed for it."""
    with open(path, "rb") as handle:
        head = handle.read(evtxscan.HEADER)
        if len(head) < 128 or head[:8] != evtxscan.FILE_MAGIC:
            raise ViewError("The file does not start with the ElfFile signature: it is not an event log")
        start = evtxscan.HEADER + chunk * evtxscan.CHUNK
        handle.seek(start)
        data = handle.read(evtxscan.CHUNK)
    if not data:
        raise ViewError(f"The log holds no chunk {chunk}: it ends before byte {start}")
    if data[:8] != evtxscan.CHUNK_MAGIC:
        raise ViewError(f"The chunk {chunk} (from byte {start}) has no chunk signature: no record can be read from it")
    return head.ljust(evtxscan.HEADER, b"\0") + data, start


def _hex_of_record(path: str, offset: int, length: int, why: str, record: int) -> dict[str, Any]:
    size = os.path.getsize(path)
    if offset >= size:
        raise ViewError(f"The file ends at byte {size}: no record at byte {offset}")
    length = min(max(length, 24), evtxscan.CHUNK, size - offset)
    with open(path, "rb") as handle:
        handle.seek(offset)
        data = handle.read(length)
    return {
        "kind": "text",
        "title": f"Record {record} at byte {offset}, {length} bytes, as the bytes of the file: {why}",
        "where": {"offset": offset, "length": length, "record": record},
        "text": viewing.hex_dump(data, offset),
    }


def view(path: str, source: str, loc: dict) -> dict:
    """The XML of the event, from the one chunk the locator names (``chunk``, or the chunk that holds
    ``offset``) and the record number ``record``. A record that the library does not return, or that
    sits in the unused space of its chunk and comes back from no one, is shown as the bytes it has in the file."""
    record = _int_of(loc, "record")
    offset, length, chunk = (_int_of(loc, name) for name in ("offset", "length", "chunk"))
    if record is None:
        raise BadLocator("The locator of the record has no record number")
    if chunk is None and offset is not None and offset >= evtxscan.HEADER:
        chunk = (offset - evtxscan.HEADER) // evtxscan.CHUNK
    if chunk is None:
        raise BadLocator(
            f"The locator of the record {record} says in which chunk it is by neither a chunk nor an offset"
        )
    log, start = mini_log(path, chunk)
    unused = False  # the offset is past the used area of the chunk: the record is one the log left behind
    if offset is not None and len(log) >= evtxscan.HEADER + 52:
        free = struct.unpack_from("<I", log, evtxscan.HEADER + 48)[0]
        unused = offset - start >= free
    where = {"chunk": chunk, "record": record}
    if offset is not None:
        where["offset"] = offset
    if length is not None:
        where["length"] = length
    found: list[dict] = []
    try:
        import evtx  # imported here, like the parse does

        library = evtx.PyEvtxParser(io.BytesIO(log), number_of_threads=0, skip_errors=True, recover_records=True)
        with warnings.catch_warnings():
            warnings.simplefilter(
                "ignore"
            )  # the library warns of a record it skips: the parse says so, a view does not
            found = [item for item in library.records() if item.get("event_record_id") == record]
    except Exception as exc:  # noqa: BLE001 - whatever the library does to a hostile chunk, the bytes can be shown
        if offset is None or length is None:
            raise ViewError(f"The record {record} cannot be read from the chunk {chunk}: {str(exc)[:200]}") from None
        return _hex_of_record(path, offset, length, f"the library could not read it ({str(exc)[:80]})", record)
    if not found:
        if offset is not None and length is not None:
            return _hex_of_record(path, offset, length, "the library returned no such record", record)
        raise ViewError(f"The chunk {chunk} holds no record {record}")
    # Two records may share a number (a record left in the unused space, and the one in use): the one that is
    # where the locator says, by whether it is in use.
    chosen = next((item for item in found if bool(item.get("recovered")) == unused), found[0])
    suffix = ", from the unused space of the chunk" if chosen.get("recovered") else ""
    place = f", at byte {offset}" if offset is not None else ""
    return {
        "kind": "xml",
        "title": f"Record {record} of chunk {chunk}{place}{suffix}",
        "where": where,
        "text": str(chosen.get("data") or ""),
    }

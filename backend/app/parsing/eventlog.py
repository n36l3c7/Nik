"""Windows event logs (.evtx) parsed on the server.

An ``.evtx`` file is a binary log (chunks of BinXML records) that the browser
cannot read, so the app uploads it as is and the server parses it with the
``evtx`` package (a Rust parser with Python bindings). Only a curated set of
forensically useful event IDs is kept (``CURATED``, mirrored by
``src/config/eventLogs.js``); the rest is counted, not stored.

Each kept record becomes a flat event::

    {id, time, eventId, channel, provider, computer, recordId, level, data,
     recovered?}

where ``data`` holds the record's EventData/UserData fields as strings (empty
values and placeholders dropped, long values such as PowerShell script blocks cut to
``MAX_VALUE``). Records left in the unused space of the file (for example
after the log was cleared) are recovered too and marked ``recovered``.

Per channel the result also carries the coverage of the whole log (first and
last record of ANY id) and its silent periods, so the analyst sees when the
log was not recording.
"""

from __future__ import annotations

import io
import json
import warnings
from datetime import datetime

# --- Curated event IDs per channel (lower-case channel name) --------------- #
# Keep in sync with CURATED_EVENTS in src/config/eventLogs.js (a frontend test
# compares the two).
CURATED: dict[str, frozenset[int]] = {
    "security": frozenset(
        {
            1102,  # audit log cleared
            4624,  # logon
            4625,  # failed logon
            4634,  # logoff
            4647,  # user-initiated logoff
            4648,  # logon with explicit credentials
            4672,  # special privileges assigned
            4688,  # process created
            4697,  # service installed
            4698,  # scheduled task created
            4699,  # scheduled task deleted
            4702,  # scheduled task updated
            4719,  # audit policy changed
            4720,  # account created
            4722,  # account enabled
            4724,  # password reset
            4726,  # account deleted
            4728,  # member added to a global group
            4732,  # member added to a local group
            4740,  # account locked out
            4756,  # member added to a universal group
            4771,  # Kerberos pre-authentication failed
            4776,  # NTLM credential validation
            4778,  # session reconnected
            4779,  # session disconnected
        }
    ),
    "system": frozenset({104, 1074, 6005, 6006, 6008, 7040, 7045}),
    "microsoft-windows-powershell/operational": frozenset({4103, 4104}),
    "windows powershell": frozenset({400, 800}),
    "microsoft-windows-terminalservices-localsessionmanager/operational": frozenset({21, 22, 23, 24, 25}),
    "microsoft-windows-terminalservices-remoteconnectionmanager/operational": frozenset({1149}),
    "microsoft-windows-windows defender/operational": frozenset({1116, 1117, 5001}),
    "microsoft-windows-taskscheduler/operational": frozenset({106, 141, 200}),
    "microsoft-windows-sysmon/operational": frozenset({1, 3, 22}),
}

# Canonical spelling of each channel (the key the incident stores it under).
CHANNEL_NAMES = {
    "security": "Security",
    "system": "System",
    "microsoft-windows-powershell/operational": "Microsoft-Windows-PowerShell/Operational",
    "windows powershell": "Windows PowerShell",
    "microsoft-windows-terminalservices-localsessionmanager/operational": (
        "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"
    ),
    "microsoft-windows-terminalservices-remoteconnectionmanager/operational": (
        "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"
    ),
    "microsoft-windows-windows defender/operational": "Microsoft-Windows-Windows Defender/Operational",
    "microsoft-windows-taskscheduler/operational": "Microsoft-Windows-TaskScheduler/Operational",
    "microsoft-windows-sysmon/operational": "Microsoft-Windows-Sysmon/Operational",
}

MAX_EVENTS_PER_CHANNEL = 20_000  # the most recent are kept
MAX_VALUE = 8_000  # characters per field value
GAP_MS = 6 * 3600 * 1000  # a silence this long is reported as a gap
MAX_GAPS = 20  # the longest ones

# Empty values and Windows placeholders ("%%1793" is "<value not set>", "%%1794"
# "<never>"): dropping them keeps a stored event to a few hundred bytes.
_DROP_VALUES = {"", "-", "%%1793", "%%1794", "{00000000-0000-0000-0000-000000000000}"}


def _event_id(value) -> int | None:
    """``EventID`` is a number, or ``{"#attributes": {...}, "#text": n}`` with qualifiers."""
    if isinstance(value, dict):
        value = value.get("#text")
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _attr(node, name):
    if isinstance(node, dict):
        attrs = node.get("#attributes")
        if isinstance(attrs, dict):
            return attrs.get(name)
    return None


def _to_ms(system_time) -> int | None:
    if not system_time:
        return None
    text = str(system_time).replace("Z", "+00:00")
    # Python < 3.11 cannot parse 7 fractional digits; keep microseconds.
    if "." in text:
        head, _, rest = text.partition(".")
        digits = "".join(ch for ch in rest if ch.isdigit())
        tz = rest[len(digits) :]
        text = f"{head}.{digits[:6].ljust(6, '0')}{tz}"
    try:
        return int(datetime.fromisoformat(text).timestamp() * 1000)
    except ValueError:
        return None


def _value(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, dict):
        value = value.get("#text", "")
        if isinstance(value, list):
            value = "\n".join(str(v) for v in value)
    if isinstance(value, list):
        value = ", ".join(str(v) for v in value if v is not None)
    text = str(value).strip()
    if text in _DROP_VALUES:
        return None
    return text if len(text) <= MAX_VALUE else text[:MAX_VALUE] + " […]"


def _flatten(node, out: dict) -> None:
    """EventData/UserData → flat ``{name: text}``.

    Named fields come as keys; unnamed ``<Data>`` elements as ``Data`` (a value
    or a list, numbered ``Data1``, ``Data2``…); UserData wraps its fields in
    one more element (``LogFileCleared``, ``EventXML``…), which is unwrapped.
    """
    if not isinstance(node, dict):
        return
    for key, value in node.items():
        if key.startswith("#"):
            continue
        if isinstance(value, dict) and "#text" not in value:
            _flatten(value, out)
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


def normalize_record(record: dict) -> tuple[str, int | None, dict | None]:
    """One parser record → ``(channel, time_ms, event | None)``.

    ``event`` is None for a record outside the curated set (it still counts
    toward the channel's coverage).
    """
    try:
        event = json.loads(record["data"])["Event"]
        system = event["System"]
    except (KeyError, TypeError, ValueError):
        return "", None, None
    channel_raw = str(system.get("Channel") or "").strip()
    channel_key = channel_raw.lower()
    time_ms = _to_ms(_attr(system.get("TimeCreated"), "SystemTime")) or _to_ms(record.get("timestamp"))
    event_id = _event_id(system.get("EventID"))
    channel = CHANNEL_NAMES.get(channel_key, channel_raw or "Unknown")
    if event_id is None or event_id not in CURATED.get(channel_key, ()):
        return channel, time_ms, None
    data: dict[str, str] = {}
    _flatten(event.get("EventData"), data)
    _flatten(event.get("UserData"), data)
    record_id = system.get("EventRecordID") or record.get("event_record_id")
    out = {
        "id": f"evt:{channel}:{record_id}",
        "time": time_ms,
        "eventId": event_id,
        "channel": channel,
        "provider": str(_attr(system.get("Provider"), "Name") or ""),
        "computer": str(system.get("Computer") or ""),
        "recordId": record_id,
        "level": system.get("Level"),
        "data": data,
    }
    if record.get("recovered"):
        out["recovered"] = True
    return channel, time_ms, out


def silent_periods(times: list[int]) -> list[list[int]]:
    """The longest gaps of at least ``GAP_MS`` between consecutive records."""
    ordered = sorted(t for t in times if t is not None)
    gaps = [[a, b] for a, b in zip(ordered, ordered[1:], strict=False) if b - a >= GAP_MS]
    gaps.sort(key=lambda g: g[1] - g[0], reverse=True)
    return sorted(gaps[:MAX_GAPS])


def _records(data: bytes):
    """Yield the parser's JSON records; damaged records are skipped, not fatal."""
    try:
        import evtx  # imported lazily: only uploads of .evtx files need it
    except ImportError as exc:  # pragma: no cover - the package is a requirement
        raise ValueError("The evtx package is not installed on the server.") from exc
    if data[:8] != b"ElfFile\x00":
        raise ValueError("Not an .evtx file (missing the ElfFile signature).")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", RuntimeWarning)
        parser = evtx.PyEvtxParser(io.BytesIO(data), number_of_threads=1, skip_errors=True, recover_records=True)
        yield from parser.records_json()


def parse_evtx(data: bytes) -> dict[str, dict]:
    """Parse an .evtx file → ``{channel: {"events": [...], "stats": {...}}}``.

    ``stats``: total records, kept, dropped (over the cap), recovered, first
    and last record time and the silent periods — of the whole log.
    """
    channels: dict[str, dict] = {}
    try:
        for record in _records(data):
            channel, time_ms, event = normalize_record(record)
            if not channel:
                continue
            slot = channels.setdefault(channel, {"events": {}, "times": [], "total": 0})
            slot["total"] += 1
            if time_ms is not None and not record.get("recovered"):
                slot["times"].append(time_ms)
            if event is None:
                continue
            # A recovered copy never replaces the live record with the same id.
            known = slot["events"].get(event["id"])
            if known is None or (known.get("recovered") and not event.get("recovered")):
                slot["events"][event["id"]] = event
    except RuntimeError as exc:
        raise ValueError(f"Unreadable .evtx file: {exc}") from exc
    if not channels:
        raise ValueError("The .evtx file holds no records.")

    out = {}
    for channel, slot in channels.items():
        events = sorted(slot["events"].values(), key=lambda e: e["time"] or 0, reverse=True)
        kept = events[:MAX_EVENTS_PER_CHANNEL]
        times = slot["times"]
        out[channel] = {
            "events": kept,
            "stats": {
                "total": slot["total"],
                "kept": len(kept),
                "dropped": len(events) - len(kept),
                "recovered": sum(1 for e in kept if e.get("recovered")),
                "first": min(times) if times else None,
                "last": max(times) if times else None,
                "gaps": silent_periods(times),
            },
        }
    return out

"""An audit entry as a syslog message (RFC 5424).

One message for each entry::

    <PRI>1 TIMESTAMP HOSTNAME APP-NAME - audit [nik@32473 seq="…" hash="…" prev="…" id="…" action="…"] {JSON}

- ``PRI`` is ``facility * 8 + severity``, both set by the administrator
  (13, "log audit", and 5, "notice", unless changed);
- ``TIMESTAMP`` is the time of the entry, in UTC with microseconds
  (``2026-11-20T09:15:02.481220Z``), or ``-`` for an entry whose time cannot
  be read (one that came in a file from another server);
- ``HOSTNAME`` and ``APP-NAME`` are the ones set; ``PROCID`` is ``-``;
- ``MSGID`` is ``audit``, ``checkpoint`` or ``test``;
- the structured data carries what a receiver indexes without parsing the
  message: the number of the entry, its hash, the hash of the entry before
  it, its id and its action. ``nik@32473`` uses the enterprise number that
  is reserved for examples: Nik has none of its own;
- the message is the entry as one JSON object in ASCII (everything else is
  escaped ``\\uXXXX``), so it holds no line break and no byte a receiver could
  take for the end of the message::

      {"nik":"audit","v":1,"seq":…,"prev":"…","hash":"…","id":"…","at":"…","actor":"…",
       "action":"…","target":…,"details":"…","incidentId":…,"incidentName":…}

  The fields are those the hash was made of: ``verifier.py`` recomputes it
  from a message as from an export.

A **checkpoint** has the same shape with ``MSGID`` ``checkpoint`` and
``{"nik":"checkpoint","v":1,"seq":…,"hash":"…","count":…,"at":"…"}``: the
head of the chain, how many entries the log holds, the time. It is sent
every few minutes whatever happened, so that silence is told from a cut line.

Over TCP and TLS a message is framed by its length (octet counting, RFC 6587
and RFC 5425): ``<length in bytes> <message>``. Over UDP a message is a
datagram, and one that would not fit is sent with its long texts shortened
and ``"truncated":true``: its number and hashes are whole, its content
cannot be hashed again.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

SD_ID = "nik@32473"
FACILITIES = {
    "kern": 0, "user": 1, "mail": 2, "daemon": 3, "auth": 4, "syslog": 5, "lpr": 6, "news": 7, "uucp": 8,
    "cron": 9, "authpriv": 10, "ftp": 11, "ntp": 12, "audit": 13, "alert": 14, "clock": 15, "local0": 16,
    "local1": 17, "local2": 18, "local3": 19, "local4": 20, "local5": 21, "local6": 22, "local7": 23,
}  # fmt: skip
SEVERITIES = {"emerg": 0, "alert": 1, "crit": 2, "err": 3, "warning": 4, "notice": 5, "info": 6, "debug": 7}
NIL = "-"
# The texts of an entry that are shortened, longest first, when a datagram has no room for them.
_SHORTENED = ("details", "target", "incidentName", "actor", "incidentId")


def timestamp(at: Any) -> str:
    """A time of the log as RFC 5424 wants it, or ``-``."""
    try:
        moment = datetime.fromisoformat(str(at))
    except (TypeError, ValueError):
        return NIL
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def header_value(text: Any, limit: int) -> str:
    """A field of the header: printable ASCII without a space, or ``-``."""
    kept = "".join(char for char in str(text or "") if 33 <= ord(char) <= 126)[:limit]
    return kept or NIL


def sd_value(text: Any) -> str:
    """A value of the structured data: ``"``, ``\\`` and ``]`` are escaped, control characters go."""
    cleaned = "".join(char for char in str(text if text is not None else "") if ord(char) >= 32 and ord(char) != 127)
    return cleaned.replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")


def _element(pairs: dict[str, Any]) -> str:
    return "[" + SD_ID + "".join(f' {name}="{sd_value(value)}"' for name, value in pairs.items()) + "]"


def _line(settings: dict[str, Any], when: str, kind: str, element: str, body: dict[str, Any]) -> bytes:
    facility = int(settings.get("facility", 13))
    severity = int(settings.get("severity", 5))
    head = " ".join(
        (
            f"<{facility * 8 + severity}>1",
            when,
            header_value(settings.get("hostname") or "nik", 255),
            header_value(settings.get("appName") or "nik", 48),
            NIL,
            kind,
            element,
        )
    )
    return (head + " " + json.dumps(body, ensure_ascii=True, separators=(",", ":"))).encode("utf-8")


def body_of(entry: dict[str, Any]) -> dict[str, Any]:
    """The JSON object of an entry (``entry`` holds the columns, ``seq``, ``prev`` and ``hash``)."""
    return {
        "nik": "audit",
        "v": 1,
        "seq": entry["seq"],
        "prev": entry["prev"],
        "hash": entry["hash"],
        "id": entry["id"],
        "at": entry["at"],
        "actor": entry["actor"],
        "action": entry["action"],
        "target": entry.get("target"),
        "details": entry.get("details"),
        "incidentId": entry.get("incident_id"),
        "incidentName": entry.get("incident_name"),
    }


def render(entry: dict[str, Any], settings: dict[str, Any], limit: int | None = None) -> bytes:
    """The message of an entry. ``limit`` is the room of a datagram, in bytes."""
    element = _element(
        {
            "seq": entry["seq"],
            "hash": entry["hash"],
            "prev": entry["prev"],
            "id": str(entry["id"])[:64],
            "action": str(entry["action"])[:64],
        }
    )
    when = timestamp(entry.get("at"))
    body = body_of(entry)
    line = _line(settings, when, "audit", element, body)
    if limit is None or len(line) <= limit:
        return line
    body["truncated"] = True
    for name in _SHORTENED:
        over = len(_line(settings, when, "audit", element, body)) - limit
        if over <= 0:
            break
        text = body.get(name)
        if isinstance(text, str) and text:
            # A character may take six bytes once escaped: cut by that, then no more than needed.
            keep = max(0, len(text) - over)
            body[name] = text[:keep]
            while body[name] and len(_line(settings, when, "audit", element, body)) > limit:
                body[name] = body[name][: max(0, len(body[name]) - 16)]
    return _line(settings, when, "audit", element, body)


def checkpoint(seq: int, hashed: str, count: int, now: float, settings: dict[str, Any]) -> bytes:
    at = datetime.fromtimestamp(now, timezone.utc).isoformat()
    return _line(
        settings,
        timestamp(at),
        "checkpoint",
        _element({"seq": seq, "hash": hashed, "count": count}),
        {"nik": "checkpoint", "v": 1, "seq": seq, "hash": hashed, "count": count, "at": at},
    )


def test_message(mark: str, now: float, settings: dict[str, Any]) -> bytes:
    at = datetime.fromtimestamp(now, timezone.utc).isoformat()
    return _line(
        settings,
        timestamp(at),
        "test",
        _element({"test": mark}),
        {"nik": "test", "v": 1, "test": mark, "at": at, "text": "A test message from Nik: not an audit entry"},
    )


def frame(message: bytes) -> bytes:
    """A message as it goes over TCP and TLS: its length in bytes, a space, the message."""
    return str(len(message)).encode("ascii") + b" " + message

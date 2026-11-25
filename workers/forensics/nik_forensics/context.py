"""What a parser says while it reads a file: the events of a parse, one JSON object per line.

A parser is given a ``Context`` and tells it everything it finds, and
everything it could not read:

    ctx.source("evtx", "1", "eventlog", "evtx", host="WKS-042")
    ctx.record(key="evtx:WKS-042:Security:1842", type="event", ts=..., data={...}, loc={"offset": 168576})
    ctx.skip("record cannot be read", offset=168576, length=1024, detail="…")   # data was lost
    ctx.note("row without a time", count=3)                                     # nothing was lost
    ctx.end(in_file=358)

The lines are what the worker answers ``POST /parse`` with, as they are
written (``server.py`` relays them), and what the backend turns into rows and
into the parse report:

    {"t": "source", "parser", "version", "kind", "source", "host", "username"}
    {"t": "r", "key", "type", "ts", "seq", "host", "username", "event_id", "channel", "summary",
     "data", "loc", "trunc", "ioc", "src", "k"}         ("src" only when a record belongs to another source than the
                                                         file's own: a registry hive holds several; "k" its section,
                                                         when it is not the file's: a Plaso export)
    {"t": "skip", "reason", "offset", "length", "lost", "detail"}
    {"t": "note", "reason", "count", "detail"}
    {"t": "det", "key", "rule"}                                     (a rule matched the record before it; "records",
                                                                      "count" on a correlation, written before "end")
    {"t": "proc", "key", "ts", "host", "pid", "ppid", "image", "command_line", "user", "logon_id", "integrity",
     "guid", "parent_guid", "parent_image", "parent_command_line", "hashes"}   (a process that started)
    {"t": "proc_end", "key", "ts", "host", "pid", "guid"}                      (a process that ended)
    {"t": "logon", "key", "ts", "host", "user", "domain", "logon_type", "logon_id", "source_ip", "source_host",
     "outcome", "method", "status", "target_host"}                                   (a logon, a failure, a logoff...)
    {"t": "end", "in_file", "read", "first_ts", "last_ts"}

**Nothing is dropped in silence.** A record a parser could not read is a
``skip`` with its reason and, where the format gives one, its place in the
file. A stream that stops before its ``end`` line is a parser that died: the
backend keeps what came and says the file was read in part.

**Values.** A text longer than ``MAX_VALUE`` characters is cut and the record
says so (``trunc``): the viewer shows the whole of it from the original. A
key longer than ``MAX_KEY`` keeps its start and ends with a hash of the whole.
``ts`` is milliseconds since the epoch, UTC, or None.

A ``detector`` (``sigma/engine.py``), when the job has a rule set, is shown every record **before** its values are
cut (a rule sees the whole of a script), and the rules that match it are written as ``det`` lines right after its
``r`` line; the correlations and the notes about rules are written when the parser ends.

The ``proc``, ``proc_end`` and ``logon`` lines are written right after the ``r`` line of the record they come from
(and its ``det`` lines), under the same ``key``; members a log does not have are left out. Their texts are cut like
the values of a record, except ``command_line``, which goes whole: a line that would pass ``MAX_LINE`` has its command
lines cut to fit and a note at the end of the parse counts them.

Standard library only (the detector is the one thing that is not, and it is given, never imported here).
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, BinaryIO

MAX_VALUE = 8000
MAX_KEY = 300
MAX_SUMMARY = 1000
MAX_DETAIL = 500
# A record whose line would be larger than this is not sent: it is a skip, with its size.
MAX_LINE = 2 * 1024 * 1024
MAX_DEPTH = 12
# The members of a ``proc`` line that are not cut at ``MAX_VALUE``.
_WHOLE = frozenset({"command_line"})


class Context:
    """Writes the events of one parse onto ``out`` (a binary stream)."""

    def __init__(self, out: BinaryIO, params: dict[str, Any] | None = None) -> None:
        self._out = out
        self.params = params or {}
        self.seq = 0
        self.read = 0
        self.lost = 0
        self.first_ts: int | None = None
        self.last_ts: int | None = None
        self._ended = False
        self.detector: Any = None
        self.kind = ""
        self.source_name = ""
        self._last_key = ""  # the key of the last ``r`` line written: the lines about a process or a logon follow it
        self._lines_cut = 0
        self._lines_orphan = 0

    @staticmethod
    def _encode(event: dict[str, Any]) -> bytes:
        return json.dumps(event, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8", "replace")

    def _write(self, event: dict[str, Any]) -> bool:
        line = self._encode(event)
        if len(line) > MAX_LINE:
            return False
        self._out.write(line + b"\n")
        return True

    # -- cutting -------------------------------------------------------------- #
    def _cut(self, value: Any, depth: int = 0) -> tuple[Any, bool]:
        if isinstance(value, str):
            return (value[:MAX_VALUE], True) if len(value) > MAX_VALUE else (value, False)
        if isinstance(value, bytes):
            return self._cut(value.hex(), depth)
        if depth >= MAX_DEPTH:
            return "…", True
        if isinstance(value, dict):
            cut = False
            held: dict[str, Any] = {}
            for name, inner in value.items():
                held[str(name)[:200]], was = self._cut(inner, depth + 1)
                cut = cut or was
            return held, cut
        if isinstance(value, (list, tuple)):
            pairs = [self._cut(inner, depth + 1) for inner in value]
            return [inner for inner, _was in pairs], any(was for _inner, was in pairs)
        if value is None or isinstance(value, (bool, int, float)):
            return value, False
        return self._cut(str(value), depth)

    @staticmethod
    def key_of(key: str) -> str:
        if len(key) <= MAX_KEY:
            return key
        return key[: MAX_KEY - 33] + ":" + hashlib.sha256(key.encode("utf-8", "replace")).hexdigest()[:32]

    # -- what a parser says --------------------------------------------------- #
    def source(self, parser: str, version: str, kind: str, source: str, host: str = "", username: str = "") -> None:
        self.kind, self.source_name = kind, source
        self._write(
            {
                "t": "source",
                "parser": parser,
                "version": version,
                "kind": kind,
                "source": source,
                "host": str(host or "")[:255],
                "username": str(username or "")[:255],
            }
        )

    def record(
        self,
        *,
        key: str,
        type: str,  # noqa: A002 - the name of the field
        ts: int | None = None,
        host: str = "",
        username: str = "",
        event_id: int | None = None,
        channel: str = "",
        summary: str = "",
        data: dict[str, Any] | None = None,
        loc: dict[str, Any] | None = None,
        ioc: list[tuple[str, str]] | tuple = (),
        source: str = "",
        kind: str = "",
    ) -> None:
        held, cut = self._cut(data or {})
        event = {
            "t": "r",
            "key": self.key_of(str(key)),
            "type": str(type)[:40],
            "ts": int(ts) if ts is not None else None,
            "seq": self.seq,
            "host": str(host or "")[:255],
            "username": str(username or "")[:255],
            "event_id": int(event_id) if event_id is not None else None,
            "channel": str(channel or "")[:120],
            "summary": str(summary or "")[:MAX_SUMMARY],
            "data": held,
            "loc": loc or {},
            "trunc": cut,
            "ioc": [[str(kind)[:16], str(value)[:1024]] for kind, value in ioc if value],
        }
        if source:
            event["src"] = str(source)[:80]
        if kind:
            event["k"] = str(kind)[:16]
        self.seq += 1
        if not self._write(event):
            # Too large to send even with its values cut: the backend is told it was there.
            self.skip("record too large to keep", offset=(loc or {}).get("offset"), detail=f"key {event['key']}")
            return
        self._last_key = event["key"]
        self.read += 1
        if ts is not None:
            self.first_ts = ts if self.first_ts is None else min(self.first_ts, ts)
            self.last_ts = ts if self.last_ts is None else max(self.last_ts, ts)
        if self.detector is not None:
            for rule in self.detector.see(
                kind or self.kind,
                event["key"],
                event["type"],
                event["ts"],
                event["host"],
                event["username"],
                event["event_id"],
                str(channel or ""),
                str(summary or ""),
                data or {},
                source or self.source_name,
            ):
                self._write({"t": "det", "key": event["key"], "rule": rule})

    # -- processes and logons: lines that belong to the record written before them ----- #
    @staticmethod
    def _members(values: dict[str, Any]) -> dict[str, Any]:
        """The members a log has: texts cut like record values, numbers as they are, nothing for what is absent."""
        held: dict[str, Any] = {}
        for name, value in values.items():
            if value is None or value == "" or value == {}:
                continue
            if isinstance(value, int):
                held[name] = value
            elif isinstance(value, dict):
                held[name] = {str(k)[:40]: str(v)[:MAX_VALUE] for k, v in value.items() if v not in (None, "")}
            elif name in _WHOLE:
                held[name] = str(value)
            else:
                held[name] = str(value)[:MAX_VALUE]
        return held

    def _tied(self, kind: str, key: str, ts: int | None, values: dict[str, Any]) -> bool:
        """Writes a line of ``kind`` for the record ``key``; False (and counted) when that record was not written."""
        key = self.key_of(str(key))
        if key != self._last_key:
            self._lines_orphan += 1
            return False
        event: dict[str, Any] = {"t": kind, "key": key}
        if ts is not None:
            event["ts"] = int(ts)
        event.update(self._members(values))
        line = self._encode(event)
        if len(line) > MAX_LINE:
            # The command lines are cut by the bytes the line is over (a character is one byte or more).
            over = len(line) - MAX_LINE + 4096
            for name in ("parent_command_line", "command_line"):
                text = event.get(name)
                if isinstance(text, str) and over > 0:
                    event[name] = text[: max(0, len(text) - over)]
                    over -= len(text) - len(event[name])
            self._lines_cut += 1
            line = self._encode(event)
            if len(line) > MAX_LINE:
                return False
        self._out.write(line + b"\n")
        return True

    def process(
        self,
        key: str,
        *,
        ts: int | None = None,
        host: str = "",
        pid: int | None = None,
        ppid: int | None = None,
        image: str = "",
        command_line: str = "",
        user: str = "",
        logon_id: str = "",
        integrity: str = "",
        guid: str = "",
        parent_guid: str = "",
        parent_image: str = "",
        parent_command_line: str = "",
        hashes: dict[str, str] | None = None,
    ) -> bool:
        """A process started, said about the record ``key`` that was written last."""
        return self._tied(
            "proc",
            key,
            ts,
            {
                "host": host,
                "pid": pid,
                "ppid": ppid,
                "image": image,
                "command_line": command_line,
                "user": user,
                "logon_id": logon_id,
                "integrity": integrity,
                "guid": guid,
                "parent_guid": parent_guid,
                "parent_image": parent_image,
                "parent_command_line": parent_command_line,
                "hashes": hashes,
            },
        )

    def process_end(
        self, key: str, *, ts: int | None = None, host: str = "", pid: int | None = None, guid: str = ""
    ) -> bool:
        """A process ended."""
        return self._tied("proc_end", key, ts, {"host": host, "pid": pid, "guid": guid})

    def logon(
        self,
        key: str,
        *,
        ts: int | None = None,
        host: str = "",
        user: str = "",
        domain: str = "",
        logon_type: int | None = None,
        logon_id: str = "",
        source_ip: str = "",
        source_host: str = "",
        outcome: str = "",
        method: str = "",
        status: str = "",
        target_host: str = "",
    ) -> bool:
        """A logon (``outcome``: success, failure, logoff, explicit, privileged)."""
        return self._tied(
            "logon",
            key,
            ts,
            {
                "host": host,
                "user": user,
                "domain": domain,
                "logon_type": logon_type,
                "logon_id": logon_id,
                "source_ip": source_ip,
                "source_host": source_host,
                "outcome": outcome,
                "method": method,
                "status": status,
                "target_host": target_host,
            },
        )

    def skip(
        self, reason: str, *, offset: int | None = None, length: int | None = None, lost: int = 1, detail: str = ""
    ) -> None:
        """Something of the file was not read: ``lost`` records (0 when their number is not known)."""
        self.lost += max(0, int(lost))
        self._write(
            {
                "t": "skip",
                "reason": str(reason)[:120],
                "offset": offset,
                "length": length,
                "lost": max(0, int(lost)),
                "detail": str(detail or "")[:MAX_DETAIL],
            }
        )

    def note(self, reason: str, *, count: int = 1, detail: str = "") -> None:
        """Something worth saying that lost nothing: rows left out for a reason, a file that is dirty."""
        self._write(
            {"t": "note", "reason": str(reason)[:120], "count": int(count), "detail": str(detail or "")[:MAX_DETAIL]}
        )

    def _finish_detection(self) -> None:
        """The correlations and the notes about the rules, before the end of the stream."""
        detector, self.detector = self.detector, None
        if detector is None:
            return
        try:
            dets, notes = detector.finish()
            for det in dets:
                self._write(det)
            for reason, count, detail in notes:
                self.note(reason, count=count, detail=detail)
        except Exception as error:  # noqa: BLE001 - a rule must never end the parse
            self.note("detection failed at the end of the file", detail=f"{type(error).__name__}: {error}")

    def end(self, in_file: int | None = None) -> None:
        """The file was read to its end. ``in_file``: the records the file itself says it holds, when
        its format says so by other means than the parser (the chunk headers of an event log)."""
        if self._ended:
            return
        self._finish_detection()
        if self._lines_cut:
            self.note(
                "process line cut",
                count=self._lines_cut,
                detail=f"a command line made a line longer than {MAX_LINE} bytes: its end is left out",
            )
        if self._lines_orphan:
            self.note(
                "process or logon line without its record",
                count=self._lines_orphan,
                detail="the record before it was not written (see the skips): the line was not written either",
            )
        self._ended = True
        self._write(
            {"t": "end", "in_file": in_file, "read": self.read, "first_ts": self.first_ts, "last_ts": self.last_ts}
        )
        self._out.flush()

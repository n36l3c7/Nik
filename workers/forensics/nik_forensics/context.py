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
     "data", "loc", "trunc", "ioc"}
    {"t": "skip", "reason", "offset", "length", "lost", "detail"}
    {"t": "note", "reason", "count", "detail"}
    {"t": "end", "in_file", "read", "first_ts", "last_ts"}

**Nothing is dropped in silence.** A record a parser could not read is a
``skip`` with its reason and, where the format gives one, its place in the
file. A stream that stops before its ``end`` line is a parser that died: the
backend keeps what came and says the file was read in part.

**Values.** A text longer than ``MAX_VALUE`` characters is cut and the record
says so (``trunc``): the viewer shows the whole of it from the original. A
key longer than ``MAX_KEY`` keeps its start and ends with a hash of the whole.
``ts`` is milliseconds since the epoch, UTC, or None.

Standard library only.
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

    def _write(self, event: dict[str, Any]) -> bool:
        line = json.dumps(event, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8", "replace")
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
        self.seq += 1
        if not self._write(event):
            # Too large to send even with its values cut: the backend is told it was there.
            self.skip("record too large to keep", offset=(loc or {}).get("offset"), detail=f"key {event['key']}")
            return
        self.read += 1
        if ts is not None:
            self.first_ts = ts if self.first_ts is None else min(self.first_ts, ts)
            self.last_ts = ts if self.last_ts is None else max(self.last_ts, ts)

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

    def end(self, in_file: int | None = None) -> None:
        """The file was read to its end. ``in_file``: the records the file itself says it holds, when
        its format says so by other means than the parser (the chunk headers of an event log)."""
        if self._ended:
            return
        self._ended = True
        self._write(
            {"t": "end", "in_file": in_file, "read": self.read, "first_ts": self.first_ts, "last_ts": self.last_ts}
        )
        self._out.flush()

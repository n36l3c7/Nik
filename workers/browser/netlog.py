"""The network log of an isolated browser session (what DevTools' Network panel shows).

Every request of the session is an entry, refused ones included: method,
URL, type, headers, bodies (in clear: the browser sees HTTPS decrypted),
the response, the server address, the TLS certificate, the timings and,
for WebSockets, the messages.

States: ``pending`` (in flight), ``done``, ``failed`` (network error),
``blocked`` (refused by Nik: no network, private address), ``held`` (a
submission Nik did not send) and ``local`` (the attachment itself, served
by Nik).

Bodies are kept up to ``BODY_MAX`` each and ``SESSION_MAX`` per session;
past that only their size and SHA-256 are. Every change gives the entry a
new ``seq``, so the backend fetches what changed since its last call.
"""

from __future__ import annotations

import base64
import hashlib
import time
from typing import Any

BODY_MAX = 2 * 1024 * 1024
SESSION_MAX = 50 * 1024 * 1024
ENTRIES_MAX = 5000
FRAMES_MAX = 1000
FRAME_TEXT_MAX = 64 * 1024


class NetworkLog:
    def __init__(self) -> None:
        self.entries: dict[int, dict[str, Any]] = {}
        # Keyed by the Playwright request / WebSocket object itself (kept alive here).
        self.by_key: dict[Any, int] = {}
        self.next_id = 0
        self.seq = 0
        self.kept = 0  # body bytes kept so far

    # -- bookkeeping ------------------------------------------------------ #
    def touch(self, entry: dict[str, Any]) -> None:
        self.seq += 1
        entry["seq"] = self.seq

    def body(self, data: bytes | None) -> dict[str, Any]:
        """A body as kept: base64 within the limits, else only its size and hash."""
        if not data:
            return {"bodySize": 0}
        out: dict[str, Any] = {"bodySize": len(data), "bodySha256": hashlib.sha256(data).hexdigest()}
        if len(data) <= BODY_MAX and self.kept + len(data) <= SESSION_MAX:
            self.kept += len(data)
            out["body"] = base64.b64encode(data).decode()
        else:
            out["bodyTruncated"] = True
        return out

    def entry(self, key: Any, **fields: Any) -> dict[str, Any] | None:
        """The entry of a request (``key``: the request object), created on first sight."""
        if key in self.by_key:
            return self.entries[self.by_key[key]]
        if len(self.entries) >= ENTRIES_MAX:
            return None
        self.next_id += 1
        item = {
            "id": self.next_id,
            "startedAt": time.time() * 1000,
            "state": "pending",
            "request": {"headers": []},
            **fields,
        }
        self.entries[item["id"]] = item
        self.by_key[key] = item["id"]
        self.touch(item)
        return item

    def get(self, key: Any) -> dict[str, Any] | None:
        return self.entries.get(self.by_key.get(key, -1))

    def update(self, key: Any, **fields: Any) -> dict[str, Any] | None:
        item = self.get(key)
        if item is None:
            return None
        item.update(fields)
        self.touch(item)
        return item

    def frame(self, key: Any, direction: str, message: str | bytes) -> None:
        item = self.get(key)
        if item is None:
            return
        frames = item.setdefault("frames", [])
        if len(frames) >= FRAMES_MAX:
            item["framesTruncated"] = True
            return
        if isinstance(message, bytes):
            record = {"binary": True, "size": len(message)}
            if self.kept + len(message) <= SESSION_MAX and len(message) <= FRAME_TEXT_MAX:
                self.kept += len(message)
                record["data"] = base64.b64encode(message).decode()
        else:
            raw = message.encode("utf-8", "replace")
            record = {"binary": False, "size": len(raw), "text": message[:FRAME_TEXT_MAX]}
        frames.append({"direction": direction, "time": time.time() * 1000, **record})
        self.touch(item)

    # -- reading ---------------------------------------------------------- #
    def since(self, cursor: int, bodies: bool) -> list[dict[str, Any]]:
        changed = sorted((e for e in self.entries.values() if e["seq"] > cursor), key=lambda e: e["id"])
        return changed if bodies else [light(e) for e in changed]

    def counts(self) -> dict[str, int]:
        states = [e["state"] for e in self.entries.values()]
        return {
            "requests": len(states),
            "blocked": states.count("blocked"),
            "held": states.count("held"),
            "failed": states.count("failed"),
        }


def light(entry: dict[str, Any]) -> dict[str, Any]:
    """The entry without bodies (for lists)."""
    out = {k: v for k, v in entry.items() if k not in ("request", "response", "frames")}
    for part in ("request", "response"):
        if entry.get(part):
            out[part] = {k: v for k, v in entry[part].items() if k not in ("body", "headers")}
    if entry.get("frames") is not None:
        out["frameCount"] = len(entry["frames"])
    return out


def timing(raw: dict[str, Any] | None) -> dict[str, float] | None:
    """Playwright's ``request.timing`` as DevTools phases, in milliseconds (-1 when absent)."""
    if not raw:
        return None

    def span(start: str, end: str) -> float:
        a, b = raw.get(start, -1), raw.get(end, -1)
        return round(b - a, 2) if a is not None and b is not None and a >= 0 and b >= 0 else -1

    response_end = raw.get("responseEnd", -1)
    return {
        "dns": span("domainLookupStart", "domainLookupEnd"),
        "connect": span("connectStart", "connectEnd"),
        "ssl": span("secureConnectionStart", "connectEnd"),
        "send": 0.0,
        "wait": span("requestStart", "responseStart"),
        "receive": span("responseStart", "responseEnd"),
        "responseStart": raw.get("responseStart", -1),
        "total": round(response_end, 2) if response_end and response_end >= 0 else -1,
    }

"""HAR 1.2 export of an isolated browser session's network log.

Opens in Chrome / Firefox DevTools, Burp, Fiddler and Charles. Bodies are
exported as kept (base64); refused and held requests are included with
``_nikState`` / ``_nikReason``, WebSocket messages as Chrome's
``_webSocketMessages``.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qsl, urlsplit


def _iso(ms: float | None) -> str:
    return datetime.fromtimestamp((ms or 0) / 1000, tz=timezone.utc).isoformat(timespec="milliseconds")


def _pairs(pairs: list[Any] | None) -> list[dict[str, str]]:
    return [{"name": str(p[0]), "value": str(p[1])} for p in pairs or []]


def _header(pairs: list[Any] | None, name: str) -> str:
    return next((str(p[1]) for p in pairs or [] if str(p[0]).lower() == name), "")


def _phase(value: Any) -> float:
    return round(float(value), 2) if isinstance(value, (int, float)) and value >= 0 else -1


def entry(item: dict[str, Any]) -> dict[str, Any]:
    request = item.get("request") or {}
    response = item.get("response") or {}
    timing = item.get("timing") or {}
    out: dict[str, Any] = {
        "startedDateTime": _iso(item.get("startedAt")),
        "time": max(0.0, _phase(timing.get("total"))),
        "request": {
            "method": item.get("method") or "GET",
            "url": item.get("url") or "",
            "httpVersion": "",
            "cookies": [],
            "headers": _pairs(request.get("headers")),
            "queryString": [{"name": k, "value": v} for k, v in parse_qsl(urlsplit(item.get("url") or "").query)],
            "headersSize": -1,
            "bodySize": int(request.get("bodySize") or 0),
        },
        "response": {
            "status": int(response.get("status") or 0),
            "statusText": response.get("statusText") or "",
            "httpVersion": "",
            "cookies": [],
            "headers": _pairs(response.get("headers")),
            "content": {
                "size": int(response.get("bodySize") or 0),
                "mimeType": response.get("mimeType") or _header(response.get("headers"), "content-type"),
            },
            "redirectURL": _header(response.get("headers"), "location"),
            "headersSize": -1,
            "bodySize": int(response.get("bodySize") or 0),
        },
        "cache": {},
        "timings": {
            "blocked": -1,
            "dns": _phase(timing.get("dns")),
            "connect": _phase(timing.get("connect")),
            "ssl": _phase(timing.get("ssl")),
            "send": 0,
            "wait": max(0.0, _phase(timing.get("wait"))),
            "receive": max(0.0, _phase(timing.get("receive"))),
        },
        "_resourceType": item.get("resourceType") or "",
        "_nikState": item.get("state"),
    }
    if request.get("body"):
        out["request"]["postData"] = {
            "mimeType": _header(request.get("headers"), "content-type"),
            "text": request["body"],
            "encoding": "base64",
        }
    if response.get("body"):
        out["response"]["content"].update(text=response["body"], encoding="base64")
    if response.get("serverIp"):
        out["serverIPAddress"] = response["serverIp"]
    if item.get("reason") or item.get("error"):
        out["_nikReason"] = item.get("reason") or item.get("error")
    if item.get("frames"):
        out["_webSocketMessages"] = [
            {
                "type": "send" if f.get("direction") == "sent" else "receive",
                "time": (f.get("time") or 0) / 1000,
                "opcode": 2 if f.get("binary") else 1,
                "data": f.get("data") if f.get("binary") else f.get("text", ""),
            }
            for f in item["frames"]
        ]
    return out


def build(entries: list[dict[str, Any]], version: str, comment: str = "") -> dict[str, Any]:
    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "Nik", "version": version},
            "comment": comment,
            "pages": [],
            "entries": [entry(item) for item in entries],
        }
    }

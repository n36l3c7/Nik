"""Clients of the preview workers: document viewer and isolated browser.

Both run in their own containers (``workers/docview/``, ``workers/browser/``) and take a
shared token. A rendered document is kept under ``SAMPLE_STORE/_previews``
(named by the attachment's SHA-256), so opening it again costs nothing.
"""

from __future__ import annotations

import base64
import json
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from ..core.config import settings

DOCUMENT_TIMEOUT = 180
BROWSER_TIMEOUT = 90
DOCUMENT_MAX_BYTES = 50 * 1024 * 1024
HTML_MAX_BYTES = 10 * 1024 * 1024

OFFICE = {
    "doc", "docx", "docm", "dot", "dotx", "dotm", "rtf", "odt", "ott",
    "xls", "xlsx", "xlsm", "xlsb", "xlt", "xltx", "xltm", "ods", "csv",
    "ppt", "pptx", "pptm", "pps", "ppsx", "ppsm", "pot", "potx", "odp",
}  # fmt: skip
IMAGES = {"png", "jpg", "jpeg", "gif", "bmp", "tif", "tiff", "webp"}
HTML = {"html", "htm", "shtml", "xhtml", "svg"}


class WorkerError(Exception):
    def __init__(self, message: str, status: int = 502) -> None:
        super().__init__(message)
        self.status = status


def docview_configured() -> bool:
    return bool(settings.DOCVIEW_URL)


def browser_configured() -> bool:
    return bool(settings.BROWSER_URL)


def kind(name: str, type_id: str) -> str | None:
    """``document``, ``html`` or None: how an attachment can be previewed."""
    base = (name or "").lower().strip(" .")
    ext = base.rsplit(".", 1)[-1] if "." in base else ""
    if ext in HTML:
        return "html"
    if type_id in ("pdf", "rtf", "png", "jpeg", "gif") or ext in OFFICE | IMAGES | {"pdf"}:
        return "document"
    return None


def _call(base: str, header: str, token: str, method: str, path: str, body: Any, timeout: int) -> Any:
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(
        f"{base}{path}", data=data, method=method, headers={header: token, "Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - operator-configured URL
            raw = response.read()
    except urllib.error.HTTPError as exc:
        try:
            detail = json.loads(exc.read()).get("detail")
        except (ValueError, AttributeError):
            detail = None
        status = exc.code if exc.code in (400, 404, 413, 422, 503) else 502
        raise WorkerError(detail or f"the worker answered HTTP {exc.code}", status) from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise WorkerError(f"the worker cannot be reached: {getattr(exc, 'reason', exc)}") from exc
    return json.loads(raw) if raw else {}


# --------------------------------------------------------------------------- #
# Documents                                                                   #
# --------------------------------------------------------------------------- #
def _cache_path(sha256: str) -> Path:
    directory = Path(settings.SAMPLE_STORE) / "_previews"
    directory.mkdir(parents=True, exist_ok=True)
    return directory / f"{sha256}.json"


def render_document(name: str, data: bytes, sha256: str) -> dict[str, Any]:
    cached = _cache_path(sha256)
    if cached.exists():
        try:
            return json.loads(cached.read_text())
        except ValueError:
            cached.unlink(missing_ok=True)
    if len(data) > DOCUMENT_MAX_BYTES:
        raise WorkerError("The document is too large to preview (50 MB at most)", 413)
    result = _call(
        settings.DOCVIEW_URL,
        "X-Docview-Token",
        settings.DOCVIEW_TOKEN,
        "POST",
        "/render",
        {"name": name, "data": base64.b64encode(data).decode()},
        DOCUMENT_TIMEOUT,
    )
    tmp = cached.with_suffix(".part")
    tmp.write_text(json.dumps(result))
    os.replace(tmp, cached)
    return result


def forget_document(sha256: str) -> None:
    _cache_path(sha256).unlink(missing_ok=True)


# --------------------------------------------------------------------------- #
# Isolated browser                                                            #
# --------------------------------------------------------------------------- #
def _browser(method: str, path: str, body: Any = None) -> Any:
    return _call(settings.BROWSER_URL, "X-Browser-Token", settings.BROWSER_TOKEN, method, path, body, BROWSER_TIMEOUT)


def open_session(
    owner: str,
    network: bool,
    html: bytes | None = None,
    url: str | None = None,
    width: int | None = None,
    height: int | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {"owner": owner, "network": network}
    if width and height:
        body.update(width=width, height=height)
    if html is not None:
        if len(html) > HTML_MAX_BYTES:
            raise WorkerError("The page is too large to open (10 MB at most)", 413)
        body["html"] = base64.b64encode(html).decode()
    else:
        body["url"] = url
    return _browser("POST", "/sessions", body)


def act(owner: str, session_id: str, action: dict[str, Any]) -> dict[str, Any]:
    return _browser("POST", f"/sessions/{session_id}/action", {**action, "owner": owner})


def close_session(owner: str, session_id: str) -> None:
    from urllib.parse import quote

    _browser("DELETE", f"/sessions/{session_id}?owner={quote(owner)}")


# --------------------------------------------------------------------------- #
# Outlook PST -> mbox (the document worker runs readpst)                      #
# --------------------------------------------------------------------------- #
PST_TIMEOUT = 900


def convert_pst(source, target) -> None:
    """Send the PST to the document worker and write the mbox it answers with
    to ``target``. Both are streamed: neither is held in memory here."""
    if not docview_configured():
        raise WorkerError("The document worker is not configured (DOCVIEW_URL): a PST cannot be read.", 503)
    size = os.path.getsize(source)
    with open(source, "rb") as handle:
        request = urllib.request.Request(  # noqa: S310 - operator-configured URL
            f"{settings.DOCVIEW_URL}/pst",
            data=handle,
            method="POST",
            headers={
                "X-Docview-Token": settings.DOCVIEW_TOKEN,
                "Content-Type": "application/octet-stream",
                "Content-Length": str(size),
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=PST_TIMEOUT) as response, open(target, "wb") as out:  # noqa: S310
                while chunk := response.read(1024 * 1024):
                    out.write(chunk)
        except urllib.error.HTTPError as exc:
            try:
                detail = json.loads(exc.read() or b"{}").get("detail")
            except ValueError:
                detail = None
            raise WorkerError(str(detail or f"The document worker answered {exc.code}"), exc.code) from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise WorkerError("The document worker cannot be reached.", 502) from exc

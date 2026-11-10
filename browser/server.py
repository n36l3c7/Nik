"""HTTP front of the Nik isolated browser worker (standard library only).

    GET    /health                      -> {"status": "ok"}
    POST   /sessions                    {"owner", "network", "html" (base64) | "url"} -> state
    POST   /sessions/{id}/action        {"owner", "type", ...}                         -> state
    DELETE /sessions/{id}?owner=…

A state is ``{id, url, title, network, width, height, screenshot (JPEG,
base64), blocked, events}``. Only the Nik backend talks to this server, with
the shared ``X-Browser-Token``; ``owner`` (the analyst) must match the one
who opened the session.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import json
import os
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from nik_browser import Browser, BrowserError

TOKEN = os.environ.get("BROWSER_TOKEN", "")
PORT = int(os.environ.get("BROWSER_PORT", "8730"))
MAX_HTML = 10 * 1024 * 1024
_SESSION_PATH = re.compile(r"^/sessions/([0-9a-f]{32})(/action)?$")
BROWSER: Browser | None = None


def browser() -> Browser:
    global BROWSER
    if BROWSER is None:
        BROWSER = Browser()
    return BROWSER


class Handler(BaseHTTPRequestHandler):
    server_version = "nik-browser"

    def _send(self, status: int, payload: dict | None = None) -> None:
        body = json.dumps(payload or {}).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        return bool(TOKEN) and hmac.compare_digest(self.headers.get("X-Browser-Token", ""), TOKEN)

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length > MAX_HTML * 4 // 3 + 4096:
            raise BrowserError("Request too large", 413)
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except ValueError as exc:
            raise BrowserError("Invalid request body", 400) from exc
        if not isinstance(body, dict) or not str(body.get("owner") or ""):
            raise BrowserError("owner is required", 400)
        return body

    def _run(self, work) -> None:
        if not self._authorized():
            return self._send(401, {"detail": "Missing or wrong browser token"})
        try:
            status, payload = work()
            self._send(status, payload)
        except BrowserError as exc:
            self._send(exc.status, {"detail": str(exc)})
        except Exception as exc:  # noqa: BLE001 - Playwright errors become a 502 for the backend
            self._send(502, {"detail": f"browser error: {str(exc).splitlines()[0][:300]}"})

    def do_GET(self) -> None:  # noqa: N802 - http.server naming
        if self.path == "/health":
            self._send(200, {"status": "ok"})
        else:
            self._send(404, {"detail": "Not found"})

    def do_POST(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path == "/sessions":

            def work():
                body = self._body()
                html = None
                if body.get("html") is not None:
                    try:
                        html = base64.b64decode(body["html"], validate=True)
                    except (binascii.Error, ValueError) as exc:
                        raise BrowserError("html must be base64", 400) from exc
                url = body.get("url")
                if (html is None) == (url is None):
                    raise BrowserError("Send either html or url", 400)
                return 201, browser().open(str(body["owner"]), bool(body.get("network")), html=html, url=url)

            return self._run(work)
        match = _SESSION_PATH.match(path)
        if match and match.group(2):

            def work():
                body = self._body()
                return 200, browser().act(match.group(1), str(body["owner"]), body)

            return self._run(work)
        self._send(404, {"detail": "Not found"})

    def do_DELETE(self) -> None:  # noqa: N802
        parts = urlsplit(self.path)
        match = _SESSION_PATH.match(parts.path)
        if not match or match.group(2):
            return self._send(404, {"detail": "Not found"})
        owner = (parse_qs(parts.query).get("owner") or [""])[0]

        def work():
            browser().close(match.group(1), owner)
            return 200, {}

        self._run(work)

    def log_message(self, fmt: str, *args) -> None:
        print(f"{self.address_string()} {fmt % args}", flush=True)


def _expire() -> None:
    while True:
        time.sleep(30)
        if BROWSER is not None:
            BROWSER.expire()


if __name__ == "__main__":
    if not TOKEN:
        raise SystemExit("BROWSER_TOKEN is not set: refusing to start without authentication.")
    print(f"nik-browser listening on :{PORT}", flush=True)
    threading.Thread(target=_expire, name="expire", daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()

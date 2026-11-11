"""HTTP front of the Nik document viewer worker (standard library only).

    GET  /health                    -> {"status": "ok"}
    POST /render {"name", "data"}   -> the first pages as PNG (``nik_docview.render``)

``data`` is the file, base64-encoded. Only the Nik backend talks to this
server, on the internal network, with the shared ``X-Docview-Token``. At most
``MAX_JOBS`` conversions run at once; extra requests get 503.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from nik_docview import PreviewError, render

TOKEN = os.environ.get("DOCVIEW_TOKEN", "")
PORT = int(os.environ.get("DOCVIEW_PORT", "8720"))
MAX_JOBS = int(os.environ.get("DOCVIEW_MAX_JOBS", "2"))
MAX_BYTES = int(os.environ.get("DOCVIEW_MAX_MB", "50")) * 1024 * 1024
_slots = threading.BoundedSemaphore(MAX_JOBS)


class Handler(BaseHTTPRequestHandler):
    server_version = "nik-docview"

    def _send(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - http.server naming
        if self.path == "/health":
            self._send(200, {"status": "ok"})
        else:
            self._send(404, {"detail": "Not found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/render":
            return self._send(404, {"detail": "Not found"})
        if not (TOKEN and hmac.compare_digest(self.headers.get("X-Docview-Token", ""), TOKEN)):
            return self._send(401, {"detail": "Missing or wrong docview token"})
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length > MAX_BYTES * 4 // 3 + 4096:
            return self._send(413, {"detail": "The document is too large to preview"})
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
            name = str(body.get("name") or "document")[:255]
            data = base64.b64decode(body.get("data") or "", validate=True)
        except (ValueError, binascii.Error, AttributeError):
            return self._send(400, {"detail": "Invalid request body"})
        if not data:
            return self._send(400, {"detail": "Empty document"})
        if not _slots.acquire(blocking=False):
            return self._send(503, {"detail": "The document viewer is busy; try again later"})
        try:
            self._send(200, render(name, data))
        except PreviewError as exc:
            self._send(422, {"detail": str(exc)})
        finally:
            _slots.release()

    def log_message(self, fmt: str, *args) -> None:
        print(f"{self.address_string()} {fmt % args}", flush=True)


if __name__ == "__main__":
    if not TOKEN or TOKEN.startswith("please-change-this"):
        # An empty token, or the public one of the example file, protects nothing.
        raise SystemExit("DOCVIEW_TOKEN is not set (or is the example value): refusing to start.")
    print(f"nik-docview listening on :{PORT}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()

"""HTTP front of the Nik capa worker (standard library only).

    GET  /health            → {"status": "ok", "engine": "capa x.y.z"}
    POST /analyze {"sha256"} → the capabilities of SAMPLE_DIR/<sha256>.bin

Only the Nik backend talks to this server: it is not published outside the
container network, and every request must carry the shared token in
``X-Analyzer-Token``. capa is CPU-bound, so at most ``CAPA_MAX_JOBS``
analyses run at once (default 1); extra requests get 503.
"""

from __future__ import annotations

import hmac
import json
import os
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from nik_capa import CapaError, CapaTimeout, analyze, capa_version

SAMPLE_DIR = os.environ.get("SAMPLE_DIR", "/samples")
TOKEN = os.environ.get("CAPA_TOKEN", "")
TIMEOUT = float(os.environ.get("CAPA_TIMEOUT", "1800"))
MAX_JOBS = int(os.environ.get("CAPA_MAX_JOBS", "1"))
PORT = int(os.environ.get("CAPA_PORT", "8710"))
SHA256 = re.compile(r"^[0-9a-f]{64}$")
_slots = threading.BoundedSemaphore(MAX_JOBS)


class Handler(BaseHTTPRequestHandler):
    server_version = "nik-capa"

    def _send(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        return bool(TOKEN) and hmac.compare_digest(self.headers.get("X-Analyzer-Token", ""), TOKEN)

    def do_GET(self) -> None:  # noqa: N802 - http.server naming
        if self.path == "/health":
            self._send(200, {"status": "ok", "engine": f"capa {capa_version()}"})
        else:
            self._send(404, {"detail": "Not found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/analyze":
            return self._send(404, {"detail": "Not found"})
        if not self._authorized():
            return self._send(401, {"detail": "Missing or wrong analyzer token"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            sha256 = json.loads(self.rfile.read(min(length, 4096)) or b"{}").get("sha256", "")
        except (ValueError, AttributeError, json.JSONDecodeError):
            return self._send(400, {"detail": "Invalid request body"})
        if not isinstance(sha256, str) or not SHA256.match(sha256):
            return self._send(400, {"detail": "sha256 must be 64 lowercase hex characters"})
        if not _slots.acquire(blocking=False):
            return self._send(503, {"detail": "capa is busy with another sample; try again later"})
        try:
            self._send(200, analyze(os.path.join(SAMPLE_DIR, f"{sha256}.bin"), timeout=TIMEOUT))
        except CapaTimeout as exc:
            self._send(504, {"detail": str(exc)})
        except CapaError as exc:
            self._send(422, {"detail": str(exc)})
        finally:
            _slots.release()

    def log_message(self, fmt: str, *args) -> None:
        print(f"{self.address_string()} {fmt % args}", flush=True)


if __name__ == "__main__":
    if not TOKEN:
        raise SystemExit("CAPA_TOKEN is not set: refusing to start without authentication.")
    print(f"nik-capa listening on :{PORT} (capa {capa_version()}, samples in {SAMPLE_DIR})", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()

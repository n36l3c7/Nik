"""HTTP front of the Nik script sandbox (standard library only).

    GET  /health                          -> {"status": "ok"}
    POST /run {"code", "args", "timeout"} -> {"ok", "result" | "error", "stdout", "duration_ms"}

Only Nik talks to this server, on an internal network, with the shared
``X-Sandbox-Token``. It runs each script in a process of its own (runner.py)
and offers nothing else: no way to read a file, no client to anything. At
most ``MAX_JOBS`` scripts run at once; extra requests get 503.
"""

from __future__ import annotations

import hmac
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import runner


def secret(name: str) -> str:
    """The secret called ``name``: the content of the file ``<name>_FILE`` names when it holds
    something (a mounted secret), else the variable itself. Never both."""
    value = os.environ.get(name, "")
    path = os.environ.get(f"{name}_FILE", "").strip()
    if not path:
        return value
    try:
        with open(path, encoding="utf-8") as handle:
            held = handle.read(65536).strip("\r\n")
    except OSError as error:
        raise SystemExit(
            f"{name}_FILE names {path}, which cannot be read ({error.strerror}): refusing to start."
        ) from None
    if held and value:
        raise SystemExit(f"{name} is given twice, in the file named by {name}_FILE and in the environment: keep one.")
    return held or value


TOKEN = secret("SANDBOX_TOKEN")
PORT = int(os.environ.get("SANDBOX_PORT", "8750"))
MAX_JOBS = int(os.environ.get("SANDBOX_MAX_JOBS", "4"))
MAX_BODY = 2 * 1024 * 1024
_slots = threading.BoundedSemaphore(MAX_JOBS)


class Handler(BaseHTTPRequestHandler):
    server_version = "nik-sandbox"

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
        if self.path != "/run":
            return self._send(404, {"detail": "Not found"})
        if not (TOKEN and hmac.compare_digest(self.headers.get("X-Sandbox-Token", ""), TOKEN)):
            return self._send(401, {"detail": "Missing or wrong sandbox token"})
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length <= 0 or length > MAX_BODY:
            return self._send(413, {"detail": "The request is empty or larger than 2 MB"})
        try:
            body = json.loads(self.rfile.read(length))
            code = body["code"]
            args = body.get("args") or {}
            timeout = body.get("timeout")
            if not isinstance(code, str) or not isinstance(args, dict):
                raise ValueError
        except (ValueError, KeyError, TypeError):
            return self._send(400, {"detail": "Invalid request body"})
        if not _slots.acquire(blocking=False):
            return self._send(503, {"detail": "The sandbox is busy; try again later"})
        try:
            self._send(200, runner.run(code, args, timeout if isinstance(timeout, int) else None))
        finally:
            _slots.release()

    def log_message(self, fmt: str, *args) -> None:
        print(f"{self.address_string()} {fmt % args}", flush=True)


if __name__ == "__main__":
    if not TOKEN or TOKEN.startswith("please-change-this"):
        # An empty token, or the public one of the example file, protects nothing.
        raise SystemExit("SANDBOX_TOKEN is not set (or is the example value): refusing to start.")
    print(f"nik-sandbox listening on :{PORT}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()  # noqa: S104 - an internal network only

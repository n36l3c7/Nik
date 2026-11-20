"""HTTP front of the Nik packet capture worker (standard library only).

    GET  /health
    PUT  /files/_captures/<id>/capture.<ext>                      -> the worker is given a capture (the body)
    POST /analyze {"id", "path", "keylog"?}                      -> summary, objects, expert counts
    POST /rpc     {"id", "path", "keylog"?, "method", "params"}  -> the sharkd result
    POST /close   {"id"}                                          -> its session ends, its file is deleted

``path`` is the name of the capture (``_captures/<id>/capture.<ext>``). Only
the Nik backend talks to this server, on the internal network, with the
shared ``X-Pcap-Token``. At most ``MAX_JOBS`` summaries run at once; extra
requests get 503.

The worker does not see the store of files, which is sealed: the backend
gives it the capture (``given.py``). A request about a capture the worker
does not hold is answered ``409`` with the name that is ``missing``; the
backend sends it and asks again. A capture of ``PCAP_MEMORY_FILE_MB`` or less
is kept in memory (``/tmp``); a larger one goes to the work volume
(``/work``), a disk, where it is **in clear** until its session is closed or
has been idle for ``PCAP_SESSION_IDLE`` seconds, and at the latest until the
worker starts again (it empties both places when it starts).
"""

from __future__ import annotations

import base64
import hmac
import json
import os
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import given
import nik_pcap

TOKEN = given.secret("PCAP_TOKEN")
PORT = int(os.environ.get("PCAP_PORT", "8740"))
MAX_JOBS = int(os.environ.get("PCAP_MAX_JOBS", "2"))
_ID = re.compile(r"^[0-9a-f]{32}$")
EXTENSIONS = ("pcap", "pcapng", "cap", "gz")
_PATH = re.compile(r"^_captures/([0-9a-f]{32})/capture\.(pcap|pcapng|cap|gz)$")
_slots = threading.BoundedSemaphore(MAX_JOBS)
GIVEN = given.Given(
    os.environ.get("PCAP_MEMORY_DIR", "/tmp/nik-given"),
    (re.compile(r"_captures/[0-9a-f]{32}/capture\.(pcap|pcapng|cap|gz)"),),
    max_bytes=int(os.environ.get("PCAP_FILES_MB", "16384")) * 1024 * 1024,
    idle=nik_pcap.SESSION_IDLE + 60.0,
    large=os.environ.get("PCAP_WORK_DIR", "/work"),
    large_from=int(os.environ.get("PCAP_MEMORY_FILE_MB", "64")) * 1024 * 1024,
)


class Missing(Exception):
    """The capture a request names was not given to the worker (or was deleted since)."""

    def __init__(self, name: str) -> None:
        super().__init__(name)
        self.name = name


class Handler(BaseHTTPRequestHandler):
    server_version = "nik-pcap"

    def _send(self, status: int, payload) -> None:
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

    def do_PUT(self) -> None:  # noqa: N802
        authorized = bool(TOKEN) and hmac.compare_digest(self.headers.get("X-Pcap-Token", ""), TOKEN)
        given.take_request(self, GIVEN, authorized)

    def _request(self) -> tuple[dict, str, str | None]:
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length > 20 * 1024 * 1024:
            raise nik_pcap.CaptureError("Request too large", 413)
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except ValueError as exc:
            raise nik_pcap.CaptureError("Invalid request body", 400) from exc
        capture_id = str(body.get("id") or "")
        if not _ID.match(capture_id):
            raise nik_pcap.CaptureError("id must be 32 hex characters", 400)
        if self.path == "/close":
            return body, capture_id, None
        match = _PATH.match(str(body.get("path") or ""))
        if not match or match.group(1) != capture_id:
            raise nik_pcap.CaptureError("Invalid capture path", 400)
        # Rebuilt from fixed parts (the extension from a fixed list).
        ext = next(e for e in EXTENSIONS if e == match.group(2))
        name = f"_captures/{capture_id}/capture.{ext}"
        path = GIVEN.path(name)
        if path is None:
            raise Missing(name)
        return body, capture_id, path

    def do_POST(self) -> None:  # noqa: N802
        if self.path not in ("/analyze", "/rpc", "/close"):
            return self._send(404, {"detail": "Not found"})
        if not (TOKEN and hmac.compare_digest(self.headers.get("X-Pcap-Token", ""), TOKEN)):
            return self._send(401, {"detail": "Missing or wrong pcap token"})
        try:
            body, capture_id, path = self._request()
            keylog = body.get("keylog") or None
            if self.path == "/close":
                nik_pcap.SESSIONS.drop(capture_id)
                GIVEN.drop_prefix(f"_captures/{capture_id}/")
                return self._send(200, {})
            if self.path == "/rpc":
                method = str(body.get("method") or "")
                params = body.get("params") or {}
                if method == "download":
                    result = nik_pcap.download(capture_id, path, keylog, str(params.get("token") or ""))
                    result["data"] = base64.b64encode(result["data"]).decode()
                    return self._send(200, result)
                return self._send(200, {"result": nik_pcap.rpc(capture_id, path, keylog, method, params)})
            if not _slots.acquire(blocking=False):
                return self._send(503, {"detail": "The capture worker is busy; try again later"})
            try:
                summary = nik_pcap.summarize(path, keylog)
                found, expert = nik_pcap.objects(capture_id, path, keylog)
                self._send(200, {**summary, "objects": found, "expert": expert})
            finally:
                _slots.release()
        except Missing as missing:
            self._send(409, {"detail": "The worker does not hold this capture", "missing": [missing.name]})
        except nik_pcap.CaptureError as exc:
            self._send(exc.status, {"detail": str(exc)})
        except (ValueError, TypeError) as exc:
            self._send(400, {"detail": f"Invalid request: {exc}"})

    def log_message(self, fmt: str, *args) -> None:
        print(f"{self.address_string()} {fmt % args}", flush=True)


def _expire() -> None:
    while True:
        time.sleep(60)
        nik_pcap.SESSIONS.expire()
        GIVEN.expire()


if __name__ == "__main__":
    if not TOKEN or TOKEN.startswith("please-change-this"):
        # An empty token, or the public one of the example file, protects nothing.
        raise SystemExit("PCAP_TOKEN is not set (or is the example value): refusing to start.")
    GIVEN.clear()
    print(f"nik-pcap listening on :{PORT}", flush=True)
    threading.Thread(target=_expire, name="expire", daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()

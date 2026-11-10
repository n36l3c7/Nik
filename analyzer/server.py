"""HTTP front of the Nik analyzer worker (standard library only).

    GET  /health                       → {"status": "ok", "engine": "rizin x.y.z"}
    POST /analyze {"sha256"}           → the analysis of SAMPLE_DIR/<sha256>.bin
    POST /decompile {"sha256", "addr"} → the pseudo-C of one function

Both POST routes accept ``"signatures": ["_flirt/<name>.sig", …]``: FLIRT
files the backend stored in the shared sample store, applied after rizin's.

Only the Nik backend talks to this server: it is not published outside the
container network, and every request must carry the shared ``X-Analyzer-Token``.
At most ``MAX_JOBS`` requests run at once; extra requests get 503.
"""

from __future__ import annotations

import hmac
import json
import os
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from nik_analyzer import AnalysisError, AnalysisTimeout, WarmSessions, analyze, decompile_one, rizin_version

SAMPLE_DIR = os.environ.get("SAMPLE_DIR", "/samples")
TOKEN = os.environ.get("ANALYZER_TOKEN", "")
TIMEOUT = float(os.environ.get("ANALYZER_TIMEOUT", "600"))
DECOMPILE_SECONDS = float(os.environ.get("ANALYZER_DECOMPILE_SECONDS", "300"))
MAX_JOBS = int(os.environ.get("ANALYZER_MAX_JOBS", "2"))
# Analysed sessions kept open for the decompilations on demand that follow an
# analysis (each holds rizin's memory for that file, ~1 GB on a large binary).
WARM = WarmSessions(
    size=int(os.environ.get("ANALYZER_WARM_SESSIONS", "1")),
    idle=float(os.environ.get("ANALYZER_WARM_IDLE", "600")),
)
PORT = int(os.environ.get("ANALYZER_PORT", "8700"))
SHA256 = re.compile(r"^[0-9a-f]{64}$")
SIGNATURE = re.compile(r"^_flirt/[0-9a-f]{32}\.(sig|pat)$")
_slots = threading.BoundedSemaphore(MAX_JOBS)


class Handler(BaseHTTPRequestHandler):
    server_version = "nik-analyzer"

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
            self._send(200, {"status": "ok", "engine": f"rizin {rizin_version()}"})
        else:
            self._send(404, {"detail": "Not found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path not in ("/analyze", "/decompile"):
            return self._send(404, {"detail": "Not found"})
        if not self._authorized():
            return self._send(401, {"detail": "Missing or wrong analyzer token"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(min(length, 4096)) or b"{}")
            sha256 = body.get("sha256", "")
            addr = body.get("addr")
            signatures = body.get("signatures") or []
        except (ValueError, AttributeError, json.JSONDecodeError):
            return self._send(400, {"detail": "Invalid request body"})
        if not isinstance(signatures, list) or not all(isinstance(s, str) and SIGNATURE.match(s) for s in signatures):
            return self._send(400, {"detail": "signatures must be _flirt/<32 hex>.sig or .pat paths"})
        signature_paths = [p for p in (os.path.join(SAMPLE_DIR, s) for s in signatures) if os.path.isfile(p)]
        if not SHA256.match(sha256 or ""):
            return self._send(400, {"detail": "sha256 must be 64 lowercase hex characters"})
        if self.path == "/decompile" and (not isinstance(addr, int) or isinstance(addr, bool) or addr < 0):
            return self._send(400, {"detail": "addr must be a non-negative integer"})
        if not _slots.acquire(blocking=False):
            return self._send(503, {"detail": "The analyzer is busy; try again later"})
        path = os.path.join(SAMPLE_DIR, f"{sha256}.bin")
        try:
            if self.path == "/analyze":
                result = analyze(
                    path, timeout=TIMEOUT, decompile_seconds=DECOMPILE_SECONDS, signatures=signature_paths, warm=WARM
                )
            else:
                result = decompile_one(path, addr, timeout=TIMEOUT, signatures=signature_paths, warm=WARM)
            self._send(200, result)
        except AnalysisTimeout as exc:
            self._send(504, {"detail": str(exc)})
        except AnalysisError as exc:
            self._send(422, {"detail": str(exc)})
        finally:
            _slots.release()

    def log_message(self, fmt: str, *args) -> None:
        print(f"{self.address_string()} {fmt % args}", flush=True)


def _expire_warm_sessions() -> None:
    while True:
        time.sleep(60)
        WARM.expire()


if __name__ == "__main__":
    if not TOKEN:
        raise SystemExit("ANALYZER_TOKEN is not set: refusing to start without authentication.")
    print(f"nik-analyzer listening on :{PORT} (rizin {rizin_version()}, samples in {SAMPLE_DIR})", flush=True)
    threading.Thread(target=_expire_warm_sessions, name="warm-sessions", daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()

"""HTTP front of the Nik analyzer worker (standard library only).

    GET  /health                       → {"status": "ok", "engine": "rizin x.y.z"}
    GET  /jobs/<name>                  → whether the worker still has a job (``jobs.py``)
    PUT  /files/<name>                 → the worker is given a file (the body)
    POST /analyze {"sha256"}           → the analysis of the sample <sha256>.bin
    POST /decompile {"sha256", "addr"} → the pseudo-C of one function

Both POST routes accept ``"signatures": ["_flirt/<name>.sig", …]``: FLIRT
files applied after rizin's.

The worker does not see the store of files, which is sealed: the backend
gives it the sample and the signatures a job needs (``given.py``). A request
that names a file the worker does not hold is answered ``409`` with the names
that are ``missing``; the backend sends them and asks again. What was given
is kept in memory (``/tmp``, never a disk) while it is used, for the
decompilations on demand that follow an analysis.

Only the Nik backend talks to this server: it is not published outside the
container network, and every request must carry the shared ``X-Analyzer-Token``.
At most ``MAX_JOBS`` requests run at once; extra requests get 503.

On SIGTERM the worker stops taking requests, lets the ones it runs finish for
``ANALYZER_STOP_GRACE`` seconds, and exits. Everything it knows is in memory:
a worker that starts again answers "unknown job" for what it was doing, and
the backend hands that out again with its file.
"""

from __future__ import annotations

import hmac
import json
import os
import re
import signal
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import given
import jobs
from nik_analyzer import AnalysisError, AnalysisTimeout, WarmSessions, analyze, decompile_one, rizin_version

TOKEN = given.secret("ANALYZER_TOKEN")
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
STOP_GRACE = float(os.environ.get("ANALYZER_STOP_GRACE", "20"))
_slots = threading.BoundedSemaphore(MAX_JOBS)
JOBS = jobs.Jobs()
# What the backend gave: in memory, and for a little longer than a warm session lives.
GIVEN = given.Given(
    os.environ.get("ANALYZER_WORK_DIR", "/tmp/nik-given"),
    (re.compile(r"[0-9a-f]{64}\.bin"), SIGNATURE),
    max_bytes=int(os.environ.get("ANALYZER_FILES_MB", "1024")) * 1024 * 1024,
    idle=max(900.0, float(os.environ.get("ANALYZER_WARM_IDLE", "600")) + 300.0),
)


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
            return self._send(200, {"status": "ok", "engine": f"rizin {rizin_version()}", "started": JOBS.started})
        if not self._authorized():
            return self._send(401, {"detail": "Missing or wrong analyzer token"})
        self._send(*(JOBS.answer(self.path) or (404, {"detail": "Not found"})))

    def do_PUT(self) -> None:  # noqa: N802
        given.take_request(self, GIVEN, self._authorized())

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
        if not isinstance(signatures, list) or not all(
            isinstance(s, str) and SIGNATURE.fullmatch(s) for s in signatures
        ):
            return self._send(400, {"detail": "signatures must be _flirt/<32 hex>.sig or .pat paths"})
        if not isinstance(sha256, str) or not SHA256.fullmatch(sha256):
            return self._send(400, {"detail": "sha256 must be 64 lowercase hex characters"})
        if self.path == "/decompile" and (not isinstance(addr, int) or isinstance(addr, bool) or addr < 0):
            return self._send(400, {"detail": "addr must be a non-negative integer"})
        names = [f"{sha256}.bin", *signatures]
        missing = GIVEN.missing(names)
        if missing:
            return self._send(409, {"detail": "The worker does not hold these files", "missing": missing})
        if not _slots.acquire(blocking=False):
            return self._send(503, {"detail": "The analyzer is busy; try again later"})
        try:
            with GIVEN.hold(names), JOBS.running(self.headers.get(jobs.HEADER)) as say:
                say("disassembling" if self.path == "/analyze" else "decompiling")
                self._run(names, sha256, addr, signatures)
        finally:
            _slots.release()

    def _run(self, names: list[str], sha256: str, addr, signatures: list[str]) -> None:
        path = GIVEN.path(f"{sha256}.bin")
        signature_paths = [found for found in (GIVEN.path(name) for name in signatures) if found]
        if path is None:
            return self._send(409, {"detail": "The worker does not hold these files", "missing": names[:1]})
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

    def log_message(self, fmt: str, *args) -> None:
        print(f"{self.address_string()} {fmt % args}", flush=True)


def _expire_warm_sessions() -> None:
    while True:
        time.sleep(60)
        WARM.expire()
        GIVEN.expire()


if __name__ == "__main__":
    if not TOKEN or TOKEN.startswith("please-change-this"):
        # An empty token, or the public one of the example file, protects nothing.
        raise SystemExit("ANALYZER_TOKEN is not set (or is the example value): refusing to start.")
    GIVEN.clear()
    print(f"nik-analyzer listening on :{PORT} (rizin {rizin_version()})", flush=True)
    threading.Thread(target=_expire_warm_sessions, name="warm-sessions", daemon=True).start()
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    # A request in flight is not cut by the stop of the server: its thread goes on for the grace.
    server.daemon_threads = True
    signal.signal(signal.SIGTERM, lambda *_: jobs.stop_politely(server))
    signal.signal(signal.SIGINT, lambda *_: jobs.stop_politely(server))
    server.serve_forever()
    jobs.drain(JOBS, STOP_GRACE)

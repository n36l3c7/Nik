"""HTTP front of the Nik capa worker (standard library only).

    GET  /health                       → {"status": "ok", "engine": "capa x.y.z"}
    GET  /jobs/<name>                  → whether the worker still has a job (``jobs.py``)
    PUT  /files/<sha256>.bin           → the worker is given a sample (the body)
    POST /analyze {"sha256", "rules"}  → the capabilities of the sample <sha256>.bin
    POST /validate {"source", "others"} → whether a capa rule parses and fits the rule set

``rules`` are the admin rules, each ``{"name": "<id>.yml", "source": "…"}``,
matched with the bundled rules; ``others`` are the sources of the other admin
rules, so a rule may depend on them.

The worker does not see the store of files, which is sealed: the backend
gives it the sample (``given.py``). ``/analyze`` on a sample the worker does
not hold is answered ``409`` with the name that is ``missing``; the backend
sends it and asks again. The sample and the rules are in memory (``/tmp``,
never a disk) for the time of the analysis and are deleted when it ends.

Only the Nik backend talks to this server: it is not published outside the
container network, and every request must carry the shared token in
``X-Analyzer-Token``. capa is CPU-bound, so at most ``CAPA_MAX_JOBS``
analyses run at once (default 1); extra requests get 503.

On SIGTERM the worker stops taking requests, lets the ones it runs finish for
``CAPA_STOP_GRACE`` seconds, and exits. Everything it knows is in memory: a
worker that starts again answers "unknown job" for what it was doing
(``jobs.py``), and the backend hands that out again with its file.
"""

from __future__ import annotations

import hmac
import json
import os
import re
import shutil
import signal
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import given
import jobs
from nik_capa import CapaError, CapaTimeout, analyze, capa_version, validate_rule

TOKEN = given.secret("CAPA_TOKEN")
TIMEOUT = float(os.environ.get("CAPA_TIMEOUT", "1800"))
MAX_JOBS = int(os.environ.get("CAPA_MAX_JOBS", "1"))
PORT = int(os.environ.get("CAPA_PORT", "8710"))
SHA256 = re.compile(r"^[0-9a-f]{64}$")
RULE_FILE = re.compile(r"^[0-9a-f]{32}\.yml$")
MAX_VALIDATE_BYTES = 4 * 1024 * 1024  # one rule plus the other admin rules it may depend on
STOP_GRACE = float(os.environ.get("CAPA_STOP_GRACE", "20"))
_slots = threading.BoundedSemaphore(MAX_JOBS)
JOBS = jobs.Jobs()
WORK_DIR = os.environ.get("CAPA_WORK_DIR", "/tmp/nik-given")
GIVEN = given.Given(
    WORK_DIR,
    (re.compile(r"[0-9a-f]{64}\.bin"),),
    max_bytes=int(os.environ.get("CAPA_FILES_MB", "1024")) * 1024 * 1024,
)


def write_rules(rules: list[dict], folder: str) -> list[str]:
    """The admin rules of one analysis as files of ``folder``; their paths, in the order given."""
    paths = []
    for rule in rules:
        path = os.path.join(folder, rule["name"])
        with open(path, "w", encoding="utf-8") as out:
            out.write(rule["source"])
        paths.append(path)
    return paths


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
            return self._send(200, {"status": "ok", "engine": f"capa {capa_version()}", "started": JOBS.started})
        if not self._authorized():
            return self._send(401, {"detail": "Missing or wrong analyzer token"})
        self._send(*(JOBS.answer(self.path) or (404, {"detail": "Not found"})))

    def _body(self, limit: int) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length > limit:
            raise ValueError("Request body too large")
        body = json.loads(self.rfile.read(length) or b"{}")
        if not isinstance(body, dict):
            raise ValueError("Request body must be an object")
        return body

    def do_PUT(self) -> None:  # noqa: N802
        given.take_request(self, GIVEN, self._authorized())

    def do_POST(self) -> None:  # noqa: N802
        if self.path not in ("/analyze", "/validate"):
            return self._send(404, {"detail": "Not found"})
        if not self._authorized():
            return self._send(401, {"detail": "Missing or wrong analyzer token"})
        try:
            body = self._body(MAX_VALIDATE_BYTES)
        except (ValueError, json.JSONDecodeError) as exc:
            return self._send(400, {"detail": f"Invalid request body: {exc}"})
        if self.path == "/validate":
            return self._validate(body)
        return self._analyze(body)

    def _validate(self, body: dict) -> None:
        source, others = body.get("source"), body.get("others") or []
        if not isinstance(source, str) or not isinstance(others, list) or not all(isinstance(o, str) for o in others):
            return self._send(400, {"detail": "source must be a string and others a list of strings"})
        self._send(200, validate_rule(source, others))

    def _analyze(self, body: dict) -> None:
        sha256, rules = body.get("sha256", ""), body.get("rules") or []
        if not isinstance(sha256, str) or not SHA256.fullmatch(sha256):
            return self._send(400, {"detail": "sha256 must be 64 lowercase hex characters"})
        if not isinstance(rules, list) or not all(
            isinstance(r, dict)
            and isinstance(r.get("name"), str)
            and RULE_FILE.fullmatch(r["name"])
            and isinstance(r.get("source"), str)
            for r in rules
        ):
            return self._send(400, {"detail": "rules must be {name: <32 hex>.yml, source} objects"})
        name = f"{sha256}.bin"
        if GIVEN.missing([name]):
            return self._send(409, {"detail": "The worker does not hold this sample", "missing": [name]})
        if not _slots.acquire(blocking=False):
            return self._send(503, {"detail": "capa is busy with another sample; try again later"})
        os.makedirs(WORK_DIR, exist_ok=True)
        folder = tempfile.mkdtemp(prefix="rules-", dir=WORK_DIR)
        try:
            with GIVEN.hold([name]), JOBS.running(self.headers.get(jobs.HEADER)) as say:
                say("matching the rules")
                path = GIVEN.path(name)
                if path is None:
                    answer = (409, {"detail": "The worker does not hold this sample", "missing": [name]})
                else:
                    answer = (200, analyze(path, timeout=TIMEOUT, extra_rules=write_rules(rules, folder)))
        except CapaTimeout as exc:
            answer = (504, {"detail": str(exc)})
        except CapaError as exc:
            answer = (422, {"detail": str(exc)})
        finally:
            # One analysis, then nothing of the sample stays here: gone before the answer leaves.
            shutil.rmtree(folder, ignore_errors=True)
            GIVEN.drop(name)
            _slots.release()
        self._send(*answer)

    def log_message(self, fmt: str, *args) -> None:
        print(f"{self.address_string()} {fmt % args}", flush=True)


if __name__ == "__main__":
    if not TOKEN or TOKEN.startswith("please-change-this"):
        # An empty token, or the public one of the example file, protects nothing.
        raise SystemExit("CAPA_TOKEN is not set (or is the example value): refusing to start.")
    GIVEN.clear()
    shutil.rmtree(WORK_DIR, ignore_errors=True)
    print(f"nik-capa listening on :{PORT} (capa {capa_version()})", flush=True)
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    # A request in flight is not cut by the stop of the server: its thread goes on for the grace.
    server.daemon_threads = True
    signal.signal(signal.SIGTERM, lambda *_: jobs.stop_politely(server))
    signal.signal(signal.SIGINT, lambda *_: jobs.stop_politely(server))
    server.serve_forever()
    jobs.drain(JOBS, STOP_GRACE)

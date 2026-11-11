"""HTTP front of the Nik capa worker (standard library only).

    GET  /health                       → {"status": "ok", "engine": "capa x.y.z"}
    POST /analyze {"sha256", "rules"}  → the capabilities of SAMPLE_DIR/<sha256>.bin
    POST /validate {"source", "others"} → whether a capa rule parses and fits the rule set

``rules`` are admin rule files the backend stored in the shared sample store
(``_capa_rules/<id>.yml``), matched with the bundled rules; ``others`` are
the sources of the other admin rules, so a rule may depend on them.

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

from nik_capa import CapaError, CapaTimeout, analyze, capa_version, validate_rule

SAMPLE_DIR = os.environ.get("SAMPLE_DIR", "/samples")
TOKEN = os.environ.get("CAPA_TOKEN", "")
TIMEOUT = float(os.environ.get("CAPA_TIMEOUT", "1800"))
MAX_JOBS = int(os.environ.get("CAPA_MAX_JOBS", "1"))
PORT = int(os.environ.get("CAPA_PORT", "8710"))
SHA256 = re.compile(r"^[0-9a-f]{64}$")
RULE_FILE = re.compile(r"^_capa_rules/[0-9a-f]{32}\.yml$")
MAX_VALIDATE_BYTES = 4 * 1024 * 1024  # one rule plus the other admin rules it may depend on
_slots = threading.BoundedSemaphore(MAX_JOBS)


def in_store(relative: str) -> str:
    """The absolute path of ``relative`` in the store; ValueError when it would leave the store."""
    root = os.path.realpath(SAMPLE_DIR)
    path = os.path.realpath(os.path.join(root, relative))
    if not path.startswith(root + os.sep):
        raise ValueError("Not a path in the sample store.")
    return path


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

    def _body(self, limit: int) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length > limit:
            raise ValueError("Request body too large")
        body = json.loads(self.rfile.read(length) or b"{}")
        if not isinstance(body, dict):
            raise ValueError("Request body must be an object")
        return body

    def do_POST(self) -> None:  # noqa: N802
        if self.path not in ("/analyze", "/validate"):
            return self._send(404, {"detail": "Not found"})
        if not self._authorized():
            return self._send(401, {"detail": "Missing or wrong analyzer token"})
        try:
            body = self._body(MAX_VALIDATE_BYTES if self.path == "/validate" else 64 * 1024)
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
        if not isinstance(rules, list) or not all(isinstance(r, str) and RULE_FILE.fullmatch(r) for r in rules):
            return self._send(400, {"detail": "rules must be _capa_rules/<32 hex>.yml paths"})
        try:
            path = in_store(f"{sha256}.bin")
            rule_paths = [p for p in (in_store(r) for r in rules) if os.path.isfile(p)]
        except ValueError:
            return self._send(400, {"detail": "Not a path in the sample store"})
        if not _slots.acquire(blocking=False):
            return self._send(503, {"detail": "capa is busy with another sample; try again later"})
        try:
            self._send(200, analyze(path, timeout=TIMEOUT, extra_rules=rule_paths))
        except CapaTimeout as exc:
            self._send(504, {"detail": str(exc)})
        except CapaError as exc:
            self._send(422, {"detail": str(exc)})
        finally:
            _slots.release()

    def log_message(self, fmt: str, *args) -> None:
        print(f"{self.address_string()} {fmt % args}", flush=True)


if __name__ == "__main__":
    if not TOKEN or TOKEN.startswith("please-change-this"):
        # An empty token, or the public one of the example file, protects nothing.
        raise SystemExit("CAPA_TOKEN is not set (or is the example value): refusing to start.")
    print(f"nik-capa listening on :{PORT} (capa {capa_version()}, samples in {SAMPLE_DIR})", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()

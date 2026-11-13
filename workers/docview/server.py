"""HTTP front of the Nik document viewer worker (standard library only).

    GET  /health                    -> {"status": "ok"}
    POST /render {"name", "data"}   -> the first pages as PNG (``nik_docview.render``)
    POST /pst    (the file as body) -> the mailbox as one mbox (``readpst``)

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
import shutil
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from nik_docview import PreviewError, render

TOKEN = os.environ.get("DOCVIEW_TOKEN", "")
PORT = int(os.environ.get("DOCVIEW_PORT", "8720"))
MAX_JOBS = int(os.environ.get("DOCVIEW_MAX_JOBS", "2"))
MAX_BYTES = int(os.environ.get("DOCVIEW_MAX_MB", "50")) * 1024 * 1024
_slots = threading.BoundedSemaphore(MAX_JOBS)
PST_MAX_BYTES = int(os.environ.get("DOCVIEW_PST_MAX_MB", "500")) * 1024 * 1024
PST_TIMEOUT = int(os.environ.get("DOCVIEW_PST_TIMEOUT", "600"))


def pst_to_mbox(source: str, folder: str) -> list[str]:
    """Run ``readpst`` on the file: one mbox per folder of the mailbox, written
    under ``folder``. Returns their paths. The file is hostile input: readpst
    runs unprivileged, with no network, and is killed after ``PST_TIMEOUT``."""
    try:
        done = subprocess.run(  # noqa: S603 - fixed arguments, no shell
            ["readpst", "-q", "-r", "-o", folder, source],  # noqa: S607
            capture_output=True,
            timeout=PST_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise PreviewError("The PST took too long to read.") from exc
    except OSError as exc:
        raise PreviewError("readpst is not installed in the document worker.") from exc
    found = []
    for root, _dirs, files in os.walk(folder):
        found += [os.path.join(root, name) for name in sorted(files) if os.path.getsize(os.path.join(root, name)) > 0]
    if done.returncode != 0 and not found:
        raise PreviewError("Not an Outlook PST file, or it is damaged.")
    if not found:
        raise PreviewError("The PST holds no message.")
    return sorted(found)


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

    def _pst(self) -> None:
        """The PST comes as the request body and the mbox goes back as the
        response body, both streamed: neither is held in memory."""
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length <= 0:
            return self._send(400, {"detail": "Empty file"})
        if length > PST_MAX_BYTES:
            return self._send(413, {"detail": f"The PST exceeds {PST_MAX_BYTES // (1024 * 1024)} MB"})
        if not _slots.acquire(blocking=False):
            return self._send(503, {"detail": "The document worker is busy; try again later"})
        work = tempfile.mkdtemp(prefix="nik-pst-")
        try:
            source = os.path.join(work, "mailbox.pst")
            with open(source, "wb") as out:
                left = length
                while left > 0:
                    chunk = self.rfile.read(min(1024 * 1024, left))
                    if not chunk:
                        break
                    out.write(chunk)
                    left -= len(chunk)
            output = os.path.join(work, "out")
            os.mkdir(output)
            parts = pst_to_mbox(source, output)
            os.unlink(source)
            self.send_response(200)
            self.send_header("Content-Type", "application/mbox")
            self.send_header("Content-Length", str(sum(os.path.getsize(p) + 1 for p in parts)))
            self.end_headers()
            for part in parts:
                with open(part, "rb") as handle:
                    shutil.copyfileobj(handle, self.wfile, 1024 * 1024)
                self.wfile.write(b"\n")  # a blank line before the next folder's first "From "
        except PreviewError as exc:
            self._send(422, {"detail": str(exc)})
        finally:
            shutil.rmtree(work, ignore_errors=True)
            _slots.release()

    def do_POST(self) -> None:  # noqa: N802
        if self.path not in ("/render", "/pst"):
            return self._send(404, {"detail": "Not found"})
        if not (TOKEN and hmac.compare_digest(self.headers.get("X-Docview-Token", ""), TOKEN)):
            return self._send(401, {"detail": "Missing or wrong docview token"})
        if self.path == "/pst":
            return self._pst()
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

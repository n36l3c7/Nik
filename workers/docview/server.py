"""HTTP front of the Nik document viewer worker (standard library only).

    GET  /health                    -> {"status": "ok"}
    POST /render {"name", "data"}   -> the first pages as PNG (``nik_docview.render``)
    POST /pst    (the file as body) -> the mailbox as one mbox (``readpst``)

``data`` is the file, base64-encoded. Only the Nik backend talks to this
server, on the internal network, with the shared ``X-Docview-Token``. At most
``MAX_JOBS`` conversions run at once; extra requests get 503.

A PST is converted on disk when the worker has a work directory (``/work``,
a volume of its own in Compose): the file and the mbox made from it do not
have to fit in memory. Before it starts, the worker checks that the disk has
room for both (about two and a half times the PST) and answers 507 when it
does not. Without a work directory it converts in ``/tmp``, which is memory,
and takes only a PST small enough for that.
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


TOKEN = secret("DOCVIEW_TOKEN")
PORT = int(os.environ.get("DOCVIEW_PORT", "8720"))
MAX_JOBS = int(os.environ.get("DOCVIEW_MAX_JOBS", "2"))
MAX_BYTES = int(os.environ.get("DOCVIEW_MAX_MB", "50")) * 1024 * 1024
_slots = threading.BoundedSemaphore(MAX_JOBS)
PST_MAX_BYTES = int(os.environ.get("DOCVIEW_PST_MAX_MB", "4096")) * 1024 * 1024
PST_TIMEOUT = int(os.environ.get("DOCVIEW_PST_TIMEOUT", "3600"))
# Where a PST is converted when it is there and can be written: a disk, not memory.
WORK_DIR = os.environ.get("DOCVIEW_WORK_DIR", "/work")
# Without it the conversion happens in /tmp (memory): only a PST this small is taken.
PST_TMP_MAX_BYTES = int(os.environ.get("DOCVIEW_PST_TMP_MAX_MB", "500")) * 1024 * 1024
# The PST itself, the mbox made from it (about as large), and some room to spare.
PST_ROOM = 2.5


def work_dir() -> str | None:
    """The work directory, when there is one that can be written to."""
    if WORK_DIR and os.path.isdir(WORK_DIR) and os.access(WORK_DIR, os.W_OK | os.X_OK):
        return WORK_DIR
    return None


def clear_work_dir() -> None:
    """What a conversion that was cut short left behind (the worker was stopped while it ran)."""
    folder = work_dir()
    if folder is None:
        return
    for name in os.listdir(folder):
        if name.startswith("nik-pst-"):
            shutil.rmtree(os.path.join(folder, name), ignore_errors=True)


def pst_refusal(length: int) -> tuple[int, str] | None:
    """Why a PST of this size is not taken, as (status, sentence); None when it can be converted."""
    if length <= 0:
        return 400, "Empty file"
    if length > PST_MAX_BYTES:
        return 413, f"The PST exceeds {PST_MAX_BYTES // (1024 * 1024)} MB"
    folder = work_dir()
    if folder is None:
        if length > PST_TMP_MAX_BYTES:
            return 413, (
                f"The document worker has no work volume: without it a PST is converted in memory and is "
                f"{PST_TMP_MAX_BYTES // (1024 * 1024)} MB at most"
            )
        return None
    free = shutil.disk_usage(folder).free
    needed = int(length * PST_ROOM)
    if free < needed:
        return 507, (
            f"Not enough room to convert this PST: it needs about {needed // (1024 * 1024)} MB "
            f"and {free // (1024 * 1024)} MB are free on the work volume"
        )
    return None


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
        refused = pst_refusal(length)
        if refused is not None:
            return self._send(refused[0], {"detail": refused[1]})
        if not _slots.acquire(blocking=False):
            return self._send(503, {"detail": "The document worker is busy; try again later"})
        work = tempfile.mkdtemp(prefix="nik-pst-", dir=work_dir())
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
    clear_work_dir()
    if not TOKEN or TOKEN.startswith("please-change-this"):
        # An empty token, or the public one of the example file, protects nothing.
        raise SystemExit("DOCVIEW_TOKEN is not set (or is the example value): refusing to start.")
    print(f"nik-docview listening on :{PORT}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()

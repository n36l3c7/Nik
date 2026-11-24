"""HTTP front of the Nik forensics worker (standard library only).

    GET  /health
    GET  /jobs/<name>                    -> whether the worker still has a job (``jobs.py``)
    PUT  /files/<sha256>.bin             -> the worker is given an original of host evidence (the body)
    POST /recognise {"name", "fileName"} -> {"parser", "version", "kind", "source"}, or 422
    POST /parse {"name", "fileName", "parser"?, "source"?, "params"?}
                                         -> the events of the parse, one JSON object per line, as they
                                            are found (``nik_forensics/context.py`` says which)
    POST /view {"name", "parser", "source", "loc"}
                                         -> the piece of the original a record came from (``view`` of the
                                            parser: ``nik_forensics/parsers/__init__.py`` says its shape);
                                            404 when the locator names nothing in the file, 422 for an
                                            unknown parser or a locator of the wrong shape (also one that
                                            lacks a member the parser needs), 504 after
                                            ``VIEW_SECONDS``

``name`` is the name the original was given under: ``<sha256>.bin``, checked
against what was received (``given.py``). Only the Nik backend talks to this
server, on the internal network, with the shared ``X-Forensics-Token``. At
most ``FORENSICS_MAX_JOBS`` parses run at once; extra requests get 503.

The worker does not see the store of files, which is sealed: the backend
gives it the file a job needs. A request about a file the worker does not
hold is answered ``409`` with the name that is ``missing``; the backend sends
it and asks again. What is given sits in the work volume (``/work``), **in
clear**, until nobody asked for it for ``FORENSICS_FILE_IDLE`` seconds, and at
the latest until the worker starts again (it empties the place when it starts).

A view is a short process of its own too (``view_job.py``), under its own small bound
(``VIEW_SLOTS`` at once), so that it never waits behind a long parse.

**Every parse is a process of its own** (``run_job.py``), with its memory and
its CPU time bounded: a file made to crash a parser ends that process. The
answer of ``/parse`` is streamed: what the parser said before it stopped has
already been sent, and the last line then says how it stopped
(``{"t": "skip", "reason": "the parser stopped", …}``) instead of ``end``. The
backend keeps what came and reports the file as read in part.

On SIGTERM the worker stops taking requests, lets the parses it runs go on for
``FORENSICS_STOP_GRACE`` seconds, and exits; one that is cut is handed out
again by the backend (``jobs.py``).
"""

from __future__ import annotations

import hmac
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import given
import jobs

TOKEN = given.secret("FORENSICS_TOKEN")
PORT = int(os.environ.get("FORENSICS_PORT", "8760"))
MAX_JOBS = int(os.environ.get("FORENSICS_MAX_JOBS", "2"))
STOP_GRACE = float(os.environ.get("FORENSICS_STOP_GRACE", "20"))
JOB_SECONDS = int(os.environ.get("FORENSICS_JOB_SECONDS", "21600"))
HERE = os.path.dirname(os.path.abspath(__file__))
RUNNER = os.path.join(HERE, "run_job.py")
VIEWER = os.path.join(HERE, "view_job.py")
VIEW_SLOTS = 4
VIEW_SECONDS = 30
# What the answer of a view may weigh, whatever the child printed.
VIEW_MAX_BYTES = 512 * 1024
_NAME = re.compile(r"^[0-9a-f]{64}\.bin$")
_slots = threading.BoundedSemaphore(MAX_JOBS)
_view_slots = threading.BoundedSemaphore(VIEW_SLOTS)
JOBS = jobs.Jobs()
GIVEN = given.Given(
    os.environ.get("FORENSICS_WORK_DIR", "/work"),
    (re.compile(r"[0-9a-f]{64}\.bin"),),
    max_bytes=int(os.environ.get("FORENSICS_FILES_MB", "49152")) * 1024 * 1024,
    idle=float(os.environ.get("FORENSICS_FILE_IDLE", "900")),
)
# What a job is started with: nothing of the worker's own environment but what it needs to run.
_JOB_ENV = ("PATH", "LANG", "LC_ALL", "FORENSICS_JOB_MEMORY_MB", "FORENSICS_JOB_SECONDS", "TMPDIR")


class Refused(Exception):
    def __init__(self, status: int, detail: str, **more) -> None:
        super().__init__(detail)
        self.status, self.body = status, {"detail": detail, **more}


def job_command(path: str, request: dict) -> list[str]:
    asked = {key: request.get(key) for key in ("fileName", "parser", "source", "params") if request.get(key)}
    return [sys.executable, "-I", RUNNER, path, json.dumps(asked)]


def check_view(body: dict) -> None:
    """The shape of a ``/view`` request, before the worker looks for the file: 422 when it is not one."""
    parser = body.get("parser")
    if not isinstance(parser, str) or parser.replace("-", "_") not in _parser_names():
        raise Refused(422, "parser is not the name of a parser of the worker")
    if not isinstance(body.get("source", ""), (str, type(None))) or len(str(body.get("source") or "")) > 200:
        raise Refused(422, "source must be a text of at most 200 characters")
    loc = body.get("loc")
    if not isinstance(loc, dict) or len(loc) > 20:
        raise Refused(422, "loc must be an object of at most 20 members")
    for key, value in loc.items():
        if len(key) > 40 or not (value is None or isinstance(value, (bool, int, str))) or len(str(value)) > 1024:
            raise Refused(422, "loc holds numbers and short texts only")


def _parser_names() -> tuple[str, ...]:
    from nik_forensics import parsers

    return parsers.NAMES


def job_env() -> dict[str, str]:
    return {name: os.environ[name] for name in _JOB_ENV if name in os.environ}


def how_it_stopped(code: int, timed_out: bool) -> dict | None:
    """The last line of a parse that did not end by itself; None when it did (exit 0), or when the
    job said why itself before it left (1: the parser raised, 3: no parser reads the file)."""
    if timed_out:
        detail = f"it ran for more than {JOB_SECONDS} seconds"
    elif code in (0, 1, 3):
        return None
    elif code < 0:
        try:
            detail = f"it was ended by the signal {signal.Signals(-code).name}"
        except ValueError:
            detail = f"it was ended by the signal {-code}"
        if -code in (signal.SIGKILL, signal.SIGSEGV, signal.SIGXCPU, signal.SIGABRT):
            detail += " (out of the memory or the time a job may use, or a crash of the library that reads this format)"
    else:
        detail = f"it left with the status {code}"
    return {"t": "skip", "reason": "the parser stopped", "offset": None, "length": None, "lost": 0, "detail": detail}


class Handler(BaseHTTPRequestHandler):
    server_version = "nik-forensics"
    protocol_version = "HTTP/1.1"  # the answer of /parse is sent in chunks, as it is made

    def _send(self, status: int, payload) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        return bool(TOKEN) and hmac.compare_digest(self.headers.get("X-Forensics-Token", ""), TOKEN)

    def do_GET(self) -> None:  # noqa: N802 - http.server naming
        if self.path == "/health":
            return self._send(200, {"status": "ok", "started": JOBS.started})
        if not self._authorized():
            return self._send(401, {"detail": "Missing or wrong forensics token"})
        self._send(*(JOBS.answer(self.path) or (404, {"detail": "Not found"})))

    def do_PUT(self) -> None:  # noqa: N802
        given.take_request(self, GIVEN, self._authorized())

    def _request(self, validate=None) -> tuple[dict, str]:
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length > 1024 * 1024:
            raise Refused(413, "Request too large")
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            raise Refused(400, "Invalid request body") from None
        name = str(body.get("name") or "") if isinstance(body, dict) else ""
        if not _NAME.fullmatch(name):
            raise Refused(400, "name must be <sha256>.bin")
        if validate is not None:
            validate(body)
        path = GIVEN.path(name)
        if path is None:
            raise Refused(409, "The worker does not hold this file", missing=[name])
        return body, path

    def do_POST(self) -> None:  # noqa: N802
        if self.path not in ("/parse", "/recognise", "/view"):
            return self._send(404, {"detail": "Not found"})
        if not self._authorized():
            return self._send(401, {"detail": "Missing or wrong forensics token"})
        try:
            body, path = self._request(check_view if self.path == "/view" else None)
        except Refused as refused:
            return self._send(refused.status, refused.body)
        except (ValueError, TypeError) as error:
            return self._send(400, {"detail": f"Invalid request: {error}"})
        name = str(body["name"])
        if self.path == "/recognise":
            return self._recognise(path, name, body)
        if self.path == "/view":
            return self._view(path, name, body)
        if not _slots.acquire(blocking=False):
            return self._send(503, {"detail": "The forensics worker is busy; try again later"})
        try:
            with GIVEN.hold([name]), JOBS.running(self.headers.get(jobs.HEADER)) as say:
                self._parse(path, body, say)
        finally:
            _slots.release()

    def _recognise(self, path: str, name: str, body: dict) -> None:
        """Which parser reads the file: asked of a job too, since looking is already reading."""
        code = (
            "import json,sys\n"
            f"sys.path.insert(0, {HERE!r})\n"
            "from nik_forensics import parsers\n"
            "try:\n"
            "    m, s = parsers.recognise(sys.argv[1], sys.argv[2])\n"
            "    print(json.dumps({'parser': m.NAME, 'version': m.VERSION, 'kind': m.KIND, 'source': s}))\n"
            "except parsers.UnknownParser as error:\n"
            "    print(json.dumps({'detail': str(error)})); sys.exit(3)\n"
        )
        with GIVEN.hold([name]):
            try:
                done = subprocess.run(  # noqa: S603 - fixed command, the file is an argument
                    [sys.executable, "-I", "-c", code, path, str(body.get("fileName") or "")[:500]],
                    capture_output=True,
                    timeout=120,
                    env=job_env(),
                    check=False,
                )
            except subprocess.TimeoutExpired:
                return self._send(422, {"detail": "The file could not be recognised in two minutes"})
        try:
            said = json.loads(done.stdout.decode("utf-8", "replace").strip().splitlines()[-1])
        except (ValueError, IndexError):
            return self._send(422, {"detail": "The file could not be recognised"})
        self._send(200 if done.returncode == 0 else 422, said)

    def _view(self, path: str, name: str, body: dict) -> None:
        """The piece of the original a record came from: asked of a child that reads the file around the place."""
        if not _view_slots.acquire(blocking=False):
            return self._send(503, {"detail": "The forensics worker is busy with views; try again later"})
        try:
            asked = {"parser": body["parser"], "source": body.get("source") or "", "loc": body["loc"]}
            with GIVEN.hold([name]):
                job = subprocess.Popen(  # noqa: S603 - fixed command, the file and the request are arguments
                    [sys.executable, "-I", VIEWER, path, json.dumps(asked)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    stdin=subprocess.DEVNULL,
                    env=job_env(),
                    cwd="/",
                )
                timed_out = threading.Event()

                def stop() -> None:
                    timed_out.set()
                    job.kill()

                clock = threading.Timer(VIEW_SECONDS, stop)
                clock.daemon = True
                clock.start()
                try:
                    out = job.stdout.read(VIEW_MAX_BYTES + 1)
                    if len(out) > VIEW_MAX_BYTES:
                        job.kill()
                    code = job.wait()
                finally:
                    clock.cancel()
                    if job.poll() is None:
                        job.kill()
                    job.wait()
                    job.stdout.close()
        finally:
            _view_slots.release()
        if timed_out.is_set():
            return self._send(504, {"detail": f"The view took more than {VIEW_SECONDS} seconds"})
        if len(out) > VIEW_MAX_BYTES:
            return self._send(502, {"detail": "The view is larger than the worker sends"})
        try:
            said = json.loads(out.decode("utf-8", "replace"))
        except ValueError:
            said = None
        if code == 0 and isinstance(said, dict):
            return self._send(200, said)
        if code == 5 and isinstance(said, dict):
            return self._send(422, {"detail": str(said.get("detail") or "The locator is of the wrong shape")})
        if code == 4 and isinstance(said, dict):
            return self._send(404, {"detail": str(said.get("detail") or "The file holds nothing there")})
        self._send(
            500,
            {
                "detail": "The view failed"
                + (f": {said['detail']}" if isinstance(said, dict) and said.get("detail") else "")
            },
        )

    def _chunk(self, data: bytes) -> None:
        self.wfile.write(f"{len(data):x}\r\n".encode("ascii") + data + b"\r\n")

    def _parse(self, path: str, body: dict, say) -> None:
        say("starting")
        job = subprocess.Popen(  # noqa: S603 - fixed command, the file and the request are arguments
            job_command(path, body),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            env=job_env(),
            cwd="/",
        )
        timed_out = threading.Event()

        def stop() -> None:
            timed_out.set()
            job.kill()

        clock = threading.Timer(JOB_SECONDS + 60, stop)
        clock.daemon = True
        clock.start()
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        sent = 0
        try:
            held: list[bytes] = []
            size = 0
            last = time.monotonic()
            for line in job.stdout:
                held.append(line)
                size += len(line)
                sent += 1
                # Sent in pieces of a quarter of a megabyte, or every second: the backend sees the
                # records as they are found, and a parser that says little is not taken for a dead one.
                if size >= 256 * 1024 or time.monotonic() - last >= 1.0:
                    self._chunk(b"".join(held))
                    held, size, last = [], 0, time.monotonic()
                    say(f"{sent} records and notes read")
            if held:
                self._chunk(b"".join(held))
            code = job.wait()
            end = how_it_stopped(code, timed_out.is_set())
            if end is not None:
                self._chunk(json.dumps(end, separators=(",", ":")).encode("utf-8") + b"\n")
            self._chunk(b"")
        except (BrokenPipeError, ConnectionError):
            # The backend went away: nobody reads this parse any more.
            self.close_connection = True
        finally:
            clock.cancel()
            if job.poll() is None:
                job.kill()
            job.wait()
            job.stdout.close()

    def log_message(self, fmt: str, *args) -> None:
        print(f"{self.address_string()} {fmt % args}", flush=True)


def _expire() -> None:
    while True:
        time.sleep(60)
        GIVEN.expire()


if __name__ == "__main__":
    if not TOKEN or TOKEN.startswith("please-change-this"):
        # An empty token, or the public one of the example file, protects nothing.
        raise SystemExit("FORENSICS_TOKEN is not set (or is the example value): refusing to start.")
    GIVEN.clear()
    print(f"nik-forensics listening on :{PORT}", flush=True)
    threading.Thread(target=_expire, name="expire", daemon=True).start()
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)  # noqa: S104 - the internal network of the stack
    # A request in flight is not cut by the stop of the server: its thread goes on for the grace.
    server.daemon_threads = True
    signal.signal(signal.SIGTERM, lambda *_: jobs.stop_politely(server))
    signal.signal(signal.SIGINT, lambda *_: jobs.stop_politely(server))
    server.serve_forever()
    jobs.drain(JOBS, STOP_GRACE)

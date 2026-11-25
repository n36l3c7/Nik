"""HTTP front of the Nik forensics worker (standard library only).

    GET  /health                         -> {"status", "started", "sigma"} (``sigma``: the version of the evaluator)
    GET  /jobs/<name>                    -> whether the worker still has a job (``jobs.py``)
    PUT  /files/<sha256>.bin             -> the worker is given an original of host evidence (the body)
    PUT  /rules/<sha256>                 -> the worker is given a set of Sigma rules (the body: one JSON rule per line;
                                            its SHA-256 is the name); {"rules": n}, 400 when it is not that
    POST /recognise {"name", "fileName"} -> {"parser", "version", "kind", "source"}; {"container": "zip", "kind":
                                            "collection", "source": "collection.zip"} for a zip; 422 {"detail"} for a
                                            file nothing reads (``refused`` is true for a kind of file Nik can say how
                                            to convert: a disk image, a ``.plaso`` file)
    POST /parse {"name", "fileName", "parser"?, "source"?, "params"?, "rules"?}
                                         -> the events of the parse, one JSON object per line, as they
                                            are found (``nik_forensics/context.py`` says which). ``rules``
                                            is the SHA-256 of a rule set: the records are matched against it
                                            and the matches come as ``det`` lines; ``params.hours`` are the
                                            working hours (``nik_forensics/sigma/hours.py``)
    POST /view {"name", "parser", "source", "loc"}
                                         -> the piece of the original a record came from (``view`` of the
                                            parser: ``nik_forensics/parsers/__init__.py`` says its shape);
                                            404 when the locator names nothing in the file, 422 for an
                                            unknown parser or a locator of the wrong shape (also one that
                                            lacks a member the parser needs), 504 after
                                            ``VIEW_SECONDS``
    POST /unpack {"name", "fileName"?, "total"?}
                                         -> a collection (a zip, given as ``<sha256>.bin``) unpacked in a process of
                                            its own
                                            (``unpack_job.py``, ``nik_forensics/triage.py``): one line per member
                                            ``{"t": "member", "n", "path", "size", "sha256", "kind", "source", "parser",
                                            "executable", "kept", "host", "username", "profile", "skip"?}`` and a last
                                            ``{"t": "end", "members", "bytes", "recognised", "skipped", ...}``.
                                            A member a parser reads is kept as a given file (``<sha256>.bin``), so the
                                            parse that follows needs no transfer
    POST /member {"sha256", "path", "name"?, "total"?}
                                         -> the bytes of one member of a collection: from the files the worker holds
                                            when
                                            it kept it, else taken out of the zip ``name`` (409 when the zip is missing)
    POST /sigma/check {"documents": [{"source"}]}
                                         -> the rules each text holds and the errors in it, with lines
                                            (``nik_forensics/sigma/check.py``)
    POST /sigma/try {"rules", "hours"?, "records"}
                                         -> {"matches", "notEvaluated"}: the rules run over the records, which come
                                            in time order (at most 20,000); ``sigma_job.py`` says the shapes
    POST /find {"sha256", "needle", "as", "from"?, "limit"?}
                                         -> where a text (as UTF-8 and UTF-16LE, any case) or some bytes (hex)
                                            are in the original, from an offset: ``{"matches", "next",
                                            "scanned", "cut"}`` (``nik_forensics/finding.py``); 400 for a bad
                                            needle. After ``FIND_STOP_SECONDS`` it answers what it found with ``next``

``name`` is the name the original was given under: ``<sha256>.bin``, checked
against what was received (``given.py``). A rule set is given the same way (``rules.py``): a ``/parse`` that
names one the worker does not hold is answered ``409`` with ``missingRules`` (the digest) and ``missing``
(the files, possibly none). Only the Nik backend talks to this
server, on the internal network, with the shared ``X-Forensics-Token``. At
most ``FORENSICS_MAX_JOBS`` parses run at once; extra requests get 503.

The worker does not see the store of files, which is sealed: the backend
gives it the file a job needs. A request about a file the worker does not
hold is answered ``409`` with the name that is ``missing``; the backend sends
it and asks again. What is given sits in the work volume (``/work``), **in
clear**, until nobody asked for it for ``FORENSICS_FILE_IDLE`` seconds, and at
the latest until the worker starts again (it empties the place when it starts).

A check or a try of Sigma rules is a short process of its own as well (``sigma_job.py``, ``SIGMA_SLOTS`` at once):
the YAML of a rule is read there, never in the server.

A view is a short process of its own too (``view_job.py``), under its own small bound
(``VIEW_SLOTS`` at once), so that it never waits behind a long parse; so is a search (``find_job.py``,
``FIND_SLOTS``).

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
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import given
import jobs
import rules
from nik_forensics.sigma import ENGINE_VERSION

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
FINDER = os.path.join(HERE, "find_job.py")
FIND_SLOTS = 2
FIND_SECONDS = 30
# The search stops reading by itself this long after it began, and answers with where to go on from.
FIND_STOP_SECONDS = 24
FIND_MAX_BYTES = 256 * 1024
UNPACKER = os.path.join(HERE, "unpack_job.py")
# The unpacked size of a collection the worker accepts (the API says its own, never more than this), in megabytes.
COLLECTION_MB = int(os.environ.get("FORENSICS_COLLECTION_MB", "20480"))
MEMBER_SLOTS = 2
SIGMA_JOB = os.path.join(HERE, "sigma_job.py")
SIGMA_SLOTS = 2
SIGMA_SECONDS = int(os.environ.get("FORENSICS_SIGMA_SECONDS", "120"))
SIGMA_MAX_BYTES = 64 * 1024 * 1024
# What the body of a request may weigh, by route (the rest: a megabyte).
BODY_LIMITS = {"/sigma/check": 16 * 1024 * 1024, "/sigma/try": 64 * 1024 * 1024}
_NAME = re.compile(r"^[0-9a-f]{64}\.bin$")
_slots = threading.BoundedSemaphore(MAX_JOBS)
_view_slots = threading.BoundedSemaphore(VIEW_SLOTS)
_find_slots = threading.BoundedSemaphore(FIND_SLOTS)
_sigma_slots = threading.BoundedSemaphore(SIGMA_SLOTS)
_member_slots = threading.BoundedSemaphore(MEMBER_SLOTS)
JOBS = jobs.Jobs()
GIVEN = given.Given(
    os.environ.get("FORENSICS_WORK_DIR", "/work"),
    (re.compile(r"[0-9a-f]{64}\.bin"),),
    max_bytes=int(os.environ.get("FORENSICS_FILES_MB", "49152")) * 1024 * 1024,
    idle=float(os.environ.get("FORENSICS_FILE_IDLE", "900")),
)
RULES = rules.RuleSets(os.environ.get("FORENSICS_WORK_DIR", "/work"))
# What a job is started with: nothing of the worker's own environment but what it needs to run.
_JOB_ENV = (
    "PATH",
    "LANG",
    "LC_ALL",
    "FORENSICS_JOB_MEMORY_MB",
    "FORENSICS_JOB_SECONDS",
    "FORENSICS_SIGMA_SECONDS",
    "FORENSICS_MEMBER_MB",
    "TMPDIR",
)


class Refused(Exception):
    def __init__(self, status: int, detail: str, **more) -> None:
        super().__init__(detail)
        self.status, self.body = status, {"detail": detail, **more}


def job_command(path: str, request: dict) -> list[str]:
    asked = {
        key: request.get(key) for key in ("fileName", "kind", "parser", "source", "params", "rules") if request.get(key)
    }
    if asked.get("rules"):  # the job is given the file of the set, not its name
        asked["rules"] = RULES.path(str(asked["rules"])) or ""
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


def check_find(body: dict) -> None:
    """The shape of a ``/find`` request, before the worker looks for the file: 400 when it is not one."""
    from nik_forensics import finding

    try:
        finding.check(body.get("needle"), body.get("as", "text"), body.get("from", 0), body.get("limit", 100))
    except finding.BadNeedle as error:
        raise Refused(400, str(error)) from None


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
            return self._send(200, {"status": "ok", "started": JOBS.started, "sigma": ENGINE_VERSION})
        if not self._authorized():
            return self._send(401, {"detail": "Missing or wrong forensics token"})
        self._send(*(JOBS.answer(self.path) or (404, {"detail": "Not found"})))

    def do_PUT(self) -> None:  # noqa: N802
        if self.path.startswith("/rules/"):
            return self._take_rules()
        given.take_request(self, GIVEN, self._authorized())

    def _take_rules(self) -> None:
        """``PUT /rules/<sha256>``: a set of rules, kept until it is the least recently used of a few."""
        if not self._authorized():
            return self._send(401, {"detail": "Missing or wrong token"})
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            return self._send(411, {"detail": "The size of the rule set must be said (Content-Length)"})
        try:
            count = RULES.put(self.path[len("/rules/") :], self.rfile, length)
        except given.Refused as refused:
            self.close_connection = True  # what was not read of the body must not be taken for the next request
            return self._send(refused.status, {"detail": refused.detail})
        self._send(200, {"rules": count})

    def _request(self, validate=None) -> tuple[dict, str]:
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length > BODY_LIMITS.get(self.path, 1024 * 1024):
            raise Refused(413, "Request too large")
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            raise Refused(400, "Invalid request body") from None
        if self.path == "/find" and isinstance(body, dict):  # a search names the original by its hash
            sha256 = body.get("sha256")
            if not isinstance(sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", sha256):
                raise Refused(400, "sha256 must be 64 hexadecimal digits")
            body["name"] = f"{sha256}.bin"
        name = str(body.get("name") or "") if isinstance(body, dict) else ""
        if not _NAME.fullmatch(name):
            raise Refused(400, "name must be <sha256>.bin")
        if validate is not None:
            validate(body)
        path = GIVEN.path(name)
        digest = body.get("rules") if self.path == "/parse" else None
        if digest is not None and (not isinstance(digest, str) or not rules.DIGEST.fullmatch(digest)):
            raise Refused(400, "rules must be the SHA-256 of a rule set (64 hexadecimal digits)")
        if digest is not None and RULES.path(digest) is None:
            raise Refused(
                409,
                "The worker does not hold this rule set" + ("" if path is not None else " nor this file"),
                missing=[] if path is not None else [name],
                missingRules=digest,
            )
        if path is None:
            raise Refused(409, "The worker does not hold this file", missing=[name])
        return body, path

    def do_POST(self) -> None:  # noqa: N802
        paths = ("/parse", "/recognise", "/unpack", "/member", "/view", "/find", "/sigma/check", "/sigma/try")
        if self.path not in paths:
            return self._send(404, {"detail": "Not found"})
        if not self._authorized():
            return self._send(401, {"detail": "Missing or wrong forensics token"})
        if self.path.startswith("/sigma/"):
            return self._sigma()
        if self.path == "/member":
            return self._member()
        try:
            body, path = self._request({"/view": check_view, "/find": check_find}.get(self.path))
        except Refused as refused:
            return self._send(refused.status, refused.body)
        except (ValueError, TypeError) as error:
            return self._send(400, {"detail": f"Invalid request: {error}"})
        name = str(body["name"])
        if self.path == "/recognise":
            return self._recognise(path, name, body)
        if self.path == "/view":
            return self._view(path, name, body)
        if self.path == "/find":
            return self._find(path, name, body)
        if not _slots.acquire(blocking=False):
            return self._send(503, {"detail": "The forensics worker is busy; try again later"})
        try:
            with GIVEN.hold([name]), RULES.hold(body.get("rules")), JOBS.running(self.headers.get(jobs.HEADER)) as say:
                if self.path == "/unpack":
                    self._unpack(path, body, say)
                else:
                    self._parse(path, body, say)
        finally:
            _slots.release()

    def _sigma(self) -> None:
        """A check or a try of rules: asked of a child that reads the YAML and runs the rules, under a clock.
        The request goes to the child on its standard input; the answer is what the child printed."""
        try:
            length = int(self.headers.get("Content-Length", "0") or 0)
        except ValueError:
            return self._send(400, {"detail": "Invalid Content-Length"})
        if length > BODY_LIMITS[self.path]:
            self.close_connection = True
            return self._send(413, {"detail": "Request too large"})
        raw = self.rfile.read(length) or b"{}"
        try:
            json.loads(raw)
        except ValueError:
            return self._send(400, {"detail": "Invalid request body"})
        if not _sigma_slots.acquire(blocking=False):
            return self._send(503, {"detail": "The forensics worker is busy with rules; try again later"})
        try:
            try:
                done = subprocess.run(  # noqa: S603 - fixed command, the request is its input
                    [sys.executable, "-I", SIGMA_JOB, self.path.rsplit("/", 1)[1]],
                    input=raw,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    timeout=SIGMA_SECONDS,
                    env=job_env(),
                    cwd="/",
                    check=False,
                )
            except subprocess.TimeoutExpired:
                return self._send(504, {"detail": f"The rules took more than {SIGMA_SECONDS} seconds"})
        finally:
            _sigma_slots.release()
        if len(done.stdout) > SIGMA_MAX_BYTES:
            return self._send(502, {"detail": "The answer is larger than the worker sends"})
        try:
            said = json.loads(done.stdout.decode("utf-8", "replace"))
        except ValueError:
            said = None
        if done.returncode == 0 and isinstance(said, dict):
            return self._send(200, said)
        if done.returncode == 5 and isinstance(said, dict):
            return self._send(400, {"detail": str(said.get("detail") or "The request is not one")})
        if isinstance(said, dict) and said.get("detail"):
            detail = said["detail"]
        else:
            ended = how_it_stopped(done.returncode, False)
            detail = ended["detail"] if ended else "it left without an answer"
        self._send(500, {"detail": f"The rules could not be run: {detail}"})

    def _recognise(self, path: str, name: str, body: dict) -> None:
        """What the file is, asked of a job too, since looking is already reading (``triage.what_is``): a parser
        and its source, a zip (a collection), or a sentence for a file Nik does not read."""
        code = (
            "import json,sys\n"
            f"sys.path.insert(0, {HERE!r})\n"
            "from nik_forensics import triage\n"
            "print(json.dumps(triage.what_is(sys.argv[1], sys.argv[2])))\n"
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
        if not isinstance(said, dict) or done.returncode != 0:
            return self._send(422, {"detail": "The file could not be recognised"})
        if said.get("refused"):
            return self._send(422, {"detail": said["refused"], "refused": True})
        if said.get("unknown"):
            return self._send(422, {"detail": said["unknown"]})
        self._send(200, said)

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

    def _find(self, path: str, name: str, body: dict) -> None:
        """Where a needle is in the original: asked of a child that reads the file in blocks, under a clock.
        The child stops reading by itself a little before the clock (``FIND_STOP_SECONDS``) and says where
        to go on from; a child that outlives the clock is killed, and that is a 504."""
        if not _find_slots.acquire(blocking=False):
            return self._send(503, {"detail": "The forensics worker is busy with searches; try again later"})
        try:
            asked = {
                "needle": body["needle"],
                "as": body.get("as", "text"),
                "from": body.get("from", 0),
                "limit": body.get("limit", 100),
                "seconds": min(FIND_STOP_SECONDS, FIND_SECONDS),
            }
            with GIVEN.hold([name]):
                job = subprocess.Popen(  # noqa: S603 - fixed command, the file and the request are arguments
                    [sys.executable, "-I", FINDER, path, json.dumps(asked)],
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

                clock = threading.Timer(FIND_SECONDS, stop)
                clock.daemon = True
                clock.start()
                try:
                    out = job.stdout.read(FIND_MAX_BYTES + 1)
                    if len(out) > FIND_MAX_BYTES:
                        job.kill()
                    code = job.wait()
                finally:
                    clock.cancel()
                    if job.poll() is None:
                        job.kill()
                    job.wait()
                    job.stdout.close()
        finally:
            _find_slots.release()
        if timed_out.is_set():
            return self._send(504, {"detail": f"The search took more than {FIND_SECONDS} seconds"})
        if len(out) > FIND_MAX_BYTES:
            return self._send(502, {"detail": "The answer of the search is larger than the worker sends"})
        try:
            said = json.loads(out.decode("utf-8", "replace"))
        except ValueError:
            said = None
        if code == 0 and isinstance(said, dict):
            return self._send(200, said)
        if code == 5 and isinstance(said, dict):
            return self._send(400, {"detail": str(said.get("detail") or "The needle cannot be searched for")})
        self._send(
            500,
            {
                "detail": "The search failed"
                + (f": {said['detail']}" if isinstance(said, dict) and said.get("detail") else "")
            },
        )

    def _chunk(self, data: bytes) -> None:
        self.wfile.write(f"{len(data):x}\r\n".encode("ascii") + data + b"\r\n")

    def _parse(self, path: str, body: dict, say) -> None:
        self._relay(job_command(path, body), say, JOB_SECONDS + 60)

    def _unpack(self, path: str, body: dict, say) -> None:
        """A collection unpacked by a child (``unpack_job.py``). What the child keeps lands in the folder of the files
        the worker holds, under the SHA-256 of each member; the lines say which."""
        try:
            limit = COLLECTION_MB * 1024 * 1024
            total = min(int(body.get("total") or limit), limit)
        except (TypeError, ValueError):
            return self._send(400, {"detail": "total must be a number of bytes"})
        try:
            # Room for what a zip of this size is likely to give, not for the most the caller allows: the job checks the
            # disk again before each member it writes.
            GIVEN.make_room(min(total, 8 * os.path.getsize(path) + 1024**3))
        except given.Refused as refused:
            return self._send(refused.status, {"detail": refused.detail})
        base = os.path.join(GIVEN.folder, "unpack")
        os.makedirs(base, exist_ok=True)
        scratch = tempfile.mkdtemp(dir=base)
        asked = {
            "total": total,
            "files": os.path.join(GIVEN.folder, "files"),
            "scratch": scratch,
            "fileName": str(body.get("fileName") or "")[:500],
        }

        def kept(line: bytes) -> None:
            # What the job keeps is marked as used now: the worker does not delete it as idle before the parse asks.
            if line.startswith(b'{"t":"member"') and b'"kept":true' in line:
                try:
                    GIVEN.path(f"{json.loads(line)['sha256']}.bin")
                except (ValueError, KeyError):
                    return

        try:
            command = [sys.executable, "-I", UNPACKER, "list", path, json.dumps(asked)]
            self._relay(command, say, JOB_SECONDS + 60, each=kept)
        finally:
            shutil.rmtree(scratch, ignore_errors=True)

    def _member(self) -> None:
        """The bytes of one member of a collection: the file the worker kept when it unpacked, else taken out of the
        zip again by a child. 409 names the zip when the worker does not hold it."""
        try:
            length = int(self.headers.get("Content-Length", "0") or 0)
            body = json.loads(self.rfile.read(length) if 0 < length <= 1024 * 1024 else b"{}")
        except ValueError:
            return self._send(400, {"detail": "Invalid request body"})
        if not isinstance(body, dict):
            return self._send(400, {"detail": "Invalid request body"})
        sha256, member = body.get("sha256"), body.get("path")
        if not isinstance(sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", sha256):
            return self._send(400, {"detail": "sha256 must be 64 hexadecimal digits"})
        kept = f"{sha256}.bin"
        with GIVEN.hold([kept]):
            held = GIVEN.path(kept)
            if held is not None:
                return self._send_file(held)
        name = str(body.get("name") or "")
        if not _NAME.fullmatch(name):
            return self._send(400, {"detail": "name must be <sha256>.bin"})
        if not isinstance(member, str) or not member or len(member) > 1000:
            return self._send(400, {"detail": "path must be the path of a member"})
        zipped = GIVEN.path(name)
        if zipped is None:
            return self._send(409, {"detail": "The worker does not hold this file", "missing": [name]})
        try:
            limit = COLLECTION_MB * 1024 * 1024
            total = min(int(body.get("total") or limit), limit)
        except (TypeError, ValueError):
            return self._send(400, {"detail": "total must be a number of bytes"})
        if not _member_slots.acquire(blocking=False):
            return self._send(503, {"detail": "The forensics worker is busy; try again later"})
        base = os.path.join(GIVEN.folder, "unpack")
        os.makedirs(base, exist_ok=True)
        scratch = tempfile.mkdtemp(dir=base)
        try:
            asked = {"path": member, "sha256": sha256, "out": os.path.join(scratch, "member"), "total": total}
            command = [sys.executable, "-I", UNPACKER, "member", zipped, json.dumps(asked)]
            with GIVEN.hold([name]):
                done = subprocess.run(  # noqa: S603 - fixed command, the zip and the request are arguments
                    command, capture_output=True, timeout=JOB_SECONDS, env=job_env(), cwd="/", check=False
                )
            try:
                said = json.loads(done.stdout.decode("utf-8", "replace").strip().splitlines()[-1])
            except (ValueError, IndexError):
                said = {}
            if done.returncode == 0 and os.path.isfile(asked["out"]):
                return self._send_file(asked["out"])
            detail = str(said.get("detail") or "") if isinstance(said, dict) else ""
            status = 404 if done.returncode == 4 else 422 if done.returncode == 2 else 500
            self._send(status, {"detail": detail or "The member could not be read"})
        except subprocess.TimeoutExpired:
            self._send(504, {"detail": "The member took too long to read"})
        finally:
            _member_slots.release()
            shutil.rmtree(scratch, ignore_errors=True)

    def _send_file(self, path: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(os.path.getsize(path)))
        self.end_headers()
        try:
            with open(path, "rb") as handle:
                while piece := handle.read(1024 * 1024):
                    self.wfile.write(piece)
        except (BrokenPipeError, ConnectionError):
            self.close_connection = True

    def _relay(self, command: list[str], say, seconds: float, each=None) -> None:
        """Run a job and send what it writes as it writes it, in chunks. ``each(line)`` sees each line it wrote."""
        say("starting")
        job = subprocess.Popen(  # noqa: S603 - fixed command, the file and the request are arguments
            command,
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

        clock = threading.Timer(seconds, stop)
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
                if each is not None:
                    each(line)
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
    RULES.clear()
    print(f"nik-forensics listening on :{PORT}", flush=True)
    threading.Thread(target=_expire, name="expire", daemon=True).start()
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)  # noqa: S104 - the internal network of the stack
    # A request in flight is not cut by the stop of the server: its thread goes on for the grace.
    server.daemon_threads = True
    signal.signal(signal.SIGTERM, lambda *_: jobs.stop_politely(server))
    signal.signal(signal.SIGINT, lambda *_: jobs.stop_politely(server))
    server.serve_forever()
    jobs.drain(JOBS, STOP_GRACE)

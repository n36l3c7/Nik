"""Waiting for a worker without mistaking a slow one for a dead one, or a restarted one for a slow one.

A long job (a disassembly, capa, a capture, a PST) is one request the
backend waits on. Three things can happen to the worker meanwhile, and a
deadline alone tells none of them apart:

- it is **slow**: the job is still there. Nothing is done but wait, up to the
  timeout the job always had;
- it **restarted** (an upgrade, a crash, the file brought it down): it knows
  nothing of the job, and its files are gone. The connection may break at
  once or hang;
- it is **cut off** or frozen: nothing answers.

So the backend names the job in the request (``X-Nik-Job``) and, while it
waits, asks the worker every few seconds whether it still has it
(``GET /jobs/<name>``, ``jobs.py`` in each worker). "Running" also carries how
far the job is, which goes to the screen. **Unknown job**, said twice, or no
answer at all for ``SILENT`` seconds, ends the wait with ``WorkerLost``; so
does a connection that broke when the worker, back up, says it does not know
the job.

``handed_out`` is the whole rule around one job: lost, it is counted against
the job (``work.py``), the worker is waited for, and the job is handed out
again with its file (the request asks the worker what it lacks, as always).
Lost ``work.MAX_ATTEMPTS`` times, the job is set aside: a file that takes the
worker down every time is not sent a fourth time.
"""

from __future__ import annotations

import contextvars
import json
import re
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any, TypeVar
from urllib.parse import quote

from .. import work

T = TypeVar("T")
HEADER = "X-Nik-Job"
ASK_EVERY = 5.0
ASK_TIMEOUT = 5.0
# A request that was just made may not be known to the worker yet (its body is still on the way).
GRACE = 20.0
SILENT = 90.0
# How long a worker that went away is waited for before the job fails with "cannot be reached".
BACK_WITHIN = 120.0
_NAME = re.compile(r"[^A-Za-z0-9:._-]")

# The name of the job the current thread is asking a worker for: the functions that make the request add it.
current_job: contextvars.ContextVar[str] = contextvars.ContextVar("nik_worker_job", default="")


class WorkerLost(Exception):
    """The worker no longer has the job: it restarted, or stopped answering."""


class SetAside(Exception):
    """The job was lost too many times and is not handed out again: the sentence to show."""


def job_name(kind: str, ref: str, attempt: int) -> str:
    return _NAME.sub("-", f"{kind}:{ref}:{attempt}")[:160]


def headers() -> dict[str, str]:
    """What a request to a worker carries besides its token: the name of the job, when it has one."""
    job = current_job.get()
    return {HEADER: job} if job else {}


def ask(base_url: str, header: str, token: str, job: str, timeout: float = ASK_TIMEOUT) -> tuple[str, str]:
    """Ask the worker about a job: (``running`` | ``finished`` | ``unknown`` | ``alive`` | "", how
    far it is). ``alive`` is the answer of a worker that answers and does not know the question (an
    image from before 6.9): it is there, which is all that can be said. "" is no answer at all."""
    request = urllib.request.Request(f"{base_url}/jobs/{quote(job, safe='')}", headers={header: token})  # noqa: S310
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - operator-configured URL
            answer = json.loads(response.read() or b"{}")
            return str(answer.get("state") or ""), str(answer.get("progress") or "")
    except urllib.error.HTTPError as error:
        try:
            answer = json.loads(error.read() or b"{}")
        except ValueError:
            answer = {}
        if error.code == 404 and isinstance(answer, dict) and answer.get("unknown"):
            return "unknown", ""
        return "alive", ""
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return "", ""


def watched(
    call: Callable[[], T],
    job: str,
    asking: Callable[[], tuple[str, str]],
    *,
    on_progress: Callable[[str], None] | None = None,
    every: float = ASK_EVERY,
    grace: float = GRACE,
    silent: float = SILENT,
    back_within: float = BACK_WITHIN,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> T:
    """Make ``call`` (the request of the job named ``job``) and wait for it, asking the worker
    meanwhile (``asking()``). Returns what the call gives or raises what it raises; raises
    ``WorkerLost`` when the worker lost the job."""
    box: dict[str, Any] = {}
    done = threading.Event()
    context = contextvars.copy_context()

    def run() -> None:
        try:
            current_job.set(job)
            box["value"] = call()
        except BaseException as error:  # noqa: BLE001 - handed to the thread that waits
            box["error"] = error
        finally:
            done.set()

    threading.Thread(target=lambda: context.run(run), name="nik-worker-call", daemon=True).start()
    started = clock()
    unknown, quiet_since = 0, None
    while not done.wait(every):
        state, progress = asking()
        if state in ("running", "finished", "alive"):
            unknown, quiet_since = 0, None
            if on_progress is not None and state == "running":
                on_progress(progress)
        elif state == "unknown":
            quiet_since = None
            if clock() - started > grace:
                unknown += 1
                if unknown >= 2:
                    raise WorkerLost("The worker was restarted while it did this: it no longer has the job")
        else:
            quiet_since = clock() if quiet_since is None else quiet_since
            if clock() - quiet_since >= silent:
                raise WorkerLost(f"The worker did not answer for {int(silent)} seconds while it did this")
    if "error" not in box:
        return box["value"]
    error = box["error"]
    if not getattr(error, "unreachable", False):
        raise error
    # The connection broke. A worker that is back and knows nothing of the job was restarted under
    # it; one that does not come back is down, which is the error the call gave.
    waited_from = clock()
    while True:
        state, _progress = asking()
        if state == "unknown":
            raise WorkerLost("The worker was restarted while it did this: it no longer has the job") from None
        if state or clock() - waited_from >= back_within:
            raise error
        sleep(min(every, 2.0))


def back(base_url: str, within: float = BACK_WITHIN, sleep: Callable[[float], None] = time.sleep) -> bool:
    """Wait for a worker that went away to answer its health check again, ``within`` seconds at most."""
    waited = 0.0
    while True:
        try:
            with urllib.request.urlopen(f"{base_url}/health", timeout=ASK_TIMEOUT) as response:  # noqa: S310
                if response.status == 200:
                    return True
        except (urllib.error.URLError, TimeoutError, OSError, ValueError):
            pass
        if waited >= within:
            return False
        sleep(3.0)
        waited += 3.0


def handed_out(
    claim: work.Claim,
    call: Callable[[], T],
    base_url: str,
    header: str,
    token: str,
    *,
    what: str,
    watch: Callable[..., T] = watched,
    **timing: Any,
) -> T:
    """Do one job on a worker, handing it out again when the worker loses it; ``what`` is the job
    in a sentence ("the disassembly of this file"). Raises ``SetAside`` when it was lost
    ``work.MAX_ATTEMPTS`` times; otherwise returns or raises as ``call`` does."""
    while True:
        job = job_name(claim.kind, claim.ref, claim.attempts)
        try:
            return watch(
                call,
                job,
                lambda name=job: ask(base_url, header, token, name),
                on_progress=claim.progress,
                **timing,
            )
        except WorkerLost as lost:
            if claim.attempts >= work.MAX_ATTEMPTS:
                sentence = (
                    f"Set aside: the worker stopped {claim.attempts} times while it did {what}, and it is not "
                    "sent again by itself. The file may be what stops the worker; ask for it again to try once more"
                )
                claim.set_aside(sentence)
                raise SetAside(sentence) from None
            claim.interrupted(str(lost))
            claim.resumed()

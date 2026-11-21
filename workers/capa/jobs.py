"""The jobs a worker is doing, so that the backend can ask whether it still has one.

A worker answers a request when the work is done: the backend waits on the
connection, for minutes on a large file. That alone cannot tell a worker
that is slow from one that was restarted, or cut off, while the backend
waited. So the backend names each long request (the header ``X-Nik-Job``) and
may ask, while it waits:

    GET /jobs/<name>     the same token as every request

    200 {"state": "running", "seconds": 42.0, "progress": "decompiling"}
    200 {"state": "finished", "seconds": 61.3, "progress": ""}
    404 {"detail": "Unknown job", "unknown": true, "started": 1795000000.0}

**Unknown job** is the answer of a worker that does not have the job: it was
restarted since (everything a worker knows is in its memory, and its files
are deleted when it starts), or the request never arrived. It is said at
once, not after a timeout: the backend hands the job out again, with its
file. ``started`` is when this worker process started. A job that ended is
remembered for ``KEPT`` seconds as finished, so that a question that crosses
the answer is not taken for a restart.

``progress`` is a few words the job says of itself where it has something to
say; the backend shows them beside "running".

This file is the same in every worker that does long jobs (analyzer, capa,
pcap, docview): each image is built from its own folder and holds its own
copy. Standard library only.
"""

from __future__ import annotations

import re
import threading
import time
from contextlib import contextmanager

HEADER = "X-Nik-Job"
NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:._-]{0,159}$")
PATH = re.compile(r"^/jobs/([A-Za-z0-9][A-Za-z0-9:._-]{0,159})$")
KEPT = 120.0
MAX_KEPT = 500


class Jobs:
    """The named jobs of this worker process: in memory, gone when it stops."""

    def __init__(self, clock=time.monotonic) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._jobs: dict[str, dict] = {}
        self.started = time.time()

    def _forget_old(self) -> None:
        now = self._clock()
        old = [name for name, job in self._jobs.items() if job["ended"] is not None and now - job["ended"] > KEPT]
        for name in old:
            del self._jobs[name]
        # Never more than a bounded number, whatever is asked of the worker.
        for name in list(self._jobs)[: max(0, len(self._jobs) - MAX_KEPT)]:
            if self._jobs[name]["ended"] is not None:
                del self._jobs[name]

    @contextmanager
    def running(self, name: str | None):
        """The job ``name`` runs while the block does. Gives a function that says how far it is.
        A request that carries no name (or one that is not a name) is simply not tracked."""
        if not name or not NAME.fullmatch(name):
            yield lambda _text: None
            return
        job = {"since": self._clock(), "ended": None, "progress": ""}
        with self._lock:
            self._forget_old()
            self._jobs[name] = job

        def say(text: str) -> None:
            job["progress"] = str(text or "")[:200]

        try:
            yield say
        finally:
            job["ended"] = self._clock()

    def state(self, name: str) -> dict | None:
        """What is known of the job, or None when this process does not have it."""
        with self._lock:
            self._forget_old()
            job = self._jobs.get(name)
            if job is None:
                return None
            end = job["ended"] if job["ended"] is not None else self._clock()
            return {
                "state": "running" if job["ended"] is None else "finished",
                "seconds": round(end - job["since"], 1),
                "progress": job["progress"] if job["ended"] is None else "",
            }

    def count(self) -> int:
        with self._lock:
            return sum(1 for job in self._jobs.values() if job["ended"] is None)

    def answer(self, path: str) -> tuple[int, dict] | None:
        """The answer to ``GET <path>`` when it asks about a job; None when it asks something else."""
        found = PATH.fullmatch(path)
        if found is None:
            return None
        state = self.state(found.group(1))
        if state is None:
            return 404, {"detail": "Unknown job", "unknown": True, "started": self.started}
        return 200, state


def stop_politely(server, say=print) -> None:
    """What SIGTERM does to a worker: it stops taking requests. Called from the signal handler:
    the work happens in a thread, because ``shutdown`` waits for the loop the handler interrupted.
    The loop then returns, and the worker lets its jobs finish (``drain``) before it exits."""
    say("stopping: no new request is taken", flush=True)
    threading.Thread(target=server.shutdown, name="stop", daemon=True).start()


def drain(jobs: Jobs, grace: float, say=print, sleep=time.sleep) -> int:
    """Let the jobs in flight finish, for ``grace`` seconds at most. Returns how many were cut: the
    backend is told "unknown job" for those by the worker that starts next, and hands them out again."""
    waited = 0.0
    while jobs.count() and waited < grace:
        sleep(0.2)
        waited += 0.2
    left = jobs.count()
    say(f"stopped ({left} job(s) cut)" if left else "stopped", flush=True)
    return left

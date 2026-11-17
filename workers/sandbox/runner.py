"""Run a script in a process of its own, under limits.

One new process per call: ``python -I -S -B harness.py``, with an empty
environment, a fresh working directory that is deleted afterwards, and limits
the process cannot raise:

    CPU time        ``timeout`` seconds (10 by default, 60 at most)
    wall clock      the same plus one second, then the whole group is killed
    memory          256 MB of address space
    files           16 descriptors, 1 MB written
    processes       none besides itself
    output          1 MB of result, 20 kB of log

The limits keep one script from starving the others. What keeps a script from
reaching anything is the container (see the Dockerfile and the Compose file):
no network, a read-only filesystem, no capabilities.
"""

from __future__ import annotations

import json
import os
import resource
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time

HARNESS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "harness.py")
SENTINEL = "NIK-SANDBOX-RESULT:"
DEFAULT_TIMEOUT = int(os.environ.get("SANDBOX_TIMEOUT", "10"))
MAX_TIMEOUT = int(os.environ.get("SANDBOX_MAX_TIMEOUT", "60"))
MEMORY_BYTES = int(os.environ.get("SANDBOX_MEMORY_MB", "256")) * 1024 * 1024
MAX_RESULT = 1_000_000
MAX_LOG = 20_000
MAX_CODE = 200_000
MAX_FILE = 1_000_000


def _limits(cpu_seconds: int):
    def apply() -> None:
        os.setsid()  # its own group, so the group can be killed
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
        resource.setrlimit(resource.RLIMIT_AS, (MEMORY_BYTES, MEMORY_BYTES))
        resource.setrlimit(resource.RLIMIT_NOFILE, (16, 16))
        resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_FILE, MAX_FILE))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        try:
            # No process besides itself (counted per user: the worker's own threads are not this process).
            resource.setrlimit(resource.RLIMIT_NPROC, (0, 0))
        except (ValueError, OSError):
            pass

    return apply


def _drain(fd: int, into: list[bytes]) -> None:
    """Read the result pipe to its end, keeping what fits and dropping the rest."""
    kept = 0
    with os.fdopen(fd, "rb") as pipe:
        while True:
            chunk = pipe.read(65536)
            if not chunk:
                return
            if kept <= MAX_RESULT + len(SENTINEL) + 2:
                into.append(chunk)
                kept += len(chunk)


def _child(result_fd: int, cpu_seconds: int):
    """What the child does before it becomes the harness: the result pipe on fd 3, then the limits."""
    limits = _limits(cpu_seconds)

    def prepare() -> None:
        if result_fd != 3:
            os.dup2(result_fd, 3)
        os.set_inheritable(3, True)
        limits()

    return prepare


def run(code: str, args: dict | None = None, timeout: int | None = None) -> dict:
    """``{ok, result | error, stdout, duration_ms}``."""
    if not isinstance(code, str) or not code.strip():
        return {"ok": False, "error": "There is no code to run", "stdout": "", "duration_ms": 0}
    if len(code) > MAX_CODE:
        return {"ok": False, "error": "The script is too long", "stdout": "", "duration_ms": 0}
    seconds = max(1, min(int(timeout or DEFAULT_TIMEOUT), MAX_TIMEOUT))
    work = tempfile.mkdtemp(prefix="nik-script-")
    read_fd, write_fd = os.pipe()
    started = time.monotonic()
    process = None
    try:
        process = subprocess.Popen(  # noqa: S603 - fixed arguments, no shell
            [sys.executable, "-I", "-S", "-B", HARNESS],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=work,
            env={},
            pass_fds=(),
            preexec_fn=_child(write_fd, seconds),  # noqa: PLW1509 - the limits must be set in the child
            close_fds=False,
        )
        os.close(write_fd)
        write_fd = -1
        # The result is read while the script runs: a large one would otherwise fill the pipe and hang it.
        collected: list[bytes] = []
        reader = threading.Thread(target=_drain, args=(read_fd, collected), daemon=True)
        reader.start()
        read_fd = -1
        try:
            log, _ = process.communicate(
                json.dumps({"code": code, "args": args or {}}).encode("utf-8"), timeout=seconds + 1
            )
            timed_out = False
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            log, _ = process.communicate()
        reader.join(timeout=5)
        raw = b"".join(collected)
    finally:
        for fd in (read_fd, write_fd):
            if fd >= 0:
                os.close(fd)
        shutil.rmtree(work, ignore_errors=True)
    duration = int((time.monotonic() - started) * 1000)
    stdout = log.decode("utf-8", errors="replace")[:MAX_LOG]
    base = {"stdout": stdout, "duration_ms": duration}
    if timed_out or process.returncode == -signal.SIGXCPU or process.returncode == -signal.SIGKILL:
        return {"ok": False, "error": f"The script ran longer than {seconds} seconds and was stopped", **base}
    text = raw.decode("utf-8", errors="replace")
    if not text.startswith(SENTINEL):
        if process.returncode not in (0, None) and "MemoryError" in stdout:
            return {"ok": False, "error": "The script used more memory than it may", **base}
        return {
            "ok": False,
            "error": "The script ended without a result (it may have used more memory than it may)",
            **base,
        }
    if len(text) > MAX_RESULT:
        return {"ok": False, "error": "The result is larger than 1 MB", **base}
    try:
        answer = json.loads(text[len(SENTINEL) :])
    except ValueError:
        return {"ok": False, "error": "The result is larger than 1 MB", **base}
    return {**answer, **base}

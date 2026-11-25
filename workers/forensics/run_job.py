"""One parse, in a process of its own: ``python -I run_job.py <path> <request as JSON>``.

``server.py`` starts this for every job and relays what it writes on its
standard output (the events of ``nik_forensics/context.py``). A process of its
own, so that what a hostile file does to a parser (a library that crashes, a
loop that eats the memory it may use) ends this process and not the worker.

Before it reads anything it gives up what it does not need: its memory
and its CPU time are bounded (``FORENSICS_JOB_MEMORY_MB``,
``FORENSICS_JOB_SECONDS``), it writes no core file and can create no file
larger than a megabyte. It runs with ``-I``: nothing of the environment or of
the folder it is started from is on its import path but the worker's own code.

When the request names a rule set (``rules``), the records are matched against it as they are found
(``nik_forensics/sigma/engine.py``) and the matches are written as ``det`` lines (``context.py``).

It exits 0 when the parser read the file to its end, 3 when no parser reads
the file (said on the output as a skip), 1 when the parser raised: the server
tells the backend, which keeps what came and reports the file as read in part.
"""

from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)


def limits() -> None:
    try:
        import resource
    except ImportError:  # not on this system (a development machine): nothing to bound with
        return
    memory = int(os.environ.get("FORENSICS_JOB_MEMORY_MB", "1536")) * 1024 * 1024
    seconds = int(os.environ.get("FORENSICS_JOB_SECONDS", "21600"))
    for what, soft in (
        # The memory of its own (heap, anonymous mappings), not its address space: a parser may map
        # a file of gigabytes read-only, which costs no memory, and must not be refused for it.
        (resource.RLIMIT_DATA, memory),
        (resource.RLIMIT_CPU, seconds),
        (resource.RLIMIT_CORE, 0),
        (resource.RLIMIT_FSIZE, 1024 * 1024),
    ):
        try:
            _soft, hard = resource.getrlimit(what)
            wanted = soft if hard == resource.RLIM_INFINITY else min(soft, hard)
            resource.setrlimit(what, (wanted, hard if hard != resource.RLIM_INFINITY else wanted))
        except (ValueError, OSError):
            continue


def rule_lines(handle):
    """The rules of a set (one JSON object per line); a line that is not JSON is handed on as text, and the engine
    lists it as a rule it could not read."""
    for line in handle:
        if line.strip():
            try:
                yield json.loads(line)
            except ValueError:
                yield line[:100].decode("utf-8", "replace")


def detector(request: dict, ctx) -> None:
    """Give the context the engine of the job's rule set (``request["rules"]``, a file of the worker's own folder
    that the server resolved), when there is one. A set that cannot be read is said, not fatal."""
    path = request.get("rules")
    if not path:
        return
    try:
        from nik_forensics.sigma.engine import Engine

        with open(path, "rb") as handle:
            ctx.detector = Engine(rule_lines(handle), ctx.params.get("hours"))
    except Exception as error:  # noqa: BLE001 - detection is on top of the reading: the parse goes on without it
        ctx.skip("the rule set could not be loaded", lost=0, detail=f"{type(error).__name__}: {error}")


def main(argv: list[str]) -> int:
    from nik_forensics import parsers
    from nik_forensics.context import Context

    path, request = argv[1], json.loads(argv[2])
    out = sys.stdout.buffer
    ctx = Context(out, request.get("params") or {})
    detector(request, ctx)
    try:
        if request.get("parser"):
            module, source = parsers.load(str(request["parser"])), str(request.get("source") or "")
        else:
            module, source = parsers.recognise(path, str(request.get("fileName") or ""))
    except parsers.UnknownParser as error:
        ctx.skip("no parser reads this file", lost=0, detail=str(error))
        out.flush()
        return 3
    try:
        module.parse(path, ctx, source)
        ctx.end()
    except MemoryError:
        ctx.skip("the parser needed more memory than a job may use", lost=0)
        out.flush()
        return 1
    except Exception as error:  # noqa: BLE001 - whatever a parser raises on a hostile file is said, not hidden
        ctx.skip("the parser stopped", lost=0, detail=f"{type(error).__name__}: {error}")
        out.flush()
        return 1
    out.flush()
    return 0


if __name__ == "__main__":
    limits()
    sys.exit(main(sys.argv))

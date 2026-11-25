"""One search, in a process of its own: ``python -I find_job.py <path> <request as JSON>``.

``server.py`` starts this for every ``POST /find``; the request is ``{"needle", "as", "from", "limit",
"seconds"}`` and the answer is one JSON object on the standard output (``nik_forensics/finding.py`` says its
shape). Like a view it has the memory of a job and a bound on its CPU time; ``seconds`` is the wall time after
which it stops reading and answers with where to go on from.

It exits 0 when the answer is on the output, 5 when the needle is bad (the output is ``{"detail": "<a
sentence>"}``), 1 for anything else.
"""

from __future__ import annotations

import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)


def say(payload: dict) -> None:
    sys.stdout.write(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
    sys.stdout.flush()


def main(argv: list[str]) -> int:
    from nik_forensics import finding

    path, request = argv[1], json.loads(argv[2])
    deadline = time.monotonic() + float(request.get("seconds", 20))
    try:
        say(
            finding.find(
                path,
                request["needle"],
                str(request.get("as") or "text"),
                int(request.get("from") or 0),
                int(request.get("limit") or 100),
                deadline,
            )
        )
        return 0
    except finding.BadNeedle as error:
        say({"detail": str(error)})
        return 5
    except MemoryError:
        say({"detail": "The search needed more memory than a job may use"})
        return 1
    except Exception as error:  # noqa: BLE001 - whatever the file or the disk does is said, not hidden
        say({"detail": f"{type(error).__name__}: {str(error)[:300]}"})
        return 1


if __name__ == "__main__":
    import run_job

    run_job.limits()
    # The same limits as a parse, with a bound on the CPU time of a search of its own.
    try:
        import resource

        wanted = int(json.loads(sys.argv[2]).get("seconds", 20)) + 10
        resource.setrlimit(resource.RLIMIT_CPU, (wanted, wanted))
    except (ImportError, ValueError, OSError):
        pass
    sys.exit(main(sys.argv))

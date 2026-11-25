"""One view, in a process of its own: ``python -I view_job.py <path> <request as JSON>``.

``server.py`` starts this for every ``POST /view``; the request is ``{"parser", "source", "loc"}`` and the
answer is one JSON object on the standard output: what ``view`` of the parser returns (``parsers/__init__.py``
says its shape), already cut to what a screen can show. As a parse is, it is a process of its own, with the
memory and the CPU it may use bounded (``run_job.limits``): what a hostile file does to a library ends this
process and not the worker.

It exits 0 when the answer is on the output, 4 when the locator names nothing in the file, 5 when the locator
lacks a member the parser needs (in both the output is ``{"detail": "<a sentence>"}``), 1 for anything else.
"""

from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

# What the answer may weigh in all, as JSON: a bit under what the server relays (512 KiB).
MAX_ANSWER = 480 * 1024


def say(payload: dict) -> None:
    sys.stdout.write(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
    sys.stdout.flush()


def main(argv: list[str]) -> int:
    from nik_forensics import parsers, viewing

    path, request = argv[1], json.loads(argv[2])
    try:
        module = parsers.load(str(request.get("parser") or ""))
        answer = module.view(path, str(request.get("source") or ""), request.get("loc") or {})
        budget = viewing.MAX_TEXT
        while True:  # a text full of control characters weighs six times its length as JSON
            shown = viewing.fit(dict(answer), budget)
            line = json.dumps(shown, ensure_ascii=False, separators=(",", ":"))
            if len(line.encode("utf-8")) <= MAX_ANSWER or budget < 1024:
                break
            budget //= 2
        sys.stdout.write(line)
        sys.stdout.flush()
        return 0
    except parsers.BadLocator as error:
        say({"detail": str(error)[:500]})
        return 5
    except parsers.ViewError as error:
        say({"detail": str(error)[:500]})
        return 4
    except parsers.UnknownParser as error:
        say({"detail": str(error)})
        return 1
    except MemoryError:
        say({"detail": "The view needed more memory than a job may use"})
        return 1
    except Exception as error:  # noqa: BLE001 - whatever a hostile file does to a parser is said, not hidden
        say({"detail": f"{type(error).__name__}: {str(error)[:300]}"})
        return 1


if __name__ == "__main__":
    import run_job

    run_job.limits()
    # The same limits as a parse, but a view that takes a minute of CPU is not a view.
    try:
        import resource

        resource.setrlimit(resource.RLIMIT_CPU, (60, 60))
    except (ImportError, ValueError, OSError):
        pass
    sys.exit(main(sys.argv))

"""One check or one try of Sigma rules, in a process of its own: ``python -I sigma_job.py check|try`` with the
request as JSON on the standard input.

``server.py`` starts this for ``POST /sigma/check`` and ``POST /sigma/try``; the answer is one JSON object on
the standard output (``nik_forensics/sigma/check.py`` and the contract in ``server.py`` say its shape). Rule texts
are hostile input like any file: YAML is read here, with the memory of a job and a bound on the CPU time
(``FORENSICS_SIGMA_SECONDS``), and never in the server.

    check  {"documents": [{"source": "<yaml, may hold several documents>"}]}
    try    {"rules": [rule lines], "hours": {...}?, "records": [{"kind", "channel", "event_id", "key", "ts", "host",
            "username", "summary", "data", "type"?, "source"?}]}   in time order
           -> {"matches": [{"rule", "key", "records"?, "count"?}], "notEvaluated": [{"rule", "reason"}], "notes": [...]}

It exits 0 when the answer is on the output, 5 when the request is not one (``{"detail": "<a sentence>"}``), 1 for
anything else.
"""

from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

MAX_RECORDS = 20000


class BadRequest(Exception):
    pass


def say(payload: dict) -> None:
    sys.stdout.write(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
    sys.stdout.flush()


def check(request: dict) -> dict:
    from nik_forensics.sigma import check as checking

    documents = request.get("documents")
    if not isinstance(documents, list) or not all(isinstance(item, dict) for item in documents):
        raise BadRequest("documents must be a list of {source}")
    if len(documents) > checking.MAX_DOCUMENTS:
        raise BadRequest(f"at most {checking.MAX_DOCUMENTS} documents in one check")
    return checking.check(documents)


def attempt(request: dict) -> dict:
    from nik_forensics.sigma.engine import Engine

    rules, records = request.get("rules"), request.get("records")
    if not isinstance(rules, list) or not isinstance(records, list):
        raise BadRequest("rules and records must be lists")
    if len(records) > MAX_RECORDS:
        raise BadRequest(f"at most {MAX_RECORDS} records in one try")
    engine = Engine(rules, request.get("hours") if isinstance(request.get("hours"), dict) else None)
    engine.compile_all()
    matches: list[dict] = []
    for record in records:
        if not isinstance(record, dict):
            raise BadRequest("a record must be an object")
        event_id = record.get("event_id")
        ts = record.get("ts")
        data = record.get("data")
        key = str(record.get("key") or "")
        for rule in engine.see(
            str(record.get("kind") or ""),
            key,
            str(record.get("type") or ""),
            ts if isinstance(ts, int) and not isinstance(ts, bool) else None,
            str(record.get("host") or ""),
            str(record.get("username") or ""),
            event_id if isinstance(event_id, int) and not isinstance(event_id, bool) else None,
            str(record.get("channel") or ""),
            str(record.get("summary") or ""),
            data if isinstance(data, dict) else {},
            str(record.get("source") or ""),
        ):
            matches.append({"rule": rule, "key": key})
    dets, notes = engine.finish()
    matches.extend(
        {"rule": det["rule"], "key": det["key"], "records": det["records"], "count": det["count"]} for det in dets
    )
    return {
        "matches": matches,
        "notEvaluated": [{"rule": rule, "reason": reason} for rule, reason in engine.not_evaluated()],
        "notes": [{"reason": reason, "count": count, "detail": detail} for reason, count, detail in notes],
    }


def main(argv: list[str]) -> int:
    try:
        request = json.loads(sys.stdin.buffer.read())
        if not isinstance(request, dict) or argv[1] not in ("check", "try"):
            raise BadRequest("the request must be an object")
        say(check(request) if argv[1] == "check" else attempt(request))
        return 0
    except (BadRequest, ValueError) as error:
        say({"detail": str(error)})
        return 5
    except MemoryError:
        say({"detail": "The rules needed more memory than a job may use"})
        return 1
    except Exception as error:  # noqa: BLE001 - whatever a rule text does is said, not hidden
        say({"detail": f"{type(error).__name__}: {str(error)[:300]}"})
        return 1


if __name__ == "__main__":
    import run_job

    run_job.limits()
    # The same limits as a parse, with a bound on the CPU time of its own.
    try:
        import resource

        wanted = int(os.environ.get("FORENSICS_SIGMA_SECONDS", "120")) + 10
        resource.setrlimit(resource.RLIMIT_CPU, (wanted, wanted))
    except (ImportError, ValueError, OSError):
        pass
    sys.exit(main(sys.argv))

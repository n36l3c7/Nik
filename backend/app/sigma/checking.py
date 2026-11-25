"""Having the worker read rule text: ``POST /sigma/check``, in batches.

A text may hold several YAML documents; the worker answers for each text with the rules it found
(``RuleInfo``: id, title, level, whether Nik can run it and why not, the YAML of that one document)
and the errors of what is not a rule, with their lines.
"""

from __future__ import annotations

from typing import Any

from ..core.models import LEVELS
from . import worker

BATCH = 200
LEVEL_NAMES = {number: name for name, number in LEVELS.items()}
TEXT_MAX = 400_000  # characters of one text sent to be checked


class Unavailable(Exception):
    """The worker could not check: a sentence, and the status the API answers with (503, 502)."""

    def __init__(self, message: str, status: int = 503):
        super().__init__(message)
        self.message = message
        self.status = status


def level_of(value: Any, default: int = 3) -> int:
    """A Sigma level as 1 to 5, from the number or the name a worker may give."""
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value if 1 <= value <= 5 else default
    return LEVELS.get(str(value or "").strip().lower(), default)


def check(texts: list[str], timeout: float = 120) -> tuple[str, list[dict[str, Any]]]:
    """``(engine, [{"rules": [...], "errors": [...]}, ...])``, one for each text, in order. The texts
    go to the worker 200 at a time. Raises ``Unavailable``."""
    if not worker.configured():
        raise Unavailable("The forensics worker is not configured (FORENSICS_URL): it checks the rules")
    engine = ""
    out: list[dict[str, Any]] = []
    for start in range(0, len(texts), BATCH):
        batch = texts[start : start + BATCH]
        status, answer = worker.ask(
            "/sigma/check",
            {"documents": [{"source": text} for text in batch]},
            timeout=timeout,
        )
        if status != 200:
            raise Unavailable(worker.sentence(status, answer), 502 if status >= 500 else 400)
        documents = answer.get("documents")
        if not isinstance(documents, list) or len(documents) != len(batch):
            raise Unavailable("The forensics worker did not answer for every rule it was given", 502)
        engine = str(answer.get("engine") or engine)
        for held in documents:
            held = held if isinstance(held, dict) else {}
            rules = [rule for rule in held.get("rules") or [] if isinstance(rule, dict)]
            errors = [error for error in held.get("errors") or [] if isinstance(error, dict)]
            out.append({"rules": rules, "errors": errors})
    return engine, out


def errors_of(held: dict[str, Any]) -> list[dict[str, Any]]:
    """The errors of one text as the API says them: ``{line, column, message}``."""
    return [
        {
            "line": error.get("line") if isinstance(error.get("line"), int) else None,
            "column": error.get("column") if isinstance(error.get("column"), int) else None,
            "message": str(error.get("message") or "This is not a Sigma rule")[:500],
        }
        for error in held["errors"]
    ]

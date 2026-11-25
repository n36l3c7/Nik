"""Asking the forensics worker about rules: one place for the address, the token and the errors.

``ask`` never raises for what the worker answers: it returns ``(status, answer)``, and a worker that
cannot be reached is a 502 with a sentence. Whoever calls decides what a refusal means.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any

from ..core.config import settings

HEADER = "X-Forensics-Token"
HEALTH_SECONDS = 60
_health: dict[str, Any] = {"at": 0.0, "url": "", "engine": None}


def configured() -> bool:
    return bool(settings.FORENSICS_URL)


def ask(
    route: str,
    body: Any = None,
    *,
    method: str = "POST",
    raw: bytes | None = None,
    timeout: float = 120,
) -> tuple[int, dict[str, Any]]:
    """Call the worker: ``(status, answer)``. ``body`` is sent as JSON, or ``raw`` as NDJSON."""
    if not configured():
        return 503, {"detail": "The forensics worker is not configured (FORENSICS_URL): it checks the rules"}
    if raw is not None:
        data, kind = raw, "application/x-ndjson"
    else:
        data, kind = (
            (json.dumps(body).encode("utf-8") if body is not None else None),
            "application/json",
        )
    request = urllib.request.Request(
        f"{settings.FORENSICS_URL}{route}",
        data=data,
        method=method,
        headers={HEADER: settings.FORENSICS_TOKEN, "Content-Type": kind},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, _answer(response.read())
    except urllib.error.HTTPError as error:
        return error.code, _answer(error.read())
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        return 502, {"detail": f"The forensics worker cannot be reached: {getattr(error, 'reason', error)}"}


def _answer(raw: bytes) -> dict[str, Any]:
    try:
        answer = json.loads(raw or b"{}")
    except ValueError:
        return {}
    return answer if isinstance(answer, dict) else {}


def sentence(status: int, answer: dict[str, Any]) -> str:
    """What a refusal of the worker says, in a sentence."""
    detail = answer.get("detail")
    return str(detail) if isinstance(detail, str) and detail else f"The forensics worker answered {status}"


def engine() -> str | None:
    """The version of the evaluator of the worker (``GET /health``, ``sigma``), asked at most once a
    minute; None when the worker is not there or is of a version that has none."""
    now = time.monotonic()
    if _health["url"] == settings.FORENSICS_URL and now - _health["at"] < HEALTH_SECONDS and _health["at"]:
        return _health["engine"]
    found = None
    if configured():
        status, answer = ask("/health", method="GET", timeout=10)
        held = answer.get("sigma") if status == 200 else None
        found = str(held) if isinstance(held, (str, int)) and not isinstance(held, bool) and str(held) else None
    _health.update(at=now, url=settings.FORENSICS_URL, engine=found)
    return found


def forget() -> None:
    _health.update(at=0.0, url="", engine=None)

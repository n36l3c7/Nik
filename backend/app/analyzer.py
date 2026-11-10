"""Client of the analyzer worker (rizin + rz-ghidra) and the background job.

The backend never runs rizin itself: it asks the worker (``ANALYZER_URL``,
see analyzer/) to disassemble and decompile a sample that is already in the
shared store, waits for the JSON result and saves it in ``sample_code``. The
worker sees the store read-only and is reachable only from the backend.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import delete

from . import flirt
from .config import settings
from .db import SessionLocal
from .models import SampleCode, SampleFunction
from .security import now_iso


class AnalyzerError(Exception):
    """The worker could not be reached or refused the request."""


class WorkerBusy(AnalyzerError):
    """The worker is running as many jobs as it allows (HTTP 503)."""


def configured() -> bool:
    return bool(settings.ANALYZER_URL and settings.ANALYZER_TOKEN)


def request_code_analysis(sha256: str, signatures: list[str]) -> dict[str, Any]:
    """POST /analyze to the worker: functions, CFGs and the up-front pseudo-C.

    ``signatures`` are the enabled admin FLIRT files, relative to the store.
    """
    return _post("/analyze", {"sha256": sha256, "signatures": signatures})


def request_decompile(sha256: str, addr: int, signatures: list[str]) -> dict[str, Any]:
    """POST /decompile to the worker: the pseudo-C of one function, on demand."""
    return _post("/decompile", {"sha256": sha256, "addr": addr, "signatures": signatures})


def _post(path: str, payload: dict[str, Any]) -> dict[str, Any]:
    """POST JSON to the rizin worker; the parsed JSON result or AnalyzerError."""
    return post_worker(
        settings.ANALYZER_URL, settings.ANALYZER_TOKEN, path, payload, timeout=settings.ANALYZER_TIMEOUT + 30
    )


def post_worker(base_url: str, token: str, path: str, payload: dict[str, Any], timeout: float) -> dict[str, Any]:
    """POST JSON to an analysis worker (rizin or capa); the parsed JSON result or AnalyzerError."""
    request = urllib.request.Request(
        f"{base_url}{path}",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Analyzer-Token": token},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            return json.loads(response.read())
    except urllib.error.HTTPError as exc:
        try:
            detail = json.loads(exc.read()).get("detail")
        except Exception:
            detail = None
        error = WorkerBusy if exc.code == 503 else AnalyzerError
        raise error(detail or f"The worker answered {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise AnalyzerError(f"Cannot reach the worker: {exc}") from exc


def split_result(result: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Separate the per-function CFGs and pseudo-C (stored one row per function) from the summary."""
    functions, rows = [], {}
    for fn in result.get("functions", []):
        fn = dict(fn)
        cfg = fn.pop("cfg", None)
        if cfg is not None:
            rows[fn["addr"]] = {"addr": fn["addr"], "cfg": cfg, "decompiled": None}
        functions.append(fn)
    for addr, code in (result.get("decompiled") or {}).items():
        rows.setdefault(int(addr), {"addr": int(addr), "cfg": None, "decompiled": None})["decompiled"] = code
    summary = {key: value for key, value in result.items() if key not in ("functions", "decompiled")}
    summary["functions"] = functions
    return summary, [rows[addr] for addr in sorted(rows)]


def run_code_job(sha256: str) -> None:
    """Background task: ask the worker, store the result or the error."""
    db = SessionLocal()
    try:
        row = db.get(SampleCode, sha256)
        if row is None:
            return
        row.status = "running"
        db.commit()
        try:
            summary, functions = split_result(request_code_analysis(sha256, flirt.enabled_paths(db)))
            db.execute(delete(SampleFunction).where(SampleFunction.sha256 == sha256))
            db.add_all(SampleFunction(sha256=sha256, **fn) for fn in functions)
            row.summary, row.status, row.error = summary, "done", None
        except AnalyzerError as exc:
            row.status, row.error = "error", str(exc)
        row.finished_at = now_iso()
        db.commit()
    finally:
        db.close()


def is_stale(row: SampleCode) -> bool:
    """A queued/running job older than the timeout (e.g. the backend restarted mid-run)."""
    if row.status not in ("queued", "running"):
        return False
    try:
        started = datetime.fromisoformat(row.requested_at.replace("Z", "+00:00"))
    except ValueError:
        return True
    return (datetime.now(timezone.utc) - started).total_seconds() > settings.ANALYZER_TIMEOUT + 120

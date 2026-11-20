"""Client of the analyzer worker (rizin + rz-ghidra) and the background job.

The backend never runs rizin itself: it asks the worker (``ANALYZER_URL``,
see workers/analyzer/) to disassemble and decompile a sample, waits for the JSON
result and saves it in ``sample_code``. The worker is reachable only from the
backend and does not see the store: it is given the sample and the signatures
it lacks (``handover.py``).
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import delete

from ..core.config import settings
from ..core.db import SessionLocal
from ..core.models import SampleCode, SampleFunction
from ..core.security import now_iso
from ..malware import flirt
from ..malware.samples import sample_path
from . import handover


class AnalyzerError(Exception):
    """The worker could not be reached or refused the request."""


class WorkerBusy(AnalyzerError):
    """The worker is running as many jobs as it allows (HTTP 503)."""


class FilesMissing(AnalyzerError):
    """The worker does not hold files the request names (HTTP 409): ``missing`` are their names."""

    def __init__(self, message: str, missing: list[str]) -> None:
        super().__init__(message)
        self.missing = missing


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
    """POST JSON to the rizin worker, giving it the sample and the signatures it lacks; the parsed
    JSON result or AnalyzerError."""
    files = {f"{payload['sha256']}.bin": sample_path(payload["sha256"])}
    files.update({name: flirt.path_of(name) for name in payload.get("signatures") or []})
    return post_with_files(
        settings.ANALYZER_URL, settings.ANALYZER_TOKEN, path, payload, settings.ANALYZER_TIMEOUT + 30, files
    )


def post_with_files(
    base_url: str, token: str, path: str, payload: dict[str, Any], timeout: float, files: dict[str, Any]
) -> dict[str, Any]:
    """``post_worker``, sending the worker the files of the store it says it does not hold."""
    return handover.with_files(
        lambda: post_worker(base_url, token, path, payload, timeout),
        files,
        base_url,
        "X-Analyzer-Token",
        token,
        AnalyzerError,
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
            body = json.loads(exc.read())
            detail = body.get("detail")
        except Exception:
            body, detail = None, None
        missing = handover.missing_of(exc, body)
        if missing:
            raise FilesMissing(detail or "The worker does not hold the files", missing) from exc
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
        # Said to the playbooks and the webhooks that wait for it, done or failed.
        from ..automation import triggers

        db.flush()
        triggers.code_analysed(db, row)
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

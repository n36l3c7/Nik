"""Client of the capa worker and the background job.

The backend never runs capa itself: it asks the worker (``CAPA_URL``, see
workers/capa/) to analyse a sample that is already in the shared store and saves the
reduced report in ``sample_capa``. capa reads x86 / x64 PE and ELF files;
other samples are marked ``unsupported`` without calling the worker.
"""

from __future__ import annotations

import threading
import time
from datetime import datetime, timezone
from typing import Any

from ..core.config import settings
from ..core.db import SessionLocal
from ..core.models import SampleCapa
from ..core.security import now_iso
from ..malware import capa_rules
from .analyzer import AnalyzerError, WorkerBusy, post_worker

SUPPORTED_TYPES = {"pe32", "pe64", "pe", "elf"}
BUSY_RETRY_SECONDS = 15
# A queued job waits for at most this many full analyses before it gives up.
QUEUE_RUNS = 4
_one_at_a_time = threading.Lock()


def configured() -> bool:
    return bool(settings.CAPA_URL and settings.CAPA_TOKEN)


def supported(type_id: str) -> bool:
    return type_id in SUPPORTED_TYPES


def request_capabilities(sha256: str, rules: list[str]) -> dict[str, Any]:
    """POST /analyze to the capa worker: the sample's capabilities.

    rules are the enabled admin rule files, relative to the store.
    """
    payload = {"sha256": sha256, "rules": rules}
    return post_worker(settings.CAPA_URL, settings.CAPA_TOKEN, "/analyze", payload, settings.CAPA_TIMEOUT + 30)


def _run_seconds() -> int:
    """How long one analysis may take, worker timeout plus transfer."""
    return settings.CAPA_TIMEOUT + 120


def _queue_seconds() -> int:
    """How long a job may wait for the worker before it is given up."""
    return QUEUE_RUNS * _run_seconds()


def _request_when_free(sha256: str, rules: list[str]) -> dict[str, Any]:
    """Ask the worker, waiting while it is busy with a sample sent by another backend process."""
    waited = 0.0
    while True:
        try:
            return request_capabilities(sha256, rules)
        except WorkerBusy:
            if waited >= _queue_seconds():
                raise AnalyzerError("capa stayed busy with other samples; run it again later") from None
            time.sleep(BUSY_RETRY_SECONDS)
            waited += BUSY_RETRY_SECONDS


def run_capa_job(sha256: str) -> None:
    """Background task: ask the worker, store the result or the error.

    capa is CPU-bound and the worker runs one analysis at a time, so jobs of
    this process run one after the other; the others stay ``queued``.
    """
    with _one_at_a_time:
        db = SessionLocal()
        try:
            row = db.get(SampleCapa, sha256)
            if row is None or row.status != "queued":
                return
            row.status, row.started_at = "running", now_iso()
            db.commit()
            try:
                rules = capa_rules.enabled_paths(db)
                row.result, row.status, row.error = _request_when_free(sha256, rules), "done", None
            except AnalyzerError as exc:
                row.status, row.error = "error", str(exc)
            row.finished_at = now_iso()
            db.commit()
        finally:
            db.close()


def _age(iso: str | None) -> float | None:
    try:
        return (datetime.now(timezone.utc) - datetime.fromisoformat((iso or "").replace("Z", "+00:00"))).total_seconds()
    except ValueError:
        return None


def is_stale(row: SampleCapa) -> bool:
    """A job that can no longer finish (e.g. the backend restarted while it was queued or running)."""
    if row.status == "running":
        age = _age(row.started_at)
        return age is None or age > _run_seconds() + _queue_seconds()
    if row.status == "queued":
        age = _age(row.requested_at)
        return age is None or age > _queue_seconds()
    return False

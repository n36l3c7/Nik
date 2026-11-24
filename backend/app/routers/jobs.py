"""Async job status.

Long-running work (currently: a file of host evidence uploaded with
``?async=true``) is tracked as a Job; poll here for its status/result.

An upload job carries the id of the source the file became (``sourceId``): its
status is the status of the reading of that source, asked each time, so it
survives a restart of the server like the reading does.
"""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session as OrmSession

from ..core.db import get_db
from ..core.models import EvidenceSource, Job
from ..core.schemas import JobOut
from ..core.security import Principal, reader_principal
from ..evidence import intake

router = APIRouter(prefix="/jobs", tags=["jobs"])

# A job of an older version had the bytes of the file in the memory of its process: a restart ended it.
INTERRUPTED = "Interrupted by a restart of the server before the file was parsed: upload the file again."
GONE = "The file was removed from the incident before it was read"


def _of_source(db: OrmSession, job: Job, held: dict) -> tuple[str, dict | None, str | None]:
    """The status, result and error of an upload job, from the source its file became."""
    source = db.get(EvidenceSource, str(held["sourceId"]))
    if source is None:
        return "error", None, GONE
    if source.state == "failed":
        return "error", None, source.error or "The file could not be read"
    if source.state == "done":
        return "done", intake.summary(source, bool(held.get("alreadyImported"))), None
    return ("running" if source.state == "parsing" else "queued"), None, None


@router.get("/{job_id}", response_model=JobOut)
def get_job(
    job_id: str,
    _caller: Principal = Depends(reader_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Return an async job's status (and result when done)."""
    job = db.get(Job, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    status, result, error = job.status, None, job.error
    held = json.loads(job.result_json) if job.result_json else None
    if job.kind == "upload" and isinstance(held, dict) and held.get("sourceId"):
        status, result, error = _of_source(db, job, held)
    else:
        result = held
        if job.kind == "upload" and status in ("queued", "running"):
            status, error = "error", INTERRUPTED
    return {
        "id": job.id,
        "kind": job.kind,
        "status": status,
        "incidentId": job.incident_id,
        "createdAt": job.created_at,
        "updatedAt": job.updated_at,
        "result": result,
        "error": error,
    }

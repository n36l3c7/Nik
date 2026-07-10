"""Async job status.

Long-running work (currently: server-side upload parsing requested with
``?async=true``) is tracked as a Job; poll here for its status/result.
"""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session as OrmSession

from ..db import get_db
from ..models import Job
from ..schemas import JobOut
from ..security import Principal, principal

router = APIRouter(prefix="/jobs", tags=["jobs"])


@router.get("/{job_id}", response_model=JobOut)
def get_job(
    job_id: str,
    _caller: Principal = Depends(principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Return an async job's status (and result when done)."""
    job = db.get(Job, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return {
        "id": job.id,
        "kind": job.kind,
        "status": job.status,
        "incidentId": job.incident_id,
        "createdAt": job.created_at,
        "updatedAt": job.updated_at,
        "result": json.loads(job.result_json) if job.result_json else None,
        "error": job.error,
    }

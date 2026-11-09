"""Malware samples: upload, static analysis, download as a protected zip.

A sample is stored once on disk (``samples.py``), analysed once
(``parsing/malware.py``) and referenced by any number of incidents under
``doc.data.malware.samples``. The incident document keeps only the light
reference; the analysis is fetched per sample, so opening an incident stays
cheap. Nothing here executes or parses the file beyond reading its bytes.
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, Query, UploadFile, status
from fastapi.responses import Response
from sqlalchemy import String, cast, select
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm.attributes import flag_modified

from ..config import settings
from ..db import get_db
from ..events import emit
from ..models import AuditEntry, Incident, Sample
from ..parsing.malware import STRINGS_STORED, analyze, iter_strings
from ..samples import DEFAULT_ZIP_PASSWORD, delete_sample, is_sha256, read_sample, write_sample, zip_sample
from ..security import Principal, now_iso, principal, writer_principal

router = APIRouter(tags=["samples"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _audit(db: OrmSession, caller: Principal, action: str, details: str, incident: Incident | None) -> None:
    """Sample actions are only reachable through this API, so every caller is logged."""
    doc = (incident.doc if incident is not None else {}) or {}
    db.add(
        AuditEntry(
            id=str(uuid.uuid4()),
            at=now_iso(),
            actor=caller.actor,
            action=action,
            target=doc.get("name"),
            details=details,
            incident_id=incident.id if incident is not None else None,
            incident_name=doc.get("name"),
        )
    )


def _incident_or_404(db: OrmSession, incident_id: str) -> Incident:
    row = db.get(Incident, incident_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return row


def _sample_or_404(db: OrmSession, sha256: str) -> Sample:
    if not is_sha256(sha256):
        raise HTTPException(status_code=404, detail="Sample not found")
    row = db.get(Sample, sha256)
    if row is None:
        raise HTTPException(status_code=404, detail="Sample not found")
    return row


def _refs(doc: dict) -> list[dict[str, Any]]:
    malware = doc.setdefault("data", {}).setdefault("malware", {})
    refs = malware.get("samples")
    if not isinstance(refs, list):
        refs = []
        malware["samples"] = refs
    return refs


def _summary(row: Sample) -> dict[str, Any]:
    """The light description of a sample (what an incident reference carries)."""
    return {
        "sha256": row.sha256,
        "sha1": row.sha1,
        "md5": row.md5,
        "size": row.size,
        "type": {"id": row.type_id, "label": row.type_label},
        "entropy": row.entropy,
        "createdAt": row.created_at,
        "createdBy": row.created_by,
    }


def _incidents_referencing(db: OrmSession, sha256: str) -> list[Incident]:
    """Incidents whose document mentions the digest (a text match, then verified)."""
    candidates = db.scalars(select(Incident).where(cast(Incident.doc, String).like(f"%{sha256}%"))).all()
    return [row for row in candidates if any(ref.get("sha256") == sha256 for ref in _refs(dict(row.doc or {})))]


def _save_doc(db: OrmSession, row: Incident, doc: dict) -> None:
    doc["updatedAt"] = now_iso()
    row.doc = doc
    row.updated_at = doc["updatedAt"]
    flag_modified(row, "doc")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@router.post("/incidents/{incident_id}/samples", status_code=status.HTTP_201_CREATED)
async def upload_sample(
    incident_id: str,
    file: UploadFile = File(..., description="The suspicious file, as is."),
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
    background_tasks: BackgroundTasks = None,
) -> dict:
    """Store a sample and attach it to the incident.

    The file is written to the sample store (named by its SHA-256, never
    executed), analysed statically (hashes, type, entropy, strings, IOC) and
    referenced from the incident under `data.malware.samples`. Uploading a
    file that is already in the store reuses its analysis.
    """
    incident = _incident_or_404(db, incident_id)
    data = await file.read()
    if not data:
        raise HTTPException(status_code=400, detail="The file is empty.")
    limit = settings.SAMPLE_MAX_MB * 1024 * 1024
    if len(data) > limit:
        raise HTTPException(status_code=413, detail=f"The file exceeds the {settings.SAMPLE_MAX_MB} MB sample limit.")

    result = analyze(data)
    sha256 = result["hashes"]["sha256"]
    row = db.get(Sample, sha256)
    if row is None:
        write_sample(sha256, data)
        row = Sample(
            sha256=sha256,
            sha1=result["hashes"]["sha1"],
            md5=result["hashes"]["md5"],
            size=result["size"],
            type_id=result["type"]["id"],
            type_label=result["type"]["label"],
            entropy=result["entropy"],
            created_at=now_iso(),
            created_by=caller.actor,
            analysis=result,
        )
        db.add(row)

    doc = dict(incident.doc or {})
    refs = _refs(doc)
    file_name = file.filename or sha256
    existing = next((ref for ref in refs if ref.get("sha256") == sha256), None)
    if existing is None:
        ref = {
            **_summary(row),
            "fileName": file_name,
            "importedAt": now_iso(),
            "importedBy": caller.actor,
        }
        refs.append(ref)
    else:
        ref = existing
    _save_doc(db, incident, doc)
    _audit(db, caller, "sample.upload", f"Uploaded sample {file_name} ({sha256[:12]}…, {row.type_label})", incident)
    db.commit()
    emit(
        db, background_tasks, "upload.completed", {"incidentId": incident_id, "target": f"malware/{sha256}", "rows": 1}
    )
    return {"sample": ref, "iocs": len(row.analysis.get("iocs", [])), "strings": row.analysis.get("stringsTotal", 0)}


@router.get("/samples/{sha256}")
def get_sample(
    sha256: str,
    _caller: Principal = Depends(principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """The sample's metadata and full static analysis (the first 5,000 strings)."""
    row = _sample_or_404(db, sha256)
    incidents = [{"id": inc.id, "name": (inc.doc or {}).get("name", "")} for inc in _incidents_referencing(db, sha256)]
    return {**_summary(row), "analysis": row.analysis, "incidents": incidents}


@router.get("/samples/{sha256}/strings")
def sample_strings(
    sha256: str,
    q: str = Query("", description="Case-insensitive substring filter."),
    min_length: int = Query(6, ge=4, le=64, alias="minLength"),
    encoding: str = Query("all", pattern="^(all|ascii|utf-16)$"),
    offset: int = Query(0, ge=0),
    limit: int = Query(500, ge=1, le=5000),
    _caller: Principal = Depends(principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Strings recomputed from the stored file, for searches beyond the stored preview."""
    _sample_or_404(db, sha256)
    needle = q.lower()
    matches = [
        item
        for item in iter_strings(read_sample(sha256), min_length)
        if (encoding == "all" or item["encoding"] == encoding) and (not needle or needle in item["value"].lower())
    ]
    return {
        "total": len(matches),
        "offset": offset,
        "items": matches[offset : offset + limit],
        "stored": STRINGS_STORED,
    }


@router.get("/samples/{sha256}/download")
def download_sample(
    sha256: str,
    password: str = Query(DEFAULT_ZIP_PASSWORD, min_length=1, max_length=128),
    name: str = Query("", max_length=255, description="File name inside the archive (default: the digest)."),
    caller: Principal = Depends(principal),
    db: OrmSession = Depends(get_db),
):
    """The sample inside an AES-256 zip protected by `password` (default `infected`)."""
    row = _sample_or_404(db, sha256)
    inner = (name or f"{sha256}.bin").replace("/", "_").replace("\\", "_")
    archive = zip_sample(read_sample(sha256), inner, password)
    _audit(db, caller, "sample.download", f"Downloaded sample {inner} ({sha256[:12]}…, {row.type_label})", None)
    db.commit()
    return Response(
        archive,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{inner}.zip"'},
    )


@router.delete("/incidents/{incident_id}/samples/{sha256}", status_code=status.HTTP_204_NO_CONTENT)
def remove_sample(
    incident_id: str,
    sha256: str,
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
) -> Response:
    """Detach the sample from the incident; the file is deleted once no incident references it."""
    incident = _incident_or_404(db, incident_id)
    row = _sample_or_404(db, sha256)
    doc = dict(incident.doc or {})
    refs = _refs(doc)
    kept = [ref for ref in refs if ref.get("sha256") != sha256]
    if len(kept) == len(refs):
        raise HTTPException(status_code=404, detail="The incident does not reference this sample")
    doc["data"]["malware"]["samples"] = kept
    _save_doc(db, incident, doc)
    db.flush()
    still_referenced = any(inc.id != incident_id for inc in _incidents_referencing(db, sha256))
    if not still_referenced:
        delete_sample(sha256)
        db.delete(row)
    _audit(db, caller, "sample.delete", f"Removed sample {sha256[:12]}… from the incident", incident)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)

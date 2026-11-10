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
from sqlalchemy import String, cast, delete, select
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm.attributes import flag_modified

from .. import analyzer, capa, capa_rules, flirt, yara_rules
from ..config import settings
from ..db import get_db
from ..events import emit
from ..iocs import reindex_incident
from ..models import AuditEntry, Incident, Sample, SampleCapa, SampleCode, SampleFunction
from ..parsing.executables import parse_structure
from ..parsing.malware import STRINGS_STORED, analyze, iter_strings
from ..samples import DEFAULT_ZIP_PASSWORD, delete_sample, is_sha256, read_sample, write_sample, zip_sample
from ..security import Principal, now_iso, principal, writer_principal
from .annotations import delete_for_sample as delete_annotations

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


ANALYSIS_VERSION = 2  # 1 = hashes/type/entropy/strings/IOC; 2 = + structure and YARA


def full_analysis(db: OrmSession, data: bytes) -> dict[str, Any]:
    """Static analysis plus the executable structure and the YARA scan."""
    result = analyze(data)
    result["structure"] = parse_structure(result["type"]["id"], data)
    result["yara"] = yara_rules.scan(db, data)
    result["analysisVersion"] = ANALYSIS_VERSION
    return result


def _queue_code(db: OrmSession, background_tasks: BackgroundTasks, sha256: str, actor: str) -> SampleCode | None:
    """(Re)start the disassembly job when the analyzer is configured; None otherwise."""
    if not analyzer.configured():
        return None
    row = db.get(SampleCode, sha256)
    if row is not None and row.status in ("queued", "running") and not analyzer.is_stale(row):
        return row
    if row is None:
        row = SampleCode(sha256=sha256, summary={})
        db.add(row)
    row.status, row.error, row.finished_at = "queued", None, None
    row.requested_at, row.requested_by = now_iso(), actor
    db.commit()
    background_tasks.add_task(analyzer.run_code_job, sha256)
    return row


def _code_state(row: SampleCode | None) -> dict[str, Any]:
    if not analyzer.configured() and (row is None or row.status != "done"):
        return {"configured": False, "status": "none"}
    if row is None:
        return {"configured": True, "status": "none"}
    stale = analyzer.is_stale(row)
    state = {
        "configured": analyzer.configured(),
        "status": "error" if stale else row.status,
        "error": "The analysis was interrupted; run it again." if stale else row.error,
        "requestedAt": row.requested_at,
        "requestedBy": row.requested_by,
        "finishedAt": row.finished_at,
    }
    if row.status == "done":
        state.update(row.summary)
    return state


def _queue_capa(db: OrmSession, background_tasks: BackgroundTasks, sample: Sample, actor: str) -> SampleCapa | None:
    """(Re)start capa on the worker when it is configured; None otherwise.

    File types capa does not read are marked ``unsupported`` without a job.
    """
    if not capa.configured():
        return None
    row = db.get(SampleCapa, sample.sha256)
    if row is not None and row.status in ("queued", "running") and not capa.is_stale(row):
        return row
    if row is None:
        row = SampleCapa(sha256=sample.sha256, result={})
        db.add(row)
    supported = capa.supported(sample.type_id)
    row.status, row.error, row.result = ("queued" if supported else "unsupported"), None, {}
    row.requested_at, row.requested_by = now_iso(), actor
    row.started_at = row.finished_at = None
    db.commit()
    if supported:
        background_tasks.add_task(capa.run_capa_job, sample.sha256)
    return row


def _capa_state(row: SampleCapa | None, sample: Sample, custom: set[str] | None = None) -> dict[str, Any]:
    """The job state; when done, the result with custom marking matches of admin rules."""
    if not capa.configured() and (row is None or row.status != "done"):
        return {"configured": False, "status": "none"}
    if row is None:
        return {"configured": True, "status": "none" if capa.supported(sample.type_id) else "unsupported"}
    stale = capa.is_stale(row)
    state = {
        "configured": capa.configured(),
        "status": "error" if stale else row.status,
        "error": "The analysis was interrupted; run it again." if stale else row.error,
        "requestedAt": row.requested_at,
        "requestedBy": row.requested_by,
        "startedAt": row.started_at,
        "finishedAt": row.finished_at,
    }
    if row.status == "done":
        state.update(row.result)
        state["capabilities"] = [
            {**c, "custom": c.get("name") in (custom or set())} for c in row.result.get("capabilities", [])
        ]
    return state


def _save_doc(db: OrmSession, row: Incident, doc: dict) -> None:
    doc["updatedAt"] = now_iso()
    row.doc = doc
    row.updated_at = doc["updatedAt"]
    flag_modified(row, "doc")
    db.flush()  # a new sample row must exist before the index reads its indicators
    reindex_incident(db, row)


def store_sample(
    db: OrmSession,
    incident: Incident,
    data: bytes,
    file_name: str,
    caller: Principal,
    background_tasks: BackgroundTasks | None,
    origin: str = "",
) -> tuple[Sample, dict[str, Any]]:
    """Analyse and store a file as a sample of the incident (upload, or a mail
    attachment sent to Malware Analysis); returns the row and the reference."""
    if not data:
        raise HTTPException(status_code=400, detail="The file is empty.")
    limit = settings.SAMPLE_MAX_MB * 1024 * 1024
    if len(data) > limit:
        raise HTTPException(status_code=413, detail=f"The file exceeds the {settings.SAMPLE_MAX_MB} MB sample limit.")

    result = full_analysis(db, data)
    sha256 = result["hashes"]["sha256"]
    # Always through the store: writes a missing file and repairs the mode of
    # one stored by an older release, even when the sample is already known.
    write_sample(sha256, data)
    row = db.get(Sample, sha256)
    if row is None:
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
    file_name = file_name or sha256
    existing = next((ref for ref in refs if ref.get("sha256") == sha256), None)
    if existing is None:
        ref = {
            **_summary(row),
            "fileName": file_name,
            "importedAt": now_iso(),
            "importedBy": caller.actor,
            **({"origin": origin} if origin else {}),
        }
        refs.append(ref)
    else:
        ref = existing
    _save_doc(db, incident, doc)
    _audit(
        db,
        caller,
        "sample.upload",
        f"Uploaded sample {file_name} ({sha256[:12]}…, {row.type_label})" + (f" from {origin}" if origin else ""),
        incident,
    )
    db.commit()
    emit(
        db, background_tasks, "upload.completed", {"incidentId": incident.id, "target": f"malware/{sha256}", "rows": 1}
    )
    if db.get(SampleCode, sha256) is None:
        _queue_code(db, background_tasks, sha256, caller.actor)
    if db.get(SampleCapa, sha256) is None:
        _queue_capa(db, background_tasks, row, caller.actor)
    return row, ref


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
    row, ref = store_sample(db, incident, data, file.filename or "", caller, background_tasks)
    return {"sample": ref, "iocs": len(row.analysis.get("iocs", [])), "strings": row.analysis.get("stringsTotal", 0)}


@router.post("/samples/{sha256}/reanalyse")
def reanalyse_sample(
    sha256: str,
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
    background_tasks: BackgroundTasks = None,
) -> dict:
    """Run the current analysis engine again on the stored file (after a Nik upgrade or a YARA rule change)."""
    row = _sample_or_404(db, sha256)
    result = full_analysis(db, read_sample(sha256))
    row.analysis = result
    row.type_id = result["type"]["id"]
    row.type_label = result["type"]["label"]
    row.entropy = result["entropy"]
    flag_modified(row, "analysis")
    _audit(db, caller, "sample.reanalyse", f"Re-analysed sample {sha256[:12]}… ({row.type_label})", None)
    db.commit()
    _queue_code(db, background_tasks, sha256, caller.actor)
    _queue_capa(db, background_tasks, row, caller.actor)
    incidents = [{"id": inc.id, "name": (inc.doc or {}).get("name", "")} for inc in _incidents_referencing(db, sha256)]
    return {**_summary(row), "analysis": row.analysis, "incidents": incidents}


@router.get("/samples/{sha256}/code")
def get_sample_code(
    sha256: str,
    _caller: Principal = Depends(principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Disassembly state and, when done, the function list with calls (no CFGs)."""
    _sample_or_404(db, sha256)
    return _code_state(db.get(SampleCode, sha256))


@router.post("/samples/{sha256}/code", status_code=status.HTTP_202_ACCEPTED)
def start_sample_code(
    sha256: str,
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
    background_tasks: BackgroundTasks = None,
) -> dict:
    """Start (or restart) the disassembly on the analyzer worker; poll GET …/code for the result."""
    _sample_or_404(db, sha256)
    if not analyzer.configured():
        raise HTTPException(status_code=503, detail="The analyzer worker is not configured (ANALYZER_URL).")
    row = _queue_code(db, background_tasks, sha256, caller.actor)
    _audit(db, caller, "sample.disassemble", f"Requested the disassembly of sample {sha256[:12]}…", None)
    db.commit()
    return _code_state(row)


@router.get("/samples/{sha256}/capabilities")
def get_sample_capabilities(
    sha256: str,
    _caller: Principal = Depends(principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """capa's state and, when done, the capabilities with their ATT&CK / MBC mappings and addresses."""
    sample = _sample_or_404(db, sha256)
    return _capa_state(db.get(SampleCapa, sha256), sample, capa_rules.custom_names(db))


@router.post("/samples/{sha256}/capabilities", status_code=status.HTTP_202_ACCEPTED)
def start_sample_capabilities(
    sha256: str,
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
    background_tasks: BackgroundTasks = None,
) -> dict:
    """Start (or restart) capa on the worker; poll GET …/capabilities for the result."""
    sample = _sample_or_404(db, sha256)
    if not capa.configured():
        raise HTTPException(status_code=503, detail="The capa worker is not configured (CAPA_URL).")
    if not capa.supported(sample.type_id):
        raise HTTPException(status_code=422, detail="capa analyses x86 and x64 PE and ELF files only.")
    row = _queue_capa(db, background_tasks, sample, caller.actor)
    _audit(db, caller, "sample.capabilities", f"Requested the capa analysis of sample {sha256[:12]}…", None)
    db.commit()
    return _capa_state(row, sample)


@router.get("/samples/{sha256}/code/functions/{addr}")
def get_function_cfg(
    sha256: str,
    addr: int,
    _caller: Principal = Depends(principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Control-flow graph of one function: blocks with their instructions and successors."""
    row = db.get(SampleCode, sha256)
    if row is None or row.status != "done":
        raise HTTPException(status_code=404, detail="No disassembly for this sample")
    function = db.get(SampleFunction, (sha256, addr))
    cfg = function.cfg if function is not None else None
    if cfg is None:
        raise HTTPException(status_code=404, detail="No control-flow graph for this function")
    return {"addr": addr, **cfg}


@router.get("/samples/{sha256}/code/functions/{addr}/decompiled")
def get_function_decompiled(
    sha256: str,
    addr: int,
    _caller: Principal = Depends(principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Pseudo-C of one function (rz-ghidra): stored by the analysis, or decompiled now and kept.

    The analysis decompiles functions up front within a time budget; the
    others are decompiled on first request: quick while the worker still
    holds the analysed sample, slower once it has to analyse it again.
    """
    row = db.get(SampleCode, sha256)
    if row is None or row.status != "done":
        raise HTTPException(status_code=404, detail="No disassembly for this sample")
    known = {fn.get("addr"): fn for fn in (row.summary or {}).get("functions", [])}
    if addr not in known or known[addr].get("kind") == "import":
        raise HTTPException(status_code=404, detail="No function of this sample starts at this address")
    engine = (row.summary or {}).get("decompile", {}).get("engine", "rz-ghidra")
    function = db.get(SampleFunction, (sha256, addr))
    stored = function.decompiled if function is not None else None
    if stored is not None:
        return {"addr": addr, "engine": engine, "source": "analysis", **stored}
    if not analyzer.configured():
        raise HTTPException(status_code=503, detail="The analyzer worker is not configured (ANALYZER_URL).")
    try:
        result = analyzer.request_decompile(sha256, addr, flirt.enabled_paths(db))
    except analyzer.AnalyzerError as exc:
        raise HTTPException(status_code=502, detail=f"The decompiler failed: {exc}") from exc
    code = {
        "code": result.get("code", ""),
        "spans": result.get("spans", []),
        "truncated": bool(result.get("truncated")),
    }
    if function is None:
        function = SampleFunction(sha256=sha256, addr=addr)
        db.add(function)
    function.decompiled = code
    db.commit()
    return {"addr": addr, "engine": result.get("engine", engine), "source": "on-demand", **code}


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
        code = db.get(SampleCode, sha256)
        if code is not None:
            db.delete(code)
        db.execute(delete(SampleFunction).where(SampleFunction.sha256 == sha256))
        capabilities = db.get(SampleCapa, sha256)
        if capabilities is not None:
            db.delete(capabilities)
        delete_annotations(db, sha256)
    _audit(db, caller, "sample.delete", f"Removed sample {sha256[:12]}… from the incident", incident)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)

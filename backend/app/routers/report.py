"""Incident report as HTML or PDF (see ``report.py``)."""

from __future__ import annotations

import re
import uuid
from typing import Any, Literal, Optional

from fastapi import APIRouter, Body, Depends, HTTPException
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from ..db import get_db
from ..iocs import Allowlist, incident_iocs
from ..models import AuditEntry, Incident, Mail, Sample, SampleCapa
from ..report import LANGS, SECTIONS, TLP_LEVELS, build_html, to_pdf
from ..security import Principal, now_iso, principal
from .settings import read_settings

router = APIRouter(tags=["report"])


class Detection(BaseModel):
    """A SOC rule's hits in the incident (the app runs the rules and sends them)."""

    id: str = Field(max_length=100)
    label: str = Field(max_length=200)
    severity: str = Field(default="medium", max_length=10)
    count: int = Field(default=1, ge=0)
    attack: list[str] = Field(default_factory=list, max_length=20)


class ReportIn(BaseModel):
    """Report options. Omitted fields come from the incident's saved report
    settings (``doc.report``), then from the defaults."""

    format: Literal["html", "pdf"] = "pdf"
    lang: Optional[Literal["en", "it"]] = None
    tlp: Optional[Literal["clear", "green", "amber", "amber+strict", "red"]] = None
    sections: Optional[list[str]] = None
    executiveSummary: Optional[str] = Field(default=None, max_length=20_000)
    detections: list[Detection] = Field(default_factory=list, max_length=500)


def _samples(db: OrmSession, doc: dict) -> list[dict[str, Any]]:
    refs = [r for r in ((doc.get("data") or {}).get("malware") or {}).get("samples") or [] if isinstance(r, dict)]
    digests = [r.get("sha256") for r in refs if r.get("sha256")]
    if not digests:
        return []
    rows = {s.sha256: s for s in db.scalars(select(Sample).where(Sample.sha256.in_(digests)))}
    capa = {c.sha256: c for c in db.scalars(select(SampleCapa).where(SampleCapa.sha256.in_(digests)))}
    out = []
    for ref in refs:
        row = rows.get(ref.get("sha256"))
        if row is None:
            continue
        capa_row = capa.get(row.sha256)
        out.append(
            {
                "fileName": ref.get("fileName") or row.sha256[:12],
                "sha256": row.sha256,
                "sha1": row.sha1,
                "md5": row.md5,
                "size": row.size,
                "typeLabel": row.type_label,
                "yara": (row.analysis or {}).get("yara") or [],
                "capa": (capa_row.result or {}).get("capabilities", [])
                if capa_row is not None and capa_row.status == "done"
                else None,
            }
        )
    return out


def _mails(db: OrmSession, doc: dict) -> list[dict[str, Any]]:
    refs = [r for r in ((doc.get("data") or {}).get("mail") or {}).get("messages") or [] if isinstance(r, dict)]
    digests = [r.get("sha256") for r in refs if r.get("sha256")]
    rows = {m.sha256: m for m in db.scalars(select(Mail).where(Mail.sha256.in_(digests)))} if digests else {}
    out = []
    for ref in refs:
        row = rows.get(ref.get("sha256"))
        findings = (row.analysis or {}).get("findings", []) if row is not None else []
        out.append(
            {
                "fileName": ref.get("fileName"),
                "subject": ref.get("subject"),
                "from": ref.get("from"),
                "date": ref.get("date"),
                "verdict": row.verdict if row is not None else ref.get("verdict"),
                "score": row.score if row is not None else ref.get("score"),
                "findings": [f.get("label") for f in findings if f.get("points")][:5],
            }
        )
    return out


_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


@router.post("/incidents/{incident_id}/report", response_model=None)
def incident_report(
    incident_id: str,
    body: ReportIn = Body(default_factory=ReportIn),
    caller: Principal = Depends(principal),
    db: OrmSession = Depends(get_db),
):
    """The incident report, as a PDF (default) or HTML.

    Sections: summary, timeline (flagged events), attack, iocs, samples,
    mails, network, eventlogs, notes, evidence. ``detections`` lists the SOC rule hits with
    their ATT&CK ids; the app sends them, API clients may leave them out.
    """
    row = db.get(Incident, incident_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    doc = row.doc or {}
    saved = doc.get("report") if isinstance(doc.get("report"), dict) else {}
    settings = read_settings(db)
    lang = body.lang or (saved.get("lang") if saved.get("lang") in LANGS else "en")
    tlp = body.tlp or (saved.get("tlp") if saved.get("tlp") in TLP_LEVELS else "amber")
    sections = body.sections if body.sections is not None else saved.get("sections") or list(SECTIONS)
    summary = body.executiveSummary if body.executiveSummary is not None else str(saved.get("executiveSummary") or "")
    now = now_iso()

    document = build_html(
        doc,
        lang=lang,
        tlp=tlp,
        sections=[s for s in sections if s in SECTIONS],
        executive_summary=summary,
        detections=[d.model_dump() for d in body.detections],
        iocs=incident_iocs(db, incident_id, Allowlist(settings.get("iocAllowlist") or [])),
        samples=_samples(db, doc),
        mails=_mails(db, doc),
        branding=settings.get("report") or {},
        generated_by=caller.actor,
        generated_at=now,
    )
    db.add(
        AuditEntry(
            id=str(uuid.uuid4()),
            at=now,
            actor=caller.actor,
            action="report.generate",
            target=doc.get("name"),
            details=f"Generated the incident report ({body.format.upper()}, {lang}, TLP:{tlp.upper()})",
            incident_id=incident_id,
            incident_name=doc.get("name"),
        )
    )
    db.commit()
    if body.format == "html":
        return HTMLResponse(document)
    base = _SAFE_NAME.sub("_", str(doc.get("name") or incident_id)).strip("_") or "incident"
    return Response(
        content=to_pdf(document),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{base}-report.pdf"'},
    )

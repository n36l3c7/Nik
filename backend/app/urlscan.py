"""URL scans: the isolated browser visits an address and Nik weighs what it finds.

``run_scan`` (a background task) opens the URL in the isolated browser worker
with network access, submissions held, and keeps:

- a screenshot (``SAMPLE_STORE/_urls/<id>.jpg``), the final address and title;
- the chain of navigations that led there (redirects, script redirects);
- what the page asks for (its forms, read from the DOM by the worker's
  ``inspect`` action);
- the network log, rebuilt as a capture like any isolated browser session.

``assess`` turns those facts into findings with points, as Mail Analysis does
for a message: a score of 70 or more is ``phishing``, 40 to 69 ``suspicious``,
less ``clean``. Nothing is typed, clicked or submitted during a scan.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import re
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm.attributes import flag_modified

from . import artifacts
from .core.config import settings
from .core.db import SessionLocal
from .core.locking import relock
from .core.models import Incident, NetworkCapture, UrlScan
from .core.security import now_iso
from .enrichment.service import internal_host
from .mail import links
from .mail.verify import org_domain
from .network import service as network_service
from .workers import previews

logger = logging.getLogger("nik.urlscan")

URL_MAX = 2000
RECENT_CERTIFICATE_DAYS = 7
CHAIN_MAX = 15
_ID_RE = re.compile(r"[0-9a-f]{32}")
# Points of the findings links.analyse() reports for an address.
_ADDRESS_POINTS = {
    "lookalike": 40,
    "punycode": 30,
    "userinfo": 30,
    "ip-host": 20,
    "risky-tld": 10,
    "shortener": 10,
    "cloud-hosted": 10,
}


class UrlError(ValueError):
    """The address cannot be scanned (not http/https, internal, too long)."""


def normalise(url: str) -> str:
    """The address as it is scanned: http or https, a public host in lower
    case, no fragment. Defanged text (``hxxp``, ``[.]``) is understood."""
    text = str(url or "").strip().replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")
    text = re.sub(r"^hxxp", "http", text, flags=re.IGNORECASE)
    if not re.match(r"^[a-z][a-z0-9+.-]*://", text, flags=re.IGNORECASE):
        text = "https://" + text
    if len(text) > URL_MAX:
        raise UrlError("The address is too long.")
    parts = urlsplit(text)
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        raise UrlError("Only http and https addresses can be scanned.")
    reason = internal_host(parts.hostname)
    if reason:
        raise UrlError(f"Not scanned: {reason}.")
    netloc = parts.hostname.lower() + (f":{parts.port}" if parts.port else "")
    return urlunsplit((parts.scheme.lower(), netloc, parts.path or "/", parts.query, ""))


def scan_id(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8")).hexdigest()[:32]


def is_scan_id(value: str) -> bool:
    return bool(_ID_RE.fullmatch(value or ""))


def display(url: str) -> str:
    """``host/path`` without the scheme and the query, for lists."""
    parts = urlsplit(url)
    path = parts.path if parts.path not in ("", "/") else ""
    return f"{parts.netloc}{path}"[:160]


def screenshot_path(scan: str) -> Path:
    if not is_scan_id(scan):
        raise ValueError("Not a scan id.")
    folder = Path(settings.SAMPLE_STORE) / "_urls"
    folder.mkdir(parents=True, exist_ok=True)
    return folder / f"{scan}.jpg"


# --------------------------------------------------------------------------- #
# Verdict                                                                     #
# --------------------------------------------------------------------------- #
def _chain(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The main frame's navigations in order: redirects and script redirects."""
    chain = []
    for entry in entries:
        if entry.get("navigation") and entry.get("frame") == "main":
            response = entry.get("response") or {}
            chain.append(
                {
                    "url": str(entry.get("url") or "")[:URL_MAX],
                    "status": response.get("status"),
                    "state": entry.get("state"),
                    "serverIp": response.get("serverIp"),
                }
            )
    return chain[:CHAIN_MAX]


def _certificate(entries: list[dict[str, Any]], final_url: str) -> dict[str, Any] | None:
    for entry in reversed(entries):
        tls = (entry.get("response") or {}).get("tls")
        if tls and entry.get("url") == final_url:
            return tls
    return next(((e.get("response") or {}).get("tls") for e in entries if (e.get("response") or {}).get("tls")), None)


def assess(
    url: str,
    final_url: str,
    title: str,
    page: dict[str, Any],
    chain: list[dict[str, Any]],
    certificate: dict[str, Any] | None,
    events: list[dict[str, Any]],
    own_domains: list[str],
    allowlist=None,
    now: float | None = None,
) -> dict[str, Any]:
    """``{findings, score, verdict}``: each finding is ``{id, points, severity, text}``."""
    findings: list[dict[str, Any]] = []

    def add(key: str, points: int, severity: str, text: str) -> None:
        if not any(f["id"] == key and f["text"] == text for f in findings):
            findings.append({"id": key, "points": points, "severity": severity, "text": text})

    addresses = [{"url": u, "text": "", "kind": "link"} for u in dict.fromkeys([url, final_url]) if u]
    for item in links.analyse(addresses, own_domains, org_domain, allowlist):
        for finding in item["findings"]:
            points = _ADDRESS_POINTS.get(finding["id"])
            if points:
                add(finding["id"], points, finding["severity"], f"{item['displayHost']}: {finding['label']}")

    final_host = links.host_of(final_url or url)
    genuine = org_domain(final_host) in links.GENUINE or org_domain(final_host) in own_domains
    forms = [f for f in page.get("forms") or [] if isinstance(f, dict)]
    asks_password = bool(page.get("passwordFields")) or any(f.get("password") for f in forms)
    if asks_password and not genuine:
        add("password", 25, "high", "the page asks for a password")
        if (final_url or url).lower().startswith("http://"):
            add("password-http", 30, "high", "the password would travel unencrypted (http)")
        lowered = (title or "").lower()
        brand = next((b for b in links.BRANDS if len(b) >= 4 and re.search(rf"\b{re.escape(b)}\b", lowered)), None)
        if brand:
            add("brand", 20, "high", f"the page presents itself as {brand} on a domain that is not its own")
    for form in forms:
        target = links.host_of(str(form.get("action") or ""))
        if target and final_host and org_domain(target) != org_domain(final_host) and not genuine:
            add("form-elsewhere", 25, "high", f"a form sends what is typed to {target}")

    domains = list(dict.fromkeys(org_domain(links.host_of(step["url"])) for step in chain if step.get("url")))
    if len(domains) >= 3:
        add("redirects", 10, "medium", f"reached through {len(domains)} domains: {' → '.join(domains[:6])}")

    issued = (certificate or {}).get("validFrom")
    if isinstance(issued, (int, float)) and issued > 0:
        age = ((now or time.time()) - issued) / 86400
        if 0 <= age < RECENT_CERTIFICATE_DAYS:
            add("new-certificate", 10, "medium", f"certificate issued {int(age)} day(s) ago")

    for event in events:
        if event.get("kind") == "download":
            add("download", 20, "high", str(event.get("text") or "the page started a download")[:200])
        elif event.get("kind") == "error":
            add("load", 0, "low", str(event.get("text") or "the page did not load")[:200])

    findings.sort(key=lambda f: -f["points"])
    score = min(100, sum(f["points"] for f in findings))
    verdict = "phishing" if score >= 70 else "suspicious" if score >= 40 else "clean"
    return {"findings": findings, "score": score, "verdict": verdict}


# --------------------------------------------------------------------------- #
# The scan                                                                    #
# --------------------------------------------------------------------------- #
class _Inline:
    """Stands in for FastAPI's BackgroundTasks inside a background task: run it now."""

    @staticmethod
    def add_task(func, *args) -> None:
        func(*args)


def _own_domains(db: OrmSession) -> tuple[list[str], Any]:
    from .iocs import Allowlist
    from .routers.settings import read_settings

    shared = read_settings(db)
    mail = shared.get("mail") or {}
    own = [str(d).lower() for d in mail.get("orgDomains") or [] if d]
    return own, Allowlist(shared.get("iocAllowlist") or [])


def _fail(scan: str, message: str) -> None:
    with SessionLocal() as db:
        row = db.get(UrlScan, scan)
        if row is None:
            return
        row.status, row.error, row.scanned_at = "error", message[:500], now_iso()
        artifacts.register_url(db, row)
        db.commit()


def run_scan(scan: str, actor: str) -> None:
    """Background task: visit the address and store the result."""
    with SessionLocal() as db:
        row = db.get(UrlScan, scan)
        if row is None:
            return
        url, previous_capture = row.url, row.capture_id
        row.status, row.error = "running", None
        artifacts.register_url(db, row)
        db.commit()

    if not previews.browser_configured():
        return _fail(scan, "The isolated browser is not configured (BROWSER_URL): the address was not visited.")
    try:
        state = previews.open_session(actor, True, None, url)
    except previews.WorkerError as exc:
        return _fail(scan, str(exc))
    session_id = state["id"]
    try:
        try:
            inspected = previews.act(actor, session_id, {"type": "inspect"})
        except previews.WorkerError as exc:
            return _fail(scan, str(exc))
        with SessionLocal() as db:
            row = db.get(UrlScan, scan)
            if row is None:
                return
            # The visit's network log, kept as a capture (an isolated browser session).
            if previous_capture:
                old = db.get(NetworkCapture, previous_capture)
                if old is not None:
                    network_service.remove_capture(db, old)
            stamp = now_iso()
            capture = NetworkCapture(
                id=session_id,
                incident_id=None,
                kind="browser",
                file_name=f"url-scan-{stamp[:19].replace(':', '').replace('-', '')}.pcapng",
                status="live",
                created_at=stamp,
                created_by=actor,
                meta={"owner": actor, "label": display(url), "source": {"url": url}, "network": True, "cursor": 0},
                summary={},
            )
            db.add(capture)
            db.flush()
            try:
                network_service.sync(db, capture)
            except previews.WorkerError:
                logger.info("The network log of scan %s could not be copied", scan)
            entries = network_service.store.read_log(session_id)

            final_url = str(inspected.get("url") or url)[:URL_MAX]
            page = inspected.get("page") if isinstance(inspected.get("page"), dict) else {}
            chain = _chain(entries)
            certificate = _certificate(entries, final_url)
            own, allowlist = _own_domains(db)
            verdict = assess(
                url,
                final_url,
                str(inspected.get("title") or ""),
                page,
                chain,
                certificate,
                inspected.get("events") or [],
                own,
                allowlist,
            )
            shot = inspected.get("screenshot")
            if shot:
                screenshot_path(scan).write_bytes(base64.b64decode(shot))
            row.result = {
                "finalUrl": final_url,
                "title": str(inspected.get("title") or "")[:300],
                "chain": chain,
                "forms": [
                    {
                        "action": str(f.get("action") or "")[:URL_MAX],
                        "method": str(f.get("method") or "get")[:10],
                        "password": bool(f.get("password")),
                        "inputs": len(f.get("inputs") or []),
                    }
                    for f in (page.get("forms") or [])[:20]
                    if isinstance(f, dict)
                ],
                "passwordFields": int(page.get("passwordFields") or 0),
                "counts": {k: int(page.get(k) or 0) for k in ("links", "scripts", "frames")},
                "text": str(page.get("text") or "")[:2000],
                "certificate": certificate,
                "serverIp": next((s["serverIp"] for s in reversed(chain) if s.get("serverIp")), None),
                "requests": len(entries),
                "held": sum(1 for e in entries if e.get("state") == "held"),
                "blocked": sum(1 for e in entries if e.get("state") == "blocked"),
                "events": [
                    {"kind": str(e.get("kind")), "text": str(e.get("text"))[:300]}
                    for e in inspected.get("events") or []
                ],
                "findings": verdict["findings"],
                "screenshot": bool(shot),
            }
            flag_modified(row, "result")
            row.verdict, row.score = verdict["verdict"], verdict["score"]
            row.status, row.error, row.scanned_at, row.capture_id = "done", None, stamp, session_id
            db.flush()
            entry = artifacts.register_url(db, row)
            db.commit()
            try:
                previews.close_session(actor, session_id)
            except previews.WorkerError:
                pass
            network_service.finalize(db, capture, _Inline)
            artifacts.relate(db, entry.id, artifacts.artifact_id("pcap", session_id), "session")
            # The incidents that reference the address take the new verdict and indicators.
            refresh_references(db, row)
            db.commit()
            session_id = None
    finally:
        if session_id:
            try:
                previews.close_session(actor, session_id)
            except previews.WorkerError:
                pass


# --------------------------------------------------------------------------- #
# Rows, incident references, indicators                                       #
# --------------------------------------------------------------------------- #
def register(db: OrmSession, url: str, actor: str) -> UrlScan:
    """The scan row of a (normalised) address, created when it is new."""
    scan = scan_id(url)
    row = db.get(UrlScan, scan)
    if row is None:
        row = UrlScan(
            id=scan,
            url=url,
            host=links.host_of(url),
            status="queued",
            created_at=now_iso(),
            created_by=actor,
            result={},
        )
        db.add(row)
        db.flush()
    artifacts.register_url(db, row)
    return row


def reference(row: UrlScan) -> dict[str, Any]:
    """What an incident keeps for a URL (``data.urls.scans``)."""
    return {
        "id": row.id,
        "url": row.url,
        "host": row.host,
        "status": row.status,
        "verdict": row.verdict,
        "score": row.score,
        "scannedAt": row.scanned_at,
        "createdAt": row.created_at,
        "createdBy": row.created_by,
    }


def _refs(doc: dict[str, Any]) -> list[dict[str, Any]]:
    urls = doc.setdefault("data", {}).setdefault("urls", {})
    if not isinstance(urls, dict):
        urls = doc["data"]["urls"] = {}
    refs = urls.get("scans")
    if not isinstance(refs, list):
        refs = urls["scans"] = []
    return refs


def _save(db: OrmSession, incident: Incident, doc: dict[str, Any]) -> None:
    from .iocs import reindex_incident
    from .routers.incidents import _sync_columns

    doc["updatedAt"] = now_iso()
    incident.doc = doc
    flag_modified(incident, "doc")
    _sync_columns(incident)
    db.flush()
    reindex_incident(db, incident)


def attach(db: OrmSession, incident: Incident, row: UrlScan, actor: str) -> dict[str, Any]:
    doc = dict(relock(db, incident).doc or {})
    refs = _refs(doc)
    ref = next((item for item in refs if item.get("id") == row.id), None)
    if ref is None:
        ref = {**reference(row), "importedAt": now_iso(), "importedBy": actor}
        refs.append(ref)
        _save(db, incident, doc)
    return ref


def detach(db: OrmSession, incident: Incident, scan: str) -> bool:
    doc = dict(relock(db, incident).doc or {})
    refs = _refs(doc)
    kept = [ref for ref in refs if ref.get("id") != scan]
    if len(kept) == len(refs):
        return False
    doc["data"]["urls"]["scans"] = kept
    _save(db, incident, doc)
    return True


def incidents_referencing(db: OrmSession, scan: str) -> list[Incident]:
    from sqlalchemy import select

    from .core.models import ArtifactLink

    ids = db.scalars(
        select(ArtifactLink.incident_id).where(ArtifactLink.artifact_id == artifacts.artifact_id("url", scan))
    ).all()
    return [row for row in (db.get(Incident, item) for item in ids) if row is not None]


def refresh_references(db: OrmSession, row: UrlScan) -> None:
    """Copy the scan's new state into the incidents that reference it."""
    for incident in incidents_referencing(db, row.id):
        doc = dict(relock(db, incident).doc or {})
        refs = _refs(doc)
        for index, ref in enumerate(refs):
            if ref.get("id") == row.id:
                refs[index] = {**ref, **reference(row)}
        _save(db, incident, doc)


def delete(db: OrmSession, row: UrlScan) -> None:
    """Delete the scan everywhere: incident references, screenshot, capture."""
    for incident in incidents_referencing(db, row.id):
        detach(db, incident, row.id)
    if row.capture_id:
        capture = db.get(NetworkCapture, row.capture_id)
        if capture is not None:
            network_service.remove_capture(db, capture)
    screenshot_path(row.id).unlink(missing_ok=True)
    artifacts.forget(db, "url", row.id)
    db.delete(row)


def url_iocs(row: UrlScan) -> list[tuple[str, str]]:
    """Indicators of a scan: the address, where it led, its hosts and server."""
    result = row.result or {}
    found: list[tuple[str, str]] = [("url", row.url)]
    if row.host:
        found.append(("domain", row.host))
    for step in result.get("chain") or []:
        if step.get("url"):
            found.append(("url", step["url"]))
            host = links.host_of(step["url"])
            if host:
                found.append(("domain", host))
        if step.get("serverIp"):
            found.append(("ip", step["serverIp"]))
    for form in result.get("forms") or []:
        host = links.host_of(form.get("action") or "")
        if host:
            found.append(("domain", host))
    return list(dict.fromkeys(found))

"""Where an indicator and an artifact are the same thing seen two ways.

An *indicator* is a value and what others say about it (its reputation). An
*artifact* is what Nik saw when it analysed something: a file, an e-mail, a
capture, an address visited by the isolated browser. This module joins them:

- ``analyses_for``: the artifacts that are the analysis of an indicator (the
  scan of that URL, the scans on that host, the file or e-mail with that hash);
- ``verdicts``: what those analyses conclude, in the words of a reputation, so
  that Nik's own analysis counts among an indicator's sources;
- ``standalone``: the indicators of the artifacts no incident references, so
  that the IoC library holds them too;
- ``indicator_of``: the indicator an artifact is the analysis of.
"""

from __future__ import annotations

import time
from typing import Any, Iterable

from sqlalchemy import func, select
from sqlalchemy.orm import Session as OrmSession

from . import artifacts, urlscan
from .core.models import Artifact, ArtifactLink, Mail, NetworkCapture, Sample, UrlScan
from .iocs import TYPES, capture_iocs, normalize, quiet_mail

Pair = tuple[str, str]
SOURCE = "nik"  # Nik's own analysis among an indicator's sources
LABEL = "Nik's analysis"
# An artifact's verdict in the words of a reputation. A clean scan or a file
# with no rule match is not a judgement that the value is harmless: it is left out.
_REPUTATION = {"phishing": "malicious", "high": "malicious", "malicious": "malicious"}
_REPUTATION.update({"suspicious": "suspicious", "medium": "suspicious"})
_RANK = {"malicious": 2, "suspicious": 1}
STANDALONE_MAX = 400
_CACHE_SECONDS = 20
_cache: dict[str, Any] = {"key": None, "at": 0.0, "value": {}}


def scan_id_of(url: str) -> str | None:
    """The id of the scan of an address, or None when it cannot be scanned."""
    try:
        return urlscan.scan_id(urlscan.normalise(url))
    except urlscan.UrlError:
        return None


def brief(row: Artifact) -> dict[str, Any]:
    return {
        "id": row.id,
        "kind": row.kind,
        "name": row.name or f"{row.ref[:16]}…",
        "verdict": row.verdict,
        "score": row.score,
        "detail": row.detail,
        "createdAt": row.created_at,
        "createdBy": row.created_by,
    }


def analyses_for(db: OrmSession, pairs: Iterable[Pair]) -> dict[Pair, list[Artifact]]:
    """The artifacts that are the analysis of each indicator, newest first."""
    wanted = list(dict.fromkeys(pairs))
    found: dict[Pair, list[Artifact]] = {}
    ids: dict[str, list[Pair]] = {}
    for kind, value in wanted:
        if kind == "url":
            scan = scan_id_of(value)
            if scan:
                ids.setdefault(artifacts.artifact_id("url", scan), []).append((kind, value))
        elif kind == "sha256":
            for prefix in ("file", "mail"):
                ids.setdefault(f"{prefix}-{value}", []).append((kind, value))
    # A file known by its MD5 or SHA-1.
    for column, kind in ((Sample.md5, "md5"), (Sample.sha1, "sha1")):
        values = [v for k, v in wanted if k == kind]
        for start in range(0, len(values), 500):
            for digest, sha256 in db.execute(
                select(column, Sample.sha256).where(column.in_(values[start : start + 500]))
            ):
                ids.setdefault(f"file-{sha256}", []).append((kind, digest))
    # The scans on a host are the analyses of that domain.
    domains = [v for k, v in wanted if k == "domain"]
    for start in range(0, len(domains), 500):
        chunk = domains[start : start + 500]
        for scan, host in db.execute(select(UrlScan.id, UrlScan.host).where(UrlScan.host.in_(chunk))):
            ids.setdefault(artifacts.artifact_id("url", scan), []).append(("domain", host))
    keys = list(ids)
    for start in range(0, len(keys), 500):
        rows = db.scalars(select(Artifact).where(Artifact.id.in_(keys[start : start + 500])))
        for row in rows:
            for pair in ids[row.id]:
                found.setdefault(pair, []).append(row)
    for rows in found.values():
        rows.sort(key=lambda r: r.created_at, reverse=True)
    return found


def reputation(row: Artifact) -> str | None:
    """What the analysis concludes about the value, or None when it flags nothing."""
    return _REPUTATION.get(str(row.verdict or "").lower())


def verdicts(db: OrmSession, pairs: Iterable[Pair]) -> dict[Pair, str]:
    """``pair -> malicious | suspicious`` for the indicators Nik's own analysis flags."""
    out: dict[Pair, str] = {}
    for pair, rows in analyses_for(db, pairs).items():
        worst = max((reputation(row) for row in rows), key=lambda v: _RANK.get(v or "", 0), default=None)
        if worst:
            # A page on a host says little about the whole domain (a shortener,
            # a hosting service): for a domain the analysis is a warning at most.
            out[pair] = "suspicious" if pair[0] == "domain" else worst
    return out


def indicator_of(db: OrmSession, row: Artifact) -> dict[str, str] | None:
    """The indicator this artifact is the analysis of: a file's or an e-mail's
    SHA-256, a scan's address. A capture is the analysis of no single value."""
    if row.kind in ("file", "mail"):
        return {"type": "sha256", "value": row.ref}
    if row.kind == "url":
        scan = db.get(UrlScan, row.ref)
        return {"type": "url", "value": scan.url} if scan is not None else None
    return None


# --------------------------------------------------------------------------- #
# Indicators of the artifacts no incident references                          #
# --------------------------------------------------------------------------- #
def _indicators(db: OrmSession, row: Artifact) -> list[Pair]:
    found: list[Pair] = []
    if row.kind == "file":
        sample = db.get(Sample, row.ref)
        if sample is not None:
            found += [("sha256", sample.sha256), ("sha1", sample.sha1), ("md5", sample.md5)]
            for ioc in (sample.analysis or {}).get("iocs") or []:
                if ioc.get("kind") in ("url", "domain", "ip", "email"):
                    found.append((ioc["kind"], ioc.get("value")))
    elif row.kind == "mail":
        mail = db.get(Mail, row.ref)
        found.append(("sha256", row.ref))
        if mail is not None and quiet_mail(mail):
            return found
        for ioc in ((mail.analysis or {}).get("iocs") if mail is not None else None) or []:
            if ioc.get("type") in TYPES:
                found.append((ioc["type"], ioc.get("value")))
    elif row.kind == "pcap":
        capture = db.get(NetworkCapture, row.ref)
        if capture is not None:
            found += [(kind, value) for kind, value, _when in capture_iocs(capture.summary or {})]
    elif row.kind == "url":
        scan = db.get(UrlScan, row.ref)
        if scan is not None:
            found += urlscan.url_iocs(scan)
    clean = []
    for kind, value in found:
        normal = normalize(kind, str(value or "")) if kind in TYPES else None
        if normal:
            clean.append((kind, normal))
    return list(dict.fromkeys(clean))[:2000]


def standalone(db: OrmSession) -> dict[Pair, list[dict[str, Any]]]:
    """``pair -> [artifact brief]`` for the artifacts analysed on their own.
    Kept for a few seconds: the library asks for it at every page."""
    linked = select(ArtifactLink.artifact_id)
    count, newest = db.execute(
        select(func.count(), func.max(Artifact.created_at)).where(Artifact.id.not_in(linked))
    ).one()
    key = (count, newest, db.scalar(select(func.max(UrlScan.scanned_at))))
    if _cache["key"] == key and time.monotonic() - _cache["at"] < _CACHE_SECONDS:
        return _cache["value"]
    rows = db.scalars(
        select(Artifact).where(Artifact.id.not_in(linked)).order_by(Artifact.created_at.desc()).limit(STANDALONE_MAX)
    ).all()
    out: dict[Pair, list[dict[str, Any]]] = {}
    for row in rows:
        summary = brief(row)
        for pair in _indicators(db, row):
            out.setdefault(pair, []).append(summary)
    _cache.update(key=key, at=time.monotonic(), value=out)
    return out


def reset_cache() -> None:
    _cache.update(key=None, at=0.0, value={})

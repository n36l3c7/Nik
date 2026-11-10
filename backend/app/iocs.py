"""Indicators of compromise across every tab and every incident.

Each time an incident's data changes, ``reindex_incident`` extracts the
indicators it holds and stores one ``ioc_index`` row per (incident, type,
value): where in the incident it was seen (``sources``), how many times, and
the first and last time. The rows answer "where else have we seen this?" for
every analyst without opening any other incident.

Types: ``ip``, ``domain``, ``url``, ``email``, ``md5``, ``sha1``, ``sha256``.

Sources:
- browser history: the visited hosts (not every URL: thousands, mostly noise);
- browser downloads: the download URL, its referrer and their hosts;
- shell commands, endpoint records: indicators in the text;
- Windows event logs: address and host fields, and indicators in command
  lines, script blocks and service paths;
- malware samples: the sample's hashes and the indicators in its strings;
- e-mails (Mail Analysis): sender addresses and domain, sending IP, link
  targets and hosts, attachment hashes, QR-code and invitation links.

The allowlist (Settings) hides well-known domains and private addresses when
the index is read; the index itself keeps everything, so editing the list
needs no reindex.
"""

from __future__ import annotations

import ipaddress
import re
import uuid
from collections.abc import Iterable
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import and_, delete, func, select
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm import aliased

from .models import Incident, IocEntry, Mail, Sample
from .parsing.malware import _FALSE_POSITIVE_DOMAINS, _IOC_PATTERNS

TYPES = ("ip", "domain", "url", "email", "md5", "sha1", "sha256")
MAX_PER_INCIDENT = 20_000
MAX_VALUE = 1024

# Text patterns: the sample-strings patterns for network indicators, plus hashes.
_TEXT_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (kind, pattern) for kind, pattern in _IOC_PATTERNS if kind in ("url", "email", "ip", "domain")
] + [
    ("sha256", re.compile(r"\b[a-fA-F0-9]{64}\b")),
    ("sha1", re.compile(r"\b[a-fA-F0-9]{40}\b")),
    ("md5", re.compile(r"\b[a-fA-F0-9]{32}\b")),
]
_HASH_FIELD = re.compile(r"\b(MD5|SHA1|SHA256)=([A-Fa-f0-9]{32,64})")

# Event-log fields that hold an address or a host name.
_EVENT_IP_FIELDS = ("IpAddress", "ClientAddress", "Address", "Param3", "SourceIp", "DestinationIp")
_EVENT_HOST_FIELDS = ("DestinationHostname", "QueryName")
_EVENT_TEXT_FIELDS = ("CommandLine", "ScriptBlockText", "Payload", "ImagePath", "ServiceFileName", "Image")

DEFAULT_ALLOWLIST: list[str] = [
    # Private, loopback, link-local and other non-routable addresses.
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "0.0.0.0/8",
    "::1/128",
    "fe80::/10",
    "fc00::/7",
    "localhost",
    # Operating-system and browser vendors, CDNs and certificate authorities
    # that every host talks to.
    "microsoft.com",
    "windows.com",
    "windowsupdate.com",
    "msftconnecttest.com",
    "live.com",
    "office.com",
    "office.net",
    "bing.com",
    "msn.com",
    "azureedge.net",
    "google.com",
    "googleapis.com",
    "gstatic.com",
    "googleusercontent.com",
    "gvt1.com",
    "youtube.com",
    "apple.com",
    "icloud.com",
    "mzstatic.com",
    "mozilla.org",
    "mozilla.net",
    "firefox.com",
    "akamaihd.net",
    "akamaized.net",
    "cloudflare.com",
    "digicert.com",
    "verisign.com",
    "letsencrypt.org",
    "ubuntu.com",
    "debian.org",
    "redhat.com",
]


def normalize(kind: str, value: str) -> str | None:
    """The stored spelling of an indicator (lower-case hosts and hashes), or None if invalid."""
    text = str(value or "").strip().rstrip(".,;:)]}'\"")
    if not text or len(text) > MAX_VALUE:
        return None
    if kind in ("domain", "email", "md5", "sha1", "sha256"):
        text = text.lower()
    if kind == "domain":
        if _FALSE_POSITIVE_DOMAINS.match(text) or "." not in text:
            return None
    if kind == "ip":
        try:
            text = str(ipaddress.ip_address(text.split("%")[0].strip("[]")))
        except ValueError:
            return None
    return text


def _host(url: str) -> tuple[str, str] | None:
    """The host of a URL as ``(type, value)``: an ``ip`` or a ``domain``."""
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return None
    if not host:
        return None
    try:
        return "ip", str(ipaddress.ip_address(host))
    except ValueError:
        return ("domain", host.lower()) if "." in host else None


def text_iocs(text: str) -> list[tuple[str, str]]:
    """Indicators in free text; a host inside a URL is reported as its own domain too."""
    found: list[tuple[str, str]] = []
    if not text:
        return found
    text = str(text)[:20_000]
    for algo, digest in _HASH_FIELD.findall(text):
        found.append((algo.lower(), digest.lower()))
    covered: set[str] = set()
    for kind, pattern in _TEXT_PATTERNS:
        for match in pattern.finditer(text):
            value = match.group()
            lowered = value.lower()
            # A digest inside a longer one, or a host inside a URL or an e-mail
            # address already found (the URL's host is added below).
            if kind in ("md5", "sha1", "domain", "ip", "email") and any(lowered in c for c in covered):
                continue
            covered.add(lowered)
            found.append((kind, value))
            if kind == "url":
                host = _host(value)
                if host:
                    found.append(host)
    return found


class _Collector:
    """Accumulates ``(type, value) → {sources, count, first, last}``."""

    def __init__(self) -> None:
        self.items: dict[tuple[str, str], dict[str, Any]] = {}

    def add(self, kind: str, value: Any, source: str, time_ms: Any = None) -> None:
        cleaned = normalize(kind, value)
        if cleaned is None:
            return
        key = (kind, cleaned)
        item = self.items.get(key)
        if item is None:
            if len(self.items) >= MAX_PER_INCIDENT:
                return
            item = self.items[key] = {"sources": set(), "count": 0, "first": None, "last": None}
        item["sources"].add(source)
        item["count"] += 1
        if isinstance(time_ms, (int, float)) and time_ms > 0:
            t = int(time_ms)
            item["first"] = t if item["first"] is None else min(item["first"], t)
            item["last"] = t if item["last"] is None else max(item["last"], t)

    def add_text(self, text: Any, source: str, time_ms: Any = None) -> None:
        for kind, value in text_iocs(text):
            self.add(kind, value, source, time_ms)

    def add_url(self, url: Any, source: str, time_ms: Any = None) -> None:
        if not url or not re.match(r"^(?:https?|ftp)://", str(url), re.IGNORECASE):
            return
        self.add("url", url, source, time_ms)
        host = _host(str(url))
        if host:
            self.add(host[0], host[1], source, time_ms)


def _dicts(value: Any) -> Iterable[dict]:
    if isinstance(value, dict):
        return (v for v in value.values() if isinstance(v, dict))
    return ()


def extract(
    doc: dict, samples: dict[str, Sample] | None = None, mails: dict[str, Mail] | None = None
) -> dict[tuple[str, str], dict[str, Any]]:
    """Every indicator of an incident document (see the module docstring)."""
    data = doc.get("data") if isinstance(doc.get("data"), dict) else {}
    out = _Collector()

    for browser_id, slot in ((k, v) for k, v in (data.get("browser", {}).get("browsers") or {}).items()):
        source = f"browser:{browser_id}"
        for profile in _dicts((slot or {}).get("profiles")):
            for entry in profile.get("history") or []:
                host = _host(str(entry.get("url") or "")) if isinstance(entry, dict) else None
                if host:
                    out.add(host[0], host[1], source, entry.get("visitTime"))
            for entry in profile.get("downloads") or []:
                if not isinstance(entry, dict):
                    continue
                out.add_url(entry.get("url"), source, entry.get("startTime"))
                out.add_url(entry.get("referrer"), source, entry.get("startTime"))

    for shell_id, slot in (data.get("commands", {}).get("shells") or {}).items():
        for entry in (slot or {}).get("commands") or []:
            if isinstance(entry, dict):
                out.add_text(entry.get("command"), f"commands:{shell_id}", entry.get("time"))

    for category_id, category in (data.get("endpoint", {}).get("categories") or {}).items():
        for source_slot in _dicts((category or {}).get("sources")):
            for record in source_slot.get("records") or []:
                if isinstance(record, dict):
                    fields = record.get("fields") or {}
                    text = " ".join(str(v) for v in fields.values() if v)
                    out.add_text(text, f"endpoint:{category_id}", record.get("time"))

    for channel, slot in (data.get("eventlogs", {}).get("channels") or {}).items():
        source = f"eventlog:{channel}"
        for event in (slot or {}).get("events") or []:
            if not isinstance(event, dict):
                continue
            fields = event.get("data") or {}
            when = event.get("time")
            for name in _EVENT_IP_FIELDS:
                value = str(fields.get(name) or "")
                if re.match(r"^[\d.]+$|^[0-9a-fA-F:]+$", value) and value not in ("LOCAL", "0", "::"):
                    out.add("ip", value, source, when)
            for name in _EVENT_HOST_FIELDS:
                if fields.get(name):
                    out.add("domain", fields[name], source, when)
            if fields.get("Hashes"):
                out.add_text(fields["Hashes"], source, when)
            for name in _EVENT_TEXT_FIELDS:
                if fields.get(name):
                    out.add_text(fields[name], source, when)

    for ref in (data.get("malware") or {}).get("samples") or []:
        if not isinstance(ref, dict):
            continue
        when = _iso_ms(ref.get("importedAt"))
        source = f"sample:{ref.get('fileName') or str(ref.get('sha256', ''))[:12]}"
        for algo in ("sha256", "sha1", "md5"):
            if ref.get(algo):
                out.add(algo, ref[algo], source, when)
        row = (samples or {}).get(ref.get("sha256"))
        for ioc in (row.analysis.get("iocs") if row is not None else None) or []:
            if ioc.get("kind") in ("url", "domain", "ip", "email"):
                out.add(ioc["kind"], ioc.get("value"), source, when)

    for ref in (data.get("mail") or {}).get("messages") or []:
        if not isinstance(ref, dict):
            continue
        source = f"mail:{ref.get('fileName') or str(ref.get('sha256', ''))[:12]}"
        when = ref.get("date") or _iso_ms(ref.get("importedAt"))
        mail = (mails or {}).get(ref.get("sha256"))
        for ioc in (mail.analysis.get("iocs") if mail is not None else None) or []:
            if ioc.get("type") in TYPES:
                out.add(ioc["type"], ioc.get("value"), source, when)

    return out.items


def _iso_ms(value: Any) -> int | None:
    from datetime import datetime

    try:
        return int(datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp() * 1000)
    except (TypeError, ValueError):
        return None


def reindex_incident(db: OrmSession, row: Incident) -> int:
    """Replace the incident's index rows with what its document holds now."""
    doc = row.doc or {}
    refs = ((doc.get("data") or {}).get("malware") or {}).get("samples") or []
    digests = [r.get("sha256") for r in refs if isinstance(r, dict) and r.get("sha256")]
    samples = {s.sha256: s for s in db.scalars(select(Sample).where(Sample.sha256.in_(digests)))} if digests else {}
    mail_refs = ((doc.get("data") or {}).get("mail") or {}).get("messages") or []
    mail_digests = [r.get("sha256") for r in mail_refs if isinstance(r, dict) and r.get("sha256")]
    mails = {m.sha256: m for m in db.scalars(select(Mail).where(Mail.sha256.in_(mail_digests)))} if mail_digests else {}
    items = extract(doc, samples, mails)
    db.execute(delete(IocEntry).where(IocEntry.incident_id == row.id))
    db.add_all(
        IocEntry(
            incident_id=row.id,
            type=kind,
            value=value,
            sources=sorted(item["sources"]),
            count=item["count"],
            first_seen=item["first"],
            last_seen=item["last"],
        )
        for (kind, value), item in items.items()
    )
    return len(items)


def reindex_all(db: OrmSession) -> int:
    """Rebuild the whole index (backup restore)."""
    count = 0
    for row in db.scalars(select(Incident)):
        count += reindex_incident(db, row)
    return count


def backfill(session_factory) -> int:
    """Index the incidents of a database that has no index yet (the first start
    after the upgrade that added it). One transaction per incident, so several
    api workers starting together only repeat each other's work."""
    with session_factory() as db:
        if db.scalar(select(IocEntry.incident_id).limit(1)) is not None:
            return 0
        ids = list(db.scalars(select(Incident.id)))
    indexed = 0
    for incident_id in ids:
        with session_factory() as db:
            row = db.get(Incident, incident_id)
            if row is None:
                continue
            try:
                indexed += reindex_incident(db, row)
                db.commit()
            except Exception:  # noqa: BLE001 - another worker got there first
                db.rollback()
    return indexed


def incident_iocs(db: OrmSession, incident_id: str, allowlist: Allowlist) -> list[dict[str, Any]]:
    """The incident's indicators with the number of OTHER incidents each is in."""
    other = aliased(IocEntry)
    counts = db.execute(
        select(IocEntry.type, IocEntry.value, func.count(other.incident_id))
        .join(
            other,
            and_(
                other.type == IocEntry.type,
                other.value == IocEntry.value,
                other.incident_id != IocEntry.incident_id,
            ),
        )
        .where(IocEntry.incident_id == incident_id)
        .group_by(IocEntry.type, IocEntry.value)
    )
    shared = {(kind, value): n for kind, value, n in counts}
    rows = db.scalars(select(IocEntry).where(IocEntry.incident_id == incident_id)).all()
    return [
        {
            "type": row.type,
            "value": row.value,
            "sources": row.sources,
            "count": row.count,
            "firstSeen": row.first_seen,
            "lastSeen": row.last_seen,
            "otherIncidents": shared.get((row.type, row.value), 0),
            "allowlisted": allowlist.matches(row.type, row.value),
        }
        for row in rows
    ]


# --------------------------------------------------------------------------- #
# Allowlist                                                                   #
# --------------------------------------------------------------------------- #
class Allowlist:
    """Entries: a domain (matches its subdomains, and URLs and e-mail addresses
    on it), an IP address or CIDR network, or any exact value (a hash)."""

    def __init__(self, entries: Iterable[str]) -> None:
        self.networks = []
        self.domains: set[str] = set()
        self.exact: set[str] = set()
        for raw in entries:
            entry = str(raw or "").strip().lower()
            if not entry or entry.startswith("#"):
                continue
            try:
                self.networks.append(ipaddress.ip_network(entry, strict=False))
                continue
            except ValueError:
                pass
            if re.fullmatch(r"[a-z0-9.-]+\.[a-z0-9-]+|localhost", entry):
                self.domains.add(entry.lstrip("."))
            else:
                self.exact.add(entry)

    def _domain(self, host: str) -> bool:
        host = host.lower().rstrip(".")
        parts = host.split(".")
        return any(".".join(parts[i:]) in self.domains for i in range(len(parts)))

    def _ip(self, value: str) -> bool:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return False
        return any(address in network for network in self.networks if network.version == address.version)

    def matches(self, kind: str, value: str) -> bool:
        if value.lower() in self.exact:
            return True
        if kind == "ip":
            return self._ip(value)
        if kind == "domain":
            return self._domain(value)
        if kind == "email":
            return self._domain(value.rsplit("@", 1)[-1])
        if kind == "url":
            host = _host(value)
            if host is None:
                return False
            return self._ip(host[1]) if host[0] == "ip" else self._domain(host[1])
        return False


# --------------------------------------------------------------------------- #
# Export                                                                      #
# --------------------------------------------------------------------------- #
_STIX_NAMESPACE = uuid.UUID("6c8f2d8e-7a33-4f0e-9f1d-6a3c1d2e5b10")
_STIX_PATTERNS = {
    "ip": lambda v: f"[{'ipv6' if ':' in v else 'ipv4'}-addr:value = '{v}']",
    "domain": lambda v: f"[domain-name:value = '{v}']",
    "url": lambda v: f"[url:value = '{v}']",
    "email": lambda v: f"[email-addr:value = '{v}']",
    "md5": lambda v: f"[file:hashes.MD5 = '{v}']",
    "sha1": lambda v: f"[file:hashes.'SHA-1' = '{v}']",
    "sha256": lambda v: f"[file:hashes.'SHA-256' = '{v}']",
}
_MISP_TYPES = {
    "ip": ("ip-dst", "Network activity"),
    "domain": ("domain", "Network activity"),
    "url": ("url", "Network activity"),
    "email": ("email-src", "Payload delivery"),
    "md5": ("md5", "Payload delivery"),
    "sha1": ("sha1", "Payload delivery"),
    "sha256": ("sha256", "Payload delivery"),
}


def _stix_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _ms_iso(ms: int | None, fallback: str) -> str:
    from datetime import datetime, timezone

    if not ms:
        return fallback
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def stix_bundle(incident: dict, iocs: list[dict], now: str) -> dict:
    """A STIX 2.1 bundle: the producer identity, one indicator per IOC and a report."""
    identity_id = f"identity--{uuid.uuid5(_STIX_NAMESPACE, 'nik')}"
    created = now.replace("+00:00", "Z")
    indicators = []
    for ioc in iocs:
        value = _stix_escape(ioc["value"])
        indicators.append(
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid5(_STIX_NAMESPACE, ioc['type'] + ':' + ioc['value'])}",
                "created_by_ref": identity_id,
                "created": created,
                "modified": created,
                "name": f"{ioc['type']}: {ioc['value']}"[:250],
                "description": f"Seen in {', '.join(ioc['sources'])} ({ioc['count']} times).",
                "indicator_types": ["malicious-activity"],
                "pattern": _STIX_PATTERNS[ioc["type"]](value),
                "pattern_type": "stix",
                "valid_from": _ms_iso(ioc.get("firstSeen"), created),
            }
        )
    report = {
        "type": "report",
        "spec_version": "2.1",
        "id": f"report--{uuid.uuid5(_STIX_NAMESPACE, 'incident:' + str(incident.get('id')))}",
        "created_by_ref": identity_id,
        "created": created,
        "modified": created,
        "name": str(incident.get("name") or incident.get("id")),
        "report_types": ["incident"],
        "published": created,
        "object_refs": [i["id"] for i in indicators] or [identity_id],
    }
    identity = {
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": created,
        "modified": created,
        "name": "Nik",
        "identity_class": "system",
    }
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": [identity, *indicators, report]}


def misp_event(incident: dict, iocs: list[dict], now: str) -> dict:
    """A MISP event (JSON import format), unpublished and limited to the organisation."""
    attributes = []
    for ioc in iocs:
        misp_type, category = _MISP_TYPES[ioc["type"]]
        attributes.append(
            {
                "type": misp_type,
                "category": category,
                "value": ioc["value"],
                "to_ids": True,
                "comment": f"Seen in {', '.join(ioc['sources'])}"[:255],
                "uuid": str(uuid.uuid5(_STIX_NAMESPACE, ioc["type"] + ":" + ioc["value"])),
            }
        )
    return {
        "Event": {
            "info": f"Nik incident: {incident.get('name') or incident.get('id')}",
            "date": now[:10],
            "threat_level_id": "2",
            "analysis": "1",
            "distribution": "0",
            "published": False,
            "uuid": str(uuid.uuid5(_STIX_NAMESPACE, "incident:" + str(incident.get("id")))),
            "Attribute": attributes,
        }
    }

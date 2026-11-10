"""Threat-intelligence providers: one function per service, one shape out.

Each lookup returns ``{verdict, summary, link, data}``:

- ``verdict``: ``malicious``, ``suspicious``, ``harmless`` or ``unknown``
  (not known to the service, or nothing conclusive);
- ``summary``: one line for the analyst ("12/94 engines", "confidence 100 %");
- ``link``: the provider's page about the indicator;
- ``data``: the few fields worth showing (never the whole answer).

Requests go out with ``urllib`` (the standard library), so the usual
``HTTPS_PROXY`` / ``NO_PROXY`` variables apply; a transparent proxy needs
nothing. Every request times out after ``TIMEOUT`` seconds.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable

TIMEOUT = 15
USER_AGENT = "Nik-forensics (threat-intel lookup)"
HASHES = ("md5", "sha1", "sha256")


class ProviderError(Exception):
    """A lookup that gave no answer. ``kind``: auth, rate, http, network."""

    def __init__(self, kind: str, message: str) -> None:
        super().__init__(message)
        self.kind = kind


def _request(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    form: dict[str, str] | None = None,
    body: Any = None,
) -> tuple[int, Any]:
    """``(status, parsed JSON or None)``; 404 is an answer, not an error."""
    data = None
    all_headers = {"User-Agent": USER_AGENT, "Accept": "application/json", **(headers or {})}
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        all_headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif body is not None:
        data = json.dumps(body).encode()
        all_headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=all_headers, method="POST" if data else "GET")
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:  # noqa: S310 - fixed provider URLs
            raw = response.read(2_000_000)
            status = response.status
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return 404, None
        if exc.code in (401, 403):
            raise ProviderError("auth", f"the provider refused the key (HTTP {exc.code})") from exc
        if exc.code == 429:
            raise ProviderError("rate", "rate limit reached") from exc
        raise ProviderError("http", f"HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ProviderError("network", f"cannot reach the provider: {getattr(exc, 'reason', exc)}") from exc
    try:
        return status, json.loads(raw) if raw else None
    except ValueError as exc:
        raise ProviderError("http", "the answer is not JSON") from exc


def _result(verdict: str, summary: str, link: str = "", **data: Any) -> dict[str, Any]:
    return {"verdict": verdict, "summary": summary, "link": link, "data": {k: v for k, v in data.items() if v}}


def _host(url: str) -> str:
    try:
        return (urllib.parse.urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


# --------------------------------------------------------------------------- #
# VirusTotal                                                                  #
# --------------------------------------------------------------------------- #
def virustotal(kind: str, value: str, key: str | None) -> dict[str, Any]:
    if kind in HASHES:
        path, page = f"files/{value}", f"file/{value}"
    elif kind == "ip":
        path, page = f"ip_addresses/{value}", f"ip-address/{value}"
    elif kind == "domain":
        path, page = f"domains/{value}", f"domain/{value}"
    else:
        ident = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
        path, page = f"urls/{ident}", f"url/{ident}"
    link = f"https://www.virustotal.com/gui/{page}"
    status, answer = _request(f"https://www.virustotal.com/api/v3/{path}", headers={"x-apikey": key or ""})
    if status == 404 or not answer:
        return _result("unknown", "not in VirusTotal", link)
    attributes = (answer.get("data") or {}).get("attributes") or {}
    stats = attributes.get("last_analysis_stats") or {}
    malicious, suspicious = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0))
    total = sum(int(v) for v in stats.values() if isinstance(v, int))
    if malicious >= 3:
        verdict = "malicious"
    elif malicious or suspicious:
        verdict = "suspicious"
    elif stats.get("harmless"):
        verdict = "harmless"
    else:
        verdict = "unknown"
    return _result(
        verdict,
        f"{malicious}/{total} engines flag it" + (f", {suspicious} suspicious" if suspicious else ""),
        link,
        name=attributes.get("meaningful_name"),
        type=attributes.get("type_description"),
        label=(attributes.get("popular_threat_classification") or {}).get("suggested_threat_label"),
        tags=(attributes.get("tags") or [])[:8],
        country=attributes.get("country"),
        owner=attributes.get("as_owner"),
        reputation=attributes.get("reputation"),
    )


# --------------------------------------------------------------------------- #
# AbuseIPDB                                                                   #
# --------------------------------------------------------------------------- #
def abuseipdb(kind: str, value: str, key: str | None) -> dict[str, Any]:
    query = urllib.parse.urlencode({"ipAddress": value, "maxAgeInDays": 90})
    _, answer = _request(f"https://api.abuseipdb.com/api/v2/check?{query}", headers={"Key": key or ""})
    info = (answer or {}).get("data") or {}
    score, reports = int(info.get("abuseConfidenceScore") or 0), int(info.get("totalReports") or 0)
    if info.get("isWhitelisted"):
        verdict = "harmless"
    elif score >= 75:
        verdict = "malicious"
    elif score >= 25:
        verdict = "suspicious"
    else:
        verdict = "unknown"
    return _result(
        verdict,
        f"confidence {score} %, {reports} report{'s' if reports != 1 else ''} in 90 days",
        f"https://www.abuseipdb.com/check/{value}",
        country=info.get("countryCode"),
        isp=info.get("isp"),
        usage=info.get("usageType"),
        domain=info.get("domain"),
        lastReported=info.get("lastReportedAt"),
    )


# --------------------------------------------------------------------------- #
# urlscan.io                                                                  #
# --------------------------------------------------------------------------- #
def _lucene(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def urlscan(kind: str, value: str, key: str | None) -> dict[str, Any]:
    query = f"page.domain:{_lucene(value)}" if kind == "domain" else f"page.url:{_lucene(value)}"
    params = urllib.parse.urlencode({"q": query, "size": 10})
    _, answer = _request(f"https://urlscan.io/api/v1/search/?{params}", headers={"API-Key": key} if key else None)
    results = (answer or {}).get("results") or []
    total = int((answer or {}).get("total") or len(results))
    link = "https://urlscan.io/search/#" + urllib.parse.quote(query)
    if not results:
        return _result("unknown", "never scanned on urlscan.io", link)
    malicious = [r for r in results if ((r.get("verdicts") or {}).get("overall") or {}).get("malicious")]
    last = results[0]
    return _result(
        "malicious" if malicious else "unknown",
        f"{total} public scan{'s' if total != 1 else ''}"
        + (f", {len(malicious)} judged malicious" if malicious else ""),
        link,
        lastScan=(last.get("task") or {}).get("time"),
        lastUrl=(last.get("page") or {}).get("url"),
        ip=(last.get("page") or {}).get("ip"),
        country=(last.get("page") or {}).get("country"),
        screenshot=last.get("screenshot"),
    )


# --------------------------------------------------------------------------- #
# abuse.ch: ThreatFox, URLhaus, MalwareBazaar (one Auth-Key)                  #
# --------------------------------------------------------------------------- #
def abusech(kind: str, value: str, key: str | None) -> dict[str, Any]:
    headers = {"Auth-Key": key or ""}
    _, fox = _request(
        "https://threatfox-api.abuse.ch/api/v1/",
        headers=headers,
        body={"query": "search_hash", "hash": value}
        if kind in HASHES
        else {"query": "search_ioc", "search_term": value, "exact_match": True},
    )
    if (fox or {}).get("query_status") == "ok" and fox.get("data"):
        first = fox["data"][0]
        return _result(
            "malicious",
            f"ThreatFox: {first.get('malware_printable') or first.get('threat_type') or 'known IOC'}"
            f" ({first.get('threat_type_desc') or first.get('threat_type') or ''})".rstrip(" ()"),
            f"https://threatfox.abuse.ch/ioc/{first.get('id')}/" if first.get("id") else "https://threatfox.abuse.ch/",
            malware=first.get("malware_printable"),
            confidence=first.get("confidence_level"),
            firstSeen=first.get("first_seen"),
            tags=(first.get("tags") or [])[:8],
        )
    if kind in HASHES:
        _, bazaar = _request(
            "https://mb-api.abuse.ch/api/v1/", headers=headers, form={"query": "get_info", "hash": value}
        )
        if (bazaar or {}).get("query_status") == "ok" and bazaar.get("data"):
            sample = bazaar["data"][0]
            return _result(
                "malicious",
                f"MalwareBazaar: {sample.get('signature') or 'known malware sample'}",
                f"https://bazaar.abuse.ch/sample/{sample.get('sha256_hash')}/",
                signature=sample.get("signature"),
                fileType=sample.get("file_type"),
                firstSeen=sample.get("first_seen"),
                tags=(sample.get("tags") or [])[:8],
            )
        return _result("unknown", "not in ThreatFox or MalwareBazaar", "https://bazaar.abuse.ch/")
    if kind == "url":
        _, haus = _request("https://urlhaus-api.abuse.ch/v1/url/", headers=headers, form={"url": value})
        if (haus or {}).get("query_status") == "ok":
            return _result(
                "malicious",
                f"URLhaus: {haus.get('threat') or 'malware URL'} ({haus.get('url_status') or 'status unknown'})",
                haus.get("urlhaus_reference") or "https://urlhaus.abuse.ch/",
                status=haus.get("url_status"),
                dateAdded=haus.get("date_added"),
                tags=(haus.get("tags") or [])[:8],
            )
        return _result("unknown", "not in ThreatFox or URLhaus", "https://urlhaus.abuse.ch/")
    _, haus = _request("https://urlhaus-api.abuse.ch/v1/host/", headers=headers, form={"host": value})
    if (haus or {}).get("query_status") == "ok" and int(haus.get("url_count") or 0):
        count = int(haus["url_count"])
        return _result(
            "suspicious",
            f"URLhaus: {count} malware URL{'s' if count != 1 else ''} on this host",
            haus.get("urlhaus_reference") or "https://urlhaus.abuse.ch/",
            firstSeen=haus.get("firstseen"),
        )
    return _result("unknown", "not in ThreatFox or URLhaus", "https://urlhaus.abuse.ch/")


# --------------------------------------------------------------------------- #
# AlienVault OTX                                                              #
# --------------------------------------------------------------------------- #
def otx(kind: str, value: str, key: str | None) -> dict[str, Any]:
    if kind == "ip":
        section = "IPv6" if ":" in value else "IPv4"
    elif kind in HASHES:
        section = "file"
    else:
        section = {"domain": "domain", "url": "url"}[kind]
    quoted = urllib.parse.quote(value, safe="")
    status, answer = _request(
        f"https://otx.alienvault.com/api/v1/indicators/{section}/{quoted}/general",
        headers={"X-OTX-API-KEY": key or ""},
    )
    page = f"https://otx.alienvault.com/indicator/{'file' if kind in HASHES else section.lower()}/{quoted}"
    if status == 404 or not answer:
        return _result("unknown", "not in OTX", page)
    pulses = (answer.get("pulse_info") or {}).get("count") or 0
    validation = answer.get("validation") or []
    families = sorted(
        {
            m.get("display_name")
            for p in (answer.get("pulse_info") or {}).get("pulses", [])[:20]
            for m in p.get("malware_families") or []
            if isinstance(m, dict) and m.get("display_name")
        }
    )
    if pulses:
        verdict = "suspicious"
        summary = f"in {pulses} OTX pulse{'s' if pulses != 1 else ''}"
    elif validation:
        verdict, summary = "harmless", "whitelisted by OTX"
    else:
        verdict, summary = "unknown", "in no OTX pulse"
    return _result(verdict, summary, page, families=families[:8])


# --------------------------------------------------------------------------- #
# GreyNoise Community                                                         #
# --------------------------------------------------------------------------- #
def greynoise(kind: str, value: str, key: str | None) -> dict[str, Any]:
    status, answer = _request(f"https://api.greynoise.io/v3/community/{value}", headers={"key": key} if key else None)
    link = f"https://viz.greynoise.io/ip/{value}"
    if status == 404 or not answer:
        return _result("unknown", "not seen scanning the internet", link)
    classification = answer.get("classification") or "unknown"
    if answer.get("riot"):
        return _result("harmless", f"common business service ({answer.get('name') or 'known'})", link)
    verdict = {"malicious": "malicious", "benign": "harmless"}.get(classification, "unknown")
    summary = (
        f"{classification} internet scanner"
        + (f" ({answer['name']})" if answer.get("name") not in (None, "unknown") else "")
        if answer.get("noise")
        else "not seen scanning the internet"
    )
    return _result(verdict, summary, link, lastSeen=answer.get("last_seen"))


# --------------------------------------------------------------------------- #
# Shodan InternetDB (no key)                                                  #
# --------------------------------------------------------------------------- #
_BAD_TAGS = {"malware", "c2", "compromised", "botnet", "tor"}


def internetdb(kind: str, value: str, key: str | None) -> dict[str, Any]:
    status, answer = _request(f"https://internetdb.shodan.io/{value}")
    link = f"https://www.shodan.io/host/{value}"
    if status == 404 or not answer:
        return _result("unknown", "no open port known to Shodan", link)
    ports, vulns, tags = answer.get("ports") or [], answer.get("vulns") or [], answer.get("tags") or []
    bad = sorted(set(tags) & _BAD_TAGS)
    summary = f"ports {', '.join(str(p) for p in ports[:8])}" if ports else "no open port"
    if vulns:
        summary += f"; {len(vulns)} CVE{'s' if len(vulns) != 1 else ''}"
    if tags:
        summary += f"; tags {', '.join(tags[:5])}"
    verdict = "malicious" if bad and bad != {"tor"} else "suspicious" if bad else "unknown"
    return _result(verdict, summary, link, hostnames=(answer.get("hostnames") or [])[:5], vulns=vulns[:10])


# --------------------------------------------------------------------------- #
# Google Safe Browsing                                                        #
# --------------------------------------------------------------------------- #
def safebrowsing(kind: str, value: str, key: str | None) -> dict[str, Any]:
    urls = [value] if kind == "url" else [f"http://{value}/", f"https://{value}/"]
    _, answer = _request(
        "https://safebrowsing.googleapis.com/v4/threatMatches:find?" + urllib.parse.urlencode({"key": key or ""}),
        body={
            "client": {"clientId": "nik", "clientVersion": "1"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": u} for u in urls],
            },
        },
    )
    link = "https://transparencyreport.google.com/safe-browsing/search?url=" + urllib.parse.quote(
        _host(urls[0]) if kind == "domain" else value, safe=""
    )
    matches = (answer or {}).get("matches") or []
    if matches:
        threats = sorted({m.get("threatType", "").replace("_", " ").lower() for m in matches})
        return _result("malicious", "Google Safe Browsing: " + ", ".join(threats), link)
    return _result("unknown", "not on Google Safe Browsing lists", link)


# --------------------------------------------------------------------------- #
# Registry                                                                    #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Provider:
    id: str
    label: str
    types: tuple[str, ...]
    key: str  # required | optional | none
    lookup: Callable[[str, str, str | None], dict[str, Any]]
    interval: float  # seconds between two requests (free tier)
    daily: int  # requests a day (free tier), 0 = no stated limit
    signup: str
    note: str = ""

    def supports(self, kind: str) -> bool:
        return kind in self.types


ALL = ("ip", "domain", "url", *HASHES)
PROVIDERS: tuple[Provider, ...] = (
    Provider(
        "virustotal", "VirusTotal", ALL, "required", virustotal, 15.0, 500,
        "https://www.virustotal.com/gui/join-us", "Free key: 4 lookups a minute, 500 a day.",
    ),
    Provider(
        "abuseipdb", "AbuseIPDB", ("ip",), "required", abuseipdb, 1.0, 1000,
        "https://www.abuseipdb.com/register", "Free key: 1,000 checks a day.",
    ),
    Provider(
        "abusech", "abuse.ch (ThreatFox, URLhaus, MalwareBazaar)", ALL, "required", abusech, 1.0, 0,
        "https://auth.abuse.ch/", "Free Auth-Key, one for the three services.",
    ),
    Provider(
        "otx", "AlienVault OTX", ALL, "required", otx, 1.0, 0,
        "https://otx.alienvault.com/", "Free key with an OTX account.",
    ),
    Provider(
        "urlscan", "urlscan.io", ("domain", "url"), "optional", urlscan, 2.0, 1000,
        "https://urlscan.io/user/signup", "Searches public scans only (nothing is submitted); a key raises the limits.",
    ),
    Provider(
        "greynoise", "GreyNoise Community", ("ip",), "optional", greynoise, 2.0, 50,
        "https://viz.greynoise.io/signup", "Internet scanners and business services; works without a key, slowly.",
    ),
    Provider(
        "internetdb", "Shodan InternetDB", ("ip",), "none", internetdb, 1.0, 0,
        "https://internetdb.shodan.io/", "Open ports, CVEs and tags; no key.",
    ),
    Provider(
        "safebrowsing", "Google Safe Browsing", ("domain", "url"), "required", safebrowsing, 1.0, 10000,
        "https://developers.google.com/safe-browsing/v4/get-started", "Free key from Google Cloud.",
    ),
)  # fmt: skip
BY_ID = {p.id: p for p in PROVIDERS}


def is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False

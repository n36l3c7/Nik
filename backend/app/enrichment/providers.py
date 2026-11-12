"""Threat-intelligence providers: one function per service, one shape out.

Each lookup returns ``{verdict, summary, link, data, raw, calls}``:

- ``verdict``: ``malicious``, ``suspicious``, ``harmless`` or ``unknown``
  (not known to the service, or nothing conclusive);
- ``summary``: one line for the analyst ("12/94 engines", "confidence 100 %");
- ``link``: the provider's page about the indicator;
- ``data``: what the indicator's page shows, in one documented shape per
  provider (engines, reports, pulses, ports…); times are Unix milliseconds;
- ``raw``: the provider's own answer, for the JSON download;
- ``calls``: how many requests it took (the rate limits count them all).

A lookup takes ``options`` (Settings -> Threat intelligence); only
VirusTotal has some: which engines to list and which extra sections to ask
for, each of them one more request.

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
from datetime import datetime, timezone
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


def _result(verdict: str, summary: str, link: str = "", raw: Any = None, calls: int = 1, **data: Any) -> dict[str, Any]:
    return {
        "verdict": verdict,
        "summary": summary,
        "link": link,
        "data": {k: v for k, v in data.items() if v not in (None, "", [], {})},
        "raw": raw,
        "calls": calls,
    }


def _host(url: str) -> str:
    try:
        return (urllib.parse.urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _ms(seconds: Any) -> int | None:
    """Unix seconds -> milliseconds (None for a missing or odd value)."""
    try:
        return int(float(seconds) * 1000) if seconds else None
    except (TypeError, ValueError):
        return None


def _iso_ms(text: Any) -> int | None:
    """An ISO 8601 or ``YYYY-MM-DD HH:MM:SS [UTC]`` time -> Unix milliseconds."""
    if not text or not isinstance(text, str):
        return None
    cleaned = text.strip().replace(" UTC", "").replace("Z", "+00:00")
    if " " in cleaned and "T" not in cleaned:
        cleaned = cleaned.replace(" ", "T", 1)
    try:
        moment = datetime.fromisoformat(cleaned)
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return int(moment.timestamp() * 1000)


def _text(value: Any, limit: int = 300) -> str:
    return str(value)[:limit] if value not in (None, "") else ""


# --------------------------------------------------------------------------- #
# VirusTotal                                                                  #
# --------------------------------------------------------------------------- #
VT_RELATIONS = {
    "ip": ("resolutions", "communicating_files"),
    "domain": ("resolutions", "communicating_files"),
    "file": ("contacted_domains", "contacted_ips"),
    "url": (),
}
VT_DEFAULTS = {"engines": "flagged", "relations": False, "comments": False}
_VT_FLAGGED = ("malicious", "suspicious")


def _vt_stats(stats: dict | None) -> dict[str, int]:
    return {k: int(v) for k, v in (stats or {}).items() if isinstance(v, int)}


def _vt_relation(name: str, items: list[dict]) -> list[dict[str, Any]]:
    out = []
    for item in items[:10]:
        attributes = item.get("attributes") or {}
        if name == "resolutions":
            out.append(
                {
                    "host": attributes.get("host_name"),
                    "ip": attributes.get("ip_address"),
                    "date": _ms(attributes.get("date")),
                }
            )
        elif name == "communicating_files":
            stats = _vt_stats(attributes.get("last_analysis_stats"))
            out.append(
                {
                    "sha256": item.get("id"),
                    "name": _text(attributes.get("meaningful_name"), 120),
                    "type": _text(attributes.get("type_description"), 60),
                    "malicious": stats.get("malicious", 0),
                    "total": sum(stats.values()),
                }
            )
        elif name == "contacted_domains":
            stats = _vt_stats(attributes.get("last_analysis_stats"))
            out.append({"domain": item.get("id"), "malicious": stats.get("malicious", 0), "total": sum(stats.values())})
        elif name == "contacted_ips":
            out.append(
                {"ip": item.get("id"), "country": attributes.get("country"), "owner": attributes.get("as_owner")}
            )
    return out


def virustotal(kind: str, value: str, key: str | None, options: dict | None = None) -> dict[str, Any]:
    opts = {**VT_DEFAULTS, **(options or {})}
    if kind in HASHES:
        family, path, page = "file", f"files/{value}", f"file/{value}"
    elif kind == "ip":
        family, path, page = "ip", f"ip_addresses/{value}", f"ip-address/{value}"
    elif kind == "domain":
        family, path, page = "domain", f"domains/{value}", f"domain/{value}"
    else:
        ident = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
        family, path, page = "url", f"urls/{ident}", f"url/{ident}"
    link = f"https://www.virustotal.com/gui/{page}"
    headers = {"x-apikey": key or ""}
    base = f"https://www.virustotal.com/api/v3/{path}"
    status, answer = _request(base, headers=headers)
    if status == 404 or not answer:
        return _result("unknown", "not in VirusTotal", link, raw=answer)
    attributes = (answer.get("data") or {}).get("attributes") or {}
    stats = _vt_stats(attributes.get("last_analysis_stats"))
    malicious, suspicious = stats.get("malicious", 0), stats.get("suspicious", 0)
    total = sum(stats.values())
    if malicious >= 3:
        verdict = "malicious"
    elif malicious or suspicious:
        verdict = "suspicious"
    elif stats.get("harmless"):
        verdict = "harmless"
    else:
        verdict = "unknown"

    results = attributes.get("last_analysis_results") or {}
    engines = [
        {"engine": name, "category": r.get("category"), "result": _text(r.get("result"), 120)}
        for name, r in sorted(results.items(), key=lambda kv: kv[0].lower())
        if isinstance(r, dict) and (opts["engines"] == "all" or r.get("category") in _VT_FLAGGED)
    ]
    engines.sort(key=lambda e: (e["category"] not in _VT_FLAGGED, e["category"] != "malicious"))

    raw: dict[str, Any] = {"object": answer}
    calls = 1
    relations: dict[str, list] = {}
    comments: list[dict[str, Any]] = []
    skipped: list[str] = []
    extras = [(name, f"{base}/{name}?limit=10") for name in VT_RELATIONS[family]] if opts["relations"] else []
    if opts["comments"]:
        extras.append(("comments", f"{base}/comments?limit=10"))
    for name, url in extras:
        try:
            calls += 1
            _, extra = _request(url, headers=headers)
        except ProviderError as exc:
            # The main answer stands; the section says why it is missing.
            skipped.append(f"{name}: {exc}")
            if exc.kind in ("rate", "auth"):
                break
            continue
        raw[name] = extra
        items = (extra or {}).get("data") or []
        if name == "comments":
            comments = [
                {
                    "text": _text((c.get("attributes") or {}).get("text"), 1000),
                    "date": _ms((c.get("attributes") or {}).get("date")),
                    "votes": (c.get("attributes") or {}).get("votes"),
                }
                for c in items[:10]
            ]
        else:
            relations[name] = _vt_relation(name, items)

    signature = attributes.get("signature_info") or {}
    return _result(
        verdict,
        f"{malicious}/{total} engines flag it" + (f", {suspicious} suspicious" if suspicious else ""),
        link,
        raw=raw,
        calls=calls,
        stats=stats,
        total=total,
        engines=engines,
        enginesShown=opts["engines"],
        reputation=attributes.get("reputation"),
        lastAnalysis=_ms(attributes.get("last_analysis_date")),
        tags=(attributes.get("tags") or [])[:12],
        categories=sorted(set((attributes.get("categories") or {}).values()))[:8],
        # Network (IP addresses and domains).
        country=attributes.get("country"),
        asn=attributes.get("asn"),
        owner=attributes.get("as_owner"),
        network=attributes.get("network"),
        registrar=attributes.get("registrar"),
        created=_ms(attributes.get("creation_date")),
        # Files.
        name=_text(attributes.get("meaningful_name"), 200),
        names=(attributes.get("names") or [])[:8],
        type=attributes.get("type_description"),
        size=attributes.get("size"),
        label=(attributes.get("popular_threat_classification") or {}).get("suggested_threat_label"),
        signer=_text(signature.get("signers"), 200),
        firstSeen=_ms(attributes.get("first_submission_date")),
        lastSeen=_ms(attributes.get("last_submission_date")),
        # URLs.
        finalUrl=_text(attributes.get("last_final_url"), 500),
        title=_text(attributes.get("title"), 200),
        httpStatus=attributes.get("last_http_response_code"),
        relations=relations,
        comments=comments,
        skipped=skipped,
    )


# --------------------------------------------------------------------------- #
# AbuseIPDB                                                                   #
# --------------------------------------------------------------------------- #
ABUSE_CATEGORIES = {
    1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders", 4: "DDoS Attack", 5: "FTP Brute-Force",
    6: "Ping of Death", 7: "Phishing", 8: "Fraud VoIP", 9: "Open Proxy", 10: "Web Spam", 11: "Email Spam",
    12: "Blog Spam", 13: "VPN IP", 14: "Port Scan", 15: "Hacking", 16: "SQL Injection", 17: "Spoofing",
    18: "Brute-Force", 19: "Bad Web Bot", 20: "Exploited Host", 21: "Web App Attack", 22: "SSH", 23: "IoT Targeted",
}  # fmt: skip


def abuseipdb(kind: str, value: str, key: str | None, options: dict | None = None) -> dict[str, Any]:
    query = urllib.parse.urlencode({"ipAddress": value, "maxAgeInDays": 90, "verbose": ""})
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
        raw=answer,
        score=score,
        scoreKnown=True,
        totalReports=reports,
        distinctUsers=info.get("numDistinctUsers"),
        lastReported=_iso_ms(info.get("lastReportedAt")),
        country=info.get("countryCode"),
        isp=info.get("isp"),
        usage=info.get("usageType"),
        domain=info.get("domain"),
        hostnames=(info.get("hostnames") or [])[:5],
        tor=info.get("isTor"),
        whitelisted=info.get("isWhitelisted"),
        reports=[
            {
                "date": _iso_ms(r.get("reportedAt")),
                "categories": [ABUSE_CATEGORIES.get(c, str(c)) for c in r.get("categories") or []],
                "comment": _text(r.get("comment"), 300),
                "country": r.get("reporterCountryCode"),
            }
            for r in (info.get("reports") or [])[:10]
        ],
    )


# --------------------------------------------------------------------------- #
# urlscan.io                                                                  #
# --------------------------------------------------------------------------- #
def _lucene(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def urlscan(kind: str, value: str, key: str | None, options: dict | None = None) -> dict[str, Any]:
    query = f"page.domain:{_lucene(value)}" if kind == "domain" else f"page.url:{_lucene(value)}"
    params = urllib.parse.urlencode({"q": query, "size": 10})
    _, answer = _request(f"https://urlscan.io/api/v1/search/?{params}", headers={"API-Key": key} if key else None)
    results = (answer or {}).get("results") or []
    total = int((answer or {}).get("total") or len(results))
    link = "https://urlscan.io/search/#" + urllib.parse.quote(query)
    if not results:
        return _result("unknown", "never scanned on urlscan.io", link, raw=answer)
    malicious = [r for r in results if ((r.get("verdicts") or {}).get("overall") or {}).get("malicious")]
    return _result(
        "malicious" if malicious else "unknown",
        f"{total} public scan{'s' if total != 1 else ''}"
        + (f", {len(malicious)} judged malicious" if malicious else ""),
        link,
        raw=answer,
        total=total,
        scans=[
            {
                "time": _iso_ms((r.get("task") or {}).get("time")),
                "url": _text((r.get("page") or {}).get("url"), 500),
                "ip": (r.get("page") or {}).get("ip"),
                "country": (r.get("page") or {}).get("country"),
                "server": _text((r.get("page") or {}).get("server"), 80),
                "title": _text((r.get("page") or {}).get("title"), 160),
                "status": (r.get("page") or {}).get("status"),
                "malicious": bool(((r.get("verdicts") or {}).get("overall") or {}).get("malicious")),
                "result": f"https://urlscan.io/result/{r['_id']}/" if r.get("_id") else "",
            }
            for r in results[:10]
        ],
    )


# --------------------------------------------------------------------------- #
# abuse.ch: ThreatFox, URLhaus, MalwareBazaar (one Auth-Key)                  #
# --------------------------------------------------------------------------- #
def abusech(kind: str, value: str, key: str | None, options: dict | None = None) -> dict[str, Any]:
    headers = {"Auth-Key": key or ""}
    raw: dict[str, Any] = {}
    _, fox = _request(
        "https://threatfox-api.abuse.ch/api/v1/",
        headers=headers,
        body={"query": "search_hash", "hash": value}
        if kind in HASHES
        else {"query": "search_ioc", "search_term": value, "exact_match": True},
    )
    raw["threatfox"] = fox
    calls = 1
    threatfox = []
    if (fox or {}).get("query_status") == "ok" and isinstance(fox.get("data"), list):
        threatfox = [
            {
                "ioc": _text(e.get("ioc"), 300),
                "threat": e.get("threat_type_desc") or e.get("threat_type"),
                "malware": e.get("malware_printable"),
                "confidence": e.get("confidence_level"),
                "firstSeen": _iso_ms(e.get("first_seen")),
                "lastSeen": _iso_ms(e.get("last_seen")),
                "reporter": e.get("reporter"),
                "tags": (e.get("tags") or [])[:8],
                "link": f"https://threatfox.abuse.ch/ioc/{e['id']}/" if e.get("id") else "",
            }
            for e in fox["data"][:10]
        ]

    if kind in HASHES:
        _, bazaar = _request(
            "https://mb-api.abuse.ch/api/v1/", headers=headers, form={"query": "get_info", "hash": value}
        )
        raw["malwarebazaar"], calls = bazaar, calls + 1
        sample = None
        if (bazaar or {}).get("query_status") == "ok" and bazaar.get("data"):
            entry = bazaar["data"][0]
            sample = {
                "sha256": entry.get("sha256_hash"),
                "signature": entry.get("signature"),
                "fileName": _text(entry.get("file_name"), 200),
                "fileType": entry.get("file_type"),
                "size": entry.get("file_size"),
                "firstSeen": _iso_ms(entry.get("first_seen")),
                "lastSeen": _iso_ms(entry.get("last_seen")),
                "delivery": entry.get("delivery_method"),
                "reporter": entry.get("reporter"),
                "tags": (entry.get("tags") or [])[:8],
            }
        if sample:
            return _result(
                "malicious",
                f"MalwareBazaar: {sample['signature'] or 'known malware sample'}",
                f"https://bazaar.abuse.ch/sample/{sample['sha256']}/",
                raw=raw,
                calls=calls,
                threatfox=threatfox,
                sample=sample,
            )
        if threatfox:
            return _threatfox_result(threatfox, raw, calls)
        return _result("unknown", "not in ThreatFox or MalwareBazaar", "https://bazaar.abuse.ch/", raw=raw, calls=calls)

    if kind == "url":
        _, haus = _request("https://urlhaus-api.abuse.ch/v1/url/", headers=headers, form={"url": value})
        raw["urlhaus"], calls = haus, calls + 1
        if (haus or {}).get("query_status") == "ok":
            return _result(
                "malicious",
                f"URLhaus: {haus.get('threat') or 'malware URL'} ({haus.get('url_status') or 'status unknown'})",
                haus.get("urlhaus_reference") or "https://urlhaus.abuse.ch/",
                raw=raw,
                calls=calls,
                threatfox=threatfox,
                urlhaus={
                    "status": haus.get("url_status"),
                    "threat": haus.get("threat"),
                    "dateAdded": _iso_ms(haus.get("date_added")),
                    "reporter": haus.get("reporter"),
                    "tags": (haus.get("tags") or [])[:8],
                    "payloads": [
                        {
                            "sha256": p.get("response_sha256"),
                            "fileType": p.get("file_type"),
                            "signature": p.get("signature"),
                            "firstSeen": _iso_ms(p.get("firstseen")),
                        }
                        for p in (haus.get("payloads") or [])[:10]
                    ],
                },
            )
    else:
        _, haus = _request("https://urlhaus-api.abuse.ch/v1/host/", headers=headers, form={"host": value})
        raw["urlhaus"], calls = haus, calls + 1
        if (haus or {}).get("query_status") == "ok" and int(haus.get("url_count") or 0):
            count = int(haus["url_count"])
            host = {
                "urlCount": count,
                "firstSeen": _iso_ms(haus.get("firstseen")),
                "blacklists": haus.get("blacklists"),
                "urls": [
                    {
                        "url": _text(u.get("url"), 500),
                        "status": u.get("url_status"),
                        "threat": u.get("threat"),
                        "dateAdded": _iso_ms(u.get("date_added")),
                        "tags": (u.get("tags") or [])[:6],
                    }
                    for u in (haus.get("urls") or [])[:10]
                ],
            }
            if threatfox:
                return _threatfox_result(threatfox, raw, calls, urlhausHost=host)
            return _result(
                "suspicious",
                f"URLhaus: {count} malware URL{'s' if count != 1 else ''} on this host",
                haus.get("urlhaus_reference") or "https://urlhaus.abuse.ch/",
                raw=raw,
                calls=calls,
                urlhausHost=host,
            )
    if threatfox:
        return _threatfox_result(threatfox, raw, calls)
    return _result("unknown", "not in ThreatFox or URLhaus", "https://urlhaus.abuse.ch/", raw=raw, calls=calls)


def _threatfox_result(entries: list[dict], raw: Any, calls: int, **more: Any) -> dict[str, Any]:
    first = entries[0]
    what = first.get("malware") or first.get("threat") or "known IOC"
    detail = f" ({first['threat']})" if first.get("threat") and first.get("malware") else ""
    return _result(
        "malicious",
        f"ThreatFox: {what}{detail}",
        first.get("link") or "https://threatfox.abuse.ch/",
        raw=raw,
        calls=calls,
        threatfox=entries,
        **more,
    )


# --------------------------------------------------------------------------- #
# AlienVault OTX                                                              #
# --------------------------------------------------------------------------- #
def otx(kind: str, value: str, key: str | None, options: dict | None = None) -> dict[str, Any]:
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
        return _result("unknown", "not in OTX", page, raw=answer)
    info = answer.get("pulse_info") or {}
    pulses = int(info.get("count") or 0)
    validation = answer.get("validation") or []
    listed = [p for p in info.get("pulses") or [] if isinstance(p, dict)]
    families = sorted(
        {
            m.get("display_name")
            for p in listed[:20]
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
    return _result(
        verdict,
        summary,
        page,
        raw=answer,
        pulseCount=pulses,
        families=families[:8],
        validation=[_text(v.get("message") or v.get("name"), 120) for v in validation if isinstance(v, dict)][:5],
        asn=answer.get("asn"),
        country=answer.get("country_name"),
        pulses=[
            {
                "name": _text(p.get("name"), 200),
                "author": (p.get("author") or {}).get("username") if isinstance(p.get("author"), dict) else None,
                "modified": _iso_ms(p.get("modified")),
                "tags": (p.get("tags") or [])[:6],
                "tlp": p.get("TLP") or p.get("tlp"),
                "link": f"https://otx.alienvault.com/pulse/{p['id']}" if p.get("id") else "",
            }
            for p in listed[:10]
        ],
    )


# --------------------------------------------------------------------------- #
# GreyNoise Community                                                         #
# --------------------------------------------------------------------------- #
def greynoise(kind: str, value: str, key: str | None, options: dict | None = None) -> dict[str, Any]:
    status, answer = _request(f"https://api.greynoise.io/v3/community/{value}", headers={"key": key} if key else None)
    link = f"https://viz.greynoise.io/ip/{value}"
    if status == 404 or not answer:
        return _result("unknown", "not seen scanning the internet", link, raw=answer, known=False)
    classification = answer.get("classification") or "unknown"
    facts = {
        "known": True,
        "classification": classification,
        "noise": bool(answer.get("noise")),
        "riot": bool(answer.get("riot")),
        "name": answer.get("name") if answer.get("name") not in (None, "unknown") else None,
        "lastSeen": _iso_ms(answer.get("last_seen")),
    }
    if answer.get("riot"):
        return _result(
            "harmless", f"common business service ({answer.get('name') or 'known'})", link, raw=answer, **facts
        )
    verdict = {"malicious": "malicious", "benign": "harmless"}.get(classification, "unknown")
    summary = (
        f"{classification} internet scanner" + (f" ({facts['name']})" if facts["name"] else "")
        if answer.get("noise")
        else "not seen scanning the internet"
    )
    return _result(verdict, summary, link, raw=answer, **facts)


# --------------------------------------------------------------------------- #
# Shodan InternetDB (no key)                                                  #
# --------------------------------------------------------------------------- #
_BAD_TAGS = {"malware", "c2", "compromised", "botnet", "tor"}


def internetdb(kind: str, value: str, key: str | None, options: dict | None = None) -> dict[str, Any]:
    status, answer = _request(f"https://internetdb.shodan.io/{value}")
    link = f"https://www.shodan.io/host/{value}"
    if status == 404 or not answer:
        return _result("unknown", "no open port known to Shodan", link, raw=answer)
    ports, vulns, tags = answer.get("ports") or [], answer.get("vulns") or [], answer.get("tags") or []
    bad = sorted(set(tags) & _BAD_TAGS)
    summary = f"ports {', '.join(str(p) for p in ports[:8])}" if ports else "no open port"
    if vulns:
        summary += f"; {len(vulns)} CVE{'s' if len(vulns) != 1 else ''}"
    if tags:
        summary += f"; tags {', '.join(tags[:5])}"
    verdict = "malicious" if bad and bad != ["tor"] else "suspicious" if bad else "unknown"
    return _result(
        verdict,
        summary,
        link,
        raw=answer,
        ports=ports[:100],
        hostnames=(answer.get("hostnames") or [])[:10],
        cpes=(answer.get("cpes") or [])[:20],
        vulns=vulns[:50],
        tags=tags[:20],
    )


# --------------------------------------------------------------------------- #
# Google Safe Browsing                                                        #
# --------------------------------------------------------------------------- #
def safebrowsing(kind: str, value: str, key: str | None, options: dict | None = None) -> dict[str, Any]:
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
    listed = [
        {
            "threat": str(m.get("threatType", "")).replace("_", " ").lower(),
            "platform": str(m.get("platformType", "")).replace("_", " ").lower(),
            "url": _text((m.get("threat") or {}).get("url"), 500),
        }
        for m in matches[:10]
    ]
    if matches:
        threats = sorted({m["threat"] for m in listed})
        return _result("malicious", "Google Safe Browsing: " + ", ".join(threats), link, raw=answer, matches=listed)
    return _result("unknown", "not on Google Safe Browsing lists", link, raw=answer or {}, checked=urls)


def _registration(kind: str, value: str, key: str | None, options: dict | None = None) -> dict[str, Any]:
    from . import registration

    return registration.lookup(kind, value, key, options)


@dataclass(frozen=True)
class Provider:
    id: str
    label: str
    types: tuple[str, ...]
    key: str  # required | optional | none
    lookup: Callable[..., dict[str, Any]]
    interval: float  # seconds between two requests (free tier)
    daily: int  # requests a day (free tier), 0 = no stated limit
    signup: str
    note: str = ""
    # How much its verdict counts in the indicator's overall score (1 to 3).
    weight: int = 1
    # Gives facts rather than a judgement: it counts in the score only when it
    # flags the value (a domain registered days ago), never by staying silent.
    informational: bool = False

    def supports(self, kind: str) -> bool:
        return kind in self.types


ALL = ("ip", "domain", "url", *HASHES)
PROVIDERS: tuple[Provider, ...] = (
    Provider(
        "virustotal", "VirusTotal", ALL, "required", virustotal, 15.0, 500,
        "https://www.virustotal.com/gui/join-us", "Free key: 4 lookups a minute, 500 a day.", weight=3,
    ),
    Provider(
        "abuseipdb", "AbuseIPDB", ("ip",), "required", abuseipdb, 1.0, 1000,
        "https://www.abuseipdb.com/register", "Free key: 1,000 checks a day.", weight=2,
    ),
    Provider(
        "abusech", "abuse.ch (ThreatFox, URLhaus, MalwareBazaar)", ALL, "required", abusech, 1.0, 0,
        "https://auth.abuse.ch/", "Free Auth-Key, one for the three services.", weight=3,
    ),
    Provider(
        "otx", "AlienVault OTX", ALL, "required", otx, 1.0, 0,
        "https://otx.alienvault.com/", "Free key with an OTX account.", weight=1,
    ),
    Provider(
        "urlscan", "urlscan.io", ("domain", "url"), "optional", urlscan, 2.0, 1000,
        "https://urlscan.io/user/signup", "Searches public scans only (nothing is submitted); a key raises the limits.",
        weight=2,
    ),
    Provider(
        "greynoise", "GreyNoise Community", ("ip",), "optional", greynoise, 2.0, 50,
        "https://viz.greynoise.io/signup", "Internet scanners and business services; works without a key, slowly.",
        weight=2,
    ),
    Provider(
        "internetdb", "Shodan InternetDB", ("ip",), "none", internetdb, 1.0, 0,
        "https://internetdb.shodan.io/", "Open ports, CVEs and tags; no key.", weight=1,
    ),
    Provider(
        "safebrowsing", "Google Safe Browsing", ("domain", "url"), "required", safebrowsing, 1.0, 10000,
        "https://developers.google.com/safe-browsing/v4/get-started", "Free key from Google Cloud.", weight=3,
    ),
    Provider(
        "registration", "Registration (RDAP / WHOIS)", ("domain", "ip"), "none", _registration, 1.0, 0,
        "https://about.rdap.org/", "Who registered a domain or holds an address, read from the registries; no key.",
        weight=2, informational=True,
    ),
)  # fmt: skip
BY_ID = {p.id: p for p in PROVIDERS}


def is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False

"""Threat-intelligence enrichment: providers, what may be sent, cache, worker, API."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.core import vault
from app.core.db import SessionLocal
from app.enrichment import providers, service, worker
from app.iocs import Allowlist
from tests.conftest import make_key

PUBLIC_IP = "185.220.101.47"
SHA = "a" * 64


@pytest.fixture(autouse=True)
def fresh_limits():
    service.limiter.reset()
    yield
    service.limiter.reset()


@pytest.fixture()
def fake_http(monkeypatch):
    """Answers by URL prefix; records every request."""
    calls: list[str] = []
    answers: dict[str, tuple[int, object]] = {}

    def request(url, *, headers=None, form=None, body=None):
        calls.append(url)
        for prefix, answer in answers.items():
            if url.startswith(prefix):
                if isinstance(answer, Exception):
                    raise answer
                return answer
        return 404, None

    monkeypatch.setattr(providers, "_request", request)
    return answers, calls


# --------------------------------------------------------------------------- #
# Providers                                                                   #
# --------------------------------------------------------------------------- #
def test_provider_answers_are_normalised(fake_http):
    answers, _ = fake_http
    answers["https://www.virustotal.com/api/v3/ip_addresses/"] = (
        200,
        {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 7, "suspicious": 1, "harmless": 60, "undetected": 20},
                    "country": "DE",
                }
            }
        },
    )
    answers["https://api.abuseipdb.com/"] = (
        200,
        {"data": {"abuseConfidenceScore": 100, "totalReports": 42, "isp": "Tor"}},
    )
    answers["https://internetdb.shodan.io/"] = (200, {"ports": [22, 443], "vulns": ["CVE-1"], "tags": ["c2"]})
    answers["https://api.greynoise.io/"] = (
        200,
        {"noise": True, "riot": False, "classification": "malicious", "name": "unknown"},
    )

    vt = providers.virustotal("ip", PUBLIC_IP, "k")
    assert vt["verdict"] == "malicious" and vt["summary"] == "7/88 engines flag it, 1 suspicious"
    assert vt["link"] == f"https://www.virustotal.com/gui/ip-address/{PUBLIC_IP}" and vt["data"]["country"] == "DE"
    assert providers.abuseipdb("ip", PUBLIC_IP, "k")["verdict"] == "malicious"
    shodan = providers.internetdb("ip", PUBLIC_IP, None)
    assert shodan["verdict"] == "malicious" and "ports 22, 443" in shodan["summary"]
    assert providers.greynoise("ip", PUBLIC_IP, None)["verdict"] == "malicious"
    # Not known: an answer, not an error.
    assert providers.virustotal("sha256", SHA, "k") == {
        "verdict": "unknown",
        "summary": "not in VirusTotal",
        "link": f"https://www.virustotal.com/gui/file/{SHA}",
        "data": {},
        "raw": None,
        "calls": 1,
    }


def test_abusech_and_safe_browsing(fake_http):
    answers, calls = fake_http
    answers["https://threatfox-api.abuse.ch/"] = (200, {"query_status": "no_result"})
    answers["https://mb-api.abuse.ch/"] = (
        200,
        {"query_status": "ok", "data": [{"sha256_hash": SHA, "signature": "AgentTesla", "tags": ["exe"]}]},
    )
    answers["https://safebrowsing.googleapis.com/"] = (200, {"matches": [{"threatType": "SOCIAL_ENGINEERING"}]})
    result = providers.abusech("sha256", SHA, "k")
    assert result["verdict"] == "malicious" and result["summary"] == "MalwareBazaar: AgentTesla"
    assert (
        providers.safebrowsing("url", "http://evil.top/x", "k")["summary"] == "Google Safe Browsing: social engineering"
    )
    assert any("threatfox" in c for c in calls) and any("mb-api" in c for c in calls)


# --------------------------------------------------------------------------- #
# What may be sent                                                            #
# --------------------------------------------------------------------------- #
def _incident(client, headers, incident_id, command, tlp=None):
    doc = {
        "id": incident_id,
        "name": incident_id,
        "data": {"commands": {"shells": {"bash": {"commands": [{"command": command, "time": 1}]}}}},
    }
    if tlp:
        doc["report"] = {"tlp": tlp}
    r = client.post("/api/incidents", headers=headers, json=doc)
    assert r.status_code == 201, r.text


def test_never_sent_private_internal_allowlisted_or_tlp_red(admin: TestClient):
    key = make_key(admin)
    _incident(admin, key, "red1", "curl http://185.220.101.9/x", tlp="red")
    allow = Allowlist(["example.com"])
    with SessionLocal() as db:
        assert "private" in service.blocked(db, "ip", "10.1.2.3", allow)
        assert "private" in service.blocked(db, "url", "http://192.168.1.1/admin", allow)
        assert "internal" in service.blocked(db, "domain", "fileserver.corp", allow)
        assert "internal" in service.blocked(db, "url", "http://intranet/", allow)
        assert "allowlist" in service.blocked(db, "domain", "www.example.com", allow)
        assert "TLP:RED" in service.blocked(db, "ip", "185.220.101.9", allow)
        assert service.blocked(db, "ip", PUBLIC_IP, allow) is None
        assert service.blocked(db, "email", "a@b.com", allow) is not None


# --------------------------------------------------------------------------- #
# Worker                                                                      #
# --------------------------------------------------------------------------- #
def test_automatic_pass_checks_new_indicators_once(admin: TestClient, fake_http):
    answers, calls = fake_http
    answers["https://internetdb.shodan.io/"] = (200, {"ports": [80], "tags": []})
    key = make_key(admin)
    _incident(admin, key, "a1", f"curl http://{PUBLIC_IP}/gate.php")
    _incident(admin, key, "r1", "curl http://185.220.101.9/x", tlp="red")
    shared = admin.get("/api/settings").json()

    with SessionLocal() as db:
        assert service.run_cycle(db, shared) == 0  # automatic lookups are off by default
    shared["enrichment"]["auto"]["ip"] = True
    assert admin.put("/api/settings", json=shared).status_code == 200
    with SessionLocal() as db:
        # Without keys: the providers that need none (InternetDB, GreyNoise Community).
        assert service.run_cycle(db, admin.get("/api/settings").json(), budget_seconds=5) == 2
        assert service.run_cycle(db, admin.get("/api/settings").json(), budget_seconds=5) == 0  # cached
    # Never the TLP:RED incident's address.
    assert sorted(calls) == [
        f"https://api.greynoise.io/v3/community/{PUBLIC_IP}",
        f"https://internetdb.shodan.io/{PUBLIC_IP}",
    ]

    iocs = admin.get("/api/incidents/a1/iocs", headers=key).json()["iocs"]
    ip = next(i for i in iocs if i["type"] == "ip")
    assert ip["reputation"] == {
        "verdict": "unknown",
        "score": 0,
        "flagged": 0,
        "checked": 2,
        "counts": {"malicious": 0, "suspicious": 0, "harmless": 0, "unknown": 2},
    }


def test_lease_lets_one_process_work():
    with SessionLocal() as db:
        db.query(worker.Lease).delete()
        db.commit()
        assert worker.acquire(db, "one", now=1000)
        assert not worker.acquire(db, "two", now=1010)
        assert worker.acquire(db, "one", now=1020)  # renewed
        assert worker.acquire(db, "two", now=1020 + worker.LEASE_SECONDS + 1)  # expired


# --------------------------------------------------------------------------- #
# Keys and API                                                                #
# --------------------------------------------------------------------------- #
def test_keys_are_encrypted_and_never_returned(admin: TestClient):
    token = vault.encrypt("vt-secret-key-123")
    assert "vt-secret" not in token and vault.decrypt(token) == "vt-secret-key-123"
    assert vault.decrypt("garbage") is None

    assert admin.put("/api/enrichment/providers/virustotal/key", json={"key": "vt-secret-key-123"}).status_code == 204
    listing = admin.get("/api/enrichment/providers")
    assert "vt-secret" not in listing.text
    vt = next(p for p in listing.json()["providers"] if p["id"] == "virustotal")
    assert vt["configured"] and vt["keyHint"] == "-123" and vt["usable"]
    with SessionLocal() as db:
        assert [k.secret for k in service.keys(db)["virustotal"]] == ["vt-secret-key-123"]

    analyst = make_key(admin, role="analyst")
    assert (
        admin.put("/api/enrichment/providers/abuseipdb/key", headers=analyst, json={"key": "x" * 10}).status_code == 403
    )
    assert admin.put("/api/enrichment/providers/internetdb/key", json={"key": "x" * 10}).status_code == 404
    assert admin.delete("/api/enrichment/providers/virustotal/key").status_code == 204


def _vt(**stats):
    return 200, {"data": {"attributes": {"last_analysis_stats": stats}}}


def test_several_keys_per_provider_are_rotated(admin: TestClient, monkeypatch):
    """Requests go round the keys; a rate-limited key waits while the next one
    answers; a refused key is marked rejected and left out."""
    used: list[str] = []
    refuse: dict[str, providers.ProviderError] = {}

    def request(url, *, headers=None, form=None, body=None):
        if "virustotal.com" not in url:
            return 404, None  # the keyless providers: not what this test is about
        key = (headers or {}).get("x-apikey")
        used.append(key)
        if key in refuse:
            raise refuse[key]
        return _vt(malicious=0, harmless=70)

    monkeypatch.setattr(providers, "_request", request)
    header = make_key(admin)
    for index, secret in enumerate(["vt-key-aaaa-0001", "vt-key-bbbb-0002", "vt-key-cccc-0003"]):
        r = admin.post("/api/enrichment/providers/virustotal/keys", json={"key": secret, "label": f"analyst {index}"})
        assert r.status_code == 201 and r.json()["hint"] == secret[-4:] and "key" not in r.json()
    assert admin.post("/api/enrichment/providers/virustotal/keys", json={"key": "vt-key-aaaa-0001"}).status_code == 409
    assert admin.post("/api/enrichment/providers/internetdb/keys", json={"key": "x" * 10}).status_code == 404
    analyst = make_key(admin, role="analyst")
    denied = admin.post("/api/enrichment/providers/virustotal/keys", headers=analyst, json={"key": "y" * 12})
    assert denied.status_code == 403

    listing = admin.get("/api/enrichment/providers")
    assert "vt-key" not in listing.text
    vt = next(p for p in listing.json()["providers"] if p["id"] == "virustotal")
    assert [k["label"] for k in vt["keys"]] == ["analyst 0", "analyst 1", "analyst 2"]
    assert {k["status"] for k in vt["keys"]} == {"ok"} and vt["configured"]

    def check(value):
        r = admin.post("/api/enrichment/check", headers=header, json={"type": "domain", "value": value, "force": True})
        assert r.status_code == 200, r.text
        return next(res for res in r.json()["results"] if res["provider"] == "virustotal")

    # Three lookups, no waiting (VirusTotal allows one request per 15 s per key): one key each.
    for name in ("one.example.com", "two.example.com", "three.example.com"):
        assert check(name)["status"] == "done"
    assert used == ["vt-key-aaaa-0001", "vt-key-bbbb-0002", "vt-key-cccc-0003"]

    # A key at its rate limit: the same lookup goes on with the next key.
    service.limiter.reset()
    used.clear()
    refuse["vt-key-aaaa-0001"] = providers.ProviderError("rate", "rate limit reached")
    assert check("four.example.com")["status"] == "done"
    assert used == ["vt-key-aaaa-0001", "vt-key-bbbb-0002"]

    # A key the provider refuses waits and is tried again; refused three times in a row it is
    # marked rejected with the reason. Each time the next key answers.
    refuse.clear()
    refuse["vt-key-aaaa-0001"] = providers.ProviderError("auth", "the provider refused the key (HTTP 401)")

    def state_of(hint):
        listing = admin.get("/api/enrichment/providers").json()["providers"]
        return next(k for k in next(p for p in listing if p["id"] == "virustotal")["keys"] if k["hint"] == hint)

    for attempt in (1, 2, 3):
        service.limiter.reset()
        used.clear()
        assert check(f"refused-{attempt}.example.com")["status"] == "done"
        assert used == ["vt-key-aaaa-0001", "vt-key-bbbb-0002"]
        assert state_of("0001")["status"] == ("rejected" if attempt == 3 else "ok")
    rejected = state_of("0001")
    assert "refused" in rejected["error"]
    vt = next(p for p in admin.get("/api/enrichment/providers").json()["providers"] if p["id"] == "virustotal")
    with SessionLocal() as db:
        assert [k.secret[-4:] for k in service.keys(db)["virustotal"]] == ["0002", "0003"]

    # Every working key is waiting for its interval: the lookup is put off, with the reason.
    r = admin.post(
        "/api/enrichment/check", headers=header, json={"type": "domain", "value": "six.example.com", "force": True}
    )
    used_before = len(used)
    r = admin.post(
        "/api/enrichment/check", headers=header, json={"type": "domain", "value": "seven.example.com", "force": True}
    )
    assert len(used) == used_before
    assert [s["provider"] for s in r.json()["skipped"]] == ["virustotal"]
    assert "rate limit" in r.json()["skipped"][0]["reason"]

    # Removing one key leaves the others; the old single-key call replaces them all.
    assert admin.delete(f"/api/enrichment/providers/virustotal/keys/{rejected['id']}").status_code == 204
    assert admin.delete(f"/api/enrichment/providers/abuseipdb/keys/{vt['keys'][1]['id']}").status_code == 404
    assert admin.put("/api/enrichment/providers/virustotal/key", json={"key": "vt-key-only-9999"}).status_code == 204
    vt = next(p for p in admin.get("/api/enrichment/providers").json()["providers"] if p["id"] == "virustotal")
    assert [k["hint"] for k in vt["keys"]] == ["9999"] and vt["keyHint"] == "9999"


def test_check_now(admin: TestClient, fake_http):
    answers, calls = fake_http
    answers["https://internetdb.shodan.io/"] = (200, {"ports": [3389], "tags": ["compromised"]})
    answers["https://api.greynoise.io/"] = providers.ProviderError("rate", "rate limit reached")
    key = make_key(admin)

    r = admin.post("/api/enrichment/check", headers=key, json={"type": "ip", "value": "10.0.0.1"})
    assert r.status_code == 422 and "private" in r.json()["detail"]

    r = admin.post("/api/enrichment/check", headers=key, json={"type": "ip", "value": PUBLIC_IP})
    assert r.status_code == 200, r.text
    by_provider = {res["provider"]: res for res in r.json()["results"]}
    assert by_provider["internetdb"]["verdict"] == "malicious"
    assert by_provider["greynoise"]["status"] == "error" and "rate limit" in by_provider["greynoise"]["error"]
    # A second check reuses the cache (an error is retried after an hour)...
    r = admin.post("/api/enrichment/check", headers=key, json={"type": "ip", "value": PUBLIC_IP})
    assert len(calls) == 2
    # ...and a forced one waits out GreyNoise's back-off instead of calling it.
    r = admin.post("/api/enrichment/check", headers=key, json={"type": "ip", "value": PUBLIC_IP, "force": True})
    assert [s["provider"] for s in r.json()["skipped"]] == ["greynoise"]
    assert len(calls) == 3

    cached = admin.get(f"/api/enrichment?type=ip&value={PUBLIC_IP}", headers=key).json()
    assert cached["blocked"] is None and "internetdb" in cached["providers"] and len(cached["results"]) == 2
    audit = admin.get("/api/audit?q=enrichment").json()
    assert any(
        e["action"] == "enrichment.check" for e in audit.get("entries", audit if isinstance(audit, list) else [])
    )


# --------------------------------------------------------------------------- #
# The indicator's page: weighted verdict, retention, history, raw answers      #
# --------------------------------------------------------------------------- #
def test_overall_verdict_weighs_the_providers():
    overall = service.overall
    assert overall([]) is None
    # VirusTotal (3), AbuseIPDB (2) and GreyNoise (2) say malicious, OTX (1) and InternetDB (1)
    # suspicious, abuse.ch (3) does not know it: (3 + 2 + 2 + 0.5 + 0.5) / 12.
    answers = [
        ("virustotal", "malicious"),
        ("abuseipdb", "malicious"),
        ("greynoise", "malicious"),
        ("otx", "suspicious"),
        ("internetdb", "suspicious"),
        ("abusech", "unknown"),
    ]
    result = overall(answers)
    assert result["verdict"] == "malicious" and result["score"] == 67
    assert result["flagged"] == 5 and result["checked"] == 6 and result["counts"]["unknown"] == 1
    # One light source alone cannot call it malicious, however high the share.
    assert overall([("internetdb", "suspicious")])["verdict"] == "suspicious"
    assert overall([("otx", "suspicious"), ("virustotal", "harmless"), ("abusech", "unknown")])["verdict"] == "unknown"
    # Any "malicious" is at least suspicious overall.
    lone = overall([("internetdb", "malicious"), ("virustotal", "harmless"), ("abuseipdb", "unknown")])
    assert lone["verdict"] == "suspicious" and lone["score"] == 17
    assert overall([("virustotal", "harmless"), ("otx", "unknown")])["verdict"] == "harmless"


def test_retention_per_type_and_refresh_of_expired_answers(admin: TestClient, fake_http):
    answers, calls = fake_http
    answers["https://internetdb.shodan.io/"] = (200, {"ports": [80], "tags": []})
    key = make_key(admin)
    shared = admin.get("/api/settings").json()
    assert shared["enrichment"]["retentionDays"] == {"ip": 30, "url": 30, "hash": 180}
    assert shared["enrichment"]["refreshExpired"] is True
    cfg = service.config(shared)
    assert service.retention(cfg, "domain").days == 30 and service.retention(cfg, "sha1").days == 180

    admin.post("/api/enrichment/check", headers=key, json={"type": "ip", "value": PUBLIC_IP})
    detail = admin.get(f"/api/enrichment?type=ip&value={PUBLIC_IP}", headers=key).json()
    assert detail["retentionDays"] == 30 and detail["refresh"] == []
    assert not any(r["expired"] for r in detail["results"])

    # 31 days later the answers are expired: the page is told to ask again.
    with SessionLocal() as db:
        for row in db.query(service.Enrichment):
            row.checked_at = "2020-01-01T00:00:00Z"
        db.commit()
    detail = admin.get(f"/api/enrichment?type=ip&value={PUBLIC_IP}", headers=key).json()
    assert all(r["expired"] for r in detail["results"])
    assert set(detail["refresh"]) == {"internetdb", "greynoise"}
    before = len(calls)
    admin.post("/api/enrichment/check", headers=key, json={"type": "ip", "value": PUBLIC_IP})
    assert len(calls) == before + 2  # asked again without "force"

    # A longer retention, and no refresh: expired answers are kept and nothing is asked.
    with SessionLocal() as db:
        for row in db.query(service.Enrichment):
            row.checked_at = "2020-01-01T00:00:00Z"
        db.commit()
    shared["enrichment"]["retentionDays"]["ip"] = 365
    shared["enrichment"]["refreshExpired"] = False
    assert admin.put("/api/settings", json=shared).status_code == 200
    detail = admin.get(f"/api/enrichment?type=ip&value={PUBLIC_IP}", headers=key).json()
    assert detail["retentionDays"] == 365 and detail["refresh"] == []
    assert all(r["expired"] for r in detail["results"])
    before = len(calls)
    admin.post("/api/enrichment/check", headers=key, json={"type": "ip", "value": PUBLIC_IP})
    assert len(calls) == before
    shared["enrichment"]["retentionDays"]["hash"] = 5000
    assert admin.put("/api/settings", json=shared).status_code == 422


def test_history_raw_answer_and_virustotal_options(admin: TestClient, monkeypatch):
    seen: list[str] = []
    state = {"malicious": 0}

    def request(url, *, headers=None, form=None, body=None):
        if "virustotal.com" not in url:
            return 404, None
        seen.append(url.split("/api/v3/")[1])
        if url.endswith("/resolutions?limit=10"):
            return 200, {"data": [{"attributes": {"host_name": "c2.example.net", "ip_address": PUBLIC_IP, "date": 1}}]}
        if url.endswith("/communicating_files?limit=10"):
            return 200, {
                "data": [{"id": SHA, "attributes": {"last_analysis_stats": {"malicious": 40, "harmless": 30}}}]
            }
        if url.endswith("/comments?limit=10"):
            return 200, {"data": [{"attributes": {"text": "Seen in a phishing kit", "date": 2}}]}
        return 200, {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": state["malicious"], "harmless": 60, "undetected": 10},
                    "last_analysis_results": {
                        "Kaspersky": {"category": "malicious", "result": "malware"},
                        "Avira": {"category": "harmless", "result": "clean"},
                    },
                    "as_owner": "Example Hosting",
                    "country": "DE",
                }
            }
        }

    monkeypatch.setattr(providers, "_request", request)
    key = make_key(admin)
    assert admin.post("/api/enrichment/providers/virustotal/keys", json={"key": "vt-key-zzzz-0009"}).status_code == 201

    def check():
        r = admin.post("/api/enrichment/check", headers=key, json={"type": "ip", "value": PUBLIC_IP, "force": True})
        assert r.status_code == 200, r.text
        return r.json()

    # Defaults: one request, only the engines that flag the value.
    first = check()
    vt = next(r for r in first["results"] if r["provider"] == "virustotal")
    assert seen == [f"ip_addresses/{PUBLIC_IP}"]
    assert [e["engine"] for e in vt["data"]["engines"]] == ["Kaspersky"] and vt["data"]["owner"] == "Example Hosting"
    assert "relations" not in vt["data"] and vt["weight"] == 3 and vt["hasRaw"] and vt["history"][0]["verdict"]
    assert first["summary"]["verdict"] == "harmless" and first["summary"]["score"] == 0

    # The raw answer downloads as a JSON file; it is not part of the page's data.
    raw = admin.get(f"/api/enrichment/raw?type=ip&value={PUBLIC_IP}&provider=virustotal", headers=key)
    assert raw.status_code == 200 and "attachment" in raw.headers["content-disposition"]
    assert raw.json()["response"]["object"]["data"]["attributes"]["country"] == "DE"
    assert "last_analysis_results" not in str(first)
    assert admin.get(f"/api/enrichment/raw?type=ip&value={PUBLIC_IP}&provider=otx", headers=key).status_code == 404

    # All engines, relations and comments: three more requests, counted against the key's limits.
    shared = admin.get("/api/settings").json()
    shared["enrichment"]["virustotal"] = {"engines": "all", "relations": True, "comments": True}
    assert admin.put("/api/settings", json=shared).status_code == 200
    service.limiter.reset()
    seen.clear()
    state["malicious"] = 9
    second = check()
    vt = next(r for r in second["results"] if r["provider"] == "virustotal")
    assert [s.split("/")[-1].split("?")[0] for s in seen] == [
        PUBLIC_IP,
        "resolutions",
        "communicating_files",
        "comments",
    ]
    assert [e["engine"] for e in vt["data"]["engines"]] == ["Kaspersky", "Avira"]
    assert vt["data"]["relations"]["resolutions"][0]["host"] == "c2.example.net"
    assert vt["data"]["relations"]["communicating_files"][0] == {
        "sha256": SHA,
        "name": "",
        "type": "",
        "malicious": 40,
        "total": 70,
    }
    assert vt["data"]["comments"][0]["text"] == "Seen in a phishing kit"
    with SessionLocal() as db:
        vt_key = service.keys(db)["virustotal"][0]
    assert service.limiter.wait_for(providers.BY_ID["virustotal"], vt_key) > 45  # four requests, 15 s apart

    # The history keeps the earlier verdict: the reputation changed.
    assert [h["verdict"] for h in vt["history"]] == ["malicious", "harmless"]
    # VirusTotal (weight 3) says malicious, GreyNoise (2) and InternetDB (1) do not know it: 3 / 6.
    assert second["summary"]["verdict"] == "malicious" and second["summary"]["score"] == 50


def test_provider_details_have_the_shape_the_page_shows(fake_http):
    answers, _ = fake_http
    answers["https://api.abuseipdb.com/"] = (
        200,
        {
            "data": {
                "abuseConfidenceScore": 80,
                "totalReports": 2,
                "numDistinctUsers": 2,
                "isTor": True,
                "lastReportedAt": "2026-11-12T08:51:00+00:00",
                "reports": [
                    {"reportedAt": "2026-11-12T08:51:00+00:00", "categories": [22, 18], "comment": "Failed password"},
                ],
            }
        },
    )
    abuse = providers.abuseipdb("ip", PUBLIC_IP, "k")
    assert abuse["data"]["reports"] == [
        {"date": 1794473460000, "categories": ["SSH", "Brute-Force"], "comment": "Failed password", "country": None}
    ]
    assert abuse["data"]["tor"] is True and abuse["data"]["distinctUsers"] == 2 and abuse["raw"]["data"]["isTor"]

    answers["https://otx.alienvault.com/"] = (
        200,
        {
            "pulse_info": {
                "count": 1,
                "pulses": [
                    {
                        "id": "p1",
                        "name": "AsyncRAT C2",
                        "author": {"username": "hunter"},
                        "modified": "2026-11-04T10:00:00",
                        "tags": ["c2"],
                        "malware_families": [{"display_name": "AsyncRAT"}],
                    }
                ],
            }
        },
    )
    otx = providers.otx("domain", "evil.example.com", "k")
    assert otx["data"]["pulses"][0]["author"] == "hunter" and otx["data"]["families"] == ["AsyncRAT"]
    assert otx["data"]["pulses"][0]["link"] == "https://otx.alienvault.com/pulse/p1"

    answers["https://threatfox-api.abuse.ch/"] = (
        200,
        {
            "query_status": "ok",
            "data": [
                {
                    "id": "77",
                    "ioc": "evil.example.com",
                    "threat_type_desc": "botnet C2",
                    "malware_printable": "Cobalt Strike",
                    "confidence_level": 100,
                    "first_seen": "2026-11-01 10:00:00 UTC",
                }
            ],
        },
    )
    answers["https://urlhaus-api.abuse.ch/"] = (200, {"query_status": "no_results"})
    fox = providers.abusech("domain", "evil.example.com", "k")
    assert fox["verdict"] == "malicious" and fox["summary"] == "ThreatFox: Cobalt Strike (botnet C2)"
    assert fox["calls"] == 2 and fox["data"]["threatfox"][0]["confidence"] == 100
    assert set(fox["raw"]) == {"threatfox", "urlhaus"}

    answers["https://internetdb.shodan.io/"] = (
        200,
        {"ports": [22], "cpes": ["cpe:/a:x"], "vulns": [], "tags": ["tor"]},
    )
    shodan = providers.internetdb("ip", PUBLIC_IP, None)
    assert shodan["verdict"] == "suspicious" and shodan["data"] == {
        "ports": [22],
        "cpes": ["cpe:/a:x"],
        "tags": ["tor"],
    }

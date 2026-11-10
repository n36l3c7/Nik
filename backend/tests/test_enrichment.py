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
    assert ip["reputation"] == {"verdict": "unknown", "flagged": 0, "checked": 2}


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
        assert service.keys(db)["virustotal"] == "vt-secret-key-123"

    analyst = make_key(admin, role="analyst")
    assert (
        admin.put("/api/enrichment/providers/abuseipdb/key", headers=analyst, json={"key": "x" * 10}).status_code == 403
    )
    assert admin.put("/api/enrichment/providers/internetdb/key", json={"key": "x" * 10}).status_code == 404
    assert admin.delete("/api/enrichment/providers/virustotal/key").status_code == 204


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

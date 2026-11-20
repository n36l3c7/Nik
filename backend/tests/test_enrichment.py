"""Threat-intelligence look-ups: the sources, what may be sent, the keys of the instances, the worker, the API.

A look-up is the reputation command of a source's connector, run on an
instance of it: the packs of the sources are installed from ``packs/`` as an
administrator would install them, and the vendors answer through the fake
outside of ``conftest.py``.
"""

from __future__ import annotations

import textwrap
import time
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.automation import connector_actions as ca
from app.automation import instance_keys
from app.core import vault
from app.core.db import SessionLocal
from app.core.models import Connection, Enrichment, IntegrationKey, Setting
from app.core.security import now_iso
from app.enrichment import old_keys, service, sources, worker
from app.iocs import Allowlist
from tests import vendor
from tests.conftest import make_key

PUBLIC_IP = "185.220.101.47"
SHA = "a" * 64
DOMAIN = "evil.example.com"
URL = "http://evil.example.com/gate.php"

# Where each source answers, and what it says when it knows the value.
HOSTS = {
    "virustotal": "www.virustotal.com",
    "abuseipdb": "api.abuseipdb.com",
    "greynoise": "api.greynoise.io",
    "otx": "otx.alienvault.com",
    "shodan": "internetdb.shodan.io",
    "rdap": "rdap.org",
    "threatfox": "threatfox-api.abuse.ch",
    "urlhaus": "urlhaus-api.abuse.ch",
    "malwarebazaar": "mb-api.abuse.ch",
    "urlscan": "urlscan.io",
    "safebrowsing": "safebrowsing.googleapis.com",
}
# The sources that are given a key here (the others answer without one).
KEYED = ("virustotal", "abuseipdb", "otx", "threatfox", "urlhaus", "malwarebazaar", "safebrowsing")
VT_STATS = {"malicious": 7, "suspicious": 1, "harmless": 60, "undetected": 20}
ANSWERS = {
    "virustotal": {
        "data": {
            "id": "x",
            "attributes": {
                "last_analysis_stats": VT_STATS,
                "last_analysis_results": {
                    "Kaspersky": {"category": "malicious", "result": "malware"},
                    "Avira": {"category": "harmless", "result": "clean"},
                },
                "as_owner": "Example Hosting",
                "country": "DE",
            },
        }
    },
    "abuseipdb": {"data": {"abuseConfidenceScore": 100, "totalReports": 42, "isp": "Tor"}},
    "greynoise": {"noise": True, "riot": False, "classification": "malicious", "name": "unknown"},
    "otx": {"pulse_info": {"count": 2, "pulses": [{"id": "p1", "name": "Tor exits"}]}},
    "shodan": {"ports": [22, 443], "vulns": ["CVE-1"], "tags": ["c2"]},
    "rdap": {"objectClassName": "ip network", "name": "EXAMPLE-NET", "country": "DE"},
    "threatfox": {"query_status": "ok", "data": [{"id": "9", "ioc": "x", "malware_printable": "Cobalt Strike"}]},
    "urlhaus": {"query_status": "ok", "threat": "malware_download", "url_status": "online", "url_count": 3},
    "malwarebazaar": {"query_status": "ok", "data": [{"sha256_hash": SHA, "signature": "AgentTesla"}]},
    "urlscan": {"total": 1, "results": [{"_id": "s1", "verdicts": {"malicious": True}, "page": {"url": URL}}]},
    "safebrowsing": {"matches": [{"threatType": "MALWARE", "threat": {"url": URL}}]},
}


def turn_on(outside, *names: str, answers: bool = True, **policy) -> None:
    """The sources named (all of them when none is): pack installed, an instance made, the vendor answering."""
    with SessionLocal() as db:
        for name in names or HOSTS:
            vendor.source(db, name, key=f"{name}-key-0001" if name in KEYED else "", **policy)
    for name in names or HOSTS:
        outside.host(HOSTS[name])
        if answers:
            outside.answer(HOSTS[name], json=ANSWERS[name])


def asked(outside, name: str) -> list[dict]:
    return [request for request in outside.requests if request["host"] == HOSTS[name]]


def check(admin: TestClient, kind: str, value: str, force: bool = False) -> dict:
    r = admin.post("/api/enrichment/check", json={"type": kind, "value": value, "force": force})
    assert r.status_code == 200, r.text
    return r.json()


def by_source(body: dict) -> dict[str, dict]:
    return {result["provider"]: result for result in body["results"]}


def expire() -> None:
    """Every stored answer is from long ago."""
    with SessionLocal() as db:
        for row in db.scalars(select(Enrichment)):
            row.checked_at = "2020-01-01T00:00:00Z"
        db.commit()


# --------------------------------------------------------------------------- #
# A look-up is a connector command                                            #
# --------------------------------------------------------------------------- #
def test_a_look_up_of_each_kind_is_the_reputation_command_of_each_source(admin: TestClient, outside):
    turn_on(outside)
    judging = {
        "ip": {"abuseipdb", "greynoise", "otx", "rdap", "shodan", "threatfox", "virustotal"},
        "domain": {"otx", "rdap", "safebrowsing", "threatfox", "urlhaus", "urlscan", "virustotal"},
        "url": {"otx", "safebrowsing", "threatfox", "urlhaus", "urlscan", "virustotal"},
        "sha256": {"malwarebazaar", "otx", "threatfox", "urlhaus", "virustotal"},
    }
    listed = {source["id"]: source for source in admin.get("/api/enrichment/sources").json()["sources"]}
    assert set(listed) == set(HOSTS) and all(source["on"] for source in listed.values())
    for kind, wanted in judging.items():
        assert {name for name, source in listed.items() if kind in source["types"]} == wanted, kind
    assert listed["virustotal"]["commands"] == {
        "ip": "virustotal.get-ip-report",
        "domain": "virustotal.get-domain-report",
        "url": "virustotal.get-url-reputation",
        "file": "virustotal.get-file-report",
    }
    assert (listed["virustotal"]["weight"], listed["otx"]["weight"], listed["rdap"]["informational"]) == (3, 1, True)

    for kind, value in (("ip", PUBLIC_IP), ("domain", DOMAIN), ("url", URL), ("sha256", SHA)):
        before = len(outside.requests)
        body = check(admin, kind, value)
        found = by_source(body)
        assert set(found) == judging[kind] and set(body["providers"]) == judging[kind], kind
        assert {result["status"] for result in found.values()} == {"done"}, kind
        # One request a source, and each answer says which command gave it, on which instance.
        assert len(outside.requests) == before + len(judging[kind])
        for name, result in found.items():
            assert result["data"]["_command"] == listed[name]["commands"]["file" if kind == "sha256" else kind]
            assert result["data"]["_instance"] == listed[name]["instance"] and result["hasRaw"]
        assert body["summary"]["verdict"] == "malicious" and body["skipped"] == []

    ip = by_source(admin.get(f"/api/enrichment?type=ip&value={PUBLIC_IP}").json())
    assert (ip["virustotal"]["verdict"], ip["virustotal"]["summary"]) == (
        "malicious",
        "7/88 engines flag it, 1 suspicious",
    )
    assert ip["virustotal"]["link"] == "https://www.virustotal.com/gui/ip-address/x"
    assert ip["virustotal"]["data"]["country"] == "DE" and ip["virustotal"]["label"] == "VirusTotal"
    assert [engine["engine"] for engine in ip["virustotal"]["data"]["engines"]] == ["Kaspersky"]
    assert ip["shodan"]["verdict"] == "malicious" and "ports 22, 443" in ip["shodan"]["summary"]
    assert ip["abuseipdb"]["verdict"] == "malicious" and ip["greynoise"]["verdict"] == "malicious"
    assert ip["rdap"]["verdict"] == "unknown" and ip["otx"]["verdict"] == "suspicious"
    # The key of the instance went with the request, in the place the vendor reads it; none where none is set.
    assert asked(outside, "virustotal")[0]["headers"]["x-apikey"] == "virustotal-key-0001"
    assert asked(outside, "abuseipdb")[0]["headers"]["Key"] == "abuseipdb-key-0001"
    assert "key=" not in asked(outside, "shodan")[0]["path"]
    # abuse.ch is three sources, each shown on its own.
    hashes = by_source(admin.get(f"/api/enrichment?type=sha256&value={SHA}").json())
    assert hashes["malwarebazaar"]["summary"] == "MalwareBazaar: AgentTesla"
    assert hashes["threatfox"]["summary"].startswith("ThreatFox: Cobalt Strike")
    assert hashes["urlhaus"]["label"] == "URLhaus"

    # The whole answer downloads as a JSON file: every output of the command.
    raw = admin.get(f"/api/enrichment/raw?type=ip&value={PUBLIC_IP}&provider=virustotal")
    assert raw.status_code == 200 and "attachment" in raw.headers["content-disposition"]
    assert raw.json()["response"]["attributes"]["country"] == "DE" and raw.json()["response"]["verdict"] == "malicious"
    assert admin.get(f"/api/enrichment/raw?type=ip&value={PUBLIC_IP}&provider=urlscan").status_code == 404
    audit = admin.get("/api/audit?q=enrichment").json()
    assert any(
        e["action"] == "enrichment.check" for e in audit.get("entries", audit if isinstance(audit, list) else [])
    )


def test_a_source_without_an_instance_that_is_on_is_off_and_says_so(admin: TestClient, outside):
    # Nothing installed: nothing is a source, nothing is asked.
    assert admin.get("/api/enrichment/sources").json()["sources"] == []
    empty = admin.get(f"/api/enrichment?type=ip&value={PUBLIC_IP}").json()
    assert (empty["providers"], empty["off"], empty["notAsked"], empty["blocked"]) == ([], [], [], None)
    assert check(admin, "ip", PUBLIC_IP)["results"] == []

    # The packs installed, no instance: the sources are listed, off, with what turning one on takes.
    with SessionLocal() as db:
        vendor.install_pack(db, "rdap")
        vendor.install_pack(db, "safebrowsing")
        db.commit()
    listed = {source["id"]: source for source in admin.get("/api/enrichment/sources").json()["sources"]}
    assert {name: (source["on"], source["instance"], source["instances"]) for name, source in listed.items()} == {
        "rdap": (False, None, 0),
        "safebrowsing": (False, None, 0),
    }
    assert listed["rdap"]["needsNothing"] is True and listed["safebrowsing"]["needsNothing"] is False
    detail = admin.get(f"/api/enrichment?type=domain&value={DOMAIN}").json()
    assert detail["providers"] == []
    assert detail["off"] == [
        {"provider": "safebrowsing", "label": "Google Safe Browsing"},
        {"provider": "rdap", "label": "RDAP (registration data)"},
    ]
    assert check(admin, "domain", DOMAIN)["results"] == [] and outside.requests == []

    # An instance that is off is no instance; the oldest that is on is the one asked.
    outside.host("rdap.org")
    outside.host("rdap.example.net")
    outside.answer("rdap.org", json=ANSWERS["rdap"])
    outside.answer("rdap.example.net", json=ANSWERS["rdap"])
    with SessionLocal() as db:
        vendor.source(db, "rdap", name="First", enabled=False)
        second = vendor.source(db, "rdap", name="Second")
        second.config = {"url": "https://rdap.example.net"}
        vendor.source(db, "rdap", name="Third")
        db.commit()
    (rdap,) = [s for s in admin.get("/api/enrichment/sources").json()["sources"] if s["id"] == "rdap"]
    assert (rdap["on"], rdap["instance"], rdap["instances"]) == (True, "Second", 3)
    assert by_source(check(admin, "ip", PUBLIC_IP))["rdap"]["data"]["_instance"] == "Second"
    assert [request["host"] for request in outside.requests] == ["rdap.example.net"]
    # A registry is asked for the registered domain of a host (its command says so: reputation_of).
    check(admin, "domain", "login.portal.example.co.uk")
    assert outside.requests[-1]["path"] == "/domain/example.co.uk"


RATED = textwrap.dedent(
    """\
    name: Rated
    id: rated
    version: 1
    lookups: { weight: 2 }
    configuration:
      - { name: credentials, type: header, header: X-Key }
    base_url: "https://rated.example.com"
    commands:
      - name: deep-ip
        description: What only a paid plan gives.
        premium: true
        reputation: ip
        arguments: [{ name: ip, type: text, required: true }]
        request: { method: GET, path: "/deep/{{ args.ip }}" }
        outputs: { verdict: malicious }
      - name: report-ip
        description: Tells the vendor.
        changes_outside: true
        reputation: ip
        arguments: [{ name: ip, type: text, required: true }]
        request: { method: POST, path: "/report", json: { ip: "{{ args.ip }}" } }
        outputs: { verdict: malicious }
      - name: check-ip
        reputation: ip
        arguments:
          - { name: ip, type: text, required: true }
          - { name: days, type: number, default: 30 }
        request: { method: GET, path: "/ip/{{ args.ip }}", query: { days: "{{ args.days }}" } }
        outputs:
          verdict: "{{ response.verdict }}"
          summary: "{{ response.line }}"
          link: "{{ response.page }}"
          hits: "{{ response.hits }}"
      - name: check-ip-again
        reputation: ip
        arguments: [{ name: ip, type: text, required: true }]
        request: { method: GET, path: "/again/{{ args.ip }}" }
        outputs: { verdict: harmless }
      - name: deep-domain
        premium: true
        reputation: domain
        arguments: [{ name: domain, type: text, required: true }]
        request: { method: GET, path: "/deep/{{ args.domain }}" }
        outputs: { verdict: malicious }
    """
)


def rated(outside, keys: int = 1, **policy) -> None:
    """A source of the test's own: a connector nobody at Nik heard of, with an instance holding ``keys`` keys."""
    outside.host("rated.example.com")
    with SessionLocal() as db:
        ca.install(db, RATED, "admin")
        row = Connection(
            id="r" * 32, name="Rated", connector_id="rated", config={}, created_at=now_iso(), updated_at=now_iso()
        )
        ca.store_secrets(row, {"value": "rated-key-1"})
        row.key_policy = instance_keys.clean_policy(policy)
        if keys > 1:
            more = [{"name": f"Key {n}", "secrets": {"value": f"rated-key-{n}"}} for n in range(2, keys + 1)]
            instance_keys.set_extra_keys(row, more, ["value"], ["value"])
        db.add(row)
        db.commit()


def test_a_connector_nik_never_heard_of_is_a_source_and_premium_or_changing_commands_are_never_chosen(
    admin: TestClient, outside
):
    rated(outside)
    outside.answer(
        "rated.example.com",
        json={"verdict": "MALICIOUS", "line": "seen 4 times", "page": "javascript:alert(1)", "hits": list(range(250))},
    )
    (source,) = admin.get("/api/enrichment/sources").json()["sources"]
    # The first command of the file that may be run: not the premium one, not the one that reports.
    assert source["commands"] == {"ip": "rated.check-ip"} and source["types"] == ["ip"]
    assert (source["label"], source["weight"], source["on"], source["keys"]) == ("Rated", 2, True, 1)
    with SessionLocal() as db:
        (found,) = sources.sources(db)
        assert not found.supports("domain")  # its only command for a domain is premium
    result = by_source(check(admin, "ip", PUBLIC_IP))["rated"]
    (request,) = outside.requests
    assert (request["method"], request["path"]) == ("GET", f"/ip/{PUBLIC_IP}?days=30")
    # The verdict is one of the four, the link an address of the web or nothing, a long list is cut for
    # the page (the download has it whole).
    assert (result["verdict"], result["summary"], result["link"], result["weight"]) == (
        "malicious",
        "seen 4 times",
        "",
        2,
    )
    assert len(result["data"]["hits"]) == service.LIST_SHOWN and result["data"]["_cut"] == {"hits": 250}
    raw = admin.get(f"/api/enrichment/raw?type=ip&value={PUBLIC_IP}&provider=rated").json()
    assert len(raw["response"]["hits"]) == 250
    # Its weight, as the file declares it, is what the overall verdict counts.
    assert admin.get(f"/api/enrichment?type=ip&value={PUBLIC_IP}").json()["summary"]["score"] == 100
    # A file that declares how it counts and judges nothing is refused.
    bad = RATED.replace("    reputation: ip\n", "").replace("    reputation: domain\n", "")
    with pytest.raises(ca.ConnectorError) as refused:
        ca.load(bad)
    assert "lookups" in str(refused.value.problems[0].message)


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


def test_never_sent_private_internal_allowlisted_or_tlp_red(admin: TestClient, outside):
    turn_on(outside, "shodan", "rdap")
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
    # With sources that are on and would answer: refused before any command is chosen.
    for kind, value, why in (
        ("ip", "10.0.0.1", "private"),
        ("ip", "169.254.1.1", "private"),
        ("domain", "fileserver.corp", "internal"),
        ("ip", "185.220.101.9", "TLP:RED"),
    ):
        r = admin.post("/api/enrichment/check", headers=key, json={"type": kind, "value": value, "force": True})
        assert r.status_code == 422 and why in r.json()["detail"], value
        assert admin.get(f"/api/enrichment?type={kind}&value={value}").json()["blocked"]
    assert outside.requests == []


# --------------------------------------------------------------------------- #
# The keys, the limits and the kept answers are the instance's                #
# --------------------------------------------------------------------------- #
def test_two_keys_with_limits_take_turns_and_a_source_that_is_used_up_is_skipped(admin: TestClient, outside):
    rated(outside, keys=2, perMinute=1, mode="each")
    outside.answer("rated.example.com", json={"verdict": "harmless", "line": "nothing"})

    def used() -> list[str]:
        return [request["headers"]["X-Key"] for request in outside.requests]

    assert by_source(check(admin, "ip", "185.220.102.1"))["rated"]["status"] == "done"
    assert by_source(check(admin, "ip", "185.220.102.2"))["rated"]["status"] == "done"
    assert used() == ["rated-key-1", "rated-key-2"]
    # Both keys reached the limit of the instance: nothing is sent, and the page says why.
    third = check(admin, "ip", "185.220.102.3")
    assert third["results"] == [] and used() == ["rated-key-1", "rated-key-2"]
    assert [(s["provider"], s["label"]) for s in third["skipped"]] == [("rated", "Rated")]
    assert "every key is used up" in third["skipped"][0]["reason"]
    with SessionLocal() as db:
        (source,) = sources.sources(db)
        assert 0 < sources.wait(db, source) <= 60
        # What was asked is counted on the instance, where Settings shows it.
        shown = instance_keys.shown(db, source.instance, ["value"])
        assert [key["total"] for key in shown["keys"]] == [1, 1]

    # A key the vendor says is used up (429) is left alone, and the same look-up goes on with the next.
    with SessionLocal() as db:
        instance_keys.forget(db, "r" * 32)
        row = db.get(Connection, "r" * 32)
        row.key_policy = instance_keys.clean_policy({"mode": "reserve"})
        db.commit()
    outside.requests.clear()

    def first_key_refused(method, host, path, headers, body):
        return (429, {}, b"{}") if headers.get("X-Key") == "rated-key-1" else None

    outside.answers.append(first_key_refused)
    assert by_source(check(admin, "ip", "185.220.102.4"))["rated"]["status"] == "done"
    assert used() == ["rated-key-1", "rated-key-2"]
    assert by_source(check(admin, "ip", "185.220.102.5"))["rated"]["status"] == "done"
    assert used() == ["rated-key-1", "rated-key-2", "rated-key-2"]


def test_a_bulk_check_counts_against_what_the_instance_may_still_ask_today(admin: TestClient, outside):
    rated(outside, keys=2, perDay=2, perMinute=30)
    outside.answer("rated.example.com", json={"verdict": "harmless", "line": "nothing"})
    check(admin, "ip", "185.220.102.1")
    pairs = [("ip", f"185.220.102.{n}") for n in range(1, 7)]
    with SessionLocal() as db:
        plan = service.plan_check(db, pairs, admin.get("/api/settings").json())
        # One was answered already; five to ask, three requests left today over the two keys.
        assert (plan["total"], plan["toAsk"], plan["reused"]) == (6, 5, 1)
        assert plan["sources"] == [
            {"provider": "rated", "label": "Rated", "keys": 2, "needed": 5, "leftToday": 3, "today": 3, "later": 2}
        ]
        row = service.start_check(db, plan, "six addresses", "admin")
        db.commit()
        assert service.run_checks(db, {}, budget_seconds=5) >= 3
        db.refresh(row)
        # The keys are used up for the day: the check waits, and says so.
        assert (row.status, row.done, row.total) == ("waiting", 3, 5)
        assert row.message == "Rated: every key is used up. It goes on by itself when one is free again."
        # The next day (the counts of the instance start again) it goes on by itself.
        instance_keys.forget(db, "r" * 32)
        db.commit()
        service.run_checks(db, {}, budget_seconds=5)
        db.refresh(row)
        assert (row.status, row.done) == ("done", 5)


def test_an_answer_the_instance_keeps_is_given_back_without_a_request(admin: TestClient, outside):
    turn_on(outside, "shodan", cacheHours=24)
    assert by_source(check(admin, "ip", PUBLIC_IP))["shodan"]["verdict"] == "malicious"
    assert len(outside.requests) == 1

    # The stored answer expired and is asked for again: the instance still keeps it, nothing leaves.
    expire()
    again = by_source(check(admin, "ip", PUBLIC_IP))["shodan"]
    assert again["verdict"] == "malicious" and not again["expired"] and len(outside.requests) == 1
    # It is the answer a playbook that runs the same command is given: one kept answer for both.
    with SessionLocal() as db:
        (source,) = sources.sources(db)
        args = sources.arguments(source.connector.command("check-ip"), PUBLIC_IP)
        kept = instance_keys.kept_answer(db, source.instance, "check-ip", args, time.time())
        assert kept["outputs"]["verdict"] == "malicious"
    # "Check again" is someone asking for a new answer: it goes past what is kept, and is kept in its turn.
    outside.answer(HOSTS["shodan"], json={"ports": [80], "tags": []})
    forced = by_source(check(admin, "ip", PUBLIC_IP, force=True))["shodan"]
    assert forced["verdict"] == "unknown" and len(outside.requests) == 2
    assert [entry["verdict"] for entry in forced["history"]] == ["unknown", "malicious", "malicious"]
    # Without kept answers (the default of an instance) an expired answer is a request.
    with SessionLocal() as db:
        db.get(Connection, "shodan-0").key_policy = None
        db.commit()
    expire()
    check(admin, "ip", PUBLIC_IP)
    assert len(outside.requests) == 3


def test_a_source_that_does_not_answer_is_an_error_of_its_own(admin: TestClient, outside):
    turn_on(outside, "shodan", "virustotal", answers=False)
    outside.answer(HOSTS["shodan"], json={"ports": [3389], "tags": ["compromised"]})
    outside.answer(HOSTS["virustotal"], status=401, json={"error": {"message": "Wrong API key"}})
    found = by_source(check(admin, "ip", PUBLIC_IP))
    assert found["shodan"]["verdict"] == "malicious"
    assert found["virustotal"]["status"] == "error" and found["virustotal"]["error"]
    # A second check reuses what is stored (an error is retried after an hour)...
    check(admin, "ip", PUBLIC_IP)
    assert len(outside.requests) == 2
    # ...the automatic look-ups leave alone for a while a source that refused its credentials...
    with SessionLocal() as db:
        by_id = {source.id: source for source in sources.sources(db)}
        assert sources.wait(db, by_id["virustotal"]) > 500 and sources.wait(db, by_id["shodan"]) == 0
    # ...and "Check again" asks it all the same.
    check(admin, "ip", PUBLIC_IP, force=True)
    assert len(asked(outside, "virustotal")) == 2
    # A host that cannot be reached is an error too, not a crash of the others.
    outside.names.pop(HOSTS["shodan"])
    found = by_source(check(admin, "ip", "185.220.102.9", force=True))
    assert found["shodan"]["status"] == "error" and "virustotal" in found


# --------------------------------------------------------------------------- #
# Worker                                                                      #
# --------------------------------------------------------------------------- #
def test_automatic_pass_checks_new_indicators_once(admin: TestClient, outside):
    turn_on(outside, "shodan", "greynoise", answers=False)
    outside.answer(HOSTS["shodan"], json={"ports": [80], "tags": []})
    key = make_key(admin)
    _incident(admin, key, "a1", f"curl http://{PUBLIC_IP}/gate.php")
    _incident(admin, key, "r1", "curl http://185.220.101.9/x", tlp="red")
    shared = admin.get("/api/settings").json()

    with SessionLocal() as db:
        assert service.run_cycle(db, shared) == 0  # automatic lookups are off by default
    shared["enrichment"]["auto"]["ip"] = True
    assert admin.put("/api/settings", json=shared).status_code == 200
    with SessionLocal() as db:
        assert service.run_cycle(db, admin.get("/api/settings").json(), budget_seconds=5) == 2
        assert service.run_cycle(db, admin.get("/api/settings").json(), budget_seconds=5) == 0  # answered
    # Never the TLP:RED incident's address.
    assert sorted((request["host"], request["path"]) for request in outside.requests) == [
        ("api.greynoise.io", f"/v3/community/{PUBLIC_IP}"),
        ("internetdb.shodan.io", f"/{PUBLIC_IP}"),
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
    # With no source that is on a pass has nothing to do, whatever is turned on.
    with SessionLocal() as db:
        for row in db.scalars(select(Connection)):
            row.enabled = False
        db.query(Enrichment).delete()
        db.commit()
        assert service.run_cycle(db, admin.get("/api/settings").json(), budget_seconds=5) == 0


def test_lease_lets_one_process_work():
    with SessionLocal() as db:
        db.query(worker.Lease).delete()
        db.commit()
        assert worker.acquire(db, "one", now=1000)
        assert not worker.acquire(db, "two", now=1010)
        assert worker.acquire(db, "one", now=1020)  # renewed
        assert worker.acquire(db, "two", now=1020 + worker.LEASE_SECONDS + 1)  # expired


# --------------------------------------------------------------------------- #
# The indicator's page: weighted verdict, retention, history                  #
# --------------------------------------------------------------------------- #
def test_overall_verdict_weighs_the_sources():
    overall = service.overall
    counted = {
        "virustotal": (3, False),
        "abuseipdb": (2, False),
        "greynoise": (2, False),
        "threatfox": (3, False),
        "rdap": (2, True),
    }
    assert overall([], counted) is None
    # VirusTotal (3), AbuseIPDB (2) and GreyNoise (2) say malicious, OTX and Shodan (1 each, they declare
    # nothing) suspicious, ThreatFox (3) does not know it: (3 + 2 + 2 + 0.5 + 0.5) / 12.
    answers = [
        ("virustotal", "malicious"),
        ("abuseipdb", "malicious"),
        ("greynoise", "malicious"),
        ("otx", "suspicious"),
        ("shodan", "suspicious"),
        ("threatfox", "unknown"),
    ]
    result = overall(answers, counted)
    assert result["verdict"] == "malicious" and result["score"] == 67
    assert result["flagged"] == 5 and result["checked"] == 6 and result["counts"]["unknown"] == 1
    # One light source alone cannot call it malicious, however high the share.
    assert overall([("shodan", "suspicious")], counted)["verdict"] == "suspicious"
    mixed = [("otx", "suspicious"), ("virustotal", "harmless"), ("threatfox", "unknown")]
    assert overall(mixed, counted)["verdict"] == "unknown"
    # Any "malicious" is at least suspicious overall.
    lone = overall([("shodan", "malicious"), ("virustotal", "harmless"), ("abuseipdb", "unknown")], counted)
    assert lone["verdict"] == "suspicious" and lone["score"] == 17
    assert overall([("virustotal", "harmless"), ("otx", "unknown")], counted)["verdict"] == "harmless"
    # A source that gives facts counts only when it flags the value.
    assert overall([("rdap", "unknown")], counted) is None
    assert overall([("rdap", "suspicious"), ("virustotal", "harmless")], counted)["score"] == 20


def test_the_weights_are_the_ones_the_connectors_of_the_sources_declare(admin: TestClient, outside):
    turn_on(outside)
    with SessionLocal() as db:
        assert sources.weights(db) == {
            "virustotal": (3, False),
            "threatfox": (3, False),
            "urlhaus": (3, False),
            "malwarebazaar": (3, False),
            "safebrowsing": (3, False),
            "abuseipdb": (2, False),
            "greynoise": (2, False),
            "urlscan": (2, False),
            "rdap": (2, True),
        }


def test_retention_per_type_and_refresh_of_expired_answers(admin: TestClient, outside):
    turn_on(outside, "shodan", "greynoise")
    key = make_key(admin)
    shared = admin.get("/api/settings").json()
    assert shared["enrichment"] == {
        "auto": {"ip": False, "url": False, "hash": False},
        "retentionDays": {"ip": 30, "url": 30, "hash": 180},
        "refreshExpired": True,
        "guardOpen": [],
    }
    cfg = service.config(shared)
    assert service.retention(cfg, "domain").days == 30 and service.retention(cfg, "sha1").days == 180

    admin.post("/api/enrichment/check", headers=key, json={"type": "ip", "value": PUBLIC_IP})
    detail = admin.get(f"/api/enrichment?type=ip&value={PUBLIC_IP}", headers=key).json()
    assert detail["retentionDays"] == 30 and detail["refresh"] == []
    assert not any(r["expired"] for r in detail["results"])

    # 31 days later the answers are expired: the page is told to ask again.
    expire()
    detail = admin.get(f"/api/enrichment?type=ip&value={PUBLIC_IP}", headers=key).json()
    assert all(r["expired"] for r in detail["results"])
    assert set(detail["refresh"]) == {"shodan", "greynoise"}
    before = len(outside.requests)
    admin.post("/api/enrichment/check", headers=key, json={"type": "ip", "value": PUBLIC_IP})
    assert len(outside.requests) == before + 2  # asked again without "force"

    # A longer retention, and no refresh: expired answers are kept and nothing is asked.
    expire()
    shared["enrichment"]["retentionDays"]["ip"] = 365
    shared["enrichment"]["refreshExpired"] = False
    # The settings of before 6.5 that a client may still send are ignored, not refused.
    shared["enrichment"]["providers"] = {"virustotal": False}
    shared["enrichment"]["virustotal"] = {"engines": "all", "relations": True, "comments": True}
    saved = admin.put("/api/settings", json=shared)
    assert saved.status_code == 200 and set(saved.json()["enrichment"]) == {
        "auto",
        "retentionDays",
        "refreshExpired",
        "guardOpen",
    }
    detail = admin.get(f"/api/enrichment?type=ip&value={PUBLIC_IP}", headers=key).json()
    assert detail["retentionDays"] == 365 and detail["refresh"] == []
    assert all(r["expired"] for r in detail["results"])
    before = len(outside.requests)
    admin.post("/api/enrichment/check", headers=key, json={"type": "ip", "value": PUBLIC_IP})
    assert len(outside.requests) == before
    shared["enrichment"]["retentionDays"]["hash"] = 5000
    assert admin.put("/api/settings", json=shared).status_code == 422


def test_an_answer_stored_before_6_5_keeps_its_verdict_and_gives_its_details_at_the_next_check(
    admin: TestClient, outside
):
    turn_on(outside, "shodan")
    with SessionLocal() as db:
        db.add(
            Enrichment(
                type="ip",
                value=PUBLIC_IP,
                provider="shodan",  # as migration 0045 files what "internetdb" had answered
                status="done",
                verdict="suspicious",
                summary="ports 9001; tags tor",
                link=f"https://www.shodan.io/host/{PUBLIC_IP}",
                data={"ports": [9001], "tags": ["tor"]},
                checked_at=now_iso(),
            )
        )
        db.commit()
    detail = admin.get(f"/api/enrichment?type=ip&value={PUBLIC_IP}").json()
    (old,) = detail["results"]
    assert (old["verdict"], old["summary"], old["before65"], old["data"]) == (
        "suspicious",
        "ports 9001; tags tor",
        True,
        {},
    )
    assert detail["summary"]["verdict"] == "suspicious"
    new = by_source(check(admin, "ip", PUBLIC_IP, force=True))["shodan"]
    assert new["before65"] is False and new["data"]["ports"] == [22, 443]


# --------------------------------------------------------------------------- #
# The keys kept before 6.5                                                    #
# --------------------------------------------------------------------------- #
def old_key(db, provider: str, secret: str, label: str = "", status: str = "ok") -> str:
    row = IntegrationKey(
        id=uuid.uuid4().hex,
        provider=provider,
        secret=vault.encrypt(secret),
        hint=secret[-4:],
        label=label,
        status=status,
        updated_at=now_iso(),
        updated_by="admin",
    )
    db.add(row)
    return row.id


def test_the_keys_kept_before_6_5_become_keys_of_instances_when_the_connectors_are_installed(
    admin: TestClient, outside
):
    with SessionLocal() as db:
        old_key(db, "virustotal", "vt-key-aaaa-0001", "analyst 0")
        old_key(db, "virustotal", "vt-key-bbbb-0002")
        refused = old_key(db, "virustotal", "vt-key-cccc-0003", status="rejected")
        old_key(db, "abusech", "abuse-ch-key-0009")
        old_key(db, "greynoise", "greynoise-key-0005")
        # GreyNoise was turned off in the settings of before.
        held = db.get(Setting, 1)
        if held is None:
            held = Setting(id=1, doc={})
            db.add(held)
        held.doc = {**(held.doc or {}), "enrichment": {"providers": {"greynoise": False}}}
        db.commit()
        # No pack is installed: nothing can be done, and nothing is lost.
        assert old_keys.adopt(db) == 0
        db.commit()
        assert db.query(IntegrationKey).count() == 5

    listing = admin.get("/api/enrichment/sources")
    assert "vt-key" not in listing.text and "abuse-ch-key" not in listing.text
    left = listing.json()["oldKeys"]
    assert sorted((key["source"], key["hint"], key["state"]) for key in left) == [
        ("abusech", "0009", "waiting"),
        ("greynoise", "0005", "waiting"),
        ("virustotal", "0001", "waiting"),
        ("virustotal", "0002", "waiting"),
        ("virustotal", "0003", "rejected"),
    ]
    abuse_ch = next(key for key in left if key["source"] == "abusech")
    assert abuse_ch["label"] == "abuse.ch" and abuse_ch["connectors"] == [
        {"id": "threatfox", "installed": False},
        {"id": "urlhaus", "installed": False},
        {"id": "malwarebazaar", "installed": False},
    ]

    # Installing the pack of a source is what moves its keys: an instance is made with them, with the
    # limits the look-ups kept for that source.
    with SessionLocal() as db:
        for pack in ("virustotal", "greynoise", "threatfox"):
            vendor.install_pack(db, pack)
        db.commit()
        made = {row.connector_id: row for row in db.scalars(select(Connection))}
        assert {name: row.name for name, row in made.items()} == {
            "virustotal": "VirusTotal (from Settings)",
            "greynoise": "GreyNoise (from Settings)",
            "threatfox": "ThreatFox (from Settings)",
        }
        vt = made["virustotal"]
        assert [(key.name, key.secrets) for key in instance_keys.keys_of(vt)] == [
            ("analyst 0", {"value": "vt-key-aaaa-0001"}),
            ("Key 2", {"value": "vt-key-bbbb-0002"}),
        ]
        policy = instance_keys.policy_of(vt)
        assert (policy["perMinute"], policy["perDay"], policy["cacheHours"], vt.enabled) == (4, 500, 0, True)
        assert instance_keys.keys_of(made["greynoise"])[0].secrets == {"api_key": "greynoise-key-0005"}
        assert made["greynoise"].enabled is False  # off, as the source was
        assert instance_keys.keys_of(made["threatfox"])[0].secrets == {"value": "abuse-ch-key-0009"}
        vt_id = vt.id
        # A key that has its home is deleted; the one of abuse.ch still waits for two connectors, and the
        # one the vendor had refused is never deleted here.
        assert sorted((row.provider, row.hint) for row in db.scalars(select(IntegrationKey))) == [
            ("abusech", "0009"),
            ("virustotal", "0003"),
        ]
    left = admin.get("/api/enrichment/sources").json()["oldKeys"]
    assert sorted((key["hint"], key["state"], tuple(c["id"] for c in key["connectors"])) for key in left) == [
        ("0003", "rejected", ()),
        ("0009", "waiting", ("urlhaus", "malwarebazaar")),
    ]
    audit = admin.get("/api/audit?q=from the").json()
    entries = audit.get("entries", audit if isinstance(audit, list) else [])
    assert sum(1 for entry in entries if entry["action"] == "connection.create") == 3
    assert not any("vt-key" in str(entry) for entry in entries)

    # The look-ups go through the instance that was made, with its keys.
    outside.host(HOSTS["virustotal"])
    outside.answer(HOSTS["virustotal"], json=ANSWERS["virustotal"])
    outside.host(HOSTS["threatfox"])
    outside.answer(HOSTS["threatfox"], json=ANSWERS["threatfox"])
    assert by_source(check(admin, "ip", PUBLIC_IP))["virustotal"]["data"]["_instance"] == "VirusTotal (from Settings)"
    assert asked(outside, "virustotal")[0]["headers"]["x-apikey"] == "vt-key-aaaa-0001"

    with SessionLocal() as db:
        # Done once: an instance someone deletes afterwards is not made again.
        db.delete(db.get(Connection, vt_id))
        db.commit()
        assert old_keys.adopt(db) == 0
        # The two other connectors of abuse.ch arrive: each gets its instance with the one key.
        vendor.install_pack(db, "malwarebazaar")
        vendor.install_pack(db, "urlhaus")
        db.commit()
        names = sorted(row.name for row in db.scalars(select(Connection)))
        assert names == [
            "GreyNoise (from Settings)",
            "MalwareBazaar (from Settings)",
            "ThreatFox (from Settings)",
            "URLhaus (from Settings)",
        ]
        # Every connector of abuse.ch has the key now: it is deleted from where it was.
        assert [row.hint for row in db.scalars(select(IntegrationKey))] == ["0003"]

    # What could not be moved is the administrator's to remove.
    analyst = make_key(admin, roles=["analyst"])
    assert admin.delete(f"/api/enrichment/old-keys/{refused}", headers=analyst).status_code == 403
    assert admin.delete(f"/api/enrichment/old-keys/{refused}").status_code == 204
    assert admin.delete(f"/api/enrichment/old-keys/{refused}").status_code == 404
    assert admin.get("/api/enrichment/sources").json()["oldKeys"] == []


def test_a_key_an_instance_holds_already_is_not_given_a_second_instance(admin: TestClient):
    with SessionLocal() as db:
        vendor.source(db, "abuseipdb", key="abuseipdb-key-0007", name="AbuseIPDB of the SOC")
        old_key(db, "abuseipdb", "abuseipdb-key-0007")
        db.commit()
        assert old_keys.adopt(db) == 0
        db.commit()
        assert [row.name for row in db.scalars(select(Connection))] == ["AbuseIPDB of the SOC"]
        assert db.query(IntegrationKey).count() == 0


# --------------------------------------------------------------------------- #
# A playbook's look-up                                                        #
# --------------------------------------------------------------------------- #
MAILREP = textwrap.dedent(
    """\
    name: Mail reputation
    id: mailrep
    version: 1
    base_url: "https://mailrep.example.com"
    commands:
      - name: check-address
        reputation: email
        arguments: [{ name: address, type: text, required: true }]
        request: { method: GET, path: "/address/{{ args.address }}" }
        outputs: { verdict: "{{ response.verdict }}", summary: "{{ response.note }}" }
    """
)


def test_a_look_up_of_a_playbook_passes_the_rule_of_the_look_ups_then_the_guard_once(admin: TestClient, outside):
    from tests.test_automation_engine import edge, go, incident, node, playbook, steps

    turn_on(outside, "shodan", "greynoise")
    outside.host("mailrep.example.com")
    outside.answer("mailrep.example.com", json={"verdict": "suspicious", "note": "a throwaway domain"})
    with SessionLocal() as db:
        ca.install(db, MAILREP, "admin")
        db.add(
            Connection(
                id="m" * 32,
                name="Mailrep",
                connector_id="mailrep",
                config={},
                created_at=now_iso(),
                updated_at=now_iso(),
            )
        )
        db.commit()
    incident(admin, "inc-rep", name=PUBLIC_IP)  # the name of an incident is of a class that is closed

    def look_up(name: str, kind: str, value: str) -> tuple[str, dict]:
        pb = playbook(
            admin,
            name,
            [node("rep", "action", action="nik.reputation", args={"kind": kind, "value": value})],
            [edge("start", "rep")],
        )
        return pb, steps(go(admin, pb, objectKind="incident", objectId="inc-rep"))["rep"]["output"]

    def open_class(pb: str, name: str, data_class: str) -> None:
        body = {"class": data_class, "allow": True, "acknowledged": True, "confirmName": name}
        assert admin.put(f"/api/automation/playbooks/{pb}/data-allow", json=body).status_code == 200

    # The guard of the playbook holds the value: no source is asked, and it is said once, not per source.
    pb, held = look_up("Looks up", "ip", "{{ trigger.incident.name }}")
    assert held["verdict"] == "" and held["sources"] == [] and outside.requests == []
    assert [item["source"] for item in held["skipped"]] == ["reputation sources"]
    assert held["skipped"][0]["reason"].startswith("Held back: incident names and tickets.")
    # Opened for the playbook, the same look-up as "Check now": each source once, the answers stored.
    open_class(pb, "Looks up", "incident_text")
    out = steps(go(admin, pb, objectKind="incident", objectId="inc-rep"))["rep"]["output"]
    assert (out["kind"], out["value"], out["verdict"], out["skipped"]) == ("ip", PUBLIC_IP, "malicious", [])
    assert sorted(item["source"] for item in out["sources"]) == ["GreyNoise", "Shodan"]
    assert sorted(request["host"] for request in outside.requests) == ["api.greynoise.io", "internetdb.shodan.io"]
    assert len(admin.get(f"/api/enrichment?type=ip&value={PUBLIC_IP}").json()["results"]) == 2
    # Asked again, the answers that stand are given: nothing leaves.
    steps(go(admin, pb, objectKind="incident", objectId="inc-rep"))
    assert len(outside.requests) == 2

    # What a look-up never sends is not sent, whatever was opened for the playbook.
    pb, inside = look_up("Looks inside", "ip", "10.1.2.3")
    open_class(pb, "Looks inside", "private_value")
    inside = steps(go(admin, pb, objectKind="incident", objectId="inc-rep"))["rep"]["output"]
    assert inside["skipped"] == [
        {"source": "reputation sources", "reason": "a private or reserved address is never sent outside"}
    ]
    assert len(outside.requests) == 2

    # An e-mail address is never looked up by itself; a playbook may ask the sources that judge one, when
    # the guard lets the address out, and nothing is stored of it.
    pb, mail = look_up("Looks up a sender", "email", "billing@invoice-portal.co")
    assert mail["skipped"][0]["reason"].startswith("Held back: 1 × e-mail addresses") and len(outside.requests) == 2
    open_class(pb, "Looks up a sender", "email_address")
    mail = steps(go(admin, pb, objectKind="incident", objectId="inc-rep"))["rep"]["output"]
    assert mail["sources"] == [{"source": "Mail reputation", "verdict": "suspicious", "summary": "a throwaway domain"}]
    assert (mail["verdict"], outside.requests[-1]["path"]) == ("suspicious", "/address/billing@invoice-portal.co")
    with SessionLocal() as db:
        assert db.scalars(select(Enrichment).where(Enrichment.type == "email")).all() == []
    assert admin.get("/api/enrichment/sources").json()["sources"][0]["id"] == "greynoise"  # not a source of the page

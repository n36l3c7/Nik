"""The IoC library: reading pastes and files, lists, export, feed, bulk check, alerts."""

from __future__ import annotations

import base64
import csv
import io
import json

import pytest
from fastapi.testclient import TestClient

from app import ioc_library as lib
from app.core.db import SessionLocal
from app.enrichment import providers, service
from tests.conftest import make_key

IP = "185.220.101.47"
SHA = "a" * 64


@pytest.fixture(autouse=True)
def fresh_limits(monkeypatch):
    service.limiter.reset()
    # The registries (RDAP / WHOIS) are a provider of their own, tested in
    # test_registration.py: left out here so these tests count the others.
    monkeypatch.setattr(service, "PROVIDERS", tuple(p for p in service.PROVIDERS if p.id != "registration"))
    yield
    service.limiter.reset()


@pytest.fixture()
def fake_http(monkeypatch):
    calls: list[str] = []
    answers: dict[str, tuple[int, object]] = {}

    def request(url, *, headers=None, form=None, body=None):
        calls.append(url)
        for prefix, answer in answers.items():
            if url.startswith(prefix):
                return answer
        return 404, None

    monkeypatch.setattr(providers, "_request", request)
    return answers, calls


def _incident(client, incident_id, command, tlp=None):
    doc = {
        "id": incident_id,
        "name": incident_id,
        "data": {"commands": {"shells": {"bash": {"commands": [{"command": command, "time": 1}]}}}},
    }
    if tlp:
        doc["report"] = {"tlp": tlp}
    assert client.post("/api/incidents", json=doc).status_code == 201


PASTE = f"""185.220.101[.]47
hxxps://cdn-update[.]top/get.php?id=7
login-microsoftonline.support
{SHA}
10.12.0.4
billing[@]invoice-portal.co
not an indicator
185.220.101.47
"""


def test_a_paste_is_read_defanged_values_included():
    parsed = lib.parse(PASTE)
    assert parsed["format"] == "text"
    assert [(i["type"], i["value"]) for i in parsed["items"]] == [
        ("ip", IP),
        ("url", "https://cdn-update.top/get.php?id=7"),
        ("domain", "login-microsoftonline.support"),
        ("sha256", SHA),
        ("ip", "10.12.0.4"),
        ("email", "billing@invoice-portal.co"),
    ]
    assert parsed["repeated"] == 1 and parsed["unrecognised"] == ["not an indicator"]
    assert lib.detect("hxxp://evil[.]example/a") == ("url", "http://evil.example/a")
    assert lib.detect("nothing here") is None
    assert lib.defang("url", "https://a.b/c") == "hxxps://a[.]b/c" and lib.defang("sha256", SHA) == SHA


def test_files_are_recognised_by_what_they_hold():
    table = "type,value,tags,note\nip,185.220.101.47,c2;tor,exit node\n,evil.example.org,,\n"
    parsed = lib.parse(table)
    assert parsed["format"] == "csv"
    assert parsed["items"][0] == {"type": "ip", "value": IP, "tags": ["c2", "tor"], "note": "exit node"}
    assert parsed["items"][1] == {"type": "domain", "value": "evil.example.org"}

    stix = {
        "type": "bundle",
        "objects": [
            {"type": "indicator", "pattern": "[ipv4-addr:value = '185.220.101.47']", "labels": ["c2"]},
            {"type": "indicator", "pattern": f"[file:hashes.'SHA-256' = '{SHA}']"},
            {"type": "identity", "name": "x"},
        ],
    }
    parsed = lib.parse(json.dumps(stix))
    assert parsed["format"] == "stix"
    assert [(i["type"], i["value"]) for i in parsed["items"]] == [("ip", IP), ("sha256", SHA)]

    misp = {"Event": {"info": "Campaign X", "Attribute": [{"type": "ip-dst", "value": IP, "comment": "c2"}]}}
    parsed = lib.parse(json.dumps(misp))
    assert parsed["format"] == "misp" and parsed["lists"] == ["Campaign X"]
    assert parsed["items"] == [{"type": "ip", "value": IP, "note": "c2"}]


def test_indicators_are_added_one_by_one_and_grouped_in_a_list_only_when_asked(admin: TestClient):
    preview = admin.post("/api/iocs/parse", json={"text": PASTE}).json()
    assert preview["summary"] == {
        "new": 6,
        "known": 0,
        "repeated": 1,
        "neverSent": 2,  # the private address and the e-mail address
        "unrecognised": 1,
        "types": {"ip": 2, "url": 1, "domain": 1, "sha256": 1, "email": 1},
    }
    assert admin.get("/api/iocs").json()["total"] == 0  # reading saves nothing

    added = admin.post("/api/iocs", json={"text": PASTE, "tags": ["Phishing"]})
    assert added.status_code == 201, added.text
    assert added.json()["added"] == 6 and added.json()["list"] is None
    assert admin.get("/api/iocs/lists").json()["lists"] == []

    one = admin.post("/api/iocs", json={"items": [{"value": "hxxp://evil[.]example/a", "note": "landing"}]})
    assert one.status_code == 201 and one.json()["added"] == 1
    assert admin.post("/api/iocs", json={"items": [{"value": "nothing"}]}).status_code == 422

    body = admin.get("/api/iocs").json()
    assert body["total"] == 7 and body["counts"]["added"] == 7 and body["counts"]["unchecked"] == 7
    row = next(r for r in body["iocs"] if r["value"] == IP)
    assert row["origin"] == "manual" and row["tags"] == ["phishing"] and row["removable"] and row["lists"] == []
    assert next(r for r in body["iocs"] if r["value"] == "10.12.0.4")["neverSent"]
    assert [r["value"] for r in admin.get("/api/iocs?q=landing").json()["iocs"]] == ["http://evil.example/a"]
    assert admin.get("/api/iocs?type=ip&sort=value&dir=desc").json()["iocs"][0]["value"] == IP


def test_an_indicator_already_known_goes_in_both_lists(admin: TestClient):
    first = admin.post("/api/iocs", json={"text": f"{IP}\nevil.example.org", "list": {"name": "Wave A"}}).json()
    assert first["listed"] == 2 and first["list"]["name"] == "Wave A"
    second = admin.post("/api/iocs", json={"text": f"{IP}\nother.example.org", "list": {"name": "Wave B"}}).json()
    assert second["added"] == 1 and second["existing"] == 1 and second["listed"] == 2

    row = next(r for r in admin.get("/api/iocs").json()["iocs"] if r["value"] == IP)
    assert sorted(entry["name"] for entry in row["lists"]) == ["Wave A", "Wave B"]
    lists = {entry["name"]: entry for entry in admin.get("/api/iocs/lists").json()["lists"]}
    assert lists["Wave A"]["count"] == 2 and lists["Wave B"]["count"] == 2
    assert admin.post("/api/iocs/lists", json={"name": "wave a"}).status_code == 409

    # Out of a list is not out of the library.
    wave_a = lists["Wave A"]["id"]
    gone = admin.post(f"/api/iocs/lists/{wave_a}/items/remove", json={"items": [{"type": "ip", "value": IP}]})
    assert gone.json() == {"removed": 1}
    assert admin.get(f"/api/iocs?list={wave_a}").json()["total"] == 1
    assert admin.get("/api/iocs").json()["total"] == 3


def test_an_indicator_of_an_incident_stays_when_removed(admin: TestClient):
    _incident(admin, "inc1", f"curl http://{IP}/gate.php")
    admin.post("/api/iocs", json={"text": f"{IP}\nevil.example.org"})
    rows = {r["value"]: r for r in admin.get("/api/iocs").json()["iocs"]}
    assert rows[IP]["origin"] == "incident" and rows[IP]["incidents"] == 1
    assert rows["evil.example.org"]["origin"] == "manual"

    removed = admin.post(
        "/api/iocs/remove",
        json={"items": [{"type": "ip", "value": IP}, {"type": "domain", "value": "evil.example.org"}]},
    )
    assert removed.json() == {"removed": 1, "kept": 1}
    values = [r["value"] for r in admin.get("/api/iocs").json()["iocs"]]
    assert IP in values and "evil.example.org" not in values


def test_tags_note_tlp_and_expiry(admin: TestClient):
    admin.post("/api/iocs", json={"items": [{"type": "domain", "value": "evil.example.org", "expires": "2020-01-01"}]})
    row = admin.get("/api/iocs").json()["iocs"][0]
    assert row["expired"] and row["expires"] == "2020-01-01"
    assert admin.get("/api/iocs?expired=false").json()["total"] == 0

    edited = admin.patch(
        "/api/iocs/item",
        json={
            "type": "domain",
            "value": "evil.example.org",
            "tags": ["C2", "c2"],
            "note": "n",
            "tlp": "red",
            "clearExpires": True,
        },
    )
    assert edited.status_code == 200, edited.text
    assert edited.json()["tags"] == ["c2"] and edited.json()["tlp"] == "red" and not edited.json()["expired"]
    assert "TLP:RED" in edited.json()["neverSent"]
    bad = admin.patch("/api/iocs/item", json={"type": "domain", "value": "evil.example.org", "expires": "soon"})
    assert bad.status_code == 422
    assert admin.patch("/api/iocs/item", json={"type": "ip", "value": "8.8.8.8", "note": "x"}).status_code == 404
    with SessionLocal() as db:
        assert "TLP:RED" in service.blocked(db, "domain", "evil.example.org", lib.Allowlist([]))


def test_export_with_chosen_fields_and_formats(admin: TestClient):
    listed = admin.post(
        "/api/iocs",
        json={"text": f"{IP}\nhttps://evil.example.org/a\n{SHA}", "tags": ["wave"], "list": {"name": "Wave A"}},
    ).json()["list"]
    scope = {"list": listed["id"]}

    default = admin.post("/api/iocs/export", json={"scope": scope})
    assert default.headers["content-disposition"] == 'attachment; filename="wave-a.csv"'
    rows = list(csv.reader(io.StringIO(default.text)))
    assert rows[0] == ["type", "value", "verdict", "score", "tags", "first_seen"]
    assert {row[1] for row in rows[1:]} == {IP, "https://evil.example.org/a", SHA}

    chosen = admin.post(
        "/api/iocs/export", json={"scope": scope, "fields": ["value", "lists", "per_source"], "defang": True}
    )
    rows = list(csv.reader(io.StringIO(chosen.text)))
    assert rows[0][:2] == ["value", "lists"] and "virustotal" in rows[0]
    assert "hxxps://evil[.]example[.]org/a" in {row[0] for row in rows[1:]} and rows[1][1] == "Wave A"

    text = admin.post("/api/iocs/export", json={"scope": scope, "format": "txt"}).text
    assert sorted(text.split()) == sorted([IP, "https://evil.example.org/a", SHA])
    stix = admin.post("/api/iocs/export", json={"scope": scope, "format": "stix"}).json()
    assert sum(1 for o in stix["objects"] if o["type"] == "indicator") == 3
    misp = admin.post("/api/iocs/export", json={"scope": scope, "format": "misp"}).json()
    assert misp["Event"]["info"] == "Nik indicators: Wave A" and len(misp["Event"]["Attribute"]) == 3

    # Nik's own JSON comes back as it left: tags and lists included.
    own = admin.post(
        "/api/iocs/export", json={"scope": scope, "format": "json", "fields": ["type", "value", "tags", "lists"]}
    ).text
    assert json.loads(own)["format"] == "nik-iocs"
    admin.post("/api/iocs/remove", json={"list": listed["id"]})
    assert admin.delete(f"/api/iocs/lists/{listed['id']}").status_code == 204
    assert admin.get("/api/iocs").json()["total"] == 0
    back = admin.post("/api/iocs", json={"text": own, "origin": "import"}).json()
    assert back["added"] == 3
    rows = admin.get("/api/iocs").json()["iocs"]
    assert all(r["origin"] == "import" and r["tags"] == ["wave"] for r in rows)
    assert all([entry["name"] for entry in r["lists"]] == ["Wave A"] for r in rows)

    selection = admin.post(
        "/api/iocs/export", json={"scope": {"items": [{"type": "ip", "value": IP}]}, "format": "txt"}
    ).text
    assert selection == f"{IP}\n"


def test_a_list_is_a_feed_for_machines(admin: TestClient):
    listed = admin.post(
        "/api/iocs",
        json={"text": f"{IP}\nevil.example.org\nold.example.org", "list": {"name": "Blocklist"}},
    ).json()["list"]
    admin.patch("/api/iocs/item", json={"type": "domain", "value": "old.example.org", "expires": "2020-01-01"})
    key = make_key(admin, scopes=["read"])
    url = f"/api/iocs/lists/{listed['id']}/feed"

    anonymous = TestClient(admin.app)
    assert anonymous.get(url).status_code == 401
    assert anonymous.get(url, headers=key).text.split() == ["evil.example.org", IP]  # the expired one is left out
    assert anonymous.get(f"{url}?types=ip", headers=key).text == f"{IP}\n"
    basic = base64.b64encode(f"nik:{key['X-API-Key']}".encode()).decode()
    assert anonymous.get(url, headers={"Authorization": f"Basic {basic}"}).status_code == 200
    wrong = base64.b64encode(b"nik:nope").decode()
    assert anonymous.get(url, headers={"Authorization": f"Basic {wrong}"}).status_code == 401

    admin.patch(f"/api/iocs/lists/{listed['id']}", json={"tlp": "red"})
    assert anonymous.get(url, headers=key).status_code == 403


def test_bulk_check_says_what_it_costs_then_works_in_the_background(admin: TestClient, fake_http):
    answers, calls = fake_http
    answers["https://internetdb.shodan.io/"] = (200, {"ports": [80], "tags": ["tor"]})
    answers["https://api.greynoise.io/"] = (200, {"classification": "malicious", "noise": True})
    listed = admin.post("/api/iocs", json={"text": f"{IP}\n185.220.101.48\n10.0.0.9", "list": {"name": "Feed"}}).json()[
        "list"
    ]
    scope = {"list": listed["id"]}

    dry = admin.post("/api/iocs/check", json={"scope": scope, "dryRun": True}).json()
    assert dry["check"] is None and calls == []
    assert dry["plan"]["total"] == 3 and dry["plan"]["toAsk"] == 2 and dry["plan"]["neverSent"] == 1
    assert {s["provider"]: s["needed"] for s in dry["plan"]["sources"]} == {"greynoise": 2, "internetdb": 2}

    started = admin.post("/api/iocs/check", json={"scope": scope}).json()["check"]
    assert started["status"] == "running" and started["total"] == 2 and started["done"] == 0
    with SessionLocal() as db:
        assert service.run_checks(db, admin.get("/api/settings").json(), budget_seconds=5) == 4
    done = admin.get(f"/api/iocs/checks/{started['id']}").json()
    assert done["status"] == "done" and done["done"] == 2 and done["verdicts"] == {"malicious": 2}
    rows = {r["value"]: r for r in admin.get("/api/iocs").json()["iocs"]}
    assert rows[IP]["verdict"] == "malicious" and rows[IP]["checkedAt"]

    # Fresh answers are reused: nothing left to ask.
    again = admin.post("/api/iocs/check", json={"scope": scope, "dryRun": True}).json()["plan"]
    assert again["toAsk"] == 0 and again["reused"] == 2
    assert (
        admin.post("/api/iocs/check", json={"scope": scope, "force": True, "dryRun": True}).json()["plan"]["toAsk"] == 2
    )


def test_a_check_out_of_quota_says_so_and_goes_on_later(admin: TestClient, fake_http):
    answers, _ = fake_http
    answers["https://internetdb.shodan.io/"] = (200, {"ports": [], "tags": []})
    answers["https://api.greynoise.io/"] = (200, {"classification": "benign", "noise": False})
    greynoise = providers.BY_ID["greynoise"]
    today = service.datetime.now(service.timezone.utc).date().isoformat()
    service.limiter.day[service._slot(greynoise, None)] = (today, greynoise.daily - 1)  # one request left
    admin.post("/api/iocs", json={"text": f"{IP}\n185.220.101.48"})
    check = admin.post("/api/iocs/check", json={"scope": {"filters": {}}}).json()
    source = next(s for s in check["plan"]["sources"] if s["provider"] == "greynoise")
    assert source["leftToday"] == 1 and source["today"] == 1 and source["later"] == 1

    with SessionLocal() as db:
        service.run_checks(db, admin.get("/api/settings").json(), budget_seconds=5)
    state = admin.get(f"/api/iocs/checks/{check['check']['id']}").json()
    assert state["status"] == "waiting" and state["done"] == 1
    assert state["message"].startswith("GreyNoise Community: daily quota used")

    service.limiter.reset()  # the next day
    with SessionLocal() as db:
        service.run_checks(db, admin.get("/api/settings").json(), budget_seconds=5)
    assert admin.get(f"/api/iocs/checks/{check['check']['id']}").json()["status"] == "done"

    stopped = admin.post("/api/iocs/check", json={"scope": {"filters": {}}, "force": True}).json()["check"]
    assert admin.post(f"/api/iocs/checks/{stopped['id']}/stop").json()["status"] == "stopped"


def test_a_watched_list_raises_an_alert_when_an_incident_holds_one_of_its_indicators(admin: TestClient):
    watched = admin.post("/api/iocs", json={"text": IP, "list": {"name": "AsyncRAT C2", "watch": True}}).json()["list"]
    assert watched["watch"] is True
    admin.post("/api/iocs", json={"text": "198.51.100.7", "list": {"name": "Quiet"}})
    assert admin.get("/api/iocs/alerts").json()["alerts"] == []

    _incident(admin, "inc1", f"curl http://{IP}/gate.php; curl http://198.51.100.7/")
    alerts = admin.get("/api/iocs/alerts").json()["alerts"]
    assert len(alerts) == 1
    assert alerts[0]["value"] == IP and alerts[0]["list"]["name"] == "AsyncRAT C2"
    assert alerts[0]["incident"] == {"id": "inc1", "name": "inc1"} and alerts[0]["seen"] is False
    assert admin.get("/api/iocs").json()["alerts"] == 1
    audit = admin.get("/api/audit").json()
    assert any(entry["action"] == "ioc.watch_hit" for entry in audit["entries"])

    # Saving the incident again does not repeat the alert.
    doc = admin.get("/api/incidents/inc1").json()
    assert admin.patch("/api/incidents/inc1", json={"data": doc["data"]}).status_code == 200
    assert len(admin.get("/api/iocs/alerts").json()["alerts"]) == 1
    assert admin.post("/api/iocs/alerts/seen").json() == {"seen": 1}
    assert admin.get("/api/iocs").json()["alerts"] == 0


def test_an_incidents_indicators_become_a_list(admin: TestClient):
    _incident(admin, "inc1", f"curl http://{IP}/gate.php")
    made = admin.post("/api/iocs/lists", json={"name": "From inc1", "scope": {"incident": "inc1"}})
    assert made.status_code == 201 and made.json()["count"] == 2  # the URL and its address
    detail = admin.get(f"/api/iocs/lists/{made.json()['id']}").json()
    assert detail["counts"]["all"] == 2 and detail["counts"]["inIncidents"] == 2


def test_only_the_author_or_an_admin_removes_a_list_and_read_keys_cannot_write(admin: TestClient):
    listed = admin.post("/api/iocs", json={"text": IP, "list": {"name": "Mine"}}).json()["list"]
    reader = make_key(admin, scopes=["read"])
    writer = make_key(admin, label="writer", scopes=["read", "write"])
    other = TestClient(admin.app)
    assert other.get("/api/iocs", headers=reader).status_code == 200
    assert other.post("/api/iocs", headers=reader, json={"text": IP}).status_code == 403
    assert other.delete(f"/api/iocs/lists/{listed['id']}", headers=writer).status_code == 403
    assert admin.delete(f"/api/iocs/lists/{listed['id']}").status_code == 204

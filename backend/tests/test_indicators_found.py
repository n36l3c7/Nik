"""A text made indicators (``nik.make-indicators``), and the indicators found by themselves when an
incident comes in: every door, the limit, the paths that are not read, a person's no, look-ups."""

from __future__ import annotations

import json

from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app import context as incident_context
from app import indicators_found as found
from app import recognise
from app.automation import payloads, triggers, worker
from app.core.db import SessionLocal
from app.core.models import AutomationEvent, FoundIndicator, FoundScan, Incident, IocEntry, Run
from app.enrichment import service
from tests.conftest import make_key
from tests.test_automation_engine import T0, edge, go, node, playbook, steps, test_actions  # noqa: F401 - a fixture
from tests.test_automation_events import on, said
from tests.test_commands import ran
from tests.test_enrichment import HOSTS, asked, turn_on
from tests.test_fetch import mapped, radar, run
from tests.test_fields import field, incident
from tests.test_mail_connector import box, instance, message  # noqa: F401 - box is a fixture
from tests.test_mirror import desk, start, sync
from tests.test_war_room import room

MD5 = "44d88612fea8a8f36de82e1278abb02f"
SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
DAY = "2026-11-20"


def iocs(admin: TestClient, incident_id: str = "i1") -> dict[tuple[str, str], list[str]]:
    listed = admin.get(f"/api/incidents/{incident_id}/iocs").json()["iocs"]
    return {(item["type"], item["value"]): item["sources"] for item in listed}


def listing(admin: TestClient, incident_id: str = "i1") -> dict:
    answer = admin.get(f"/api/incidents/{incident_id}/iocs/found")
    assert answer.status_code == 200, answer.text
    return answer.json()


def found_lines(admin: TestClient, incident_id: str = "i1") -> list[str]:
    return [entry["body"]["text"] for entry in room(admin, incident_id) if "found" in entry["body"]]


def setting(admin: TestClient, **changes) -> dict:
    answer = admin.put("/api/iocs/found/settings", json=changes)
    assert answer.status_code == 200, answer.text
    return answer.json()


# --------------------------------------------------------------------------- #
# A text made indicators                                                      #
# --------------------------------------------------------------------------- #
def test_a_text_is_made_indicators_of_the_incident_and_twice_makes_nothing_new(admin: TestClient, test_actions):  # noqa: F811
    incident(admin)
    done = ran(
        admin, '!nik-make-indicators text="C2 hxxp://bad-domain[.]net/gate.php and 185.220.101.47, kernel32.dll"'
    )
    output = done["step"]["output"]
    assert output["indicators"] == [
        {"type": "url", "value": "http://bad-domain.net/gate.php", "new": True, "marks": []},
        {"type": "domain", "value": "bad-domain.net", "new": True, "marks": []},
        {"type": "ip", "value": "185.220.101.47", "new": True, "marks": []},
    ]
    assert (output["created"], output["linked"], output["not_recognised"]) == (3, 3, [])
    # A URL gave two; they are the incident's, with where they came from.
    assert iocs(admin) == {
        ("url", "http://bad-domain.net/gate.php"): ["warroom"],
        ("domain", "bad-domain.net"): ["warroom"],
        ("ip", "185.220.101.47"): ["warroom"],
    }
    # Again: found, not made twice.
    again = ran(admin, '!nik-make-indicators text="hxxp://bad-domain[.]net/gate.php 185.220.101.47"')["step"]["output"]
    assert (again["created"], again["linked"]) == (0, 0)
    assert [item["new"] for item in again["indicators"]] == [False, False, False]
    assert len(iocs(admin)) == 3
    with SessionLocal() as db:
        assert len(db.get(Incident, "i1").doc["data"]["iocs"]["manual"]) == 3

    # A value alone is the first argument; a list is read item by item, and what is nothing says why.
    assert ran(admin, f"!nik-make-indicators {MD5}")["step"]["output"]["indicators"][0]["type"] == "md5"
    mixed = ran(admin, '!nik-make-indicators text=`["install.sh", "1.2.3", "evil-site.com", "10.1.2.3"]`')
    assert mixed["step"]["output"]["not_recognised"] == [
        {"text": "install.sh", "reason": "it reads as a file name: write it as a URL, or say it is a domain"},
        {"text": "1.2.3", "reason": "it reads as a version number, not as an address"},
    ]
    assert [(item["value"], item["marks"]) for item in mixed["step"]["output"]["indicators"]] == [
        ("evil-site.com", []),
        ("10.1.2.3", ["private", "allowlisted"]),
    ]
    # The type can be said; what is harmless can be left out.
    forced = ran(admin, "!nik-make-indicators text=update.pl type=domain")["step"]["output"]
    assert forced["indicators"] == [{"type": "domain", "value": "update.pl", "new": True, "marks": []}]
    wrong = ran(admin, "!nik-make-indicators text=evil-site.com type=ip")["step"]["output"]
    assert wrong["indicators"] == [] and wrong["not_recognised"][0]["reason"] == "it is not an IP address"
    left = ran(admin, '!nik-make-indicators text="192.168.1.1 example.com other-site.org" leave_out_harmless=true')
    assert [item["value"] for item in left["step"]["output"]["indicators"]] == ["other-site.org"]
    assert left["step"]["output"]["not_recognised"] == [
        {"text": "192.168.1.1", "reason": "left out: private, allowlisted"},
        {"text": "example.com", "reason": "left out: benign"},
    ]
    # Each call that made something is in the audit log, signed by the engine.
    audit = [entry for entry in admin.get("/api/audit").json()["entries"] if entry["action"] == "ioc.add"]
    assert audit and all(entry["actor"] == "nik-automation" for entry in audit)

    # Who may: what running a command asks, as for every command.
    viewer = make_key(admin, label="v", roles=["viewer"])
    assert typed_as(admin, "!nik-make-indicators evil-site.com", viewer).status_code == 403


def typed_as(admin: TestClient, line: str, headers: dict):
    return admin.post("/api/incidents/i1/war-room/command", headers=headers, json={"line": line})


def test_with_no_incident_the_indicators_page_keeps_them_and_a_dry_run_makes_nothing(admin: TestClient, test_actions):  # noqa: F811
    make = node(
        "make",
        "action",
        action="nik.make-indicators",
        args={
            "text": ["hxxps://evil-site[.]com/a", "bob[at]evil-site.com", "nothing"],
            "tags": ["c2"],
            "note": "From a feed",
        },
    )
    book = playbook(admin, "Feed", [make], [edge("start", "make")])
    dry = go(admin, book, dryRun=True)
    assert steps(dry)["make"]["output"]["created"] == 3 and admin.get("/api/iocs").json()["total"] == 0

    real = go(admin, book)
    output = steps(real)["make"]["output"]
    assert [(item["type"], item["value"]) for item in output["indicators"]] == [
        ("url", "https://evil-site.com/a"),
        ("domain", "evil-site.com"),
        ("email", "bob@evil-site.com"),
    ]
    assert (output["created"], output["linked"]) == (3, 0)
    assert output["not_recognised"] == [{"text": "nothing", "reason": "no indicator was recognised in it"}]
    rows = admin.get("/api/iocs").json()["iocs"]
    assert sorted((row["type"], row["value"], row["tags"], row["note"]) for row in rows) == [
        ("domain", "evil-site.com", ["c2"], "From a feed"),
        ("email", "bob@evil-site.com", ["c2"], "From a feed"),
        ("url", "https://evil-site.com/a", ["c2"], "From a feed"),
    ]
    assert steps(go(admin, book))["make"]["output"]["created"] == 0 and admin.get("/api/iocs").json()["total"] == 3


def test_making_indicators_asks_no_source_about_them(admin: TestClient, outside, test_actions):  # noqa: F811
    turn_on(outside, "shodan", "greynoise")
    shared = admin.get("/api/settings").json()
    shared["enrichment"]["auto"] = {"ip": True, "url": True, "hash": True}
    assert admin.put("/api/settings", json=shared).status_code == 200
    incident(admin)
    ran(admin, '!nik-make-indicators text="185.220.101.47 hxxp://bad-domain[.]net/gate.php"')
    assert outside.requests == []


# --------------------------------------------------------------------------- #
# Found when an incident comes in: the doors                                  #
# --------------------------------------------------------------------------- #
def test_an_incident_made_by_a_person_or_the_api_is_read(admin: TestClient):
    incident(admin, name="Beacon to evil-site.com from 10.1.2.3", host="WKS-01")
    shown = listing(admin)
    assert [(row["type"], row["value"], row["path"], row["door"]) for row in shown["found"]] == [
        ("domain", "evil-site.com", "incident.name", "hand")
    ]
    assert shown["removed"] == [] and shown["on"] is True
    assert (shown["scan"]["new"], shown["scan"]["leftOut"], shown["scan"]["over"]) == (1, {"private": 1}, 0)
    # It is one of the incident's indicators, with where it was read; one line of the War Room says so.
    assert iocs(admin) == {("domain", "evil-site.com"): ["found:incident.name"]}
    assert found_lines(admin) == ["1 indicator found: 1 domain; 1 left out as private."]
    audit = [entry for entry in admin.get("/api/audit").json()["entries"] if entry["action"] == "ioc.found"]
    assert [(entry["actor"], entry["details"]) for entry in audit] == [
        ("nik", "Found 1 indicators in the incident (hand)")
    ]

    key = make_key(admin, label="siem", roles=["analyst"])
    doc = {"id": "i2", "name": f"Dropper {SHA256}", "ticketId": "see hxxp://bad-domain[.]net/x", "data": {}}
    assert admin.post("/api/incidents", headers=key, json=doc).status_code == 201
    assert sorted((row["type"], row["path"], row["door"]) for row in listing(admin, "i2")["found"]) == [
        ("domain", "incident.ticket", "api"),
        ("sha256", "incident.name", "api"),
        ("url", "incident.ticket", "api"),
    ]
    assert found_lines(admin, "i2") == ["3 indicators found: 1 domain, 1 URL, 1 hash."]
    # An incident with nothing in it gets no line, and is still marked as read.
    incident(admin, "i3", name="Laptop of finance")
    assert found_lines(admin, "i3") == [] and listing(admin, "i3")["scan"]["new"] == 0
    # What was found goes with the incident when it is deleted.
    for incident_id in ("i1", "i2", "i3"):
        assert admin.delete(f"/api/incidents/{incident_id}").status_code == 204
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(FoundIndicator)) == 0
        assert db.scalar(select(func.count()).select_from(FoundScan)) == 0


def test_an_incident_a_playbook_makes_is_read(admin: TestClient, test_actions):  # noqa: F811
    make = node("make", "action", action="nik.create-incident", args={"title": "Phish from evil-site.com"})
    run_made = go(admin, playbook(admin, "Open", [make], [edge("start", "make")]))
    incident_id = steps(run_made)["make"]["output"]["incident"]["id"]
    assert [(row["value"], row["door"]) for row in listing(admin, incident_id)["found"]] == [
        ("evil-site.com", "playbook")
    ]


ALERTS = [
    {
        "id": "A-1",
        "title": "Beacon from WKS-01",
        "score": 91,
        "created": f"{DAY}T08:00:00Z",
        "host": "WKS-01",
        "c2": "hxxp://bad-domain[.]net/gate.php",
        "src": "10.1.2.3",
        "dst": "185.220.101.47",
        "sha": SHA256,
        "agentUuid": "b5a3c5f1e8d94f0c9a3d2e1f4a5b6c7d",
        "console": "https://radar.example.com/alerts/A-1",
        "note": "Seen with other-site.org and kernel32.dll, agent 4.2.1.900",
        "more": {
            "dns": ["cdn.bad-domain.net", "www.w3.org", "printer.local"],
            "xmlns": "http://schemas.microsoft.com/x",
        },
    }
]
RULES = [
    {"to": "name", "from": "{{ item.title }}"},
    {"to": "host", "from": "{{ item.host }}"},
    {"to": "source_url", "from": "{{ item.console }}"},
    {
        "to": "Alert(val.ID == obj.ID)",
        "from": {"ID": "{{ item.id }}", "Name": "{{ item.title }}", "URL": "{{ item.console }}"},
    },
    {"to": "URL(val.Data == obj.Data)", "from": {"Data": "{{ item.c2 }}"}},
    {"to": "IP(val.Address == obj.Address)", "from": {"Address": "{{ item.dst }}"}},
    {"to": "Host(val.Name == obj.Name)", "from": {"Name": "{{ item.host }}", "IP": "{{ item.src }}"}},
    {"to": "File(val.SHA256 == obj.SHA256)", "from": {"SHA256": "{{ item.sha }}"}},
    {"to": "ext.radar.agentUuid", "from": "{{ item.agentUuid }}"},
    {"to": "ext.radar.consoleUrl", "from": "{{ item.console }}"},
    {"to": "ext.radar.note", "from": "{{ item.note }}"},
    {"to": "ext.radar.more", "from": "{{ item.more }}"},
]


def fetched(admin: TestClient, outside, alerts: list | None = None) -> dict:
    """Radar installed, mapped with the rules above and told to fetch: its connection."""
    day = radar_day()
    served = [{**alert, "created": alert["created"].replace(DAY, day)} for alert in (alerts or ALERTS)]
    connection = radar(admin, outside, served)
    mapped(admin, RULES)
    assert admin.put(f"/api/fetch/{connection['id']}", json={"enabled": True}).status_code == 200
    return connection


def radar_day() -> str:
    from tests.test_fetch import DAY as yesterday

    return yesterday


def only_incident(admin: TestClient) -> str:
    with SessionLocal() as db:
        return db.scalars(select(Incident.id)).one()


def test_a_fetched_incident_is_read_once_and_says_where_each_indicator_was(admin: TestClient, outside):
    connection = fetched(admin, outside)
    done = run(admin, connection)["result"]
    assert (done["created"], done["incomplete"]) == (1, 0)
    incident_id = only_incident(admin)
    shown = listing(admin, incident_id)
    assert [(row["type"], row["value"], row["path"]) for row in shown["found"]] == [
        ("domain", "bad-domain.net", "context.URL[0].Data"),
        ("domain", "cdn.bad-domain.net", "context.ext.radar.more.dns[0]"),
        ("domain", "other-site.org", "context.ext.radar.note"),
        ("ip", "185.220.101.47", "context.IP[0].Address"),
        ("sha256", SHA256, "context.File[0].SHA256"),
        ("url", "http://bad-domain.net/gate.php", "context.URL[0].Data"),
    ]
    assert {row["door"] for row in shown["found"]} == {"fetch"}
    # Left out: the private address of the host, and the name of a schema host. Never read: the
    # address of the alert in Radar and the console link, the namespace of a document, and two
    # things 32 hex characters long that are no MD5: the agent's id, the id of the instance.
    assert shown["scan"]["leftOut"] == {"private": 1, "benign": 1}
    assert found_lines(admin, incident_id) == [
        "6 indicators found: 3 domains, 1 URL, 1 address, 1 hash; 2 left out as private or benign."
    ]
    held = iocs(admin, incident_id)
    assert held[("ip", "185.220.101.47")] == ["found:context.IP[0].Address"]
    assert ("md5", "b5a3c5f1e8d94f0c9a3d2e1f4a5b6c7d") not in held and len(held) == 6
    # The line of the item comes first, then the one line of what was found: two lines in all.
    assert len(room(admin, incident_id)) == 2

    # The next cycle brings nothing new, and nothing is found twice.
    assert run(admin, connection)["result"]["new"] == 0
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(FoundIndicator)) == 6
    # Asking for it again changes nothing either: no second line.
    again = admin.post(f"/api/incidents/{incident_id}/iocs/found/scan")
    assert again.status_code == 200 and again.json()["scan"]["new"] == 0 and again.json()["scan"]["door"] == "asked"
    assert len(found_lines(admin, incident_id)) == 1


def test_the_limit_of_an_incident_is_said_and_nothing_is_dropped_in_silence(admin: TestClient):
    assert setting(admin, cap=2)["cap"] == 2
    names = " ".join(f"host{index}.evil-site.com" for index in range(5))
    incident(admin, name=names[:200])
    shown = listing(admin)
    assert [row["value"] for row in shown["found"]] == ["host0.evil-site.com", "host1.evil-site.com"]
    assert (shown["scan"]["new"], shown["scan"]["over"], shown["scan"]["cap"]) == (2, 3, 2)
    assert found_lines(admin) == [
        "2 indicators found: 2 domains; 3 more were not kept: an incident is given 2 at most this way "
        "(Settings, Indicators found)."
    ]
    # Read again as it is: the same three are over, and it is not said twice.
    assert admin.post("/api/incidents/i1/iocs/found/scan").json()["scan"]["over"] == 3
    assert len(found_lines(admin)) == 1
    # The limit raised, a person asks: the rest is kept.
    setting(admin, cap=50)
    assert len(admin.post("/api/incidents/i1/iocs/found/scan").json()["found"]) == 5
    assert found_lines(admin)[-1] == "3 indicators found: 3 domains."


def test_the_setting_says_what_is_read_and_who_may_change_it(admin: TestClient):
    shown = admin.get("/api/iocs/found/settings").json()
    assert (shown["enabled"], shown["cap"], shown["leaveOutPrivate"], shown["leaveOutBenign"], shown["lookUps"]) == (
        True,
        500,
        True,
        True,
        False,
    )
    assert shown["types"] == shown["allTypes"] == ["ip", "domain", "url", "email", "md5", "sha1", "sha256"]
    assert "*uuid" in shown["skip"] and shown["skip"] == shown["skipDefault"] and shown["instances"] == {}
    analyst = make_key(admin, label="a", roles=["analyst"])
    assert admin.get("/api/iocs/found/settings", headers=analyst).status_code == 200
    assert admin.put("/api/iocs/found/settings", headers=analyst, json={"enabled": False}).status_code == 403
    wrong = {
        "cap": [0, 1001, "many", True],
        "types": [["registry"], "ip"],
        "skip": [["two words"], "x", ["x" * 201]],
        "enabled": ["yes"],
    }
    for name, values in wrong.items():
        for value in values:
            assert admin.put("/api/iocs/found/settings", json={name: value}).status_code == 400, (name, value)
    # Never saved, the limit is 500; it goes from 1 to 1000, and a saved one is kept as it was saved.
    assert (found.CAP_DEFAULT, found.CAP_MAX, shown["capMax"]) == (500, 1000, 1000)
    assert setting(admin, cap=1000)["cap"] == 1000 and setting(admin, cap=1)["cap"] == 1
    assert setting(admin, cap=50)["cap"] == 50
    with SessionLocal() as db:
        assert found.config(db)["cap"] == 50

    # Only some types; private and harmless values kept; a path of its own never read.
    field(admin, "details_note")
    setting(admin, types=["ip", "domain"], leaveOutPrivate=False, leaveOutBenign=False, skip=["incident.details_note"])
    doc = {
        "id": "i1",
        "name": "evil-site.com 10.1.2.3 example.com hxxp://bad-domain[.]net/x",
        "fields": {"details_note": "other-site.org"},
        "data": {},
    }
    assert admin.post("/api/incidents", json=doc).status_code == 201
    assert sorted(row["value"] for row in listing(admin)["found"]) == [
        "10.1.2.3",
        "bad-domain.net",
        "evil-site.com",
        "example.com",
    ]
    audit = [entry for entry in admin.get("/api/audit").json()["entries"] if entry["action"] == "settings.update"]
    assert audit[0]["details"] == "Changed how indicators are found: leaveOutBenign, leaveOutPrivate, skip, types"

    # Off: an incident is not read, and is not marked as read.
    setting(admin, enabled=False)
    incident(admin, "i2", name="evil-site.com again")
    assert listing(admin, "i2") == {"found": [], "removed": [], "scan": None, "on": False}
    assert iocs(admin, "i2") == {}
    # A person can still ask for that one.
    asked_for = admin.post("/api/incidents/i2/iocs/found/scan").json()
    assert [row["value"] for row in asked_for["found"]] == ["evil-site.com"]
    viewer = make_key(admin, label="v", roles=["viewer"])
    assert admin.post("/api/incidents/i2/iocs/found/scan", headers=viewer).status_code == 403
    assert admin.get("/api/incidents/i2/iocs/found", headers=viewer).status_code == 200
    assert admin.get("/api/incidents/nope/iocs/found").status_code == 404


def test_an_instance_can_be_told_apart_from_the_setting(admin: TestClient, outside):
    connection = fetched(admin, outside)
    setting(admin, enabled=False)
    said = admin.put(f"/api/iocs/found/instances/{connection['id']}", json={"enabled": True})
    assert said.status_code == 200 and said.json() == {"id": connection["id"], "enabled": True, "setting": False}
    assert admin.get("/api/iocs/found/settings").json()["instances"] == {connection["id"]: True}
    run(admin, connection)
    incident_id = only_incident(admin)
    assert len(listing(admin, incident_id)["found"]) == 6 and listing(admin, incident_id)["on"] is True
    # An incident made by hand follows the setting, which is off.
    incident(admin, "byhand", name="evil-site.com")
    assert listing(admin, "byhand")["scan"] is None
    # Back to what the setting says; an instance that does not exist; who may.
    back = admin.put(f"/api/iocs/found/instances/{connection['id']}", json={"enabled": None}).json()
    assert back["enabled"] is None and admin.get("/api/iocs/found/settings").json()["instances"] == {}
    assert admin.get(f"/api/iocs/found/instances/{connection['id']}").json()["enabled"] is None
    assert admin.put("/api/iocs/found/instances/nope", json={"enabled": True}).status_code == 404
    analyst = make_key(admin, label="a", roles=["analyst"])
    refused = admin.put(f"/api/iocs/found/instances/{connection['id']}", headers=analyst, json={"enabled": True})
    assert refused.status_code == 403


def test_an_instance_told_not_to_be_read_is_not(admin: TestClient, outside):
    connection = fetched(admin, outside)
    assert admin.put(f"/api/iocs/found/instances/{connection['id']}", json={"enabled": False}).status_code == 200
    run(admin, connection)
    incident_id = only_incident(admin)
    assert listing(admin, incident_id) == {"found": [], "removed": [], "scan": None, "on": False}
    assert len(room(admin, incident_id)) == 1


def test_a_message_the_mail_connector_brings_in_is_read_after_it_is_analysed(admin: TestClient, box):  # noqa: F811
    from app import fetch
    from app.core.models import Connection

    text = "Dear user, confirm at https://login-portal.top/a?id=7 today."
    subject = "Your mailbox is full: see portal-notice.org or login-portal.top"
    box.folders["INBOX"] = {21: [message(21, subject, sender="it-desk@mail-notice.net", text=text), set()]}
    with SessionLocal() as db:
        instance(db)
        done = fetch.cycle(db, db.get(Connection, "m" * 32))
        assert (done["created"], done["incomplete"]) == (1, 0), done
    incident_id = only_incident(admin)
    held = iocs(admin, incident_id)
    # Mail Analysis gave the incident the sender and the link of the message, as for an uploaded
    # .eml: the incident is read after that, so what was found is only what the analysis did not give.
    assert held[("email", "it-desk@mail-notice.net")] == ["mail:message-21.eml"]
    assert held[("domain", "login-portal.top")] == ["mail:message-21.eml"]
    shown = listing(admin, incident_id)
    assert [(row["type"], row["value"], row["path"], row["door"]) for row in shown["found"]] == [
        ("domain", "portal-notice.org", "context.Mail[0].Subject", "fetch")
    ]
    assert held[("domain", "portal-notice.org")] == ["found:context.Mail[0].Subject"]
    assert found_lines(admin, incident_id) == ["1 indicator found: 1 domain."]


# --------------------------------------------------------------------------- #
# Updates, a person's no, loops                                               #
# --------------------------------------------------------------------------- #
def test_a_mirror_update_adds_what_is_new_and_a_removed_indicator_does_not_come_back(admin: TestClient, outside):
    connection, world = desk(admin, outside)
    incident(admin)
    assert start(admin, connection, "in").status_code == 201
    world.ticket["title"] = "Laptop of finance talks to evil-site.com"
    assert "name" in sync(admin)["changed"]
    shown = listing(admin)
    assert [(row["value"], row["path"], row["door"]) for row in shown["found"]] == [
        ("evil-site.com", "incident.name", "mirror")
    ]
    assert found_lines(admin) == ["1 indicator found: 1 domain."]
    # Read again with nothing changed, then with something else changed: nothing twice.
    sync(admin)
    world.ticket["priority"] = 1
    sync(admin)
    assert len(listing(admin)["found"]) == 1 and len(found_lines(admin)) == 1

    # A person says no to it: it leaves the incident, and the next update does not bring it back.
    gone = admin.post("/api/incidents/i1/iocs/found/remove", json={"type": "domain", "value": "evil-site.com"})
    assert gone.status_code == 200 and gone.json()["found"] == []
    assert [(row["value"], row["removedBy"]) for row in gone.json()["removed"]] == [("evil-site.com", "admin")]
    assert iocs(admin) == {}
    world.ticket["title"] = "Laptop of finance talks to evil-site.com and bad-domain.net"
    sync(admin)
    after = listing(admin)
    assert [row["value"] for row in after["found"]] == ["bad-domain.net"] and after["scan"]["removed"] == 1
    assert iocs(admin) == {("domain", "bad-domain.net"): ["found:incident.name"]}
    assert found_lines(admin)[-1] == "1 indicator found: 1 domain."
    # Asked for by hand, it is still a no; put back, it is there again.
    assert [row["value"] for row in admin.post("/api/incidents/i1/iocs/found/scan").json()["found"]] == [
        "bad-domain.net"
    ]
    back = admin.post("/api/incidents/i1/iocs/found/restore", json={"type": "domain", "value": "evil-site.com"})
    assert back.status_code == 200 and len(back.json()["found"]) == 2 and back.json()["removed"] == []
    assert ("domain", "evil-site.com") in iocs(admin)
    # What is not there cannot be removed or put back; a viewer does neither.
    nothing = {"type": "domain", "value": "never.seen.com"}
    assert admin.post("/api/incidents/i1/iocs/found/remove", json=nothing).status_code == 404
    assert admin.post("/api/incidents/i1/iocs/found/restore", json=nothing).status_code == 404
    viewer = make_key(admin, label="v", roles=["viewer"])
    pair = {"type": "domain", "value": "evil-site.com"}
    assert admin.post("/api/incidents/i1/iocs/found/remove", headers=viewer, json=pair).status_code == 403
    actions = [entry["action"] for entry in admin.get("/api/audit").json()["entries"]]
    assert "ioc.found_removed" in actions and "ioc.found_restored" in actions


def test_an_incident_that_was_never_read_is_not_read_by_an_update(admin: TestClient, outside):
    # An incident from before incidents were read: no mark of a reading.
    connection, world = desk(admin, outside)
    incident(admin)
    with SessionLocal() as db:
        db.delete(db.get(FoundScan, "i1"))
        db.commit()
    assert start(admin, connection, "in").status_code == 201
    world.ticket["title"] = "Laptop of finance talks to evil-site.com"
    sync(admin)
    assert listing(admin) == {"found": [], "removed": [], "scan": None, "on": True}


def test_what_a_run_writes_to_the_context_is_not_read_and_what_a_connector_writes_is(admin: TestClient):
    incident(admin)
    with SessionLocal() as db:
        row = db.get(Incident, "i1")
        incident_context.apply(db, row, [("IP", {"Address": "185.220.101.47"})], "run:abc")
        db.commit()
    assert listing(admin)["found"] == []
    with SessionLocal() as db:
        row = db.get(Incident, "i1")
        incident_context.apply(db, row, [("Domain", {"Name": "evil-site.com"})], "connector:desk")
        db.commit()
    # The whole incident is read then: what the run had written is there too.
    assert sorted((row["value"], row["path"]) for row in listing(admin)["found"]) == [
        ("185.220.101.47", "context.IP[0].Address"),
        ("evil-site.com", "context.Domain[0].Name"),
    ]


def test_events_are_written_once_and_a_playbook_they_start_does_not_start_itself_again(admin: TestClient, test_actions):  # noqa: F811
    watched = admin.post(
        "/api/iocs", json={"text": "evil-site.com\nbad-domain.net", "list": {"name": "C2", "watch": True}}
    )
    assert watched.status_code == 201, watched.text
    # A playbook that waits for a watched indicator, and makes another indicator of the incident.
    make = node("make", "action", action="nik.make-indicators", args={"text": "bad-domain.net"})
    book = playbook(
        admin, "On a hit", [make], [edge("start", "make")], trigger={"event": "ioc.watch_hit"}, enabled=True
    )
    incident(admin, name="Beacon to evil-site.com")

    def hits() -> list[dict]:
        with SessionLocal() as db:
            wanted = select(AutomationEvent).where(AutomationEvent.kind == "ioc.watch_hit")
            return [event.payload for event in db.scalars(wanted.order_by(AutomationEvent.created_at))]

    assert len(hits()) == 1 and hits()[0]["caused_by_run"] is None
    # Read again: the indicator is not new, and no second event is written.
    admin.post("/api/incidents/i1/iocs/found/scan")
    assert len(hits()) == 1
    for _ in range(4):  # the event starts the playbook; what the playbook causes starts nothing
        worker.drain()
    with SessionLocal() as db:
        runs = db.scalars(select(Run).where(Run.playbook_id == book)).all()
        assert [run_row.status for run_row in runs] == ["done"]
        run_id = runs[0].id
    assert ("domain", "bad-domain.net") in iocs(admin)
    # The hit the run caused says so, which is what keeps the playbook from starting on it.
    assert [payload["caused_by_run"] for payload in hits()] == [None, run_id]


def many_hosts(db, count: int, source: str = "connector:desk") -> None:
    """Write ``count`` names nobody has seen to the context of i1, 300 to a text."""
    row = db.get(Incident, "i1")
    names = [f"host{index:04d}.evil-site.com" for index in range(count)]
    writes = [(f"ext.report.part{at // 300}", " ".join(names[at : at + 300])) for at in range(0, count, 300)]
    incident_context.apply(db, row, writes, source)
    db.commit()


def test_at_the_largest_limit_a_thousand_are_kept_and_the_rest_is_counted_and_said(admin: TestClient):
    assert setting(admin, cap=1000)["cap"] == 1000
    incident(admin)
    with SessionLocal() as db:
        many_hosts(db, 1200)
    shown = listing(admin)
    scan = shown["scan"]
    assert (len(shown["found"]), scan["new"], scan["kept"], scan["over"], scan["cap"]) == (1000, 1000, 1000, 200, 1000)
    assert scan["unread"] == 0 and scan["byType"] == {"domain": 1000}
    # In the order they were read: the first thousand, each with where it was.
    assert shown["found"][0]["value"] == "host0000.evil-site.com"
    assert shown["found"][-1]["value"] == "host0999.evil-site.com"
    assert shown["found"][-1]["path"] == "context.ext.report.part3"
    assert found_lines(admin) == [
        "1000 indicators found: 1000 domains; 200 more were not kept: an incident is given 1000 at most this way "
        "(Settings, Indicators found)."
    ]
    # All of them are the incident's indicators, not only a first page of them.
    assert len(iocs(admin)) == 1000
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(IocEntry).where(IocEntry.incident_id == "i1")) == 1000
        # One event for the reading, small: how many of each type, the first hundred, and that it was cut.
        (event,) = db.scalars(select(AutomationEvent).where(AutomationEvent.kind == "indicators.found")).all()
    said = event.payload["data"]["found"]
    assert (said["count"], said["kept"], said["by_type"]["domain"], said["cut"], said["more"]) == (
        1000, 1000, 1000, True, 900
    )  # fmt: skip
    assert len(said["indicators"]) == len(said["values"]) == payloads.FOUND_LISTED == 100
    assert len(json.dumps(event.payload)) < 20_000
    # Read again: nothing new, the same two hundred are over, no second line and no second event.
    again = admin.post("/api/incidents/i1/iocs/found/scan").json()["scan"]
    assert (again["new"], again["over"]) == (0, 200) and len(found_lines(admin)) == 1
    with SessionLocal() as db:
        assert len(db.scalars(select(AutomationEvent).where(AutomationEvent.kind == "indicators.found")).all()) == 1


def test_an_install_that_never_saved_the_setting_keeps_five_hundred(admin: TestClient):
    incident(admin)
    with SessionLocal() as db:
        assert db.get(found.Setting, found.SETTINGS_ID) is None
        many_hosts(db, 520)
    scan = listing(admin)["scan"]
    assert (scan["new"], scan["over"], scan["cap"]) == (500, 20, 500)
    assert found_lines(admin)[0].endswith(
        "20 more were not kept: an incident is given 500 at most this way (Settings, Indicators found)."
    )


# --------------------------------------------------------------------------- #
# The event of a reading                                                      #
# --------------------------------------------------------------------------- #
def found_events() -> list[AutomationEvent]:
    with SessionLocal() as db:
        wanted = select(AutomationEvent).where(AutomationEvent.kind == "indicators.found")
        return list(db.scalars(wanted.order_by(AutomationEvent.created_at, AutomationEvent.id)))


def runs_of_book(book: str) -> list[Run]:
    with SessionLocal() as db:
        return list(db.scalars(select(Run).where(Run.playbook_id == book).order_by(Run.started_at)))


def test_a_reading_that_kept_something_new_writes_one_event_and_starts_a_playbook_once(
    admin: TestClient,
    test_actions,  # noqa: F811
):
    offered = admin.get("/api/automation/catalog").json()["events"]
    assert "indicators.found" in offered and triggers.object_of({"event": "indicators.found"}) == "incident"
    text = (
        "{{ trigger.found.count }} by {{ trigger.found.door }} in {{ trigger.incident.id }}: "
        "{{ trigger.found.values | join(' ') }} ({{ trigger.found.by_type.domain }} domains)"
    )
    book = on(admin, "On found", "indicators.found", text)
    incident(admin, name="Beacon to evil-site.com and 185.220.101.47, also 10.1.2.3")
    (event,) = found_events()
    data, classes = event.payload["data"], event.payload["classes"]
    assert (event.object_kind, event.object_id, event.payload["caused_by_run"]) == ("incident", "i1", None)
    assert data["incident"]["id"] == "i1"
    assert data["found"] == {
        "door": "hand",
        "count": 2,
        "by_type": {"ip": 1, "domain": 1, "url": 0, "email": 0, "md5": 0, "sha1": 0, "sha256": 0},
        "indicators": [
            {"type": "domain", "value": "evil-site.com", "path": "incident.name"},
            {"type": "ip", "value": "185.220.101.47", "path": "incident.name"},
        ],
        "values": ["evil-site.com", "185.220.101.47"],
        "cut": False,
        "more": 0,
        "kept": 2,
    }
    assert classes["found.indicators.value"] == classes["found.values"] == ["public_indicator"]
    assert classes["found.count"] == ["verdict"] and classes["incident.name"] == ["incident_text"]
    # The same event read twice by the worker, and read again by hand: one run, whatever the order.
    worker.drain()
    with SessionLocal() as db:
        again = db.get(AutomationEvent, event.id)
        assert triggers.handle_event(db, again, T0) == []
        db.commit()
    worker.drain()
    assert said(admin, book) == ["2 by hand in i1: evil-site.com 185.220.101.47 (1 domains)"]
    # A reading that finds nothing new writes no event: asked again, or updated with what it holds.
    admin.post("/api/incidents/i1/iocs/found/scan")
    assert len(found_events()) == 1
    # A playbook that waits for many of them is not started by few.
    many = {"all": [{"left": "{{ trigger.found.count }}", "op": "gte", "right": 10}]}
    quiet = on(admin, "On many", "indicators.found", "many", conditions=many)
    with SessionLocal() as db:
        incident_context.apply(db, db.get(Incident, "i1"), [("Domain", {"Name": "bad-domain.net"})], "connector:desk")
        db.commit()
    assert sorted(item.payload["data"]["found"]["door"] for item in found_events()) == ["hand", "mirror"]
    worker.drain()
    assert len(runs_of_book(book)) == 2 and runs_of_book(quiet) == []
    # A private address that the setting keeps is said to be one, to the playbook and to the guard.
    setting(admin, leaveOutPrivate=False, leaveOutBenign=False)
    admin.post("/api/incidents/i1/iocs/found/scan")
    (inside,) = [item for item in found_events() if item.payload["data"]["found"]["values"] == ["10.1.2.3"]]
    assert "private_value" in inside.payload["classes"]["found.values"]
    assert "public_indicator" not in inside.payload["classes"]["found.values"]


def test_a_playbook_started_by_what_was_found_cannot_start_itself_again(admin: TestClient, outside, test_actions):  # noqa: F811
    """The loop, tried three ways, each bounded by a counter: the run makes an incident with
    indicators (read: the event names the run, and its playbook does not start on it); the run writes
    to the context (that starts no reading); and the other side says something new at every turn, as
    if the run made it do so (each reading with something new is one run, and none past the limit of
    the setting)."""
    assert setting(admin, cap=4)["cap"] == 4
    make = node("make", "action", action="nik.create-incident", args={"title": "Seen with other-site.org"})
    book = playbook(
        admin, "On found", [make], [edge("start", "make")], trigger={"event": "indicators.found"}, enabled=True
    )
    connection, world = desk(admin, outside)
    incident(admin, name="Beacon to evil-site.com")
    assert start(admin, connection, "in").status_code == 201
    for _turn in range(5):
        worker.drain()
    first = runs_of_book(book)
    assert [row.status for row in first] == ["done"]
    # The incident the run made was read, and the event of that reading names the run.
    (made,) = [item for item in found_events() if item.object_id != "i1"]
    assert (made.payload["caused_by_run"], made.payload["depth"]) == (first[0].id, 1)
    # What a run writes to the context of the incident starts no reading, so no event.
    with SessionLocal() as db:
        wrote = [("Domain", {"Name": "run-wrote.net"})]
        incident_context.apply(db, db.get(Incident, "i1"), wrote, f"run:{first[0].id}")
        db.commit()
    assert len(found_events()) == 2 and len(listing(admin)["found"]) == 1

    # The other side changes at every other turn. Ten turns: the same thing said twice is one
    # reading with something new. The first of them reads the whole incident, what the run wrote
    # too; the limit of four is reached at the second, and nothing is kept or started after it.
    names = ["evil-site.com"]
    for turn in range(10):
        if turn % 2 == 0:
            names.append(f"c2-{turn}.bad-domain.net")
        world.ticket["title"] = "Laptop talks to " + " ".join(names)
        sync(admin)
        for _again in range(3):
            worker.drain()
    kept = [row["value"] for row in listing(admin)["found"]]
    assert kept == ["evil-site.com", "c2-0.bad-domain.net", "run-wrote.net", "c2-2.bad-domain.net"]
    assert listing(admin)["scan"]["over"] == 3
    mine = [item.payload for item in found_events() if item.object_id == "i1"]
    assert sorted(payload["data"]["found"]["count"] for payload in mine) == [1, 1, 2]
    assert [payload["caused_by_run"] for payload in mine] == [None, None, None]
    runs = runs_of_book(book)
    # One run for each reading of i1 that kept something new, and none for the incidents those runs made.
    assert len(runs) == 3 and {row.status for row in runs} == {"done"}
    assert len({row.event_key for row in runs}) == 3 and all(row.event_key for row in runs)
    others = [item for item in found_events() if item.object_id != "i1"]
    assert len(others) == 3 and all(item.payload["caused_by_run"] for item in others)


# --------------------------------------------------------------------------- #
# Look-ups                                                                    #
# --------------------------------------------------------------------------- #
def test_found_indicators_start_no_storm_of_look_ups(admin: TestClient, outside):
    turn_on(outside, "shodan", answers=False)
    outside.answer(HOSTS["shodan"], json={"ports": [80], "tags": []})
    shared = admin.get("/api/settings").json()
    shared["enrichment"]["auto"]["ip"] = True
    assert admin.put("/api/settings", json=shared).status_code == 200
    addresses = [f"185.220.101.{index}" for index in range(1, 31)]
    field(admin, "seen_addresses")
    doc = {"id": "i1", "name": "Scan", "fields": {"seen_addresses": " ".join(addresses)}, "data": {}}
    assert admin.post("/api/incidents", json=doc).status_code == 201
    assert len(listing(admin)["found"]) == 30
    # Making the incident asked nothing; the automatic look-ups, which are on for addresses, leave
    # out what nobody chose.
    assert outside.requests == []
    with SessionLocal() as db:
        assert service.run_cycle(db, admin.get("/api/settings").json(), budget_seconds=5) == 0
    assert outside.requests == []

    # One of them is also looked at by a person: that one is asked about, once.
    with SessionLocal() as db:
        from app import iocs as index

        index.add_manual(db, db.get(Incident, "i1"), "ip", addresses[0], "warroom", "admin")
        db.commit()
        assert service.run_cycle(db, admin.get("/api/settings").json(), budget_seconds=5) == 1
    assert [request["path"] for request in asked(outside, "shodan")] == [f"/{addresses[0]}"]

    # The setting says to ask about the found ones too: each once, and no more than a pass allows.
    assert setting(admin, lookUps=True)["lookUps"] is True
    with SessionLocal() as db:
        assert service.run_cycle(db, admin.get("/api/settings").json(), budget_seconds=5, max_calls=10) == 10
        assert service.run_cycle(db, admin.get("/api/settings").json(), budget_seconds=5) == 19
        assert service.run_cycle(db, admin.get("/api/settings").json(), budget_seconds=5) == 0
    assert sorted(request["path"] for request in asked(outside, "shodan")) == sorted(f"/{ip}" for ip in addresses)


def test_five_hundred_found_addresses_are_left_alone_by_the_automatic_look_ups(admin: TestClient, outside):
    """The limit as it is when nobody set it: an incident given 500 addresses by finding, with the
    automatic look-ups on for addresses, asks no source about any of them."""
    turn_on(outside, "shodan", answers=False)
    outside.answer(HOSTS["shodan"], json={"ports": [80], "tags": []})
    shared = admin.get("/api/settings").json()
    shared["enrichment"]["auto"]["ip"] = True
    assert admin.put("/api/settings", json=shared).status_code == 200
    incident(admin)
    addresses = [f"185.220.{100 + index // 250}.{1 + index % 250}" for index in range(500)]
    with SessionLocal() as db:
        writes = [(f"ext.scan.part{at // 250}", " ".join(addresses[at : at + 250])) for at in range(0, 500, 250)]
        incident_context.apply(db, db.get(Incident, "i1"), writes, "connector:desk")
        db.commit()
    shown = listing(admin)
    assert (len(shown["found"]), shown["scan"]["new"], shown["scan"]["over"]) == (500, 500, 0)
    assert len(iocs(admin)) == 500
    with SessionLocal() as db:
        assert service.run_cycle(db, admin.get("/api/settings").json(), budget_seconds=5) == 0
    assert outside.requests == []


# --------------------------------------------------------------------------- #
# Reading: paths and bounds                                                   #
# --------------------------------------------------------------------------- #
def test_a_path_is_written_as_a_playbook_writes_it_and_skipped_by_key_or_by_path():
    material = {
        "incident": {"name": "n", "url": "/incident/1"},
        "context": {
            "URL": [{"Data": "a"}, {"Data": "b"}],
            "Ticket": [{"URL": "t", "Number": "INC1"}],
            "ext": {
                "check-point": {
                    "a key": ["x"],
                    'say "hi"': "y",
                    "agentUuid": "u",
                    "Deep": {"permaLink": "p", "ok": "z"},
                }
            },
        },
    }
    read = list(found.strings(material, list(found.SKIP_DEFAULT)))
    assert read == [
        ("context.URL[0].Data", "a"),
        ("context.URL[1].Data", "b"),
        ("context.Ticket[0].Number", "INC1"),
        ("incident.name", "n"),
        ('context.ext["check-point"]["a key"][0]', "x"),
        ('context.ext["check-point"]["say \\"hi\\""]', "y"),
        ('context.ext["check-point"].Deep.ok', "z"),
    ]
    # A whole branch can be left unread; a pattern with dots is a whole path, without the numbers.
    assert [path for path, _ in found.strings(material, ["context.ext.check-point.*", "context.URL.Data"])] == [
        "context.Ticket[0].URL",
        "context.Ticket[0].Number",
        "incident.name",
        "incident.url",
    ]
    # Each of those paths reads back to its value as an expression.
    from app.automation import expressions as ex

    scope = ex.Scope(values=material)
    for path, text in read:
        assert ex.render_text("{{ " + path + " }}", scope).data == text, path


def test_an_incident_too_large_is_read_as_far_as_the_bound_and_says_so(monkeypatch):
    monkeypatch.setattr(found, "STRINGS_MAX", 3)
    material = {
        "incident": {},
        "context": {"ext": {"x": {"list": [f"host{index}.evil-site.com" for index in range(10)]}}},
    }
    cfg = {**found.DEFAULTS, "skip": []}
    result = found.read(material, cfg, recognise.NOTHING_KNOWN)
    assert [item.value for item, _ in result["found"]] == [f"host{index}.evil-site.com" for index in range(3)]
    assert result["unread"] == 7
    summary = {"new": 3, "byType": {"domain": 3}, "leftOut": {}, "over": 0, "unread": 7, "cap": 50}
    assert found.sentence(summary) == (
        "3 indicators found: 3 domains; 7 values of the incident were not read: it holds too many."
    )
    # One string longer than the bound is read as far as it.
    monkeypatch.setattr(found, "STRING_MAX", 30)
    long = {"incident": {"name": "evil-site.com " + "x" * 100 + " bad-domain.net"}, "context": {}}
    assert [item.value for item, _ in found.read(long, cfg, recognise.NOTHING_KNOWN)["found"]] == ["evil-site.com"]


def test_the_organisations_own_names_and_its_allowlist_are_left_out(admin: TestClient):
    shared = admin.get("/api/settings").json()
    shared["mail"] = {"orgDomains": ["corp-bank.com"], "trustedAuthServers": []}
    shared["iocAllowlist"] = [*shared["iocAllowlist"], "partner-site.org"]
    assert admin.put("/api/settings", json=shared).status_code == 200
    incident(
        admin, name="anna@corp-bank.com clicked hxxp://evil-site[.]com/a, then login.microsoft.com, partner-site.org"
    )
    shown = listing(admin)
    assert sorted(row["value"] for row in shown["found"]) == ["evil-site.com", "http://evil-site.com/a"]
    assert shown["scan"]["leftOut"] == {"benign": 3}


def test_what_the_incident_holds_already_is_not_found_again(admin: TestClient):
    doc = {
        "id": "i1",
        "name": "curl to 185.220.101.47 and evil-site.com",
        "data": {
            "commands": {"shells": {"bash": {"commands": [{"command": "curl http://185.220.101.47/x", "time": 1}]}}}
        },
    }
    assert admin.post("/api/incidents", json=doc).status_code == 201
    # The address is the incident's from its shell history: only the name is new.
    assert [row["value"] for row in listing(admin)["found"]] == ["evil-site.com"]
    held = iocs(admin)
    assert held[("ip", "185.220.101.47")] == ["commands:bash"] and held[("domain", "evil-site.com")] == [
        "found:incident.name"
    ]
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(IocEntry).where(IocEntry.incident_id == "i1")) == 3
    assert json.dumps(listing(admin)["scan"]["byType"]) == '{"domain": 1}'

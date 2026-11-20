"""What starts a playbook besides an incident: an e-mail, a file or an address
analysed, a verdict that changed, a watched indicator, a disk nearly full, a
request from outside; and runs started by hand on those objects."""

from __future__ import annotations

import hashlib
import json
import time
from collections import namedtuple

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.automation import state, triggers, worker
from app.core.db import SessionLocal
from app.core.models import AutomationEvent, Playbook, Run
from app.core.ratelimit import limiter
from app.events import KNOWN_EVENTS
from app.routers import automation as automation_routes
from tests import vendor
from tests.conftest import make_key
from tests.test_analysis_links import SCANNED, _scan
from tests.test_automation_engine import (  # noqa: F401 - test_actions is a fixture
    T0,
    echo,
    edge,
    node,
    playbook,
    run_of,
    runs_of,
    steps,
    test_actions,
)
from tests.test_mail import no_dns, phishing_message  # noqa: F401 - no_dns is a fixture
from tests.test_malware import fake_pe
from tests.test_urls import browser  # noqa: F401 - a fixture

IP = "185.220.101.47"


def events(kind: str) -> list[AutomationEvent]:
    with SessionLocal() as db:
        rows = db.scalars(select(AutomationEvent).where(AutomationEvent.kind == kind)).all()
        return sorted(rows, key=lambda row: row.created_at)


def on(admin: TestClient, name: str, event: str, text: str, **trigger) -> str:
    return playbook(
        admin, name, [echo("a", text)], [edge("start", "a")], trigger={"event": event, **trigger}, enabled=True
    )


def said(admin: TestClient, playbook_id: str) -> list[str]:
    return [steps(run_of(admin, run["id"]))["a"]["output"]["text"] for run in reversed(runs_of(admin, playbook_id))]


# --------------------------------------------------------------------------- #
# E-mails, files, addresses                                                   #
# --------------------------------------------------------------------------- #
def test_an_analysed_mail_starts_the_playbooks_that_wait_for_it(admin: TestClient, no_dns):  # noqa: F811
    flagged = {"all": [{"left": "{{ trigger.mail.verdict }}", "op": "in", "right": ["phishing", "suspicious"]}]}
    pb = on(
        admin,
        "Reported mail",
        "mail.analysed",
        "{{ trigger.mail.sender_domain }} sent {{ trigger.mail.attachments | length }} files",
        conditions=flagged,
    )
    mail = admin.post("/api/artifacts/mails", files={"file": ("reported.eml", phishing_message())}).json()
    (event,) = events("mail.analysed")
    assert (event.object_kind, event.object_id) == ("artifact", mail["id"])
    data, classes = event.payload["data"], event.payload["classes"]
    held = data["mail"]
    assert held["sha256"] == mail["ref"] and held["artifact_id"] == mail["id"]
    assert held["url"] == f"/artifact/{mail['id']}" and data["from_mailbox"] == ""
    assert "@" in held["sender"] and held["sender_domain"] == held["sender"].split("@")[1]
    assert held["sender_sha256"] == hashlib.sha256(held["sender"].encode()).hexdigest()
    assert held["verdict"] in ("phishing", "suspicious") and held["score"] > 0
    assert held["attachments"] and set(held["attachments"][0]) == {"name", "sha256", "size"}
    assert all(url.startswith("http") for url in held["urls"])
    # The guard is told what each field is.
    assert classes["mail.sender"] == ["email_address"] and classes["mail.subject"] == ["subject"]
    assert classes["mail.attachments.name"] == ["attachment_name"] and classes["mail.sha256"] == ["hash"]
    assert "incident" not in data

    worker.drain()
    (run,) = runs_of(admin, pb)
    assert (run["trigger"], run["artifactId"], run["incidentId"]) == ("mail.analysed", mail["id"], None)
    assert said(admin, pb) == [f"{held['sender_domain']} sent {len(held['attachments'])} files"]
    assert admin.get(f"/api/automation/runs?artifact={mail['id']}").json()["total"] == 1

    # In an incident, the event carries the incident and the run belongs to it too.
    assert admin.post("/api/incidents", json={"id": "i1", "name": "i1", "data": {}}).status_code == 201
    added = admin.post("/api/incidents/i1/mails", files={"file": ("reported.eml", phishing_message())})
    assert added.status_code in (200, 201), added.text
    last = events("mail.analysed")[-1]
    assert last.payload["data"]["incident"]["id"] == "i1"
    assert last.payload["classes"]["incident.name"] == ["incident_text"]
    worker.drain()
    assert runs_of(admin, pb)[0]["incidentId"] == "i1"


def test_an_analysed_file_and_a_scanned_address_start_playbooks(admin: TestClient, browser):  # noqa: F811
    on_file = on(admin, "On file", "file.analysed", "{{ trigger.file.name }} is {{ trigger.file.type }}")
    on_url = on(admin, "On address", "url.analysed", "{{ trigger.scan.host }}: {{ trigger.scan.verdict }}")
    made = admin.post("/api/artifacts/files", files={"file": ("invoice.exe", fake_pe())}).json()
    (event,) = events("file.analysed")
    held = event.payload["data"]["file"]
    assert (event.object_kind, event.object_id) == ("artifact", made["id"])
    assert held["sha256"] == made["ref"] and held["name"] == "invoice.exe" and held["size"] > 0
    assert isinstance(held["yara"], list) and held["url"] == f"/artifact/{made['id']}"
    assert event.payload["classes"]["file.name"] == ["attachment_name"]

    scan = _scan(admin)
    worker.drain()
    (found,) = events("url.analysed")
    assert found.object_id == scan["artifactId"] and found.payload["data"]["scan"]["url"] == SCANNED
    assert found.payload["data"]["scan"]["artifact_id"] == scan["artifactId"]
    assert said(admin, on_file) == [f"invoice.exe is {held['type']}"]
    (text,) = said(admin, on_url)
    assert text.startswith(found.payload["data"]["scan"]["host"])
    assert runs_of(admin, on_url)[0]["artifactId"] == scan["artifactId"]


# --------------------------------------------------------------------------- #
# Indicators                                                                  #
# --------------------------------------------------------------------------- #
def lookup(verdict: str | Exception, provider: str = "virustotal", value: str = IP) -> None:
    with SessionLocal() as db:
        vendor.said(db, provider, "ip", value, verdict)


def test_a_verdict_that_changes_is_an_event_and_one_that_stays_is_not(admin: TestClient):
    pb = on(
        admin,
        "Worse",
        "ioc.verdict_changed",
        "{{ trigger.ioc.value }}: {{ trigger.ioc.old }} to {{ trigger.ioc.new }}",
        conditions={"all": [{"left": "{{ trigger.ioc.new }}", "op": "eq", "right": "malicious"}]},
    )
    admin.post("/api/iocs", json={"text": IP, "list": {"name": "Tor exits"}})
    lookup("unknown")  # a first answer that says nothing: not a change
    assert events("ioc.verdict_changed") == []
    lookup("malicious")
    lookup("malicious")  # asked again, the same answer
    (event,) = events("ioc.verdict_changed")
    held = event.payload["data"]["ioc"]
    assert (event.object_kind, event.object_id) == ("indicator", f"ip:{IP}")
    assert (held["kind"], held["value"], held["old"], held["new"]) == ("ip", IP, "unknown", "malicious")
    assert held["sources"] == ["virustotal"] and held["lists"] == ["Tor exits"]
    assert held["private"] is False and held["allowlisted"] is False
    assert event.payload["classes"]["ioc.value"] == ["public_indicator"]
    lookup("harmless")
    assert [e.payload["data"]["ioc"]["new"] for e in events("ioc.verdict_changed")] == ["malicious", "harmless"]
    worker.drain()
    assert said(admin, pb) == [f"{IP}: unknown to malicious"]

    # An address of the inside and an allowlisted one say so, to the playbook and to the guard.
    lookup("malicious", value="10.1.2.3")
    inside = events("ioc.verdict_changed")[-1].payload
    assert inside["data"]["ioc"]["private"] is True and "private_value" in inside["classes"]["ioc.value"]
    doc = admin.get("/api/settings").json()
    assert admin.put("/api/settings", json={**doc, "iocAllowlist": ["203.0.113.9"]}).status_code == 200
    lookup("suspicious", value="203.0.113.9")
    known = events("ioc.verdict_changed")[-1].payload
    assert known["data"]["ioc"]["allowlisted"] is True and "allowlisted" in known["classes"]["ioc.value"]


def test_a_watched_indicator_in_an_incident_starts_a_playbook_on_the_incident(admin: TestClient):
    pb = on(
        admin,
        "Watched",
        "ioc.watch_hit",
        '{{ trigger.ioc.value }} of "{{ trigger.list.name }}" in {{ trigger.incident.id }}',
    )
    admin.post("/api/iocs", json={"text": IP, "list": {"name": "AsyncRAT C2", "watch": True}})
    doc = {
        "id": "inc1",
        "name": "inc1",
        "data": {"commands": {"shells": {"bash": {"commands": [{"command": f"curl http://{IP}/gate", "time": 1}]}}}},
    }
    assert admin.post("/api/incidents", json=doc).status_code == 201
    (event,) = events("ioc.watch_hit")
    data = event.payload["data"]
    assert (event.object_kind, event.object_id) == ("incident", "inc1")
    assert data["hits"][0]["value"] == IP and data["hits"][0]["list"]["name"] == "AsyncRAT C2"
    assert event.payload["classes"]["hits.value"] == ["public_indicator"]
    worker.drain()
    assert said(admin, pb) == [f'{IP} of "AsyncRAT C2" in inc1']
    assert runs_of(admin, pb)[0]["incidentId"] == "inc1"


# --------------------------------------------------------------------------- #
# The disk                                                                    #
# --------------------------------------------------------------------------- #
def test_a_disk_nearly_full_is_said_once_a_day(admin: TestClient):
    Disk = namedtuple("Disk", "total used free")
    pb = on(admin, "Disk", "storage.low", "{{ trigger.disk.free_percent }}% free")
    with SessionLocal() as db:
        assert worker.storage_low(db, T0, usage=lambda path: Disk(1000, 500, 500)) is False  # room enough
        assert worker.storage_low(db, T0, usage=lambda path: Disk(1000, 920, 80)) is True
        assert worker.storage_low(db, T0 + 3600, usage=lambda path: Disk(1000, 950, 50)) is False  # said today
        assert state.read(db)["storageLowAt"] == T0

        def gone(path):
            raise OSError("no such disk")

        assert worker.storage_low(db, T0 + 90000, usage=gone) is False
        assert worker.storage_low(db, T0 + 90000, usage=lambda path: Disk(1000, 950, 50)) is True
    assert [e.payload["data"]["disk"] for e in events("storage.low")] == [
        {"total": 1000, "used": 920, "free": 80, "free_percent": 8.0},
        {"total": 1000, "used": 950, "free": 50, "free_percent": 5.0},
    ]
    worker.drain()
    assert sorted(said(admin, pb)) == ["5.0% free", "8.0% free"]


def test_the_new_events_are_offered_to_triggers_and_to_webhooks(admin: TestClient):
    offered = admin.get("/api/automation/catalog").json()["events"]
    new = {"mail.analysed", "file.analysed", "url.analysed", "ioc.verdict_changed", "ioc.watch_hit", "storage.low"}
    assert new <= set(offered) and new <= set(KNOWN_EVENTS)
    hook = admin.post(
        "/api/webhooks", json={"url": "https://siem.example.org/nik", "events": ["mail.analysed", "storage.low"]}
    )
    assert hook.status_code == 201, hook.text


def test_an_event_reaches_the_webhooks_subscribed_to_it(admin: TestClient, monkeypatch):
    sent: list[tuple[str, dict]] = []
    monkeypatch.setattr("app.events._deliver", lambda url, secret, event, data: sent.append((event, data)))
    admin.post("/api/webhooks", json={"url": "https://siem.example.org/nik", "events": ["file.analysed"]})
    admin.post("/api/artifacts/files", files={"file": ("invoice.exe", fake_pe())})
    for _ in range(100):  # delivered from a thread of its own
        if sent:
            break
        time.sleep(0.02)
    assert [(event, data["file"]["name"]) for event, data in sent] == [("file.analysed", "invoice.exe")]


# --------------------------------------------------------------------------- #
# By hand, on an object                                                       #
# --------------------------------------------------------------------------- #
def test_a_playbook_is_run_by_hand_on_what_its_event_is_about(admin: TestClient, no_dns):  # noqa: F811
    mail = admin.post("/api/artifacts/mails", files={"file": ("reported.eml", phishing_message())}).json()
    made = admin.post("/api/artifacts/files", files={"file": ("invoice.exe", fake_pe())}).json()
    admin.post("/api/iocs", json={"text": IP})
    triage = playbook(
        admin,
        "Triage",
        [echo("a", "{{ trigger.mail.subject }} by {{ trigger.actor }}")],
        [edge("start", "a")],
        trigger={"event": "mail.analysed", "manual": True},
    )
    anything = playbook(admin, "Anything", [echo("a", "{{ trigger.actor }}")], [edge("start", "a")])
    on_ioc = playbook(
        admin,
        "Indicator",
        [echo("a", "{{ trigger.ioc.kind }} {{ trigger.ioc.value }}")],
        [edge("start", "a")],
        trigger={"event": "ioc.verdict_changed", "manual": True},
    )
    listed = {row["name"]: row["runsOn"] for row in admin.get("/api/automation/playbooks").json()["playbooks"]}
    assert listed == {"Triage": "mail", "Anything": "", "Indicator": "indicator"}

    def run(playbook_id: str, kind: str, object_id: str):
        return admin.post(
            f"/api/automation/playbooks/{playbook_id}/run", json={"objectKind": kind, "objectId": object_id}
        )

    started = run(triage, "artifact", mail["id"])
    assert started.status_code == 201, started.text
    assert started.json()["artifactId"] == mail["id"] and started.json()["objectKind"] == "artifact"
    wrong = run(triage, "artifact", made["id"])
    assert (wrong.status_code, wrong.json()["detail"]) == (400, "This playbook runs on an e-mail, not on a file")
    assert run(triage, "indicator", f"ip:{IP}").status_code == 400
    assert run(triage, "artifact", "mail-" + "0" * 64).status_code == 404
    assert run(anything, "artifact", made["id"]).status_code == 201  # reads nothing of the object: any will do
    assert run(on_ioc, "indicator", f"ip:{IP}").status_code == 201
    assert run(on_ioc, "indicator", "nonsense").status_code == 404
    assert run(on_ioc, "indicator", "colour:red").status_code == 404
    worker.drain()
    assert said(admin, triage)[0].endswith(" by admin")
    assert said(admin, on_ioc) == [f"ip {IP}"]
    with SessionLocal() as db:
        run_row = db.scalars(select(Run).where(Run.playbook_id == triage)).one()
        assert run_row.context_classes["trigger"]["mail.sender"] == ["email_address"]


# --------------------------------------------------------------------------- #
# From outside                                                                #
# --------------------------------------------------------------------------- #
@pytest.fixture()
def fresh_limits():
    limiter.reset()
    yield
    limiter.reset()


def hooked(admin: TestClient, name: str = "From outside", **more) -> tuple[str, str]:
    pb = playbook(
        admin,
        name,
        [
            node(
                "a",
                "action",
                action="test.echo",
                args={
                    "text": "{{ trigger.body.alert }} from {{ trigger.query.source }}",
                    "extra": "{{ trigger.headers }}",
                },
            )
        ],
        [edge("start", "a")],
        trigger={"webhook": True},
        enabled=True,
        **more,
    )
    made = admin.post(f"/api/automation/playbooks/{pb}/hook")
    assert made.status_code == 201, made.text
    assert made.json()["path"] == f"/api/automation/hooks/{made.json()['token']}"
    return pb, made.json()["token"]


def test_a_request_from_outside_starts_the_playbook_its_token_belongs_to(
    admin: TestClient, client: TestClient, fresh_limits
):
    pb, token = hooked(admin)
    # The token is kept as its hash, and no answer gives it again.
    with SessionLocal() as db:
        assert db.get(Playbook, pb).hook_hash == hashlib.sha256(token.encode()).hexdigest()
    detail = admin.get(f"/api/automation/playbooks/{pb}").json()
    assert detail["hook"]["since"] and token not in json.dumps(detail)
    assert detail["trigger"] == "webhook"

    anyone = TestClient(client.app)  # no cookie, no key
    sent = anyone.post(
        f"/api/automation/hooks/{token}?source=siem",
        json={"alert": "beacon"},
        headers={
            "X-Event-Id": "42",
            "Authorization": "Bearer of-the-sender",
            "Cookie": "session=abc",
            "X-Api-Key": "k",
            "X-Forwarded-For": "10.0.0.1",
            "X-Hub-Signature": "sha1=abc",
        },
    )
    assert (sent.status_code, sent.json()) == (202, {"accepted": True})
    worker.drain()
    (run,) = runs_of(admin, pb)
    assert (run["trigger"], run["startedBy"], run["objectKind"]) == ("webhook", "webhook", "webhook")
    step = steps(run_of(admin, run["id"]))["a"]
    assert step["output"]["text"] == "beacon from siem"
    kept = step["output"]["extra"]
    assert kept["x-event-id"] == "42" and kept["content-type"] == "application/json"
    assert not {"authorization", "cookie", "x-api-key", "x-forwarded-for", "x-hub-signature"} & set(kept)

    # A body that is not JSON is read as text.
    plain = anyone.post(
        f"/api/automation/hooks/{token}", content=b"alert=beacon", headers={"Content-Type": "text/plain"}
    )
    assert plain.status_code == 202
    with SessionLocal() as db:
        last = db.scalars(select(Run).order_by(Run.started_at.desc())).first()
        assert last.context["trigger"]["body"] == "alert=beacon"
    broken = anyone.post(
        f"/api/automation/hooks/{token}", content=b"{not json", headers={"Content-Type": "application/json"}
    )
    assert (broken.status_code, broken.json()["detail"]) == (400, "The body is not valid JSON")


def test_what_a_token_cannot_do(admin: TestClient, client: TestClient, fresh_limits):
    pb, token = hooked(admin)
    anyone = TestClient(client.app)
    address = f"/api/automation/hooks/{token}"

    # Larger than 256 kB: refused, whether it says so or not.
    big = anyone.post(address, content=b"x" * (256 * 1024 + 1), headers={"Content-Type": "text/plain"})
    assert (big.status_code, big.json()["detail"]) == (413, "The body is larger than 256 kB")

    # Every reason a token starts nothing gives the same answer.
    assert anyone.post(address.replace(token, "A" * 43), json={}).status_code == 404
    assert anyone.post("/api/automation/hooks/short", json={}).status_code == 404
    assert anyone.get(address).status_code == 405
    admin.put(f"/api/automation/playbooks/{pb}/enabled", json={"enabled": False})
    assert anyone.post(address, json={}).status_code == 404
    admin.put(f"/api/automation/playbooks/{pb}/enabled", json={"enabled": True})
    admin.put("/api/automation/state", json={"enabled": False})
    assert anyone.post(address, json={}).status_code == 404
    admin.put("/api/automation/state", json={"enabled": True})
    assert anyone.post(address, json={}).status_code == 202

    # A new address replaces the old one; removing it leaves none.
    replaced = admin.post(f"/api/automation/playbooks/{pb}/hook").json()["token"]
    assert replaced != token and anyone.post(address, json={}).status_code == 404
    assert anyone.post(f"/api/automation/hooks/{replaced}", json={}).status_code == 202
    assert admin.delete(f"/api/automation/playbooks/{pb}/hook").status_code == 204
    assert anyone.post(f"/api/automation/hooks/{replaced}", json={}).status_code == 404
    assert admin.get(f"/api/automation/playbooks/{pb}").json()["hook"] is None
    actions = [entry["action"] for entry in admin.get("/api/audit").json()["entries"]]
    assert actions.count("playbook.hook") == 3

    # A playbook whose trigger is not a webhook has no use for an address.
    other = playbook(admin, "By hand", [echo("a", "x")], [edge("start", "a")], enabled=True)
    token = admin.post(f"/api/automation/playbooks/{other}/hook").json()["token"]
    assert anyone.post(f"/api/automation/hooks/{token}", json={}).status_code == 404

    # Giving an address is for who builds playbooks.
    analyst = make_key(admin, label="an", roles=["analyst"])
    assert admin.post(f"/api/automation/playbooks/{pb}/hook", headers=analyst).status_code == 403
    assert admin.delete(f"/api/automation/playbooks/{pb}/hook", headers=analyst).status_code == 403


def test_a_token_is_limited_on_its_own_and_by_the_playbook(
    admin: TestClient, client: TestClient, fresh_limits, monkeypatch
):
    slow, slow_token = hooked(admin, "Slow", maxRunsPerHour=2, onePerObject=False)
    other, other_token = hooked(admin, "Other")
    anyone = TestClient(client.app)
    codes = [anyone.post(f"/api/automation/hooks/{slow_token}", json={}).status_code for _ in range(3)]
    assert codes == [202, 202, 429]  # the playbook's runs per hour
    assert len(runs_of(admin, slow)) == 2

    # Requests per minute are counted per token: one sender's noise is not another's.
    assert automation_routes.HOOK_LIMIT == "60/minute"
    limiter.reset()
    for _ in range(60):
        anyone.post(f"/api/automation/hooks/{'B' * 43}", json={})
    assert anyone.post(f"/api/automation/hooks/{'B' * 43}", json={}).status_code == 429
    assert anyone.post(f"/api/automation/hooks/{other_token}", json={}).status_code == 202


def test_headers_a_playbook_reads_of_a_request():
    kept = automation_routes.hook_headers(
        {
            "Content-Type": "application/json",
            "User-Agent": "siem/1.0",
            "X-Event": "alert",
            "X-Auth-Token": "t",
            "X-Secret": "s",
            "X-Nik-Signature": "sha256=…",
            "X-Real-IP": "10.0.0.1",
            "Host": "nik.corp",
            "Accept": "*/*",
        }
    )
    assert kept == {"content-type": "application/json", "user-agent": "siem/1.0", "x-event": "alert"}


def test_triggers_say_what_they_run_on():
    assert triggers.object_of({"event": "ioc.watch_hit"}) == "incident"
    assert triggers.object_of({"event": "url.analysed"}) == "url"
    assert triggers.object_of({"event": "storage.low"}) == "" and triggers.object_of({"cron": "0 7 * * *"}) == ""
    assert triggers.manual_problem({"event": "file.analysed"}, "") is None
    assert triggers.manual_problem({"event": "incident.created"}, "indicator") == (
        "This playbook runs on an incident, not on an indicator"
    )
    assert triggers.describe({"webhook": True, "manual": True}) == "webhook, by hand"

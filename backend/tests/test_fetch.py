"""Fetching: a connection brings alerts in, each becomes an incident once."""

from __future__ import annotations

import json
import textwrap
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlsplit

from fastapi.testclient import TestClient
from sqlalchemy import select

from app import fetch
from app.automation import worker
from app.core.db import SessionLocal
from app.core.models import AutomationEvent, Connection, Incident, Notification
from tests.conftest import make_key
from tests.test_automation_engine import T0, test_actions  # noqa: F401 - test_actions is a fixture
from tests.test_fields import field

BASE = "/api/automation"

RADAR = textwrap.dedent(
    """\
    name: Radar
    id: radar
    version: 1
    description: Alerts of Radar.
    configuration:
      - { name: url, type: url, required: true }
      - { name: token, type: bearer }
    base_url: "{{ config.url }}"
    test:
      request: { method: GET, path: /me }
    commands:
      - name: get-alert
        arguments: [{ name: id, type: text, required: true }]
        request: { method: GET, path: "/alerts/{{ args.id }}" }
        outputs: { alert: "{{ response }}" }
    fetch:
      interval_seconds: 120
      first_fetch: 3 days
      request:
        method: GET
        path: /alerts
        query: { since: "{{ state.last_time }}", limit: 2 }
      pagination:
        type: cursor
        param: cursor
        items: "{{ response.data }}"
        next: "{{ response.next }}"
        max_pages: 5
      item_id: "{{ item.id }}"
      occurred: "{{ item.created }}"
      first_state: { last_time: "{{ first.iso }}" }
      next_state: { last_time: "{{ items | last | get('created') }}" }
    schema:
      incoming:
        - { name: id, type: text }
        - { name: title, type: text }
    ext_fields:
      - { name: agent, type: text }
    """
)

# The alerts are of yesterday, whenever the tests run: Radar's fetch looks three days back, and
# alerts with a date written here once fell out of that window as the days went by.
DAY = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")

ALERTS = [
    {"id": "A-1", "title": "Emotet on WKS-01", "score": 91, "created": f"{DAY}T08:00:00Z", "host": "WKS-01"},
    {"id": "A-2", "title": "Phishing page opened", "score": 40, "created": f"{DAY}T09:00:00Z", "host": "WKS-02"},
    {"id": "A-3", "title": "Port scan", "score": 10, "created": f"{DAY}T10:00:00Z", "host": "SRV-01"},
]

MAPPER = [
    {"to": "name", "from": "{{ item.title }}"},
    {"to": "severity", "from": "{{ item.score | severity }}"},
    {"to": "host", "from": "{{ item.host }}"},
    {"to": "source_url", "from": "https://radar.example.com/alerts/{{ item.id }}"},
    {"to": "Alert(val.ID == obj.ID)", "from": {"ID": "{{ item.id }}", "Name": "{{ item.title }}"}},
    {"to": "ext.radar.agent", "from": "{{ item.host }}"},
]


def radar(admin: TestClient, outside, alerts: list | None = None) -> dict:
    """Radar installed, a connection to it, and a fake Radar that serves ``alerts`` two a page."""
    assert admin.post(f"{BASE}/connectors", json={"source": RADAR}).status_code == 201
    made = admin.post(
        f"{BASE}/connections",
        json={
            "name": "Radar SOC",
            "connector": "radar",
            "config": {"url": "https://radar.example.com/api"},
            "secrets": {"token": "s3cret-token"},
        },
    )
    assert made.status_code == 201, made.text
    outside.host("radar.example.com")
    served = alerts if alerts is not None else ALERTS

    def reply(method, host, target, _headers, _body):
        parts = urlsplit(target)
        if host != "radar.example.com" or parts.path != "/api/alerts":
            return None
        query = parse_qs(parts.query)
        since = query.get("since", [""])[0]
        newer = [alert for alert in served if alert["created"] > since]
        start = int(query.get("cursor", ["0"])[0])
        page = newer[start : start + 2]
        body = {"data": page, "next": str(start + 2) if start + 2 < len(newer) else ""}
        return 200, {"content-type": "application/json"}, json.dumps(body).encode()

    outside.answers.append(reply)
    return made.json()


def mapped(admin: TestClient, rules: list | None = None) -> None:
    saved = admin.put(
        "/api/mappers",
        json={"connectorId": "radar", "direction": "incoming", "rules": MAPPER if rules is None else rules},
    )
    assert saved.status_code == 200, saved.text


def run(admin: TestClient, connection: dict) -> dict:
    answer = admin.post(f"/api/fetch/{connection['id']}/run")
    assert answer.status_code == 200, answer.text
    return answer.json()


def incidents(admin: TestClient) -> dict[str, dict]:
    with SessionLocal() as db:
        ids = [row.id for row in db.scalars(select(Incident))]
    return {found["name"]: found for found in (admin.get(f"/api/incidents/{one}").json() for one in ids)}


def sinces(outside) -> list[str]:
    return [parse_qs(urlsplit(request["path"]).query).get("since", [""])[0] for request in outside.requests]


def test_a_connection_fetches_and_each_new_alert_becomes_an_incident_once(admin: TestClient, outside):
    connection = radar(admin, outside)
    mapped(admin)
    rules = [{"when": {"all": [{"left": "{{ item.score }}", "op": "gte", "right": 80}]}, "type": "malware"}]
    assert admin.put(f"/api/classifiers/{connection['id']}", json={"rules": rules}).status_code == 200

    # Nothing is fetched until the connection is told to.
    assert admin.post(f"/api/fetch/{connection['id']}/run").status_code == 409
    listed = admin.get("/api/fetch").json()["connections"]
    assert [(row["connection"], row["state"], row["enabled"]) for row in listed] == [("Radar SOC", "off", False)]
    turned = admin.put(f"/api/fetch/{connection['id']}", json={"enabled": True})
    assert turned.status_code == 200 and turned.json()["state"] == "ok" and turned.json()["intervalSeconds"] == 120

    done = run(admin, connection)
    assert done["result"] == {
        "state": "ok",
        "fetched": 3,
        "new": 3,
        "created": 3,
        "incomplete": 0,
        "dropped": 0,
        "linked": 0,
        "duplicate": 0,
        "pausedWhy": "",
    }
    # The first cycle looked back three days; its pages were read to the end, with the credentials.
    assert len(outside.requests) == 2 and sinces(outside)[0].endswith("Z") and sinces(outside)[0] < "2099"
    assert outside.requests[0]["headers"]["Authorization"] == "Bearer s3cret-token"
    found = incidents(admin)
    assert sorted(found) == ["Emotet on WKS-01", "Phishing page opened", "Port scan"]
    emotet = found["Emotet on WKS-01"]
    assert (emotet["type"], emotet["severity"], emotet["host"], emotet["status"]) == (
        "malware",
        "critical",
        "WKS-01",
        "open",
    )
    assert emotet["createdBy"] == "connector:radar" and found["Port scan"]["type"] == "unclassified"
    assert emotet["fields"]["occurred"] == f"{DAY}T08:00:00Z"
    registry = admin.get(f"/api/incidents/{emotet['id']}/fields").json()["fields"]
    assert registry["source_id"] == "A-1" and emotet["fields"]["source_connector"] == "radar"
    assert registry["source_instance"] == connection["id"]
    assert emotet["fields"]["source_url"] == "https://radar.example.com/alerts/A-1"
    context = admin.get(f"/api/incidents/{emotet['id']}/context").json()
    assert context["context"]["Alert"] == [{"ID": "A-1", "Name": "Emotet on WKS-01"}]
    assert context["context"]["ext"]["radar"]["agent"] == "WKS-01"
    # Its War Room holds the item as it came, and playbooks hear of the new incident.
    room = admin.get(f"/api/incidents/{emotet['id']}/war-room").json()["entries"]
    assert room[0]["author"] == "connector:radar" and room[0]["body"]["item"] == ALERTS[0]
    assert room[0]["body"]["text"] == "Fetched from Radar SOC (Radar), item A-1"
    with SessionLocal() as db:
        events = db.scalars(select(AutomationEvent).where(AutomationEvent.kind == "incident.created")).all()
        assert len(events) == 3
        # The state moved to the last alert read.
        assert db.get(Connection, connection["id"]).fetch_state == {"last_time": f"{DAY}T10:00:00Z"}

    # Again: the request asks for what is newer, and an alert seen before makes no second incident.
    again = run(admin, connection)
    assert (again["result"]["fetched"], again["result"]["new"]) == (0, 0)
    assert sinces(outside)[-1] == f"{DAY}T10:00:00Z" and len(incidents(admin)) == 3
    with SessionLocal() as db:
        db.get(Connection, connection["id"]).fetch_state = {"last_time": f"{DAY}T08:30:00Z"}
        db.commit()
    overlap = run(admin, connection)
    assert (overlap["result"]["fetched"], overlap["result"]["new"]) == (2, 0) and len(incidents(admin)) == 3

    status = admin.get("/api/fetch").json()["connections"][0]
    assert (status["state"], status["madeLastHour"], status["hasSample"]) == ("ok", 3, True)
    assert status["last"]["fetched"] == 2 and status["fetchState"] == {"last_time": f"{DAY}T10:00:00Z"}
    items = admin.get(f"/api/fetch/{connection['id']}/items").json()["items"]
    assert sorted((item["itemId"], item["outcome"]) for item in items) == [
        ("A-1", "created"),
        ("A-2", "created"),
        ("A-3", "created"),
    ]
    assert all(item["incidentId"] for item in items)
    assert admin.get(f"/api/fetch/{connection['id']}/sample").json()["item"] == ALERTS[2]

    analyst = make_key(admin, label="a", roles=["analyst"])
    assert admin.get("/api/fetch", headers=analyst).status_code == 403
    assert admin.put("/api/fetch/nope", json={"enabled": True}).status_code == 404


def test_an_item_the_mapper_cannot_make_whole_is_still_an_incident_and_says_so(admin: TestClient, outside):
    connection = radar(admin, outside, ALERTS[:2])
    admin.put(f"/api/fetch/{connection['id']}", json={"enabled": True})
    # No mapper at all: the incident is made with a name of its own.
    first = run(admin, connection)
    assert (first["result"]["created"], first["result"]["incomplete"]) == (0, 2)
    assert sorted(incidents(admin)) == ["Radar A-1", "Radar A-2"]
    items = admin.get(f"/api/fetch/{connection['id']}/items", params={"outcome": "incomplete"}).json()["items"]
    assert items[0]["note"].startswith("There is no incoming mapper for this connector")

    # A type that needs a field nothing gives, and a value a field refuses.
    made = admin.post("/api/incident-types", json={"name": "Endpoint alert"}).json()
    field(admin, "agent_group", allTypes=False)
    admin.put(f"/api/incident-types/{made['id']}", json={"fields": [{"name": "agent_group", "required": True}]})
    admin.put(f"/api/classifiers/{connection['id']}", json={"rules": [], "defaultType": made["id"]})
    mapped(admin, [{"to": "name", "from": "{{ item.title }}"}, {"to": "severity", "from": "{{ item.title }}"}])
    with SessionLocal() as db:
        db.get(Connection, connection["id"]).fetch_state = None
        db.commit()
    newer = {"id": "A-9", "title": "Beacon", "score": 70, "created": f"{DAY}T11:00:00Z", "host": "WKS-09"}
    ALERTS_NOW = [*ALERTS[:2], newer]
    outside.answers.clear()
    outside.answers.append(
        lambda method, host, target, _h, _b: (
            200,
            {"content-type": "application/json"},
            json.dumps({"data": ALERTS_NOW, "next": ""}).encode(),
        )
    )
    second = run(admin, connection)
    assert (second["result"]["fetched"], second["result"]["new"], second["result"]["incomplete"]) == (3, 1, 1)
    beacon = incidents(admin)["Beacon"]
    assert beacon["type"] == made["id"] and beacon.get("severity", "") == ""
    note = admin.get(f"/api/fetch/{connection['id']}/items").json()["items"][0]["note"]
    assert "needed and not given: agent_group" in note and "Severity" in note


def test_a_fetch_that_fails_is_tried_later_and_later_and_says_why(admin: TestClient, outside):
    connection = radar(admin, outside)
    admin.put(f"/api/fetch/{connection['id']}", json={"enabled": True})
    outside.answers.clear()
    outside.answer("radar.example.com", status=503, json={"error": "maintenance"})

    first = run(admin, connection)
    assert first["result"]["state"] == "failing" and first["status"]["state"] == "failing"
    assert "503" in first["status"]["error"]
    wait_one = first["status"]["nextAt"]
    second = run(admin, connection)
    assert second["status"]["nextAt"] - wait_one > 100  # later each time
    with SessionLocal() as db:
        told = db.scalars(select(Notification).where(Notification.kind == "fetch.failing")).all()
        assert [(note.username, note.link) for note in told] == [("admin", "/settings/automation/fetch-status")]  # once
        assert db.get(Connection, connection["id"]).fetch_state is None  # nothing moved
    assert incidents(admin) == {}

    # It answers again: the cycle goes through and the connection is well.
    radar_again = [reply for reply in outside.answers if False]
    outside.answers[:] = radar_again
    outside.answers.append(
        lambda method, host, target, _h, _b: (
            200,
            {"content-type": "application/json"},
            json.dumps({"data": ALERTS[:1], "next": ""}).encode(),
        )
    )
    third = run(admin, connection)
    assert (third["result"]["state"], third["status"]["error"], third["result"]["new"]) == ("ok", "", 1)


def test_a_connection_that_makes_too_many_incidents_is_paused_until_someone_looks(
    admin: TestClient, outside, monkeypatch
):
    connection = radar(admin, outside)
    mapped(admin)
    admin.put(f"/api/fetch/{connection['id']}", json={"enabled": True})
    monkeypatch.setattr(fetch, "INCIDENTS_PER_HOUR", 2)

    first = run(admin, connection)
    assert (first["result"]["state"], first["result"]["new"]) == ("paused", 2)
    assert first["status"]["pausedWhy"].startswith("More than 2 incidents in an hour")
    assert len(incidents(admin)) == 2
    with SessionLocal() as db:
        # The state stopped at what became an incident: the third alert is not lost.
        assert db.get(Connection, connection["id"]).fetch_state == {"last_time": f"{DAY}T09:00:00Z"}
        assert [note.kind for note in db.scalars(select(Notification))] == ["fetch.paused"]
        assert fetch.due(db, T0 * 2) == []  # paused: the worker leaves it alone

    resumed = admin.post(f"/api/fetch/{connection['id']}/resume")
    assert resumed.status_code == 200 and resumed.json()["state"] == "ok"
    after = run(admin, connection)
    assert (after["result"]["state"], after["result"]["new"]) == ("ok", 1)
    assert sorted(incidents(admin)) == ["Emotet on WKS-01", "Phishing page opened", "Port scan"]


def test_the_worker_fetches_the_connections_whose_time_has_come(admin: TestClient, outside):
    connection = radar(admin, outside)
    mapped(admin)
    # A connector that says nothing of fetching cannot be told to fetch.
    plain = RADAR.split("fetch:")[0].replace("id: radar", "id: quiet").replace("name: Radar", "name: Quiet")
    assert admin.post(f"{BASE}/connectors", json={"source": plain}).status_code == 201
    quiet = admin.post(
        f"{BASE}/connections",
        json={"name": "Quiet", "connector": "quiet", "config": {"url": "https://radar.example.com/api"}},
    ).json()
    refused = admin.put(f"/api/fetch/{quiet['id']}", json={"enabled": True})
    assert (refused.status_code, refused.json()["detail"]) == (
        400,
        "The connector of this instance does not say how to fetch",
    )
    assert [row["connection"] for row in admin.get("/api/fetch").json()["connections"]] == ["Radar SOC"]

    worker.tick(T0)
    assert incidents(admin) == {}  # not told to fetch
    admin.put(f"/api/fetch/{connection['id']}", json={"enabled": True})
    with SessionLocal() as db:
        row = db.get(Connection, connection["id"])
        row.fetch_status = {**row.fetch_status, "nextAt": T0 + 60}
        # The clock of the tests is in 2027: the cycle starts from where a cycle before it left.
        row.fetch_state = {"last_time": "2026-11-01T00:00:00Z"}
        db.commit()
    worker.tick(T0)
    assert incidents(admin) == {}  # not its time yet
    worker.tick(T0 + 61)
    assert len(incidents(admin)) == 3
    with SessionLocal() as db:
        assert db.get(Connection, connection["id"]).fetch_status["nextAt"] == T0 + 61 + 120
    # With automation stopped nothing fetches.
    assert admin.put(f"{BASE}/state", json={"enabled": False}).status_code == 200
    requests_before = len(outside.requests)
    worker.tick(T0 + 1000)
    assert len(outside.requests) == requests_before


# --------------------------------------------------------------------------- #
# Pre-processing rules                                                        #
# --------------------------------------------------------------------------- #
def rule(admin: TestClient, **body) -> dict:
    made = admin.post("/api/preprocess-rules", json=body)
    assert made.status_code == 201, made.text
    return made.json()


def test_rules_decide_what_becomes_of_an_item_before_it_is_an_incident(admin: TestClient, outside):
    connection = radar(admin, outside)
    mapped(admin)
    admin.put(f"/api/fetch/{connection['id']}", json={"enabled": True})
    # An incident that is there already, open, about the same host as the second alert.
    from app.core.security import now_iso

    old = {"id": "old", "name": "Old case", "host": "wks-02", "createdAt": now_iso()}
    assert admin.post("/api/incidents", json=old).status_code == 201

    scan = rule(
        admin,
        name="Port scans are noise",
        when={"all": [{"left": "{{ item.title }}", "op": "contains", "right": "Port scan"}]},
        action="drop",
    )
    same_host = rule(
        admin,
        name="Same host, same case",
        when={"all": [{"left": "{{ incident.severity }}", "op": "ne", "right": "critical"}]},
        action="link_to_existing",
        params={"same": ["host"], "within_hours": 48},
    )
    assert [item["name"] for item in admin.get("/api/preprocess-rules").json()["rules"]] == [
        "Port scans are noise",
        "Same host, same case",
    ]
    # What would become of a sample, without doing it.
    tried = admin.post("/api/preprocess-rules/try", json={"connectionId": connection["id"], "item": ALERTS[1]}).json()
    assert tried["incident"]["host"] == "WKS-02" and tried["incident"]["type"] == "unclassified"
    assert tried["decision"] == {
        "rule": "Same host, same case",
        "action": "link_to_existing",
        "incident": {"id": "old", "name": "Old case"},
    }
    assert admin.post("/api/preprocess-rules/try", json={"connectionId": connection["id"], "item": ALERTS[0]}).json()[
        "decision"
    ] == {"rule": None, "action": "create", "incident": None}

    done = run(admin, connection)["result"]
    assert (done["new"], done["created"], done["linked"], done["dropped"]) == (3, 1, 1, 1)
    # The critical alert is an incident; the scan is nothing; the other is a line of the case it belongs to.
    assert sorted(incidents(admin)) == ["Emotet on WKS-01", "Old case"]
    room = admin.get("/api/incidents/old/war-room").json()["entries"]
    assert (
        room[-1]["body"]["text"] == "Another alert of the same came in from Radar SOC: Phishing page opened (item A-2)"
    )
    assert room[-1]["body"]["item"] == ALERTS[1]
    items = {item["itemId"]: item for item in admin.get(f"/api/fetch/{connection['id']}/items").json()["items"]}
    assert (items["A-2"]["outcome"], items["A-2"]["incidentId"]) == ("linked", "old")
    assert (items["A-3"]["outcome"], items["A-3"]["note"]) == ("dropped", 'Dropped by the rule "Port scans are noise"')
    # Dropped or linked, an item does not come back.
    with SessionLocal() as db:
        db.get(Connection, connection["id"]).fetch_state = None
        db.commit()
    assert run(admin, connection)["result"]["new"] == 0

    # A rule turned off decides nothing; the order of the rules is theirs to change.
    off = admin.put(f"/api/preprocess-rules/{scan['id']}", json={**scan, "enabled": False})
    assert off.status_code == 200 and off.json()["enabled"] is False
    ordered = admin.put("/api/preprocess-rules/order", json={"ids": [same_host["id"], scan["id"]]})
    assert [item["name"] for item in ordered.json()["rules"]] == ["Same host, same case", "Port scans are noise"]
    assert admin.delete(f"/api/preprocess-rules/{scan['id']}").status_code == 204
    assert admin.delete(f"/api/preprocess-rules/{scan['id']}").status_code == 404

    def refused(**body) -> str:
        answer = admin.post("/api/preprocess-rules", json=body)
        assert answer.status_code == 400, answer.text
        return answer.json()["detail"]

    assert refused(name="x", action="explode").startswith("A rule does one of")
    assert refused(name="x", action="link_to_existing").startswith("Say which fields are the same")
    assert refused(name="x", action="close_duplicate", params={"same": ["colour"]}).startswith("Say which fields")
    assert refused(name="x", action="run_script", params={"script": "nope"}).startswith("Choose a script")
    assert refused(name="x", action="drop", when={"all": [{"left": "{{ trigger.x }}", "op": "eq", "right": 1}]}) == (
        'The condition: "trigger" cannot be read here, only incident, item'
    )
    analyst = make_key(admin, label="a", roles=["analyst"])
    assert admin.get("/api/preprocess-rules", headers=analyst).status_code == 403


def test_a_duplicate_is_made_and_closed_at_once_and_a_script_can_decide(admin: TestClient, outside, monkeypatch):
    connection = radar(admin, outside, ALERTS[:2])
    mapped(admin)
    admin.put(f"/api/fetch/{connection['id']}", json={"enabled": True})
    assert admin.post("/api/incidents", json={"id": "old", "name": "Emotet on WKS-01"}).status_code == 201
    rule(admin, name="Same name twice", action="close_duplicate", params={"same": ["name"]})

    done = run(admin, connection)["result"]
    assert (done["new"], done["created"], done["duplicate"]) == (2, 1, 1)
    with SessionLocal() as db:
        twin = db.scalars(select(Incident).where(Incident.name == "Emotet on WKS-01", Incident.id != "old")).one()
        assert (twin.status, twin.close_reason, twin.close_notes) == (
            "closed",
            "Duplicate",
            'Duplicate of "Emotet on WKS-01" (old)',
        )
        twin_id = twin.id
    assert admin.get(f"/api/incidents/{twin_id}").json()["fields"]["related_incidents"] == ["old"]
    room = admin.get("/api/incidents/old/war-room").json()["entries"]
    assert room[-1]["body"]["text"] == '"Emotet on WKS-01" came in and was closed as a duplicate of this incident'
    items = {item["itemId"]: item for item in admin.get(f"/api/fetch/{connection['id']}/items").json()["items"]}
    assert (items["A-1"]["outcome"], items["A-1"]["incidentId"]) == ("duplicate", twin_id)

    # A script of the library decides: here it drops what scores under fifty.
    from app.automation import scripts
    from app.core.models import Script, ScriptVersion

    with SessionLocal() as db:
        db.add(Script(id="s1", name="LowScore", description="", current_version=1, created_at="x", updated_at="x"))
        db.add(
            ScriptVersion(
                script_id="s1",
                version=1,
                code="def main(item, incident): ...",
                arguments=[],
                outputs=[],
                created_at="x",
                created_by="admin",
            )  # fmt: skip
        )
        db.commit()
    seen = []

    def execute(code, args, timeout=None):
        seen.append(args)
        return {"ok": True, "result": {"action": "drop" if args["item"]["score"] < 50 else "create"}}

    monkeypatch.setattr(scripts, "execute", execute)
    rule(admin, name="Ask the script", action="run_script", params={"script": "LowScore"})
    served = [
        {"id": "B-1", "title": "Low thing", "score": 12, "created": f"{DAY}T12:00:00Z", "host": "X"},
        {"id": "B-2", "title": "High thing", "score": 88, "created": f"{DAY}T13:00:00Z", "host": "Y"},
    ]
    outside.answers.clear()
    outside.answers.append(
        lambda method, host, target, _h, _b: (
            200,
            {"content-type": "application/json"},
            json.dumps({"data": served, "next": ""}).encode(),
        )
    )
    done = run(admin, connection)["result"]
    assert (done["new"], done["created"], done["dropped"]) == (2, 1, 1)
    assert seen[0]["incident"]["name"] == "Low thing" and seen[0]["item"]["id"] == "B-1"
    assert "High thing" in incidents(admin) and "Low thing" not in incidents(admin)

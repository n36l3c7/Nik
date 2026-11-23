"""SLA timers: the rules of a type, business hours, breaches; and what accounts are told."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi.testclient import TestClient
from sqlalchemy import select

from app import timers
from app.core.db import SessionLocal
from app.core.models import AutomationEvent, Incident, Notification
from tests.conftest import make_key
from tests.test_automation_engine import (  # noqa: F401 - test_actions is a fixture
    T0,
    edge,
    go,
    node,
    playbook,
    steps,
    test_actions,
)
from tests.test_fields import field, incident
from tests.test_tasks import person

HOURS = {"startHour": 8, "endHour": 18, "flagWeekends": True}


def at(text: str) -> float:
    return datetime.fromisoformat(text).replace(tzinfo=timezone.utc).timestamp()


def sla(admin: TestClient, rules: list[dict], type_id: str = "unclassified") -> dict:
    saved = admin.put(f"/api/incident-types/{type_id}", json={"sla": rules})
    assert saved.status_code == 200, saved.text
    return saved.json()


def shown(admin: TestClient, incident_id: str = "i1") -> dict[str, dict]:
    answer = admin.get(f"/api/incidents/{incident_id}/timers")
    assert answer.status_code == 200, answer.text
    return {item["field"]: item for item in answer.json()["timers"]}


def tick(now: float) -> int:
    with SessionLocal() as db:
        return timers.tick(db, now)


def age(incident_id: str, seconds: float) -> None:
    """Make every running timer of the incident have started ``seconds`` earlier."""
    with SessionLocal() as db:
        row = db.get(Incident, incident_id)
        stored = dict(row.fields or {})
        for name, timer in stored.items():
            if isinstance(timer, dict) and timer.get("state") == "running":
                stored[name] = {**timer, "started_at": timer["started_at"] - seconds}
        row.fields = stored
        db.commit()


def test_business_time_counts_only_the_hours_the_organisation_works():
    # 2026-11-16 is a Monday.
    assert timers.business_seconds(at("2026-11-16 09:00"), at("2026-11-16 11:30"), HOURS) == 9000
    assert timers.business_seconds(at("2026-11-16 06:00"), at("2026-11-16 09:00"), HOURS) == 3600
    assert timers.business_seconds(at("2026-11-16 17:00"), at("2026-11-17 09:00"), HOURS) == 7200  # the night is out
    # From Friday afternoon to Monday morning: the weekend counts nothing.
    assert timers.business_seconds(at("2026-11-13 16:00"), at("2026-11-16 10:00"), HOURS) == 4 * 3600
    assert timers.business_seconds(at("2026-11-14 10:00"), at("2026-11-15 10:00"), HOURS) == 0
    every_day = {**HOURS, "flagWeekends": False}
    assert timers.business_seconds(at("2026-11-14 10:00"), at("2026-11-15 10:00"), every_day) == 10 * 3600
    assert timers.business_seconds(at("2026-11-16 12:00"), at("2026-11-16 11:00"), HOURS) == 0

    running = {"state": "running", "started_at": at("2026-11-16 17:00"), "accumulated_s": 600, "business": True}
    assert timers.elapsed(running, at("2026-11-17 09:00"), HOURS) == 600 + 7200
    assert timers.elapsed({**running, "business": False}, at("2026-11-17 09:00"), HOURS) == 600 + 16 * 3600
    assert timers.elapsed({"state": "stopped", "accumulated_s": 42}, at("2026-11-17 09:00"), HOURS) == 42
    assert timers.elapsed(None, 0, HOURS) == 0


def test_the_sla_of_a_type_is_checked_when_it_is_saved(admin: TestClient):
    saved = sla(
        admin,
        [
            {"field": "time_to_assign", "minutes": 30, "bySeverity": {"critical": 5}, "businessHours": True},
            {"field": "time_to_close", "minutes": 2880},
        ],
    )
    assert saved["sla"] == [
        {"field": "time_to_assign", "minutes": 30, "bySeverity": {"critical": 5}, "businessHours": True},
        {"field": "time_to_close", "minutes": 2880, "bySeverity": {}, "businessHours": False},
    ]

    def refused(rules) -> str:
        answer = admin.put("/api/incident-types/unclassified", json={"sla": rules})
        assert answer.status_code == 400, answer.text
        return answer.json()["detail"]

    assert refused([{"field": "severity", "minutes": 5}]).startswith("Each rule of an SLA names a timer, once")
    assert refused([{"field": "time_to_close", "minutes": 5}, {"field": "time_to_close", "minutes": 9}])
    assert refused([{"field": "time_to_close", "minutes": 0}]).startswith("Time to close: the time allowed")
    assert refused([{"field": "time_to_close", "minutes": 5, "bySeverity": {"huge": 1}}]).startswith(
        "The times by severity"
    )
    # A timer is never written like another field.
    incident(admin)
    written = admin.patch("/api/incidents/i1/fields", json={"changes": {"time_to_close": "2026-01-01T00:00:00Z"}})
    assert written.status_code == 400 and "cannot be set" in written.json()["detail"]
    field(admin, "time_to_notify", "timer")
    written = admin.patch("/api/incidents/i1/fields", json={"changes": {"time_to_notify": "2026-01-01T00:00:00Z"}})
    assert written.json()["detail"] == "time_to_notify is a timer: it is started and stopped, not written"
    assert sla(admin, [{"field": "time_to_notify", "minutes": 60}])["sla"][0]["field"] == "time_to_notify"


def test_the_type_starts_the_timers_of_an_incident_and_what_happens_stops_them(admin: TestClient):
    person(admin, "anna", ["analyst"])
    sla(
        admin,
        [
            {"field": "time_to_assign", "minutes": 30, "bySeverity": {"critical": 5}},
            {"field": "time_to_contain", "minutes": 240},
            {"field": "time_to_close", "minutes": 1440},
        ],
    )
    incident(admin, severity="high")
    found = shown(admin)
    assert list(found) == ["time_to_assign", "time_to_contain", "time_to_close"]
    assert (found["time_to_assign"]["state"], found["time_to_assign"]["dueS"]) == ("running", 1800)
    assert found["time_to_assign"]["breached"] is False and found["time_to_assign"]["label"] == "Time to assign"

    # The severity changes: the time allowed follows.
    assert admin.patch("/api/incidents/i1/fields", json={"changes": {"severity": "critical"}}).status_code == 200
    assert shown(admin)["time_to_assign"]["dueS"] == 300
    # An owner: the time to assign is over; the others go on.
    age("i1", 120)
    assert admin.patch("/api/incidents/i1/fields", json={"changes": {"owner": "anna"}}).status_code == 200
    found = shown(admin)
    assert found["time_to_assign"]["state"] == "stopped" and 120 <= found["time_to_assign"]["elapsedS"] <= 125
    assert found["time_to_contain"]["state"] == found["time_to_close"]["state"] == "running"

    # By hand: paused, started again (it goes on from where it was), stopped.
    assert admin.post("/api/incidents/i1/timers/time_to_contain/pause", json={}).status_code == 200
    paused = shown(admin)["time_to_contain"]
    assert paused["state"] == "paused" and paused["elapsedS"] >= 120
    assert admin.post("/api/incidents/i1/timers/time_to_contain/start", json={"minutes": 60}).status_code == 200
    again = shown(admin)["time_to_contain"]
    assert (again["state"], again["dueS"]) == ("running", 3600) and again["elapsedS"] >= 120
    stopped = admin.post("/api/incidents/i1/timers/time_to_contain/stop", json={})
    assert {item["field"]: item for item in stopped.json()["timers"]}["time_to_contain"]["state"] == "stopped"
    assert admin.post("/api/incidents/i1/timers/severity/start", json={}).status_code == 400
    assert admin.post("/api/incidents/i1/timers/time_to_close/explode", json={}).status_code == 404
    viewer = make_key(admin, label="v", roles=["viewer"])
    assert admin.get("/api/incidents/i1/timers", headers=viewer).status_code == 200
    assert admin.post("/api/incidents/i1/timers/time_to_close/stop", headers=viewer, json={}).status_code == 403

    # Closing stops the time to close; opening the incident again lets it go on.
    assert admin.patch("/api/incidents/i1", json={"status": "closed"}).status_code == 200
    assert shown(admin)["time_to_close"]["state"] == "stopped"
    assert admin.patch("/api/incidents/i1", json={"status": "open"}).status_code == 200
    assert shown(admin)["time_to_close"]["state"] == "running"
    # The one stopped by hand stays stopped.
    assert shown(admin)["time_to_contain"]["state"] == "stopped"


def test_a_time_given_when_a_timer_is_started_is_kept_by_the_rules_of_the_type(admin: TestClient):
    sla(admin, [{"field": "time_to_close", "minutes": 1440, "bySeverity": {"critical": 240}}])
    incident(admin, severity="high")
    assert shown(admin)["time_to_close"]["dueS"] == 1440 * 60
    # One minute of its own, by hand: the next change of the incident, and the next read, keep it.
    assert admin.post("/api/incidents/i1/timers/time_to_close/start", json={"minutes": 1}).status_code == 200
    assert shown(admin)["time_to_close"]["dueS"] == 60
    assert admin.patch("/api/incidents/i1/fields", json={"changes": {"name": "Renamed"}}).status_code == 200
    assert admin.patch("/api/incidents/i1/fields", json={"changes": {"severity": "critical"}}).status_code == 200
    assert shown(admin)["time_to_close"]["dueS"] == 60
    # Counted again from nothing, with no time given: the rule's time, by the severity, again.
    started = admin.post("/api/incidents/i1/timers/time_to_close/start", json={"restart": True})
    assert started.status_code == 200, started.text
    assert admin.patch("/api/incidents/i1/fields", json={"changes": {"severity": "high"}}).status_code == 200
    assert shown(admin)["time_to_close"]["dueS"] == 1440 * 60


def test_a_timer_past_its_time_is_breached_once_and_everyone_concerned_is_told(admin: TestClient):
    person(admin, "anna", ["analyst"])
    sla(admin, [{"field": "time_to_contain", "minutes": 60}])
    incident(admin, assignee="anna")
    with SessionLocal() as db:
        started = db.get(Incident, "i1").fields["time_to_contain"]["started_at"]
    assert tick(started + 3500) == 0
    assert shown(admin)["time_to_contain"]["breached"] is False
    assert tick(started + 3601) == 1
    assert tick(started + 4000) == 0  # once
    found = shown(admin)["time_to_contain"]
    assert found["breachedAt"] and found["state"] == "running"  # breached, and still to do
    assert admin.get("/api/incidents/i1").json()["fields"]["sla_breached"] is True
    # The War Room says it, the owner is told, and playbooks and webhooks hear `sla.breached`.
    room = admin.get("/api/incidents/i1/war-room").json()["entries"]
    assert [entry["body"]["text"] for entry in room if entry["kind"] == "system"] == [
        "Time to contain is past its time (60 min)"
    ]
    with SessionLocal() as db:
        (told,) = db.scalars(select(Notification).where(Notification.kind == "sla.breached")).all()
        assert (told.username, told.link) == ("anna", "/incident/i1")
        (event,) = db.scalars(select(AutomationEvent).where(AutomationEvent.kind == "sla.breached")).all()
        assert event.payload["data"]["timer"] == {
            "field": "time_to_contain",
            "label": "Time to contain",
            "due_minutes": 60,
            "elapsed_minutes": 60,
        }
        assert event.payload["data"]["incident"]["id"] == "i1"
    # An SLA saved on a type reaches its open incidents at once.
    incident(admin, "i3")
    assert "time_to_close" not in shown(admin, "i3")
    sla(admin, [{"field": "time_to_contain", "minutes": 60}, {"field": "time_to_close", "minutes": 600}])
    assert shown(admin, "i3")["time_to_close"]["dueS"] == 36000
    # A closed incident breaches nothing: closing stopped its timers.
    incident(admin, "i2")
    assert admin.patch("/api/incidents/i2", json={"status": "closed"}).status_code == 200
    tick(started + 999_999)
    closed = shown(admin, "i2")
    assert closed and all(item["state"] == "stopped" and not item["breachedAt"] for item in closed.values())


def test_a_playbook_starts_pauses_and_stops_timers(admin: TestClient):
    incident(admin)
    nodes = [
        node("begin", "action", action="timer.start", args={"timer": "time_to_contain", "minutes": 90}),
        node("hold", "action", action="timer.pause", args={"timer": "time_to_contain"}),
        node("end", "action", action="timer.stop", args={"timer": "time_to_contain"}),
        node("wrong", "action", action="timer.start", args={"timer": "severity"}),
    ]
    edges = [edge("start", "begin"), edge("begin", "hold"), edge("hold", "end"), edge("end", "wrong")]
    pb = playbook(admin, "Timers", nodes, edges)
    dry = go(admin, pb, objectKind="incident", objectId="i1", dryRun=True)
    assert steps(dry)["begin"]["output"] == {"state": "dry-run"} and shown(admin) == {}
    run = go(admin, pb, objectKind="incident", objectId="i1")
    found = steps(run)
    assert found["begin"]["output"] == {"state": "running", "elapsed_minutes": 0, "due_minutes": 90, "breached": False}
    assert found["hold"]["output"]["state"] == "paused" and found["end"]["output"]["state"] == "stopped"
    assert found["wrong"]["status"] == "failed" and '"severity" is not a timer' in found["wrong"]["error"]
    assert shown(admin)["time_to_contain"]["state"] == "stopped"


def test_accounts_are_told_of_approvals_and_mentions_and_read_what_they_were_told(admin: TestClient):
    incident(admin)
    anna = person(admin, "anna", ["analyst"])
    reader = person(admin, "rita", ["viewer"])
    pb = playbook(admin, "Asks", [node("ok", "approval", question="Block the address?")], [edge("start", "ok")])
    go(admin, pb, objectKind="incident", objectId="i1")
    noted = admin.post("/api/incidents/i1/war-room", json={"text": "@anna and @Rita, see this. Not @nobody, a@b.c"})
    assert noted.status_code == 201

    told = anna.get("/api/notifications").json()
    assert told["unread"] == 2
    assert [(item["kind"], item["read"]) for item in told["notifications"]] == [("mention", False), ("approval", False)]
    assert told["notifications"][0]["text"] == "admin mentioned you in Laptop of finance"
    assert told["notifications"][1] == {
        **told["notifications"][1],
        "text": "An approval waits: Block the address?",
        "link": "/incident/i1",
    }
    # A viewer cannot answer approvals, and is not told of them; the mention reaches her.
    assert [item["kind"] for item in reader.get("/api/notifications").json()["notifications"]] == ["mention"]
    # Whoever wrote the note is not told of their own mention; the approval is theirs to answer too.
    assert [item["kind"] for item in admin.get("/api/notifications").json()["notifications"]] == ["approval"]

    one = told["notifications"][0]["id"]
    after = anna.post("/api/notifications/read", json={"ids": [one]}).json()
    assert after["unread"] == 1 and [item["read"] for item in after["notifications"]] == [True, False]
    assert anna.post("/api/notifications/read", json={}).json()["unread"] == 0
    # Nobody reads what another account was told.
    assert reader.post("/api/notifications/read", json={"ids": [told["notifications"][1]["id"]]}).json()["unread"] == 1

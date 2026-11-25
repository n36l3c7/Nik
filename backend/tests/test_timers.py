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


# --------------------------------------------------------------------------- #
# The time zone the hours are read in (7.0)                                    #
# --------------------------------------------------------------------------- #
ROME = {**HOURS, "tz": "Europe/Rome"}


def rome(text: str) -> float:
    """A moment written as the wall clock of Rome."""
    from zoneinfo import ZoneInfo

    return datetime.fromisoformat(text).replace(tzinfo=ZoneInfo("Europe/Rome")).timestamp()


def test_the_default_zone_is_utc_and_gives_what_it_always_gave():
    for hours in (HOURS, {**HOURS, "tz": "UTC"}, {**HOURS, "tz": ""}, {**HOURS, "tz": "No/Such_Zone"}):
        assert timers.business_seconds(at("2026-11-16 09:00"), at("2026-11-16 11:30"), hours) == 9000
        assert timers.business_seconds(at("2026-11-13 16:00"), at("2026-11-16 10:00"), hours) == 4 * 3600
        assert timers.business_seconds(at("2026-11-14 10:00"), at("2026-11-15 10:00"), hours) == 0


def test_business_hours_are_read_on_the_wall_clock_of_the_zone():
    # Monday 2026-11-16, Rome is UTC+1: 08:00-18:00 there is 07:00-17:00 UTC.
    assert timers.business_seconds(at("2026-11-16 06:00"), at("2026-11-16 09:00"), ROME) == 2 * 3600
    assert timers.business_seconds(at("2026-11-16 16:00"), at("2026-11-16 20:00"), ROME) == 3600
    # From Friday afternoon to Monday morning in Rome: two hours on each side of the weekend.
    assert timers.business_seconds(rome("2026-11-13 16:00"), rome("2026-11-16 10:00"), ROME) == 4 * 3600


def test_business_hours_keep_their_place_on_the_clock_across_a_change_of_summer_time():
    # 2026-03-29 is the last Sunday of March (the clock goes forward at 02:00), 2026-10-25 of October (back at 03:00).
    # Monday the 30th of March, 08:00-18:00 in Rome is 06:00-16:00 UTC, while the week before it was 07:00-17:00.
    every_day = {**ROME, "flagWeekends": False}
    assert timers.business_seconds(rome("2026-03-30 07:00"), rome("2026-03-30 19:00"), ROME) == 10 * 3600
    assert timers.business_seconds(at("2026-03-30 05:00"), at("2026-03-30 17:00"), ROME) == 10 * 3600
    assert timers.business_seconds(at("2026-03-23 05:00"), at("2026-03-23 17:00"), ROME) == 10 * 3600
    assert (
        timers.business_seconds(at("2026-03-23 05:00"), at("2026-03-23 06:00"), ROME) == 0
    )  # 05:00-06:00 UTC is 06:00-07:00 in Rome
    assert timers.business_seconds(at("2026-03-30 05:00"), at("2026-03-30 06:00"), ROME) == 0
    assert timers.business_seconds(at("2026-03-30 06:00"), at("2026-03-30 07:00"), ROME) == 3600
    # The day of the change itself, every day counted: Sunday the 29th has 23 hours, and its 10 of work stay 10.
    assert timers.business_seconds(rome("2026-03-29 00:00"), rome("2026-03-30 00:00"), every_day) == 10 * 3600
    assert timers.business_seconds(at("2026-03-28 23:00"), at("2026-03-29 23:00"), every_day) == 10 * 3600
    # From Friday afternoon to Monday morning across the change: the same two hours.
    assert timers.business_seconds(rome("2026-03-27 17:00"), rome("2026-03-30 09:00"), ROME) == 2 * 3600
    # October: Sunday the 25th is 25 hours long; Friday 23rd 17:00 to Monday 26th 09:00 is still two hours.
    assert timers.business_seconds(rome("2026-10-23 17:00"), rome("2026-10-26 09:00"), ROME) == 2 * 3600
    assert timers.business_seconds(rome("2026-10-25 00:00"), rome("2026-10-26 00:00"), every_day) == 10 * 3600
    assert timers.business_seconds(at("2026-10-24 22:00"), at("2026-10-25 23:00"), every_day) == 10 * 3600
    assert timers.business_seconds(at("2026-10-26 06:00"), at("2026-10-26 07:00"), ROME) == 0  # 07:00-08:00 in Rome
    assert timers.business_seconds(at("2026-10-26 07:00"), at("2026-10-26 08:00"), ROME) == 3600


def test_a_timer_counts_in_the_zone_of_the_incident_else_the_one_of_nik(admin: TestClient):
    incident(admin)
    incident(admin, "i2")
    assert admin.put("/api/settings", json={"businessHours": {**HOURS, "tz": "Europe/Rome"}}).status_code == 200
    assert admin.patch("/api/incidents/i2", json={"tz": "UTC"}).status_code == 200
    with SessionLocal() as db:
        assert timers.business_hours(db, db.get(Incident, "i1"))["tz"] == "Europe/Rome"
        assert timers.business_hours(db, db.get(Incident, "i2"))["tz"] == "UTC"
        assert timers.business_hours(db)["tz"] == "Europe/Rome"
        # 06:00-09:00 UTC on a Monday: two hours of work in Rome (07:00 UTC is 08:00 there), one in UTC.
        one = timers.business_hours(db, db.get(Incident, "i1"))
        two = timers.business_hours(db, db.get(Incident, "i2"))
    assert timers.business_seconds(at("2026-11-16 06:00"), at("2026-11-16 09:00"), one) == 2 * 3600
    assert timers.business_seconds(at("2026-11-16 06:00"), at("2026-11-16 09:00"), two) == 3600
    shown = admin.get("/api/incidents/i1/timers").json()
    assert shown["businessHours"]["tz"] == "Europe/Rome"


def test_the_zone_of_nik_is_checked_when_it_is_set(admin: TestClient):
    assert admin.get("/api/settings").json()["businessHours"]["tz"] == "UTC"
    refused = admin.put("/api/settings", json={"businessHours": {**HOURS, "tz": "Mars/Olympus"}})
    assert refused.status_code == 422 and "is not a time zone name" in refused.json()["detail"]
    assert admin.put("/api/settings", json={"businessHours": {**HOURS, "tz": "Europe/Rome"}}).status_code == 200
    assert admin.get("/api/settings").json()["businessHours"]["tz"] == "Europe/Rome"
    listed = admin.put("/api/lists/business_hours/items", json={"document": {**HOURS, "tz": "../etc/passwd"}})
    assert listed.status_code == 400 and "time zone" in listed.json()["detail"]


def test_the_incident_can_be_read_and_set_in_a_zone_of_its_own(admin: TestClient):
    incident(admin)
    assert admin.get("/api/incidents/i1").json()["tz"] == ""
    assert admin.patch("/api/incidents/i1", json={"tz": "Europe/Rome"}).json()["tz"] == "Europe/Rome"
    assert admin.get("/api/incidents/i1").json()["tz"] == "Europe/Rome"
    refused = admin.patch("/api/incidents/i1", json={"tz": "Nowhere/Land"})
    assert refused.status_code == 422 and "is not a time zone name" in refused.json()["detail"]
    assert admin.get("/api/incidents/i1").json()["tz"] == "Europe/Rome"
    # Other changes leave it; empty gives it back to Nik; it is a column, never a key of the document.
    assert admin.patch("/api/incidents/i1", json={"host": "WKS-1"}).json()["tz"] == "Europe/Rome"
    assert admin.patch("/api/incidents/i1", json={"tz": ""}).json()["tz"] == ""
    assert admin.patch("/api/incidents/i1", json={"tz": "UTC"}).status_code == 200
    merged = admin.patch(
        "/api/incidents/i1", json={"tz": None}, headers={"Content-Type": "application/merge-patch+json"}
    )
    assert merged.json()["tz"] == ""
    made = admin.post("/api/incidents", json={"id": "i3", "data": {}, "tz": "Asia/Tokyo"})
    assert made.status_code == 201 and made.json()["tz"] == "Asia/Tokyo"
    with SessionLocal() as db:
        assert "tz" not in db.get(Incident, "i3").doc
    assert admin.post("/api/incidents", json={"id": "i4", "data": {}, "tz": "x"}).status_code == 422


def test_hours_kept_without_a_zone_are_read_in_utc_and_a_page_that_does_not_send_one_keeps_it(admin: TestClient):
    from app import lists

    with SessionLocal() as db:
        lists.apply_setting(db, "businessHours", {"startHour": 9, "endHour": 17, "flagWeekends": False}, "tester")
        db.commit()
    assert admin.get("/api/settings").json()["businessHours"] == {
        "startHour": 9,
        "endHour": 17,
        "flagWeekends": False,
        "tz": "UTC",
    }
    assert admin.put("/api/settings", json={"businessHours": {**HOURS, "tz": "Europe/Rome"}}).status_code == 200
    assert admin.put("/api/settings", json={"businessHours": {"startHour": 7, "endHour": 19}}).status_code == 200
    held = admin.get("/api/settings").json()["businessHours"]
    assert held["tz"] == "Europe/Rome" and held["startHour"] == 7 and held["flagWeekends"] is True

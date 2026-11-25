"""Bulk actions: one action on many incidents, artifacts or indicators.

Each action is tried on a few items that end in each of the ways an item can:
done, skipped, refused by a permission, refused by a rule, failed. Then the
job itself: selection by query, the bounds, the confirmation, a restart in the
middle, a cancel, the audit log, the events and the pace of the engine.
"""

from __future__ import annotations

import csv
import io
import json
import re
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import bulk, bulk_incidents, mirror, work
from app.auditlog import chain
from app.automation import triggers, worker
from app.core import leases
from app.core.config import settings
from app.core.db import SessionLocal
from app.core.models import (
    AuditEntry,
    AutomationEvent,
    BulkItem,
    BulkJob,
    Connection,
    FoundIndicator,
    Incident,
    IocCheck,
    IocEntry,
    Lease,
    MirrorJob,
    WorkClaim,
)
from app.health import checks, thresholds
from tests import vendor
from tests.conftest import make_key
from tests.test_automation_engine import (  # noqa: F401 - test_actions is a fixture
    echo,
    edge,
    playbook,
    runs_of,
    test_actions,
)
from tests.test_fields import field
from tests.test_mail import no_dns, phishing_message  # noqa: F401 - no_dns is a fixture
from tests.test_malware import STRINGS_PAYLOAD, fake_pe
from tests.test_mirror import desk
from tests.test_mirror_instance import push_all
from tests.test_shipped_connectors import DATA
from tests.test_tasks import person


def incidents(admin: TestClient, count: int, **more) -> list[str]:
    ids = [f"i{index}" for index in range(1, count + 1)]
    for index, incident_id in enumerate(ids, 1):
        doc = {"id": incident_id, "name": f"Case {index}", "data": {}, **more}
        assert admin.post("/api/incidents", json=doc).status_code == 201
    return ids


def ask(client: TestClient, things: str, action: str, params: dict | None = None, **selection):
    return client.post(f"/api/{things}/bulk", json={"action": action, "params": params or {}, **selection})


def done(client: TestClient, things: str, action: str, params: dict | None = None, **selection) -> dict:
    answer = ask(client, things, action, params, **selection)
    assert answer.status_code == 200, answer.text
    return answer.json()


def states(job: dict) -> dict[str, tuple[str, str]]:
    return {item["ref"]: (item["state"], item["note"]) for item in job["items"]}


def counts(job: dict) -> tuple[int, int, int, int]:
    return job["done"], job["skipped"], job["refused"], job["failed"]


def audit_of(action: str) -> list[AuditEntry]:
    with SessionLocal() as db:
        return list(db.scalars(select(AuditEntry).where(AuditEntry.action == action).order_by(AuditEntry.at)))


def fields_of(admin: TestClient, incident_id: str) -> dict:
    return admin.get(f"/api/incidents/{incident_id}/fields").json()["fields"]


# --------------------------------------------------------------------------- #
# Incidents                                                                   #
# --------------------------------------------------------------------------- #
def test_fields_are_set_on_each_incident_through_the_registry(admin: TestClient):
    field(admin, "floor", "number")
    ids = incidents(admin, 3)
    assert admin.patch("/api/incidents/i2/fields", json={"changes": {"severity": "high"}}).status_code == 200
    job = done(admin, "incidents", "set", {"changes": {"severity": "high", "floor": 3}}, ids=[*ids, "ghost"])
    assert job["state"] == "done" and job["total"] == 4 and counts(job) == (3, 0, 1, 0)
    assert job["label"] == "Set severity to high, floor to 3: 4 incidents"
    assert states(job)["ghost"] == ("refused", "There is no such incident any more")
    assert all(fields_of(admin, item)["severity"] == "high" and fields_of(admin, item)["floor"] == 3 for item in ids)
    # Again: every one is so already.
    again = done(admin, "incidents", "set", {"changes": {"severity": "high", "floor": 3}}, ids=ids)
    assert counts(again) == (0, 3, 0, 0) and states(again)["i1"] == ("skipped", "It was so already")
    # One entry of the audit log for each field of each incident, as a single change leaves, linked to the job.
    entries = [entry for entry in audit_of("incident.field") if "bulk" in entry.details]
    assert len(entries) == 5  # i1 and i3: two fields each; i2: the floor only
    assert all(entry.details.endswith(f" · bulk {job['id'][:8]}") for entry in entries)
    (started,) = [entry for entry in audit_of("bulk.start") if entry.target == job["id"]]
    assert "4 incidents" in started.details and "bulk" not in started.details.split("Bulk job")[0]
    (ended,) = [entry for entry in audit_of("bulk.end") if entry.target == job["id"]]
    assert ended.details.endswith("3 done, 0 skipped, 1 refused, 0 failed")
    with SessionLocal() as db:
        assert chain.verify(db)["problem"] is None


def test_what_a_rule_of_a_field_refuses_is_refused_for_that_incident_only(admin: TestClient):
    made = admin.post("/api/incident-types", json={"name": "Bulk case", "closeReasons": ["Resolved", "False positive"]})
    assert made.status_code == 201, made.text
    kind = made.json()["id"]
    field(admin, "verdict_note")
    types = admin.put(
        f"/api/incident-types/{kind}", json={"fields": [{"name": "verdict_note", "requiredOnClose": True}]}
    )
    assert types.status_code == 200, types.text
    ids = incidents(admin, 3)
    assert admin.patch("/api/incidents/i2/fields", json={"changes": {"type": kind}}).status_code == 200
    # Which fields are not for many at once is said before any item.
    for name in ("name", "ticket", "labels", "affected_hosts", "created"):
        refused = ask(admin, "incidents", "set", {"changes": {name: "x"}}, ids=ids)
        assert refused.status_code == 422 and name in refused.json()["detail"]
    job = done(admin, "incidents", "set", {"changes": {"status": "closed", "close_reason": "Resolved"}}, ids=ids)
    assert counts(job) == (2, 0, 1, 0) and job["label"] == "Close: 3 incidents"
    assert states(job)["i2"] == ("refused", "To close this incident, fill in: verdict_note")
    assert fields_of(admin, "i2")["status"] == "open" and fields_of(admin, "i1")["status"] == "closed"
    # A value that is not one of the field's is refused for all of them, each with the sentence.
    wrong = done(admin, "incidents", "set", {"changes": {"severity": "enormous"}}, ids=ids)
    assert counts(wrong) == (0, 0, 3, 0) and "Severity" in states(wrong)["i1"][1]


def test_tags_are_added_and_removed_and_what_was_there_stays(admin: TestClient):
    ids = incidents(admin, 3)
    assert admin.patch("/api/incidents/i1/fields", json={"changes": {"labels": ["phishing", "old"]}}).status_code == 200
    job = done(admin, "incidents", "tags", {"add": ["Phishing", "q4"], "remove": ["old"]}, ids=ids)
    assert counts(job) == (3, 0, 0, 0)
    assert fields_of(admin, "i1")["labels"] == ["phishing", "q4"] and fields_of(admin, "i2")["labels"] == [
        "phishing",
        "q4",
    ]
    assert counts(done(admin, "incidents", "tags", {"add": ["q4"]}, ids=ids)) == (0, 3, 0, 0)
    assert ask(admin, "incidents", "tags", {"add": ["not a tag!"]}, ids=ids).status_code == 422
    assert ask(admin, "incidents", "tags", {}, ids=ids).status_code == 422


def test_deleting_asks_for_the_words_and_a_second_time_finds_nothing(admin: TestClient):
    ids = incidents(admin, 3)
    plan = admin.post("/api/incidents/bulk/plan", json={"action": "delete", "ids": ids[:2]}).json()
    assert plan["typed"] == "delete 2" and plan["count"] == 2 and plan["inline"] is True
    refused = ask(admin, "incidents", "delete", ids=ids[:2])
    assert refused.status_code == 409 and refused.json()["detail"] == 'To confirm, type "delete 2"'
    assert ask(admin, "incidents", "delete", ids=ids[:2], confirm={"typed": "delete 3"}).status_code == 409
    job = done(admin, "incidents", "delete", ids=ids[:2], confirm={"typed": "delete 2"})
    assert counts(job) == (2, 0, 0, 0)
    assert [row["id"] for row in admin.get("/api/incidents?view=summary").json()["incidents"]] == ["i3"]
    assert len([entry for entry in audit_of("incident.delete") if "bulk" in entry.details]) == 2
    again = done(admin, "incidents", "delete", ids=ids[:2], confirm={"typed": "delete 2"})
    assert counts(again) == (0, 2, 0, 0)


def test_a_viewer_does_nothing_and_each_action_asks_for_its_own_permission(admin: TestClient):
    ids = incidents(admin, 2)
    viewer = person(admin, "vera", ["viewer"])
    assert ask(viewer, "incidents", "tags", {"add": ["x"]}, ids=ids).status_code == 403
    assert viewer.post("/api/incidents/bulk/plan", json={"action": "tags", "ids": ids}).status_code == 403
    # Who builds playbooks may run one on many, and may not change the incidents.
    pb = playbook(admin, "Triage", [echo("a", "hi")], [edge("start", "a")], enabled=True)
    builder = person(admin, "paul", ["playbooks"])
    assert ask(builder, "incidents", "tags", {"add": ["x"]}, ids=ids).status_code == 403
    assert ask(builder, "incidents", "playbook", {"playbook": pb}, ids=ids).status_code == 200
    # A job is read by who asked for it, by an administrator and by who reads the audit log.
    job = done(person(admin, "anna", ["analyst"]), "incidents", "tags", {"add": ["mine"]}, ids=ids)
    assert viewer.get(f"/api/bulk/{job['id']}").status_code == 404
    assert admin.get(f"/api/bulk/{job['id']}").json()["actor"] == "anna"
    assert viewer.get("/api/bulk").json()["jobs"] == []
    assert [row["actor"] for row in admin.get("/api/bulk?everybody=true").json()["jobs"]] == ["anna", "paul"]


def test_an_account_that_lost_its_roles_while_its_job_ran_does_nothing_more(admin: TestClient):
    ids = incidents(admin, 4)
    anna = person(admin, "anna", ["analyst"])
    admin.put("/api/bulk/settings", json={"inlineItems": 0})
    started = ask(anna, "incidents", "tags", {"add": ["late"]}, ids=ids)
    assert started.status_code == 202  # the test client ran it before answering: do it by hand instead
    with SessionLocal() as db:
        assert db.get(BulkJob, started.json()["id"]).done == 4
    # The same, cut after two items; the roles go before the rest.
    job = _made(anna, "incidents", "tags", {"add": ["later"]}, ids)
    assert bulk.run(job, items=2) == "paused"
    user = next(row for row in admin.get("/api/users").json()["users"] if row["username"] == "anna")
    assert admin.patch(f"/api/users/{user['id']}", json={"roles": ["viewer"]}).status_code == 200
    assert bulk.run(job) == "done"
    read = admin.get(f"/api/bulk/{job}").json()
    assert counts(read) == (2, 0, 2, 0)
    refused = admin.get(f"/api/bulk/{job}/items?state=refused").json()["items"]
    assert {item["note"] for item in refused} == {"You do not have the permission this needs"}


def _made(client: TestClient, things: str, action: str, params: dict, ids: list[str] | None = None, **more) -> str:
    """A job that is written down and not started: what a request leaves when its process stops at once."""
    caller = client.get("/api/auth/me").json()["user"]
    from app.core.security import Principal

    with SessionLocal() as db:
        who = Principal(kind="user", actor=caller["username"], roles=caller["roles"])
        return bulk.start(
            db, bulk_routes_name(things), action, params, who, ids, more.get("query"), more.get("confirm")
        ).id


def bulk_routes_name(things: str) -> str:
    from app.routers.bulk import LISTS

    return LISTS[things]


def test_a_playbook_is_run_on_each_and_one_not_meant_for_it_is_refused_first(admin: TestClient):
    ids = incidents(admin, 3)
    by_hand = playbook(admin, "Triage", [echo("a", "{{ trigger.incident.name }}")], [edge("start", "a")], enabled=True)
    on_event = playbook(admin, "Auto", [echo("a", "x")], [edge("start", "a")], trigger={"event": "incident.created"})
    assert ask(admin, "incidents", "playbook", {"playbook": on_event}, ids=ids).status_code == 400
    assert ask(admin, "incidents", "playbook", {"playbook": "nope"}, ids=ids).status_code == 404
    job = done(admin, "incidents", "playbook", {"playbook": by_hand}, ids=[*ids, "ghost"])
    assert counts(job) == (3, 0, 1, 0) and job["label"] == 'Run the playbook "Triage" on each: 4 incidents'
    assert states(job)["ghost"][1] == "The object to run the playbook on does not exist"
    assert states(job)["i1"][1].startswith("Run ") and len(runs_of(admin, by_hand)) == 3
    assert len([entry for entry in audit_of("playbook.run") if "bulk" in entry.details]) == 3
    # The limit of the playbook holds, as for a run started by hand: past it, refused with its sentence.
    worker.drain()
    assert admin.put(f"/api/automation/playbooks/{by_hand}", json={"maxRunsPerHour": 4}).status_code == 200
    more = done(admin, "incidents", "playbook", {"playbook": by_hand}, ids=ids)
    assert counts(more) == (1, 0, 2, 0), more["items"]
    assert states(more)["i3"] == ("refused", "The playbook reached its runs per hour")
    plan = admin.post(
        "/api/incidents/bulk/plan",
        json={"action": "playbook", "params": {"playbook": by_hand}, "ids": [*ids, "a", "b"]},
    ).json()
    assert any("4 runs an hour" in note for note in plan["notes"]) and any(
        "20 at a time" in note for note in plan["notes"]
    )


def test_mirroring_changes_where_it_applies_and_a_change_is_sent_once_for_each(admin: TestClient, outside):
    connection, _world = desk(admin, outside)
    ids = incidents(admin, 3)
    for incident_id, ticket in (("i1", "T-9"), ("i2", "T-10")):
        made = admin.post(
            f"/api/incidents/{incident_id}/mirror",
            json={"instanceId": connection["id"], "mirrorId": ticket, "direction": "both"},
        )
        assert made.status_code == 201, made.text
    with SessionLocal() as db:
        before = len(db.scalars(select(MirrorJob)).all())
    plan = admin.post(
        "/api/incidents/bulk/plan", json={"action": "set", "params": {"changes": {"severity": "critical"}}, "ids": ids}
    ).json()
    assert plan["notes"] == ["2 of these are mirrored Out: their tickets will be updated, one update for each"]
    job = done(admin, "incidents", "set", {"changes": {"severity": "critical"}}, ids=ids)
    assert counts(job) == (3, 0, 0, 0)
    with SessionLocal() as db:
        queued = [row.incident_id for row in db.scalars(select(MirrorJob))][before:]
    assert sorted(queued) == ["i1", "i2"]  # one update for each mirrored incident, none for the third
    # The direction: where there is a mirror; None stops it.
    plan = admin.post("/api/incidents/bulk/plan", json={"action": "mirror", "params": {"direction": "in"}, "ids": ids})
    assert plan.json()["applies"] == 2 and plan.json()["count"] == 3
    turned = done(admin, "incidents", "mirror", {"direction": "in"}, ids=ids)
    assert counts(turned) == (2, 1, 0, 0) and states(turned)["i3"] == ("skipped", "It is not mirrored")
    assert admin.get("/api/incidents/i1/mirror").json()["direction"] == "in"
    assert counts(done(admin, "incidents", "mirror", {"direction": "in"}, ids=ids)) == (0, 3, 0, 0)
    assert counts(done(admin, "incidents", "mirror", {"direction": "none"}, ids=ids)) == (2, 1, 0, 0)
    assert admin.get("/api/incidents/i1/mirror").json().get("direction") is None
    # Sending out needs the permission to run playbooks, said before any item.
    writer = make_key(admin, roles=["viewer"])
    assert admin.post("/api/incidents/bulk", headers=writer, json={"action": "mirror", "ids": ids}).status_code == 403
    assert ask(admin, "incidents", "mirror", {"direction": "sideways"}, ids=ids).status_code == 422


def test_incidents_are_read_for_indicators_each_once(admin: TestClient):
    field(admin, "seen", "long_text")
    ids = incidents(admin, 2)
    # A field a person sets is not read by itself (an incident is read when it is made): the job reads it.
    for incident_id in ids:
        written = {"changes": {"seen": f"Beacon to files-{incident_id}.evil-site.com"}}
        assert admin.patch(f"/api/incidents/{incident_id}/fields", json=written).status_code == 200
    with SessionLocal() as db:
        assert db.scalars(select(FoundIndicator)).all() == []
        before = {event.id for event in db.scalars(select(AutomationEvent))}
    job = done(admin, "incidents", "find_indicators", ids=ids)
    assert counts(job) == (2, 0, 0, 0)
    assert len([entry for entry in audit_of("ioc.found_scan") if "bulk" in entry.details]) == 2
    with SessionLocal() as db:
        assert len(db.scalars(select(FoundIndicator)).all()) >= 2
        events = [event for event in db.scalars(select(AutomationEvent)) if event.id not in before]
    # Whatever a reading writes for the playbooks says that the job wrote it: it is held to the pace
    # of the engine as every event of a job is (the action is one that writes events).
    assert all(event.payload.get("bulk") == job["id"] for event in events)
    assert sorted(event.object_id for event in events if event.kind == "indicators.found") == ids
    assert bulk.listings()["incidents"].actions["find_indicators"].events is True


def test_a_playbook_on_what_a_job_found_runs_once_for_each_incident_that_found_something(
    admin: TestClient,
    monkeypatch,
    test_actions,  # noqa: F811
):
    """ "Find indicators now" on four incidents, three of which hold something to find, with a playbook
    that waits for ``indicators.found`` and makes an incident that holds an indicator too. The job keeps
    to the pace of the engine; the playbook runs once for each of the three; the incidents its runs make
    are read, their events name the run and start nothing; and no step of it starts a bulk job."""
    field(admin, "seen", "long_text")
    ids = incidents(admin, 4)
    # What a person writes in a field is not read by itself: the job is the reading.
    for incident_id in ids[:3]:
        written = admin.patch(
            f"/api/incidents/{incident_id}/fields",
            json={"changes": {"seen": f"Beacon to c2-{incident_id}.evil-site.com"}},
        )
        assert written.status_code == 200
    make = {
        "id": "make",
        "kind": "action",
        "name": "make",
        "config": {"action": "nik.create-incident", "args": {"title": "Seen with other-site.org"}},
    }
    book = playbook(
        admin, "On found", [make], [edge("start", "make")], trigger={"event": "indicators.found"}, enabled=True
    )
    worker.drain()
    with SessionLocal() as db:
        before = {event.id for event in db.scalars(select(AutomationEvent))}
    monkeypatch.setattr(bulk, "EVENTS_AHEAD", 1)
    monkeypatch.setattr(bulk, "engine_reads", lambda db, now: True)
    high = {"ahead": 0, "pauses": 0}

    def the_worker_turns(_seconds: float) -> bool:
        # The pause of the job is the turn of the worker. Bounded by the items.
        high["pauses"] += 1
        assert high["pauses"] < 20
        with SessionLocal() as db:
            waiting = db.scalars(select(AutomationEvent).where(AutomationEvent.done.is_(False))).all()
            high["ahead"] = max(high["ahead"], len([event for event in waiting if event.payload.get("bulk")]))
        worker.drain()
        return False

    job = _made(admin, "incidents", "find_indicators", {}, ids)
    assert bulk.run(job, pause=the_worker_turns) == "done"
    assert counts(admin.get(f"/api/bulk/{job}").json()) == (4, 0, 0, 0)
    assert high["pauses"] >= 2 and high["ahead"] == 1  # never more of the job's events waiting than it may hold
    for _turn in range(3):
        worker.drain()
    with SessionLocal() as db:
        found = [
            event
            for event in db.scalars(select(AutomationEvent).where(AutomationEvent.kind == "indicators.found"))
            if event.id not in before
        ]
        made = [event for event in found if event.object_id not in ids]
        # One event for each incident the job found something in, and none for the fourth.
        assert sorted(event.object_id for event in found if event.payload.get("bulk") == job) == ids[:3]
        runs = runs_of(admin, book)
        assert sorted(run["incidentId"] for run in runs) == ids[:3] and {run["status"] for run in runs} == {"done"}
        # The incidents the runs made were read: their events name the run, are not the job's, start nothing.
        assert len(made) == 3 and all(event.payload["caused_by_run"] and "bulk" not in event.payload for event in made)
        assert {event.payload["caused_by_run"] for event in made} == {run["id"] for run in runs}
        assert len(db.scalars(select(BulkJob)).all()) == 1
    # No step of a playbook starts a bulk job: only the route of the lists makes one.
    app = Path(bulk.__file__).parent
    makers = sorted(
        path.relative_to(app).as_posix()
        for path in app.rglob("*.py")
        if re.search(r"bulk\.start\(|(?<!class )BulkJob\(", path.read_text(encoding="utf-8"))
    )
    assert makers == ["bulk.py", "routers/bulk.py"]


def test_closing_many_alerts_of_the_siem_mirrored_from_the_instance_sends_one_status_to_each(
    admin: TestClient, outside
):
    """SentinelOne SIEM mirrors in the direction of its instance since 6.10. Closing many of its
    incidents at once is counted in the confirmation and sends one status to each alert mirrored Out or
    In-out, and nothing to one mirrored In; a field the pack does not send is not counted."""
    held = json.loads((DATA / "sentinelone-sdl" / "connection.json").read_text(encoding="utf-8"))
    with SessionLocal() as db:
        vendor.install_pack(db, "sentinelone-sdl")
        db.commit()
    made = admin.post(
        "/api/automation/instances",
        json={"name": "SIEM", "connector": "sentinelone-sdl", "config": held["config"], "secrets": held["secrets"]},
    )
    assert made.status_code == 201, made.text
    ids = incidents(admin, 4)
    alerts = {"i1": ("0195-a001", "both"), "i2": ("0195-a002", "out"), "i3": ("0195-a003", "in")}
    with SessionLocal() as db:
        connection = db.get(Connection, made.json()["id"])
        for incident_id, (alert, direction) in alerts.items():
            mirror.start(
                db, db.get(Incident, incident_id), connection, alert, direction, "connector:sentinelone-sdl",
                time.time(), origin="instance",
            )  # fmt: skip
        db.commit()
    assert {admin.get(f"/api/incidents/{ref}/mirror").json()["origin"] for ref in alerts} == {"instance"}

    other = {"action": "set", "params": {"changes": {"severity": "high"}}, "ids": ids}
    assert admin.post("/api/incidents/bulk/plan", json=other).json()["notes"] == []  # the pack sends the status alone
    changes = {"status": "closed", "close_reason": "False positive"}
    plan = admin.post("/api/incidents/bulk/plan", json={"action": "set", "params": {"changes": changes}, "ids": ids})
    assert plan.json()["notes"][0] == "2 of these are mirrored Out: their tickets will be updated, one update for each"
    closed = done(admin, "incidents", "set", {"changes": changes}, ids=ids)
    assert counts(closed) == (4, 0, 0, 0)
    with SessionLocal() as db:
        queued = [
            (job.incident_id, job.kind) for job in db.scalars(select(MirrorJob).where(MirrorJob.status == "pending"))
        ]
    assert sorted(queued) == [("i1", "update"), ("i2", "update")]

    outside.host("acme.sentinelone.net")
    answer = {"data": {"alertTriggerActions": {"actions": [{"actionId": "S1/alert/statusUpdate", "alertCount": 1}]}}}
    outside.answer("acme.sentinelone.net", json=answer, path="/web/api/v2.1/unifiedalerts/graphql")
    push_all(time.time())
    sent = sorted(
        (json.loads(request["body"])["variables"]["id"], json.loads(request["body"])["variables"]["status"])
        for request in outside.requests
    )
    assert sent == [("0195-a001", "FALSE_POSITIVE"), ("0195-a002", "FALSE_POSITIVE")]
    with SessionLocal() as db:
        assert {job.status for job in db.scalars(select(MirrorJob))} == {"done"}


# --------------------------------------------------------------------------- #
# Selection by query                                                          #
# --------------------------------------------------------------------------- #
QUERIES = ("status:open", "severity:>=high", 'owner:""', "Case 1", "severity:high tag:vip", "-status:closed")


def test_a_query_selects_what_the_list_shows_for_it(admin: TestClient):
    ids = incidents(admin, 6)
    admin.patch("/api/incidents/i1/fields", json={"changes": {"severity": "high", "labels": ["vip"]}})
    admin.patch("/api/incidents/i2/fields", json={"changes": {"severity": "critical", "owner": "admin"}})
    admin.patch("/api/incidents/i3/fields", json={"changes": {"status": "closed"}})
    for q in QUERIES:
        listed = [
            row["id"] for row in admin.get("/api/incidents", params={"view": "summary", "q": q}).json()["incidents"]
        ]
        plan = admin.post(
            "/api/incidents/bulk/plan", json={"action": "tags", "params": {"add": ["x"]}, "query": {"q": q}}
        )
        assert plan.status_code == 200, plan.text
        assert plan.json()["refs"] == listed and plan.json()["count"] == len(listed), q
    # A query that cannot be read is answered as the list answers it.
    assert (
        admin.post("/api/incidents/bulk/plan", json={"action": "delete", "query": {"q": "status:("}}).status_code == 422
    )
    # The count shown is sent back; a selection that changed meanwhile is not acted on.
    stale = ask(admin, "incidents", "tags", {"add": ["x"]}, query={"q": "status:open"}, confirm={"count": 4})
    assert (
        stale.status_code == 409
        and stale.json()["detail"] == "The selection is 5 incidents now, not 4: look at it again"
    )
    assert ask(admin, "incidents", "tags", {"add": ["x"]}, query={"q": "status:open"}).status_code == 409
    job = done(admin, "incidents", "tags", {"add": ["x"]}, query={"q": "status:open"}, confirm={"count": 5})
    assert counts(job) == (5, 0, 0, 0) and job["selection"] == {"query": {"q": "status:open"}}
    assert "x" not in fields_of(admin, "i3").get("labels", []) and len(ids) == 6
    assert ask(admin, "incidents", "tags", {"add": ["x"]}, ids=ids, query={"q": ""}).status_code == 422
    assert ask(admin, "incidents", "tags", {"add": ["x"]}).status_code == 422
    assert ask(admin, "incidents", "nothing", ids=ids).status_code == 422


def test_the_bounds_of_a_job_and_the_closing_of_many(admin: TestClient):
    ids = incidents(admin, 6)
    assert admin.put("/api/bulk/settings", json={"maxItems": 0}).status_code == 400
    limits = admin.put("/api/bulk/settings", json={"maxItems": 5, "typedAbove": 3}).json()
    assert limits == {"maxItems": 5, "inlineItems": 50, "typedAbove": 3, "defaults": bulk.DEFAULTS}
    plan = admin.post("/api/incidents/bulk/plan", json={"action": "tags", "params": {"add": ["x"]}, "ids": ids}).json()
    assert plan["over"] is True and plan["limit"] == 5
    over = ask(admin, "incidents", "tags", {"add": ["x"]}, ids=ids)
    assert over.status_code == 422 and "takes 5 at most" in over.json()["detail"]
    # Closing more than the threshold is confirmed by typing; fewer, or another change, is not.
    close = {"changes": {"status": "closed"}}
    plan = admin.post("/api/incidents/bulk/plan", json={"action": "set", "params": close, "ids": ids[:4]}).json()
    assert plan["typed"] == "close 4"
    assert ask(admin, "incidents", "set", close, ids=ids[:4]).status_code == 409
    assert counts(done(admin, "incidents", "set", close, ids=ids[:3])) == (3, 0, 0, 0)
    assert counts(done(admin, "incidents", "set", close, ids=ids[:4], confirm={"typed": "close 4"})) == (1, 3, 0, 0)
    assert counts(done(admin, "incidents", "set", {"changes": {"severity": "low"}}, ids=ids[:5])) == (5, 0, 0, 0)
    assert len(audit_of("bulk.settings")) == 1


# --------------------------------------------------------------------------- #
# The job: a failure, the result, trying again, a restart, a cancel           #
# --------------------------------------------------------------------------- #
def test_an_item_that_fails_stops_nothing_and_can_be_tried_again(admin: TestClient, monkeypatch):
    ids = incidents(admin, 4)
    real = bulk_incidents.registry.update

    def broken(db, incident, *args, **kwargs):
        if incident.id in ("i2", "i3"):
            raise RuntimeError("the disk under i2 =cmd")
        return real(db, incident, *args, **kwargs)

    monkeypatch.setattr(bulk_incidents.registry, "update", broken)
    job = done(admin, "incidents", "set", {"changes": {"severity": "high"}}, ids=ids)
    assert counts(job) == (2, 0, 0, 2)
    # What failed is said without the words of the error: they are in the log of the server.
    assert states(job)["i2"] == ("failed", "It failed (RuntimeError): the log of the server has the detail")
    assert fields_of(admin, "i1")["severity"] == "high" and "severity" not in fields_of(admin, "i2")
    text = admin.get(f"/api/bulk/{job['id']}/result.csv")
    assert text.headers["content-type"].startswith("text/csv")
    rows = list(csv.reader(io.StringIO(text.text)))
    assert rows[0] == ["item", "name", "result", "note"] and rows[2][:3] == ["i2", "#2 Case 2", "failed"]
    assert [row[2] for row in rows[1:]] == ["done", "failed", "failed", "done"]
    monkeypatch.setattr(bulk_incidents.registry, "update", real)
    again = admin.post(f"/api/bulk/{job['id']}/retry")
    assert again.status_code == 200, again.text
    assert again.json()["retryOf"] == job["id"] and again.json()["total"] == 2 and counts(again.json()) == (2, 0, 0, 0)
    assert admin.post(f"/api/bulk/{again.json()['id']}/retry").status_code == 409  # nothing of it failed
    assert bulk._csv_safe("=1+1") == "'=1+1"


def test_a_job_cut_in_the_middle_goes_on_and_does_nothing_twice(admin: TestClient, monkeypatch):
    ids = incidents(admin, 7)
    seen: list[str] = []
    real = bulk_incidents.registry.update

    def counting(db, incident, *args, **kwargs):
        seen.append(incident.id)
        return real(db, incident, *args, **kwargs)

    monkeypatch.setattr(bulk_incidents.registry, "update", counting)
    job = _made(admin, "incidents", "set", {"changes": {"severity": "high"}}, ids)
    with SessionLocal() as db:
        claim = db.get(WorkClaim, ("bulk", job))
        assert claim.state == "wanted"  # written with the job, before any item
    # The process that does it is killed after three items: it held the work, and says nothing more.
    with SessionLocal() as db:
        work.take(db, "bulk", job)
    assert bulk.run(job, items=3) == "paused"
    with SessionLocal() as db:
        db.get(WorkClaim, ("bulk", job)).holder = "a-process-that-is-gone"
        db.get(WorkClaim, ("bulk", job)).beat_at = 1.0
        db.commit()
    assert admin.get(f"/api/bulk/{job}").json()["pending"] == 4
    # The sweeper of the process that is alive takes it back and starts it again, here in its thread's place.
    started: list[str] = []
    monkeypatch.setattr(work, "thread", lambda target, *args: started.append(args[0]))
    swept = work.sweep(now=time.time() + work.STALE_AFTER + work.WANTED_GRACE + 5)
    assert ("bulk", job, "again") in swept["taken_back"] and started == [job]
    bulk.run_held(job)
    read = admin.get(f"/api/bulk/{job}").json()
    assert read["state"] == "done" and counts(read) == (7, 0, 0, 0)
    assert read["work"]["attempts"] == 2 and read["work"]["interruptedAt"]
    assert sorted(seen) == sorted(ids)  # each incident once, over the two processes
    assert len([entry for entry in audit_of("incident.field") if "bulk" in entry.details]) == 7
    with SessionLocal() as db:
        assert db.get(WorkClaim, ("bulk", job)).state == "done"
        assert db.get(Lease, f"bulk-{job}") is None  # given back when the job ended


def test_a_job_interrupted_every_time_is_given_up_and_says_what_it_did_not_do(admin: TestClient, monkeypatch):
    ids = incidents(admin, 4)
    job = _made(admin, "incidents", "tags", {"add": ["x"]}, ids)
    monkeypatch.setattr(work, "thread", lambda target, *args: None)
    now = time.time()
    for turn in range(work.MAX_ATTEMPTS):  # bounded: as many tries as the work may have
        with SessionLocal() as db:
            work.take(db, "bulk", job, now=now)
            db.get(WorkClaim, ("bulk", job)).beat_at = 1.0
            db.commit()
        if turn == 0:
            assert bulk.run(job, items=1) == "paused"
        now += work.STALE_AFTER + work.WANTED_GRACE + 5
        work.sweep(now=now)
    read = admin.get(f"/api/bulk/{job}").json()
    assert read["state"] == "failed" and read["pending"] == 3 and "try again on what was not" in read["note"]
    # Closed before the next test drops the tables: on PostgreSQL a session left open holds them.
    with SessionLocal() as db:
        rows = {row["id"]: row for row in checks.gather(db, thresholds.read(db))}
    assert rows["work.bulk"]["state"] == checks.ATTENTION and "1 given up" in rows["work.bulk"]["value"]
    again = admin.post(f"/api/bulk/{job}/retry")
    assert again.status_code == 200 and counts(again.json()) == (3, 0, 0, 0)


def test_a_job_can_be_cancelled_and_what_was_done_stays(admin: TestClient):
    ids = incidents(admin, 5)
    job = _made(admin, "incidents", "tags", {"add": ["x"]}, ids)
    assert bulk.run(job, items=2) == "paused"
    # One job at a time for a person and a list; another list is free.
    busy = ask(admin, "incidents", "tags", {"add": ["y"]}, ids=ids)
    assert busy.status_code == 409 and "still running" in busy.json()["detail"]
    cancelled = admin.post(f"/api/bulk/{job}/cancel").json()
    assert cancelled["cancelling"] is True and cancelled["state"] == "running"
    assert bulk.run(job) == "cancelled"
    read = admin.get(f"/api/bulk/{job}").json()
    assert read["state"] == "cancelled" and counts(read) == (2, 0, 0, 0) and read["pending"] == 3
    assert read["note"] == "Cancelled after 2 of 5: what was done stays"
    assert "x" in fields_of(admin, "i1")["labels"] and "labels" not in fields_of(admin, "i5")
    assert [row[2] for row in csv.reader(io.StringIO(admin.get(f"/api/bulk/{job}/result.csv").text))][-1] == "not done"
    assert len(audit_of("bulk.cancel")) == 1 and audit_of("bulk.end")[-1].details.endswith("3 not done")
    assert ask(admin, "incidents", "tags", {"add": ["y"]}, ids=ids).status_code == 200


def test_a_job_stops_politely_and_writes_nothing_on_a_server_that_does_not_serve(admin: TestClient, monkeypatch):
    ids = incidents(admin, 3)
    job = _made(admin, "incidents", "tags", {"add": ["x"]}, ids)
    monkeypatch.setattr(leases, "may_work", lambda db: False)
    bulk.run_held(job)
    with SessionLocal() as db:
        claim = db.get(WorkClaim, ("bulk", job))
        # Given back as wanted, and the try is not counted against it.
        assert (claim.state, claim.attempts) == ("wanted", 0)
        assert db.get(BulkJob, job).done == 0 and db.get(Lease, f"bulk-{job}") is None
    monkeypatch.undo()
    # Asked to stop between two items: it stops there, and the next process goes on.
    job_state = {"count": 0}

    def stop_after_one() -> bool:
        job_state["count"] += 1
        return job_state["count"] > 1

    monkeypatch.setattr(work, "stopping", stop_after_one)
    assert bulk.run(job) == "stopping"
    monkeypatch.undo()
    with SessionLocal() as db:
        assert db.get(BulkJob, job).done == 1 and db.get(BulkJob, job).state == "running"
    assert bulk.run(job) == "done"


# --------------------------------------------------------------------------- #
# Events, playbooks and the pace of the engine                                #
# --------------------------------------------------------------------------- #
def test_events_of_a_bulk_change_say_so_and_a_playbook_runs_once_for_each(admin: TestClient):
    ids = incidents(admin, 4)
    pb = playbook(
        admin,
        "On update",
        [echo("a", "{{ trigger.incident.id }} by {{ trigger.bulk }}")],
        [edge("start", "a")],
        trigger={"event": "incident.updated"},
        enabled=True,
    )
    worker.drain()
    job = done(admin, "incidents", "set", {"changes": {"severity": "high"}}, ids=ids)
    with SessionLocal() as db:
        events = [row for row in db.scalars(select(AutomationEvent).where(AutomationEvent.kind == "incident.updated"))]
    marked = [event for event in events if event.payload.get("bulk")]
    assert len(marked) == 4 and {event.object_id for event in marked} == set(ids)
    assert all(event.payload["bulk"] == job["id"] == event.payload["data"]["bulk"] for event in marked)
    assert all(event.payload["classes"]["bulk"] == ["nik_id"] for event in marked)
    worker.drain()
    worker.drain()
    runs = runs_of(admin, pb)
    assert sorted(run["incidentId"] for run in runs) == ids  # once for each incident
    # A change made alone carries no mark.
    assert admin.patch("/api/incidents/i1/fields", json={"changes": {"severity": "low"}}).status_code == 200
    with SessionLocal() as db:
        last = db.scalars(select(AutomationEvent).order_by(AutomationEvent.created_at.desc())).first()
    assert "bulk" not in last.payload and "bulk" not in last.payload["data"]
    assert triggers.current_run.get() is None


def test_a_job_does_not_write_events_faster_than_the_engine_reads_them(admin: TestClient, monkeypatch):
    ids = incidents(admin, 6)
    monkeypatch.setattr(bulk, "EVENTS_AHEAD", 2)
    monkeypatch.setattr(bulk, "engine_reads", lambda db, now: True)
    monkeypatch.setattr(bulk, "listens", lambda db: True)
    with SessionLocal() as db:
        for event in db.scalars(select(AutomationEvent)):
            event.done = True
        db.commit()
    high = {"ahead": 0, "pauses": 0}

    def engine_reads_them(_seconds: float) -> bool:
        # The pause of the job is the turn of the worker: it reads what waits. Bounded by the items.
        high["pauses"] += 1
        assert high["pauses"] < 50
        with SessionLocal() as db:
            waiting = list(db.scalars(select(AutomationEvent).where(AutomationEvent.done.is_(False))))
            high["ahead"] = max(high["ahead"], len(waiting))
            for event in waiting:
                event.done = True
            db.commit()
        return False

    job = _made(admin, "incidents", "set", {"changes": {"severity": "high"}}, ids)
    assert bulk.run(job, pause=engine_reads_them) == "done"
    read = admin.get(f"/api/bulk/{job}").json()
    assert counts(read) == (6, 0, 0, 0) and read["note"] == ""
    assert high["pauses"] >= 2 and high["ahead"] == 2  # never more than the outbox may hold ahead


def test_an_engine_that_does_not_read_does_not_hold_a_job_for_ever(admin: TestClient, monkeypatch):
    ids = incidents(admin, 5)
    monkeypatch.setattr(bulk, "EVENTS_AHEAD", 1)
    monkeypatch.setattr(bulk, "PATIENCE", 1.0)
    monkeypatch.setattr(bulk, "engine_reads", lambda db, now: True)
    monkeypatch.setattr(bulk, "listens", lambda db: True)
    pauses: list[float] = []
    job = _made(admin, "incidents", "set", {"changes": {"severity": "high"}}, ids)
    assert bulk.run(job, pause=lambda seconds: pauses.append(seconds) or False) == "done"
    read = admin.get(f"/api/bulk/{job}").json()
    assert counts(read) == (5, 0, 0, 0) and read["note"] == bulk.GONE_ON
    assert len(pauses) == 4  # a second of patience in quarters, once for the whole job
    # Asked to stop while it waits, it stops.
    monkeypatch.setattr(bulk, "PATIENCE", 60.0)
    job = _made(admin, "incidents", "set", {"changes": {"severity": "low"}}, ids)
    assert bulk.run(job, pause=lambda _seconds: True) == "stopping"

    # Cancelled while it waits for an engine that moves slowly: it does not wait for the room.
    def cancel_it(_seconds: float) -> bool:
        with SessionLocal() as db:
            bulk.cancel(db, db.get(BulkJob, job), "admin")
            db.commit()
        return False

    assert bulk.run(job, pause=cancel_it) == "cancelled"
    assert admin.get(f"/api/bulk/{job}").json()["state"] == "cancelled"


def test_runs_started_on_each_wait_for_those_before_them(admin: TestClient, monkeypatch):
    ids = incidents(admin, 5)
    pb = playbook(admin, "Slow", [echo("a", "x")], [edge("start", "a")], enabled=True)
    monkeypatch.setattr(bulk, "RUNS_AHEAD", 2)
    monkeypatch.setattr(bulk, "engine_reads", lambda db, now: True)
    monkeypatch.setattr(bulk, "listens", lambda db: True)
    high = {"unfinished": 0, "pauses": 0}

    def the_worker_turns(_seconds: float) -> bool:
        high["pauses"] += 1
        assert high["pauses"] < 50
        unfinished = [run for run in runs_of(admin, pb) if run["status"] not in ("done", "failed", "stopped")]
        high["unfinished"] = max(high["unfinished"], len(unfinished))
        worker.drain()
        return False

    job = _made(admin, "incidents", "playbook", {"playbook": pb}, ids)
    assert bulk.run(job, pause=the_worker_turns) == "done"
    assert counts(admin.get(f"/api/bulk/{job}").json()) == (5, 0, 0, 0)
    assert high["unfinished"] == 2 and settings.AUTOMATION_MAX_ACTIVE_RUNS >= 2


# --------------------------------------------------------------------------- #
# Artifacts                                                                   #
# --------------------------------------------------------------------------- #
def artifacts(admin: TestClient) -> tuple[str, str]:
    file = admin.post("/api/artifacts/files", files={"file": ("invoice.exe", fake_pe(payload=STRINGS_PAYLOAD))})
    mail = admin.post("/api/artifacts/mails", files={"file": ("reported.eml", phishing_message())})
    assert file.status_code == 201 and mail.status_code == 201, (file.text, mail.text)
    return file.json()["id"], mail.json()["id"]


def test_artifacts_are_tagged_linked_given_a_day_and_deleted(admin: TestClient, no_dns):  # noqa: F811
    file, mail = artifacts(admin)
    incidents(admin, 1)
    refs = [file, mail, "file-" + "0" * 64]
    job = done(admin, "artifacts", "tags", {"add": ["Campaign", "q4"]}, ids=refs)
    assert counts(job) == (2, 0, 1, 0) and states(job)[refs[2]] == ("refused", "There is no such artifact any more")
    assert job["items"][0]["name"] == "invoice.exe"
    assert admin.get(f"/api/artifacts/{file}").json()["tags"] == ["campaign", "q4"]
    assert counts(done(admin, "artifacts", "tags", {"add": ["q4"], "remove": ["nothing"]}, ids=refs[:2])) == (
        0,
        2,
        0,
        0,
    )
    assert counts(done(admin, "artifacts", "tags", {"remove": ["q4"]}, ids=refs[:2])) == (2, 0, 0, 0)
    assert len([entry for entry in audit_of("artifact.tags") if "bulk" in entry.details]) == 4
    # Twelve tags at most: one more is a refusal for that artifact.
    many = [f"t{index}" for index in range(11)]
    assert counts(done(admin, "artifacts", "tags", {"add": many}, ids=[file])) == (1, 0, 0, 0)
    full = done(admin, "artifacts", "tags", {"add": ["one-more"]}, ids=[file])
    assert states(full)[file] == ("refused", "An artifact holds 12 tags at most")

    linked = done(admin, "artifacts", "link", {"incident": "i1"}, ids=refs[:2])
    assert counts(linked) == (2, 0, 0, 0) and linked["label"] == 'Link to the incident "Case 1": 2 artifacts'
    assert [row["id"] for row in admin.get(f"/api/artifacts/{mail}").json()["incidents"]] == ["i1"]
    assert counts(done(admin, "artifacts", "link", {"incident": "i1"}, ids=refs[:2])) == (0, 2, 0, 0)
    assert ask(admin, "artifacts", "link", {"incident": "nope"}, ids=refs[:2]).status_code == 404
    plan = admin.post("/api/artifacts/bulk/plan", json={"action": "unlink", "params": {"incident": "i1"}, "ids": refs})
    assert plan.json()["applies"] == 2 and plan.json()["count"] == 3
    assert counts(done(admin, "artifacts", "unlink", {"incident": "i1"}, ids=refs[:2])) == (2, 0, 0, 0)
    assert counts(done(admin, "artifacts", "unlink", {"incident": "i1"}, ids=refs[:2])) == (0, 2, 0, 0)

    assert ask(admin, "artifacts", "expiry", {"expiresAt": "yesterday"}, ids=refs[:2]).status_code == 400
    assert counts(done(admin, "artifacts", "expiry", {"expiresAt": SOON}, ids=refs[:2])) == (2, 0, 0, 0)
    assert admin.get(f"/api/artifacts/{file}").json()["expiresAt"] == SOON
    assert counts(done(admin, "artifacts", "expiry", {"expiresAt": SOON}, ids=refs[:2])) == (0, 2, 0, 0)
    assert counts(done(admin, "artifacts", "expiry", {"expiresAt": None}, ids=refs[:2])) == (2, 0, 0, 0)

    again = done(admin, "artifacts", "reanalyse", ids=refs[:2])
    assert counts(again) == (2, 0, 0, 0)
    assert len(audit_of("sample.reanalyse")) == 1 and len(audit_of("mail.reanalyse")) == 1

    assert ask(admin, "artifacts", "delete", ids=refs[:2]).status_code == 409
    gone = done(admin, "artifacts", "delete", ids=refs[:2], confirm={"typed": "delete 2"})
    assert counts(gone) == (2, 0, 0, 0) and admin.get("/api/artifacts").json()["total"] == 0
    assert counts(done(admin, "artifacts", "delete", ids=refs[:2], confirm={"typed": "delete 2"})) == (0, 2, 0, 0)


def test_artifacts_are_selected_by_what_their_list_was_filtered_by(admin: TestClient, no_dns):  # noqa: F811
    file, mail = artifacts(admin)
    for query in ({"q": "invoice"}, {"kind": "mail"}, {"q": "kind:file"}, {"mine": True}, {"linked": False}, {}):
        params = {key: str(value).lower() if isinstance(value, bool) else value for key, value in query.items()}
        listed = [row["id"] for row in admin.get("/api/artifacts", params=params).json()["artifacts"]]
        plan = admin.post("/api/artifacts/bulk/plan", json={"action": "reanalyse", "query": query})
        assert plan.status_code == 200, plan.text
        assert plan.json()["refs"] == listed, query
    assert (
        admin.post("/api/artifacts/bulk/plan", json={"action": "delete", "query": {"kind": "nope"}}).status_code == 422
    )
    job = done(admin, "artifacts", "tags", {"add": ["seen"]}, query={"kind": "mail"}, confirm={"count": 1})
    assert counts(job) == (1, 0, 0, 0) and admin.get(f"/api/artifacts/{file}").json()["tags"] == []
    assert admin.get(f"/api/artifacts/{mail}").json()["tags"] == ["seen"]


# --------------------------------------------------------------------------- #
# Indicators                                                                  #
# --------------------------------------------------------------------------- #
SOON = time.strftime("%Y-%m-%d", time.gmtime(time.time() + 400 * 86400))
VALUES = ["evil-one.com", "evil-two.com", "evil-three.com"]


def library(admin: TestClient) -> list[str]:
    added = admin.post("/api/iocs", json={"items": [{"type": "domain", "value": value} for value in VALUES]})
    assert added.status_code == 201, added.text
    return [f"domain:{value}" for value in VALUES]


def row_of(admin: TestClient, value: str) -> dict:
    return next(row for row in admin.get("/api/iocs", params={"q": value}).json()["iocs"] if row["value"] == value)


def test_indicators_are_tagged_classified_listed_and_removed(admin: TestClient):
    refs = library(admin)
    job = done(admin, "iocs", "tags", {"add": ["apt", "q4"]}, ids=[*refs, "domain:not known.example", "nonsense"])
    assert counts(job) == (3, 0, 2, 0)
    assert states(job)["nonsense"] == ("refused", "This is not an indicator")
    assert row_of(admin, VALUES[0])["tags"] == ["apt", "q4"]
    assert counts(done(admin, "iocs", "tags", {"add": ["apt"], "remove": ["zzz"]}, ids=refs)) == (0, 3, 0, 0)
    assert len([entry for entry in audit_of("ioc.edit") if "bulk" in entry.details]) == 3

    assert ask(admin, "iocs", "tlp", {"tlp": "purple"}, ids=refs).status_code == 422
    assert counts(done(admin, "iocs", "tlp", {"tlp": "red"}, ids=refs)) == (3, 0, 0, 0)
    assert row_of(admin, VALUES[1])["tlp"] == "red"
    assert counts(done(admin, "iocs", "tlp", {"tlp": "red"}, ids=refs)) == (0, 3, 0, 0)

    made = admin.post("/api/iocs/lists", json={"name": "Campaign"}).json()
    assert ask(admin, "iocs", "list_add", {"list": "nope"}, ids=refs).status_code == 404
    added = done(admin, "iocs", "list_add", {"list": made["id"]}, ids=refs)
    assert counts(added) == (3, 0, 0, 0) and added["label"] == 'Add to the list "Campaign": 3 indicators'
    assert counts(done(admin, "iocs", "list_add", {"list": made["id"]}, ids=refs)) == (0, 3, 0, 0)
    assert admin.get(f"/api/iocs/lists/{made['id']}").json()["counts"]["all"] == 3
    assert counts(done(admin, "iocs", "list_remove", {"list": made["id"]}, ids=refs[:2])) == (2, 0, 0, 0)
    assert counts(done(admin, "iocs", "list_remove", {"list": made["id"]}, ids=refs)) == (1, 2, 0, 0)

    allowed = done(admin, "iocs", "allowlist", ids=refs[:2])
    assert counts(allowed) == (2, 0, 0, 0) and VALUES[0] in admin.get("/api/settings").json()["iocAllowlist"]
    assert counts(done(admin, "iocs", "allowlist", ids=refs[:2])) == (0, 2, 0, 0)

    assert ask(admin, "iocs", "delete", ids=refs).status_code == 409
    gone = done(admin, "iocs", "delete", ids=refs, confirm={"typed": "remove 3"})
    assert counts(gone) == (3, 0, 0, 0) and admin.get("/api/iocs").json()["total"] == 0
    assert counts(done(admin, "iocs", "delete", ids=refs, confirm={"typed": "remove 3"})) == (0, 3, 0, 0)
    assert len([entry for entry in audit_of("ioc.remove") if "bulk" in entry.details]) == 3


def test_indicators_are_selected_by_the_filter_of_their_page(admin: TestClient):
    refs = library(admin)
    done(admin, "iocs", "tags", {"add": ["apt"]}, ids=refs[:2])
    for query in ({"q": "evil-two"}, {"q": "tag:apt"}, {"type": "domain"}, {"origin": "manual"}, {"type": "ip"}, {}):
        listed = admin.get("/api/iocs", params=query).json()["iocs"]
        plan = admin.post("/api/iocs/bulk/plan", json={"action": "tags", "params": {"add": ["x"]}, "query": query})
        assert plan.status_code == 200, plan.text
        assert plan.json()["refs"] == [f"{row['type']}:{row['value']}" for row in listed], query
    job = done(admin, "iocs", "tlp", {"tlp": "green"}, query={"q": "tag:apt"}, confirm={"count": 2})
    assert counts(job) == (2, 0, 0, 0) and row_of(admin, VALUES[2])["tlp"] != "green"
    assert (
        admin.post("/api/iocs/bulk/plan", json={"action": "delete", "query": {"incident": "nope"}}).status_code == 404
    )


def test_found_indicators_are_removed_from_their_incident_and_not_found_again(admin: TestClient):
    hosts = [f"drop-{index}.evil-site.com" for index in range(6)]
    incidents(admin, 1, name=" ".join(hosts))
    admin.post("/api/incidents/i1/iocs/found/scan")
    held = admin.get("/api/incidents/i1/iocs").json()["iocs"]
    found = [f"{row['type']}:{row['value']}" for row in held if row["type"] == "domain"]
    assert len(found) >= 5
    # All that the incident holds, as its tab asks for them.
    plan = admin.post(
        "/api/iocs/bulk/plan",
        json={"action": "incident_remove", "params": {"incident": "i1"}, "query": {"incident": "i1", "type": "domain"}},
    ).json()
    assert sorted(plan["refs"]) == sorted(found) and plan["applies"] == len(found)
    job = done(admin, "iocs", "incident_remove", {"incident": "i1"}, ids=[*found[:4], "domain:elsewhere.example"])
    assert counts(job) == (4, 1, 0, 0)
    assert states(job)["domain:elsewhere.example"] == ("skipped", "The incident does not hold it")
    left = {f"{row['type']}:{row['value']}" for row in admin.get("/api/incidents/i1/iocs").json()["iocs"]}
    assert not left & set(found[:4]) and set(found[4:]) <= left
    assert len(admin.get("/api/incidents/i1/iocs/found").json()["removed"]) == 4
    assert len([entry for entry in audit_of("ioc.found_removed") if "bulk" in entry.details]) == 4
    # Read again, what was removed is not found again.
    admin.post("/api/incidents/i1/iocs/found/scan")
    left = {f"{row['type']}:{row['value']}" for row in admin.get("/api/incidents/i1/iocs").json()["iocs"]}
    assert not left & set(found[:4])
    assert counts(done(admin, "iocs", "incident_remove", {"incident": "i1"}, ids=found[:4])) == (0, 4, 0, 0)
    with SessionLocal() as db:
        assert db.get(IocEntry, ("i1", *found[0].split(":", 1))) is None


def test_removing_a_found_indicator_leaves_the_rest_of_the_index_as_it_is(admin: TestClient, monkeypatch):
    from app import iocs

    hosts = [f"drop-{index}.evil-site.com" for index in range(4)]
    incidents(admin, 1, name=" ".join(hosts))
    admin.post("/api/incidents/i1/iocs/found/scan")
    built: list[str] = []
    real = iocs.reindex_incident
    monkeypatch.setattr(iocs, "reindex_incident", lambda db, row, **more: built.append(row.id) or real(db, row, **more))
    job = done(admin, "iocs", "incident_remove", {"incident": "i1"}, ids=[f"domain:{host}" for host in hosts[:3]])
    assert counts(job) == (3, 0, 0, 0) and built == []  # not built again for each one removed
    assert [row["value"] for row in admin.get("/api/incidents/i1/iocs").json()["iocs"]] == [hosts[3]]


@pytest.mark.parametrize("many", [500, 1000])
def test_an_incident_that_found_hundreds_of_indicators_has_them_all_checked_exported_and_removed(
    admin: TestClient, many: int
):
    from app import indicators_found

    # An incident is given 500 found indicators when nobody set the number, and up to 1000 when it is set.
    assert (indicators_found.CAP_DEFAULT, indicators_found.CAP_MAX) == (500, 1000)
    if many != indicators_found.CAP_DEFAULT:
        assert admin.put("/api/iocs/found/settings", json={"cap": many}).status_code == 200
    with SessionLocal() as db:
        vendor.source(db, "shodan")
        vendor.source(db, "greynoise")
    field(admin, "seen", "long_text")
    addresses = [f"185.220.{100 + index // 250}.{index % 250 + 1}" for index in range(many)]
    incidents(admin, 1)
    assert admin.patch("/api/incidents/i1/fields", json={"changes": {"seen": " ".join(addresses)}}).status_code == 200
    scanned = admin.post("/api/incidents/i1/iocs/found/scan").json()
    assert scanned["scan"]["new"] == many and scanned["scan"]["over"] == 0
    held = [f"{row['type']}:{row['value']}" for row in admin.get("/api/incidents/i1/iocs").json()["iocs"]]
    assert sorted(held) == sorted(f"ip:{address}" for address in addresses)

    # Checked: one queue of the look-ups, its cost said first, every one of them in it.
    plan = admin.post("/api/iocs/bulk/plan", json={"action": "check", "ids": held}).json()
    assert plan["count"] == many and plan["applies"] == many and plan["inline"] is False
    assert {note.split(":")[0] for note in plan["notes"]} == {"Shodan", "GreyNoise"}
    checked = ask(admin, "iocs", "check", ids=held)
    assert checked.status_code == 202, checked.text
    read = admin.get(f"/api/bulk/{checked.json()['id']}").json()
    assert read["state"] == "done" and counts(read) == (many, 0, 0, 0)
    with SessionLocal() as db:
        (check,) = db.scalars(select(IocCheck)).all()
        assert check.total == many and len(check.pending) == many

    # Exported, as the bar of the tab asks for the rows it has.
    rows = [{"type": "ip", "value": ref.split(":", 1)[1]} for ref in held]
    exported = admin.post("/api/iocs/export", json={"scope": {"items": rows}, "format": "csv"})
    assert exported.status_code == 200 and exported.headers["x-nik-count"] == str(many)
    assert len(list(csv.reader(io.StringIO(exported.text)))) == many + 1

    # Tagged, all that the incident holds, as its tab selects them all.
    selected = {"incident": "i1"}
    tagged = ask(admin, "iocs", "tags", {"add": ["found-many"]}, query=selected, confirm={"count": many})
    assert tagged.status_code == 202, tagged.text
    read = admin.get(f"/api/bulk/{tagged.json()['id']}").json()
    assert read["state"] == "done" and counts(read) == (many, 0, 0, 0)
    assert admin.get("/api/iocs", params={"q": "tag:found-many"}).json()["total"] == many

    # All that the incident holds, removed: each remembered, none found again.
    plan = admin.post(
        "/api/iocs/bulk/plan", json={"action": "incident_remove", "params": selected, "query": selected}
    ).json()
    assert plan["count"] == many and plan["applies"] == many
    removed = ask(admin, "iocs", "incident_remove", selected, query=selected, confirm={"count": many})
    assert removed.status_code == 202, removed.text
    read = admin.get(f"/api/bulk/{removed.json()['id']}").json()
    assert read["state"] == "done" and counts(read) == (many, 0, 0, 0)
    assert admin.get("/api/incidents/i1/iocs").json()["iocs"] == []
    assert len(admin.get("/api/incidents/i1/iocs/found").json()["removed"]) == many
    assert admin.post("/api/incidents/i1/iocs/found/scan").json()["scan"]["new"] == 0
    assert admin.get("/api/incidents/i1/iocs").json()["iocs"] == []


def test_a_check_of_many_is_one_queue_and_says_what_it_costs_first(admin: TestClient, monkeypatch):
    from app.enrichment import service

    refs = library(admin)
    plans: list[int] = []
    real = service.plan_check
    monkeypatch.setattr(
        service, "plan_check", lambda db, pairs, *a, **k: plans.append(len(list(pairs))) or _plan(pairs)
    )

    def _plan(pairs):
        wanted = [list(pair) for pair in pairs]
        return {
            "total": len(wanted),
            "toAsk": 2,
            "reused": 1,
            "neverSent": 0,
            "held": 0,
            "seconds": 2,
            "sources": [
                {
                    "provider": "vt",
                    "label": "VirusTotal",
                    "keys": 1,
                    "needed": 2,
                    "leftToday": 1,
                    "today": 1,
                    "later": 1,
                }
            ],
            "pending": [[*wanted[0], ["vt"]], [*wanted[1], ["vt"]]],
            "items": wanted,
        }

    plan = admin.post("/api/iocs/bulk/plan", json={"action": "check", "ids": refs}).json()
    assert plan["applies"] == 2 and plan["notes"] == [
        "VirusTotal: 2 requests, 1 left today (1 wait for tomorrow's quota)",
        "1 have a fresh answer already: not asked again",
    ]
    job = done(admin, "iocs", "check", ids=refs)
    assert counts(job) == (2, 1, 0, 0) and plans == [3, 3]
    with SessionLocal() as db:
        (check,) = db.scalars(select(IocCheck)).all()  # one check, in the queue the look-ups work through
        assert check.total == 2 and len(check.pending) == 2 and check.created_by == "admin"
    assert states(job)[refs[0]] == ("done", f"In the queue of the check {check.id}")
    assert states(job)[refs[2]][0] == "skipped" and real is not None
    with SessionLocal() as db:
        assert len(db.scalars(select(BulkItem).where(BulkItem.state == "pending")).all()) == 0


def test_the_health_page_and_the_list_of_jobs_say_what_there_is(admin: TestClient):
    ids = incidents(admin, 2)
    done(admin, "incidents", "tags", {"add": ["x"]}, ids=ids)
    listed = admin.get("/api/bulk").json()
    assert [job["label"] for job in listed["jobs"]] == ["Add the tags x: 2 incidents"]
    assert {action["name"] for action in listed["actions"]["incidents"]} == {
        "set",
        "tags",
        "delete",
        "playbook",
        "mirror",
        "find_indicators",
        "archive",
        "unarchive",
    }
    assert {action["name"] for action in listed["actions"]["artifacts"]} == {
        "tags",
        "reanalyse",
        "link",
        "unlink",
        "expiry",
        "delete",
    }
    assert len(listed["actions"]["indicators"]) == 8 and listed["limits"] == bulk.DEFAULTS
    names = {item["name"] for item in admin.get("/api/bulk/fields").json()["fields"]}
    assert {"status", "severity", "owner", "type", "tlp", "close_reason"} <= names
    assert not names & {"name", "ticket", "labels", "created", "affected_hosts", "time_to_close", "mirror_id"}
    with SessionLocal() as db:
        rows = {row["id"]: row for row in checks.gather(db, thresholds.read(db))}
    assert rows["work.bulk"]["state"] == checks.FINE and rows["work.bulk"]["value"].startswith("0 running")
    # Old jobs go, with their items, when a new one is made.
    with SessionLocal() as db:
        db.scalars(select(BulkJob)).one().updated_at = time.time() - bulk.KEPT_SECONDS - 10
        db.commit()
    done(admin, "incidents", "tags", {"add": ["y"]}, ids=ids)
    assert len(admin.get("/api/bulk").json()["jobs"]) == 1


@pytest.mark.parametrize("things", ["incidents", "artifacts", "iocs"])
def test_the_three_lists_answer_the_same_way(admin: TestClient, things: str):
    assert ask(admin, things, "tags", {"add": ["x"]}, ids=[]).status_code == 422
    plan = admin.post(f"/api/{things}/bulk/plan", json={"action": "tags", "params": {"add": ["x"]}, "ids": ["a:b"]})
    assert plan.status_code == 200 and set(plan.json()) == {
        "list",
        "action",
        "label",
        "count",
        "applies",
        "notes",
        "limit",
        "over",
        "inline",
        "typed",
        "refs",
    }
    job = done(admin, things, "tags", {"add": ["x"]}, ids=["a:b"])
    assert counts(job) == (0, 0, 1, 0) and job["state"] == "done"


def test_a_job_keeps_no_pace_when_no_playbook_waits_for_an_event(admin: TestClient, monkeypatch):
    ids = incidents(admin, 4)
    monkeypatch.setattr(bulk, "EVENTS_AHEAD", 1)
    monkeypatch.setattr(bulk, "engine_reads", lambda db, now: True)
    pauses: list[float] = []
    # A playbook run by hand waits for no event: the outbox may fill, nothing starts from it.
    playbook(admin, "By hand", [echo("a", "x")], [edge("start", "a")], enabled=True)
    with SessionLocal() as db:
        assert bulk.listens(db) is False
    job = _made(admin, "incidents", "set", {"changes": {"severity": "high"}}, ids)
    assert bulk.run(job, pause=lambda seconds: pauses.append(seconds) or False) == "done"
    assert pauses == [] and admin.get(f"/api/bulk/{job}").json()["note"] == ""
    playbook(
        admin, "On update", [echo("a", "x")], [edge("start", "a")], trigger={"event": "incident.updated"}, enabled=True
    )
    with SessionLocal() as db:
        assert bulk.listens(db) is True


def test_a_job_asked_with_a_key_is_the_key_and_ends_with_it(admin: TestClient):
    from app.core.models import ApiKey
    from app.core.security import Principal, now_iso

    ids = incidents(admin, 3)
    key = make_key(admin, label="robot", roles=["analyst"])
    assert admin.put("/api/bulk/settings", json={"inlineItems": 0}).status_code == 200
    asked = TestClient(admin.app).post(
        "/api/incidents/bulk", headers=key, json={"action": "tags", "params": {"add": ["by-key"]}, "ids": ids}
    )
    assert asked.status_code == 202, asked.text
    read = admin.get(f"/api/bulk/{asked.json()['id']}").json()
    assert read["actor"] == "api:robot" and counts(read) == (3, 0, 0, 0)
    assert {entry.actor for entry in audit_of("incident.field") if "bulk" in entry.details} == {"api:robot"}
    # The key is revoked while a job of its own waits: nothing more is done in its name.
    with SessionLocal() as db:
        robot = Principal(kind="apikey", actor="api:robot", roles=["analyst"])
        job = bulk.start(db, "incidents", "tags", {"add": ["later"]}, robot, ids, None).id
        db.scalars(select(ApiKey).where(ApiKey.label == "robot")).one().revoked_at = now_iso()
        db.commit()
    assert bulk.run(job) == "done"
    read = admin.get(f"/api/bulk/{job}").json()
    assert counts(read) == (0, 0, 3, 0)
    refused = admin.get(f"/api/bulk/{job}/items").json()["items"]
    assert {item["note"] for item in refused} == {"The account that asked for this may not act any more"}

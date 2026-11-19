"""Counting and measuring what a query finds: the numbers behind a dashboard."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm.attributes import flag_modified

from app.core.db import SessionLocal
from app.core.models import Approval, Incident, Playbook, Run, Task
from app.query import aggregate as agg
from app.query.parser import QueryError
from tests.conftest import make_key

NOW = datetime(2026, 11, 18, 12, 0, 0, tzinfo=timezone.utc)

INCIDENTS = [
    # name, severity, status, created, closed, fields
    ("a", "high", "open", "2026-11-18T08:00:00+00:00", None, {"sla_breached": True}),
    ("b", "high", "closed", "2026-11-17T08:00:00+00:00", "2026-11-17T10:00:00+00:00", {}),
    ("c", "low", "closed", "2026-11-17T09:00:00+00:00", "2026-11-17T09:30:00+00:00", {}),
    ("d", "critical", "open", "2026-11-15T23:59:00+00:00", None, {}),
    ("e", "", "closed", "2026-11-10T08:00:00+00:00", "2026-11-10T16:00:00+00:00", {}),
    ("f", "low", "open", "2026-10-01T08:00:00+00:00", None, {}),
]


@pytest.fixture()
def held(admin: TestClient):
    with SessionLocal() as db:
        for name, severity, status, created, closed, fields in INCIDENTS:
            timer = {"state": "stopped", "accumulated_s": 600 if name == "b" else 1800, "due_s": 3600}
            row = Incident(
                id=f"agg-{name}", name=name, severity=severity, status=status, created_at=created, updated_at=created,
                closed_at=closed, doc={}, fields={**fields, **({"time_to_assign": timer} if closed else {})},
            )  # fmt: skip
            db.add(row)
            flag_modified(row, "fields")
        db.commit()
    return admin


def ask(client: TestClient, **body) -> dict:
    answer = client.post("/api/query/aggregate", json={"entity": "incidents", **body})
    assert answer.status_code == 200, answer.text
    return answer.json()


def run(**wanted) -> dict:
    with SessionLocal() as db:
        return agg.run(db, wanted.pop("entity", "incidents"), wanted.pop("query", "id:agg-*"), None, now=NOW, **wanted)


def test_a_count_by_a_field_is_grouped_and_ordered(held):
    out = ask(held, query="id:agg-*", groupBy=["status"])
    assert out["total"] == 6
    assert out["rows"] == [["closed", 3], ["open", 3]]
    assert [column["name"] for column in out["columns"]] == ["status", "count"]
    # A field with an order keeps it, the worst first; what has none of it is last.
    assert run(group_by=["severity"])["rows"] == [["critical", 1], ["high", 2], ["low", 2], ["", 1]]
    # Two groups: a row for each pair that exists.
    pairs = run(group_by=["status", "severity"])["rows"]
    assert ["open", "high", 1] in pairs and ["closed", "", 1] in pairs and len(pairs) == 6
    # The first N, and how many groups were left out.
    cut = run(group_by=["name"], limit=4)
    assert len(cut["rows"]) == 4 and cut["more"] == 2
    # A bool is true or false, never empty.
    assert run(group_by=["slaBreached"])["rows"] == [["false", 5], ["true", 1]]


def test_a_date_is_grouped_by_a_stretch_of_time_with_no_holes(held):
    days = run(group_by=["created@day"], time_field="created", time_range_="4d")
    assert days["range"] == {"from": "2026-11-14T12:00:00Z", "to": "2026-11-18T12:00:00Z"}
    assert days["rows"] == [
        ["2026-11-14", 0],
        ["2026-11-15", 1],
        ["2026-11-16", 0],
        ["2026-11-17", 2],
        ["2026-11-18", 1],
    ]
    assert days["total"] == 4
    assert run(group_by=["created@month"])["rows"] == [["2026-10", 1], ["2026-11", 5]]
    # A week is named by its Monday.
    weeks = run(group_by=["created@week"], query="id:agg-* created:>=2026-11-09")["rows"]
    assert weeks == [["2026-11-09", 2], ["2026-11-16", 3]]
    # Over time and by a field: the series of a stacked chart.
    stacked = run(group_by=["created@day", "status"], time_field="created", time_range_="2d")["rows"]
    assert stacked == [["2026-11-17", "closed", 2], ["2026-11-18", "open", 1]]
    # A time range by its two ends.
    exact = run(time_field="created", time_range_={"from": "2026-11-17T00:00:00Z", "to": "2026-11-18T00:00:00Z"})
    assert exact["total"] == 2


def test_a_measure_is_worked_out_from_a_number_or_from_the_time_between_two_dates(held):
    took = run(query="id:agg-* status:closed", measure="avg:duration(created,closed)")
    assert took["total"] == (7200 + 1800 + 28800) / 3 and took["rows"] == []
    assert run(query="id:agg-* status:closed", measure="median:duration(created,closed)")["total"] == 7200
    assert run(query="id:agg-* status:closed", measure="max:duration(created,closed)")["total"] == 28800
    p90 = run(query="id:agg-* status:closed", measure="p90:duration(created,closed)")["total"]
    assert 7200 < p90 < 28800
    # What has no end is not measured; "now" measures an age.
    assert run(measure="min:duration(created,closed)")["total"] == 1800
    assert run(query="id:agg-a", measure="avg:duration(created,now)")["total"] == 4 * 3600
    # A timer of the SLA is a number of seconds.
    timers = run(measure="avg:timeToAssign", group_by=["severity"])
    assert timers["total"] == 1400 and ["high", 600] in timers["rows"] and ["critical", None] in timers["rows"]
    assert run(measure="sum:timeToAssign")["total"] == 4200
    assert run(query="id:agg-* slaBreached:true")["total"] == 1


def test_the_period_before_is_counted_for_a_comparison(held):
    out = run(time_field="created", time_range_="2d", compare="previous")
    assert out["total"] == 3
    assert out["previous"] == {"total": 1, "range": {"from": "2026-11-14T12:00:00Z", "to": "2026-11-16T12:00:00Z"}}


def test_what_cannot_be_counted_is_refused_with_why(held):
    def refused(**wanted) -> str:
        with pytest.raises(QueryError) as caught:
            run(**wanted)
        assert caught.value.code == "bad_aggregate"
        return caught.value.message

    assert "not a field" in refused(group_by=["nothing"])
    assert "hour, day, week, month or year" in refused(group_by=["created@decade"])
    assert "not a date" in refused(group_by=["status@day"])
    assert "2 fields at most" in refused(group_by=["status", "severity", "owner"])
    assert "one group" in refused(group_by=["status", "status"])
    assert "A measure is" in refused(measure="mode:score")
    assert "not a number" in refused(measure="avg:name")
    assert "needs a field" in refused(measure="avg")
    assert "not a date" in refused(measure="avg:duration(name,closed)")
    assert "length of time" in refused(time_field="created", time_range_="soon")
    assert "needs a time range" in refused(compare="previous")
    assert "not a field" in refused(time_range_="7d")
    assert "searched, not counted" in refused(entity="artifacts", query="", group_by=["linked"])
    answer = held.post("/api/query/aggregate", json={"entity": "incidents", "groupBy": ["nothing"]})
    assert answer.status_code == 422 and answer.json()["query"]["code"] == "bad_aggregate"
    assert held.post("/api/query/aggregate", json={"entity": "incidents", "query": "status:nope"}).status_code == 422


def test_runs_approvals_and_tasks_are_counted_by_who_may_see_them(held):
    with SessionLocal() as db:
        db.add(
            Playbook(
                id="pb-agg",
                name="Agg playbook",
                created_at="2026-11-01T00:00:00+00:00",
                updated_at="2026-11-01T00:00:00+00:00",
            )
        )
        db.flush()
        for index, status in enumerate(("done", "failed", "failed")):
            db.add(
                Run(
                    id=f"run-agg-{index}",
                    playbook_id="pb-agg",
                    version=1,
                    status=status,
                    incident_id="agg-a",
                    started_at=f"2026-11-18T0{index}:00:00+00:00",
                    finished_at=f"2026-11-18T0{index}:00:30+00:00",
                    started_by="alice",
                    error="boom" if status == "failed" else None,
                )  # fmt: skip
            )
        db.flush()
        db.add(
            Approval(
                id="ap-agg",
                run_id="run-agg-0",
                step_id="s",
                question="Isolate?",
                status="waiting",
                asked_at="2026-11-18T10:00:00+00:00",
                asked_epoch=0,
            )  # fmt: skip
        )
        for index, status in enumerate(("open", "overdue", "done")):
            db.add(
                Task(
                    id=f"task-agg-{index}",
                    incident_id="agg-a",
                    title=f"Task {index}",
                    status=status,
                    assignee_user="alice",
                    created_at="2026-11-18T09:00:00+00:00",
                )  # fmt: skip
            )
        db.commit()
    by_status = run(entity="runs", query="playbook:agg", group_by=["playbook", "status"])
    assert by_status["rows"] == [["Agg playbook", "failed", 2], ["Agg playbook", "done", 1]]
    assert run(entity="runs", query="id:run-agg-*", measure="avg:duration(started,finished)")["total"] == 30
    assert run(entity="approvals", query="status:waiting", measure="max:duration(asked,now)")["total"] == 7200
    assert run(entity="approvals", query="playbook:agg")["total"] == 1
    assert run(entity="tasks", query="incident:agg-a", group_by=["status"])["rows"] == [
        ["done", 1], ["open", 1], ["overdue", 1],
    ]  # fmt: skip
    # The list behind a number: the rows, by their fields.
    listed = held.post("/api/query", json={"entity": "runs", "query": "status:failed id:run-agg-*"}).json()
    assert listed["total"] == 2
    assert [row["id"] for row in listed["items"]] == ["run-agg-2", "run-agg-1"]
    assert listed["items"][0]["playbook"] == "Agg playbook" and listed["items"][0]["error"] == "boom"
    tasks = held.post("/api/query", json={"entity": "tasks", "query": "status:overdue"}).json()
    assert [row["title"] for row in tasks["items"]] == ["Task 1"]
    # Someone who only reads counts incidents and tasks, not runs or approvals, and does not learn they exist.
    from app.main import app

    reader = make_key(held, label="r", roles=["viewer"])
    client = TestClient(app)
    assert client.post("/api/query/aggregate", json={"entity": "tasks"}, headers=reader).status_code == 200
    assert client.post("/api/query/aggregate", json={"entity": "runs"}, headers=reader).status_code == 403
    assert client.post("/api/query", json={"entity": "approvals"}, headers=reader).status_code == 403
    names = [item["entity"] for item in client.get("/api/query/schema", headers=reader).json()["entities"]]
    assert "tasks" in names and "runs" not in names and "approvals" not in names


def test_indicators_are_counted_from_the_rows_of_the_library(held):
    for value in ("198.51.100.7", "198.51.100.8", "evil.example"):
        added = held.post("/api/iocs", json={"items": [{"value": value, "tags": ["agg", "c2"]}]})
        assert added.status_code in (200, 201), added.text
    out = ask(held, entity="indicators", query="tag:agg", groupBy=["type"])
    assert out["total"] == 3 and out["rows"] == [["ip", 2], ["domain", 1]]
    # A value with several tags is counted under each; the total stays the indicators.
    tags = ask(held, entity="indicators", query="tag:agg", groupBy=["tags"])
    assert tags["rows"] == [["agg", 3], ["c2", 3]] and tags["total"] == 3

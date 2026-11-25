"""The playbook nodes that read host evidence (7.0): its files with their parse reports, and its records.

Records are made the way the app makes them, through ``parse.read`` with the worker's events written here
(see ``test_evidence_api``); the nodes are run by a playbook, as a script is given what they give.
"""

# ruff: noqa: F811 - the fixture ``env`` is imported, and each test names it as its argument
from __future__ import annotations

import itertools

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.automation import actions, evidence_actions
from app.core.db import SessionLocal
from app.core.models import EvidenceDetection, EvidenceRecord, Incident
from tests.test_automation_engine import steps
from tests.test_evidence_api import BASE, SOURCE, end, env, event, make_source  # noqa: F401 - env is a fixture
from tests.test_file_actions import act, chain, go

NODES = {"nik.list-evidence-files", "nik.get-evidence-records"}


_made = itertools.count(1)


def run_one(admin: TestClient, *nodes, incident: str = "ev-api", dry: bool = False) -> dict:
    name = f"Reads evidence {next(_made)}"
    return go(admin, chain(admin, name, *nodes), objectKind="incident", objectId=incident, dryRun=dry)


@pytest.fixture()
def held(env, admin):
    """Two files in the incident: 25 events (some are logons of one host, one is a detection), and a syslog."""
    rows = [
        event(
            number,
            host="WKS-A" if number % 2 else "WKS-B",
            event_id=4624 if number % 5 else 4688,
            summary=f"logon {number}" if number % 5 else f"process {number} started",
            data={"TargetUserName": f"user{number}", "IpAddress": "10.0.0.7", "Long": "x" * 900},
        )
        for number in range(1, 26)
    ]
    first = make_source(env, [SOURCE, *rows, {"t": "skip", "reason": "a bad record", "lost": 2}, end(25)], data=b"one")
    lines = [
        {
            "t": "r",
            "key": f"sys:{n}",
            "type": "line",
            "ts": BASE + n,
            "seq": n,
            "channel": "sshd",
            "summary": f"Failed password {n}",
            "data": {},
            "loc": {"line": n},
            "trunc": False,
        }
        for n in range(3)
    ]
    second = make_source(
        env,
        [{"t": "source", "parser": "syslog", "version": "2", "kind": "syslog", "source": "auth.log"}, *lines, end(3)],
        data=b"two",
        kind="syslog",
    )
    with SessionLocal() as db:
        found = db.scalar(select(EvidenceRecord).where(EvidenceRecord.key == "evtx:WKS-042:Security:5"))
        db.add(
            EvidenceDetection(
                incident_id="ev-api",
                record_id=found.id,
                rule_id="r-1",
                rule_title="Rule",
                rule_author="A",
                level=4,
                tags=[],
                records=[],
                created_at="2026-01-01T00:00:00Z",
            )
        )
        found.level = 4
        db.commit()
    return {"first": first, "second": second, "env": env}


def test_the_nodes_are_in_the_catalogue_and_change_nothing(admin: TestClient):
    found = {entry["id"]: entry for entry in admin.get("/api/automation/catalog").json()["nodes"]}
    assert NODES <= set(found)
    for name in NODES:
        assert found[name]["group"] == "Host evidence" and found[name]["changesOutside"] is False
        assert found[name]["description"] and all(item["description"] for item in found[name]["arguments"])
    assert [item["name"] for item in found["nik.get-evidence-records"]["arguments"]][:3] == ["incident", "kind", "type"]


def test_the_files_of_an_incident_come_with_their_counts_and_their_report(held, admin: TestClient):
    run = run_one(
        admin,
        act("all", "nik.list-evidence-files"),
        act("logs", "nik.list-evidence-files", kind="syslog"),
        act("bad", "nik.list-evidence-files", partial=True),
        act("other", "nik.list-evidence-files", incident="ev-other"),
    )
    assert run["status"] == "done", run["error"]
    out = {key: step["output"] for key, step in steps(run).items()}
    assert out["all"]["count"] == out["all"]["total"] == 2 and out["all"]["records"] == 28
    files = {item["kind"]: item for item in out["all"]["files"]}
    assert set(out["all"]["ids"]) == {held["first"], held["second"]} and files["eventlog"]["file"] == held["first"]
    log = files["eventlog"]
    assert (log["name"], log["state"], log["read"], log["kept"], log["read_count"], log["skipped"]) == (
        "Security.evtx",
        "done",
        "partial",
        25,
        25,
        2,
    )
    assert len(log["sha256"]) == 64 and log["host"] == "WKS-042" and log["seen"] is False
    assert log["report"]["reasons"] == [{"reason": "a bad record", "count": 1, "lost": 2}]
    assert log["report"]["ended"] is True and isinstance(log["report"]["seconds"], float)
    assert [item["file"] for item in out["logs"]["files"]] == [held["second"]] and out["logs"]["records"] == 3
    assert [item["file"] for item in out["bad"]["files"]] == [held["first"]]
    assert out["other"]["files"] == [] and out["other"]["count"] == 0
    # What a script is given of a file is the file's own, not its bytes: nothing of a record is in the list.
    assert "logon 1" not in str(out["all"])


def test_records_are_read_by_the_filters_of_the_api_and_paged_with_the_cursor(held, admin: TestClient):
    run = run_one(
        admin,
        act("page", "nik.get-evidence-records", limit=10),
        act("more", "nik.get-evidence-records", limit=10, cursor="{{ page.next }}"),
        act("host", "nik.get-evidence-records", host="WKS-A", kind="eventlog", limit=100),
        act("event", "nik.get-evidence-records", event_id="4688"),
        act("words", "nik.get-evidence-records", q="process 10"),
        act("rule", "nik.get-evidence-records", level=4),
        act("syslog", "nik.get-evidence-records", kind="syslog", order="-time"),
        act("file", "nik.get-evidence-records", file=held["second"], order="file"),
        act("window", "nik.get-evidence-records", **{"from": BASE + 2000, "to": "2023-11-14T22:13:25Z"}),
    )
    assert run["status"] == "done", run["error"] or steps(run)
    out = {key: step["output"] for key, step in steps(run).items()}
    page, more = out["page"], out["more"]
    assert page["returned"] == 10 and page["count"] == 28 and page["count_capped"] is False and page["next"]
    # The count is made on the first page only; the next is another page, with no overlap.
    assert more["count"] is None and more["returned"] == 10
    assert not {item["key"] for item in page["records"]} & {item["key"] for item in more["records"]}
    assert all(item["host"] == "WKS-A" for item in out["host"]["records"]) and out["host"]["count"] == 13
    assert out["event"]["count"] == 5 and all(item["event_id"] == 4688 for item in out["event"]["records"])
    assert out["words"]["count"] == 1 and out["words"]["records"][0]["summary"] == "process 10 started"
    assert [item["key"] for item in out["rule"]["records"]] == ["evtx:WKS-042:Security:5"]
    assert out["rule"]["records"][0]["level"] == 4
    assert [item["summary"] for item in out["syslog"]["records"]] == [
        "Failed password 2",
        "Failed password 1",
        "Failed password 0",
    ]
    assert [item["seq"] for item in out["file"]["records"]] == [0, 1, 2] and out["file"]["next"] == ""
    assert {item["file"] for item in out["file"]["records"]} == {held["second"]}
    # The records are light: no data unless it was asked for.
    assert page["records"][0]["data"] == {} and "level" in page["records"][0]
    assert out["window"]["returned"] == 0 or all(2000 <= item["ts"] - BASE for item in out["window"]["records"])


def test_the_keys_of_data_asked_for_come_cut_and_not_more_than_twelve(held, admin: TestClient):
    run = run_one(
        admin, act("data", "nik.get-evidence-records", limit=2, kind="eventlog", fields="TargetUserName, Long, Absent")
    )
    assert run["status"] == "done", run["error"]
    first = steps(run)["data"]["output"]["records"][0]
    assert (
        first["data"]["TargetUserName"] == "user1"
        and len(first["data"]["Long"]) == 500
        and "Absent" not in first["data"]
    )
    too_many = run_one(admin, act("data", "nik.get-evidence-records", fields=",".join(f"k{n}" for n in range(13))))
    assert too_many["status"] == "failed" and steps(too_many)["data"]["error"] == "fields is 12 keys at most"


@pytest.mark.parametrize(
    ("args", "says"),
    [
        ({"limit": 501}, "limit is 1 to 500"),
        ({"limit": "many"}, "limit is a whole number"),
        ({"level": 9}, "level is 1 to 5"),
        ({"cursor": "not-a-cursor"}, "The cursor is not one this list gave"),
        ({"order": "file"}, "The order file needs a sourceId"),
        ({"from": "yesterday"}, "from is ms since the epoch"),
    ],
)
def test_what_cannot_be_asked_is_refused_with_a_sentence(held, admin: TestClient, args, says):
    run = run_one(admin, act("bad", "nik.get-evidence-records", **args))
    assert run["status"] == "failed" and steps(run)["bad"]["error"].startswith(says), steps(run)["bad"]["error"]


def test_no_incident_a_missing_one_and_an_archived_one_are_said(held, admin: TestClient):
    nobody = go(admin, chain(admin, "No incident given", act("x", "nik.get-evidence-records")))
    assert steps(nobody)["x"]["error"] == "No incident was given"
    gone = run_one(admin, act("x", "nik.list-evidence-files", incident="nope"))
    assert steps(gone)["x"]["error"] == "The incident does not exist"
    with SessionLocal() as db:
        db.get(Incident, "ev-api").archived_at = "2026-11-01T00:00:00Z"
        db.commit()
    archived = run_one(admin, act("x", "nik.get-evidence-records", incident="ev-api"), incident="ev-other", dry=True)
    assert steps(archived)["x"]["error"].startswith("The incident is archived: its records are not loaded")
    # Its files are still listed: their reports stay.
    listed = run_one(admin, act("y", "nik.list-evidence-files", incident="ev-api"), incident="ev-other", dry=True)
    assert steps(listed)["y"]["output"]["count"] == 2


def test_a_dry_run_reads_too(held, admin: TestClient):
    run = run_one(admin, act("x", "nik.get-evidence-records", limit=3), act("y", "nik.list-evidence-files"), dry=True)
    assert run["status"] == "done", run["error"]
    assert steps(run)["x"]["output"]["returned"] == 3 and steps(run)["y"]["output"]["count"] == 2


def test_every_path_the_editor_offers_is_there_when_a_playbook_runs(held, admin: TestClient):
    entries = {entry["id"]: entry for entry in admin.get("/api/automation/catalog").json()["nodes"]}
    nodes = [
        act("files", "nik.list-evidence-files"),
        act("recs", "nik.get-evidence-records", limit=3, fields="TargetUserName"),
    ]
    wanted = []
    for item in nodes:
        for output in entries[item["config"]["action"]]["outputs"]:
            wanted.append(f"{item['id']}.{output['name']}")
            for shape in output.get("shape") or []:
                joint = "" if shape["name"].startswith("[") else "."
                wanted.append(f"{item['id']}.{output['name']}{joint}{shape['name']}")
    assert "files.files[0].report.reasons" in wanted and "recs.records[0].summary" in wanted
    reading = act("reads", "nik.add-note", text=" ".join(f"{{{{ {path} | json }}}}" for path in wanted))
    run = run_one(admin, *nodes, reading)
    assert run["status"] == "done", run["error"] or steps(run)
    for spec in actions.all_specs():
        for output in spec.outputs if spec.group == evidence_actions.GROUP else ():
            shape = output.get("shape")
            assert shape is None or all(set(item) == {"name", "type", "description"} for item in shape), spec.id


def test_what_is_read_carries_the_classes_of_internal_names_and_does_not_leave(held, admin: TestClient):
    nodes = [
        act("read", "nik.get-evidence-records", limit=1),
        act("send", "http.request", url="https://example.org/x", query={"summary": "{{ read.records[0].summary }}"}),
    ]
    run = run_one(admin, *nodes)
    assert run["status"] == "failed" and steps(run)["send"]["error"].startswith("Held back: ")
    assert "private_value" in steps(run)["send"]["request"]["held"]["held"]

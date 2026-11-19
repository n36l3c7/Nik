"""The Playground (5.3): commands outside any incident, each person's own."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.automation import worker
from app.main import app as fastapi_app
from tests.conftest import make_key
from tests.test_automation_engine import CALLS, test_actions  # noqa: F401 - test_actions is a fixture

URL = "/api/playground"


def test_a_command_runs_with_no_incident_and_its_result_is_under_it(admin: TestClient, test_actions):  # noqa: F811
    assert admin.get(URL).json() == {"entries": []}
    sent = admin.post(f"{URL}/command", json={"line": '!test-echo text="hello there"'})
    assert sent.status_code == 201, sent.text
    command = sent.json()
    assert command["kind"] == "command" and command["body"]["line"] == '!test-echo text="hello there"'
    worker.drain()
    assert CALLS[-1]["text"] == "hello there"

    entries = admin.get(URL).json()["entries"]
    assert [entry["kind"] for entry in entries] == ["command", "result"]
    result = entries[1]
    assert result["parentId"] == command["id"] and result["runId"] == command["runId"]
    detail = admin.get(f"{URL}/{result['id']}").json()
    assert detail["step"]["output"]["text"] == "hello there" and detail["step"]["status"] == "done"
    # The run is a run like any other, of nothing: no incident was touched.
    run = admin.get(f"/api/automation/runs/{command['runId']}").json()
    assert run["incidentId"] is None and run["status"] == "done"
    assert admin.get("/api/incidents").json()["incidents"] == []

    # What is not a command belongs to an incident; what is wrong with a line is said.
    for line, why in (
        ("Just a note", "The Playground runs commands"),
        ("/assign @admin", "The Playground runs commands"),
        ("!no-such-command", "There is no command called"),
        ("!test-echo colour=red", "is not an argument of this command"),
    ):
        refused = admin.post(f"{URL}/command", json={"line": line})
        assert refused.status_code == 400 and why in refused.json()["detail"], line
    audit = admin.get("/api/audit", params={"q": "action:playground.command"}).json()["entries"]
    assert len(audit) == 1 and "test-echo" in audit[0]["details"]


def test_a_command_that_needs_an_incident_says_so_and_a_failure_is_shown(admin: TestClient, test_actions):  # noqa: F811
    sent = admin.post(f"{URL}/command", json={"line": '!nik-add-note text="No incident here"'})
    assert sent.status_code == 201, sent.text
    worker.drain()
    entries = admin.get(URL).json()["entries"]
    assert entries[-1]["kind"] == "error" and entries[-1]["parentId"] == sent.json()["id"]
    assert entries[-1]["body"]["error"]


def test_a_playground_is_its_owners_and_is_cleared_by_them(admin: TestClient, test_actions):  # noqa: F811
    admin.post(f"{URL}/command", json={"line": "!test-echo text=mine"})
    worker.drain()
    runner = make_key(admin, label="runner", roles=["analyst", "playbooks"])
    viewer = make_key(admin, label="viewer", roles=["viewer"])
    mine = admin.get(URL).json()["entries"]
    with TestClient(fastapi_app) as other:
        assert other.get(URL, headers=viewer).status_code == 403
        assert other.post(f"{URL}/command", headers=viewer, json={"line": "!test-echo text=x"}).status_code == 403
        assert other.get(URL, headers=runner).json() == {"entries": []}
        assert other.get(f"{URL}/{mine[0]['id']}", headers=runner).status_code == 404
        theirs = other.post(f"{URL}/command", headers=runner, json={"line": "!test-echo text=theirs"})
        assert theirs.status_code == 201
        worker.drain()
        assert len(other.get(URL, headers=runner).json()["entries"]) == 2
        # Clearing is of one's own history only.
        assert other.delete(URL, headers=runner).status_code == 204
        assert other.get(URL, headers=runner).json() == {"entries": []}
    assert len(admin.get(URL).json()["entries"]) == 2
    assert admin.delete(URL).status_code == 204 and admin.get(URL).json() == {"entries": []}

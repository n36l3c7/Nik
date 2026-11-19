"""A branch of a playbook runs only in the debugger (6.3): nothing else that starts a run ever uses
the graph of a branch, and a debug run of one says which branch it was."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.automation import engine, worker
from app.core.db import SessionLocal
from app.core.models import AutomationSchedule, Playbook
from app.main import app as fastapi_app
from tests.conftest import make_key
from tests.test_automation_engine import (  # noqa: F401 - test_actions is the fixture that registers the test actions
    CALLS,
    T0,
    echo,
    edge,
    go,
    incident,
    node,
    playbook,
    run_of,
    runs_of,
    steps,
    test_actions,
)
from tests.test_debugger import at, debug, tell

BASE = "/api/automation"

# A branch whose trigger asks for everything: an event, a schedule, a request from outside, a hand.
EVERY_WAY = {"manual": True, "event": "incident.created", "cron": "*/5 * * * *", "timezone": "UTC", "webhook": True}


def loud(text: str = "the branch") -> dict:
    return {"nodes": [node("start", "trigger", **EVERY_WAY), echo("a", text)], "edges": [edge("start", "a")]}


def quiet(admin: TestClient, name: str = "Quiet") -> tuple[str, dict]:
    """A playbook that is on and runs by hand only, with a branch that asks to be started in every way."""
    pb = playbook(admin, name, [echo("a", "main")], [edge("start", "a")], enabled=True)
    made = admin.post(f"{BASE}/playbooks/{pb}/branches", json={"name": "loud", "graph": loud()})
    assert made.status_code == 201, made.text
    return pb, made.json()


def said(admin: TestClient, playbook_id: str) -> list[tuple[str, str]]:
    """What started each run of the playbook, and what its node said."""
    return [
        (run["trigger"], steps(run_of(admin, run["id"]))["a"]["output"]["text"])
        for run in reversed(runs_of(admin, playbook_id))
    ]


def test_nothing_but_the_debugger_starts_a_branch(admin: TestClient):
    pb, branch = quiet(admin)
    url = f"{BASE}/playbooks/{pb}"

    # By hand: the version in use runs; naming the branch is refused, as a dry run too.
    assert steps(go(admin, pb))["a"]["output"]["text"] == "main"
    for body in ({"branch": branch["id"]}, {"branch": branch["id"], "dryRun": True}):
        refused = admin.post(f"{url}/run", json=body)
        assert refused.status_code == 400 and "only in the debugger" in refused.json()["detail"]

    # Turned on: what is on is main. The schedule drawn on the branch is no schedule.
    refused = admin.put(f"{url}/enabled", json={"enabled": True, "branch": branch["id"]})
    assert refused.status_code == 400 and "only in the debugger" in refused.json()["detail"]
    admin.put(f"{url}/enabled", json={"enabled": False})
    assert admin.put(f"{url}/enabled", json={"enabled": True}).json()["enabled"] is True
    with SessionLocal() as db:
        assert db.scalars(select(AutomationSchedule)).all() == []
    worker.drain(T0 + 3600)

    # The event the branch waits for, and the address a request from outside would use.
    incident(admin, "i-quiet", severity="high")
    worker.drain()
    token = admin.post(f"{url}/hook").json()["token"]
    with TestClient(fastapi_app) as anyone:
        assert anyone.post(f"{BASE}/hooks/{token}", json={}).status_code == 404

    # Another playbook that runs this one runs its version in use.
    caller = playbook(admin, "Caller", [node("call", "playbook", playbook="Quiet")], [edge("start", "call")])
    assert go(admin, caller)["status"] == "done"

    assert said(admin, pb) == [("manual", "main"), ("playbook", "main")]
    assert all(run["branch"] is None for run in runs_of(admin, pb))

    # Saving the branch again changes none of that, and the engine itself gives a graph to a debug run only.
    admin.put(f"{url}/branches/{branch['id']}", json={"graph": loud("louder")})
    incident(admin, "i-quiet-2")
    worker.drain()
    assert len(runs_of(admin, pb)) == 2
    with SessionLocal() as db:
        for more in ({"shape": loud()}, {"branch": {"id": branch["id"], "name": "loud"}}):
            with pytest.raises(ValueError, match="Only a debug run"):
                engine.start_run(db, db.get(Playbook, pb), kind="manual", now=T0, **more)
        db.rollback()


def test_a_branch_is_debugged_as_it_was_saved_and_the_run_names_it(admin: TestClient):
    pb, branch = quiet(admin)
    url = f"{BASE}/playbooks/{pb}"

    run_id = debug(admin, pb, branch=branch["id"])
    run = run_of(admin, run_id)
    assert run["branch"] == {"id": branch["id"], "name": "loud"}
    assert (run["debug"]["branch"], run["debug"]["draft"], run["trigger"], run["dryRun"]) == (
        "loud",
        False,
        "debug",
        True,
    )
    assert run["graph"] == loud() and at(run) == ["a"] and CALLS == []
    # The branch is saved again and renamed meanwhile: the run goes on with what it was started with.
    admin.put(f"{url}/branches/{branch['id']}", json={"graph": loud("something else"), "name": "louder"})
    tell(admin, run_id, "step")
    run = run_of(admin, run_id)
    assert run["status"] == "done" and steps(run)["a"]["output"]["text"] == "the branch"
    assert run["branch"]["name"] == "loud"

    # Listed with the debug runs, under the name of its branch; counted nowhere else.
    (listed,) = admin.get(f"{BASE}/runs", params={"debug": True, "playbook": pb}).json()["runs"]
    assert listed["id"] == run_id and listed["branch"]["name"] == "loud"
    assert runs_of(admin, pb) == [] and admin.get(url).json()["week"]["total"] == 0
    # A debug run of main has no branch.
    assert run_of(admin, debug(admin, pb))["branch"] is None
    entries = admin.get("/api/audit", params={"q": "action:playbook.debug"}).json()["entries"]
    assert sum('the branch "loud"' in str(entry) for entry in entries) == 1


def test_a_branch_that_cannot_run_says_why_and_only_who_edits_debugs_one(admin: TestClient):
    pb, branch = quiet(admin)
    other, _theirs = quiet(admin, "Other")
    url = f"{BASE}/playbooks/{pb}"

    broken = {"nodes": [node("start", "trigger", manual=True), echo("a", "{{ nobody.text }}")], "edges": []}
    half = admin.post(f"{url}/branches", json={"name": "half", "graph": broken}).json()
    refused = admin.post(f"{url}/debug", json={"branch": half["id"]})
    assert refused.status_code == 400 and refused.json()["detail"]["message"] == "The branch cannot run yet"
    assert refused.json()["detail"]["problems"]

    assert admin.post(f"{url}/debug", json={"branch": branch["id"], "draft": True}).status_code == 400
    assert admin.post(f"{url}/debug", json={"branch": "nope"}).status_code == 404
    # A branch belongs to its playbook.
    assert admin.post(f"{BASE}/playbooks/{other}/debug", json={"branch": branch["id"]}).status_code == 404

    builder = make_key(admin, label="builder", roles=["playbooks", "analyst"])
    runner = make_key(admin, label="runner", roles=["analyst"])
    with TestClient(fastapi_app) as client:
        assert client.post(f"{url}/debug", headers=runner, json={"branch": branch["id"]}).status_code == 403
        # Who edits playbooks debugs anybody's branch: looking at it changes nothing in it.
        started = client.post(f"{url}/debug", headers=builder, json={"branch": branch["id"]})
        assert started.status_code == 201, started.text
        assert started.json()["branch"]["name"] == "loud" and started.json()["startedBy"] == "api:builder"

"""The debugger: a run that stops before its nodes and is told what to do next."""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.automation import debugger, engine, worker
from app.core.db import SessionLocal
from app.core.models import Run, RunStep
from app.main import app
from app.query import aggregate
from tests.conftest import make_key
from tests.test_automation_engine import (  # noqa: F401 - test_actions is the fixture that registers the test actions
    CALLS,
    T0,
    echo,
    edge,
    node,
    playbook,
    run_of,
    start,
    steps,
    test_actions,
)

BASE = "/api/automation"


def three(admin: TestClient, name: str = "Three", **settings) -> str:
    nodes = [echo("a", "one"), echo("b", "{{ a.text }} two"), echo("c", "{{ b.text }} three")]
    return playbook(admin, name, nodes, [edge("start", "a"), edge("a", "b"), edge("b", "c")], **settings)


def debug(client: TestClient, playbook_id: str, now: float = T0, headers=None, **body) -> str:
    res = client.post(f"{BASE}/playbooks/{playbook_id}/debug", json=body, headers=headers)
    assert res.status_code == 201, res.text
    run_id = res.json()["id"]
    with SessionLocal() as db:
        # The API uses the real clock: the run is re-dated to the clock of the test.
        run = db.get(Run, run_id)
        run.started_at, run.deadline = engine.iso(now), now + 86400
        for step in db.scalars(select(RunStep).where(RunStep.run_id == run_id, RunStep.status == "pending")):
            step.next_at = now
        db.commit()
    worker.drain(now)
    return run_id


def tell(
    client: TestClient, run_id: str, action: str, now: float = T0, expect: int = 200, headers=None, **body
) -> dict:
    res = client.post(f"{BASE}/runs/{run_id}/debug", json={"action": action, **body}, headers=headers)
    assert res.status_code == expect, res.text
    if expect == 200:
        with SessionLocal() as db:
            for step in db.scalars(select(RunStep).where(RunStep.run_id == run_id, RunStep.status == "pending")):
                step.next_at = now
            db.commit()
        worker.drain(now)
    return res.json()


def at(run: dict) -> list[str]:
    return [where["node"] for where in run["debug"]["at"]]


def test_a_debug_run_stops_before_each_node_and_goes_on_when_told(admin: TestClient):
    pb = three(admin)
    run_id = debug(admin, pb)
    run = run_of(admin, run_id)
    assert run["debug"]["stepMode"] and at(run) == ["a"] and run["status"] == "waiting" and run["dryRun"]
    assert run["trigger"] == "debug" and not run["debug"]["draft"]
    # Stopped before the node: nothing ran, and its step shows what it would be given.
    assert CALLS == []
    assert steps(run)["a"]["status"] == "waiting" and steps(run)["a"]["waiting"] == "debug"
    assert steps(run)["a"]["input"] == {"action": "test.echo", "args": {"text": "one", "extra": None}}
    # One node on: it runs, and the run stops before the next.
    tell(admin, run_id, "step")
    run = run_of(admin, run_id)
    assert steps(run)["a"]["status"] == "done" and at(run) == ["b"]
    assert steps(run)["b"]["input"]["args"]["text"] == "one two"
    assert run["debug"]["context"]["a"] == {"text": "one", "extra": None}
    # To the end: no breakpoint is left, so it finishes.
    tell(admin, run_id, "continue")
    run = run_of(admin, run_id)
    assert run["status"] == "done" and at(run) == [] and steps(run)["c"]["output"]["text"] == "one two three"
    assert tell(admin, run_id, "step", expect=409)["detail"] == "The run is over"


def test_a_breakpoint_stops_the_run_there_and_a_node_can_be_skipped(admin: TestClient):
    pb = three(admin)
    run_id = debug(admin, pb, stepMode=False, breakpoints=["b", "nothing", "start"])
    run = run_of(admin, run_id)
    assert run["debug"]["breakpoints"] == ["b"] and not run["debug"]["stepMode"]
    assert steps(run)["a"]["status"] == "done" and at(run) == ["b"]
    # Skipped: the node does nothing, what comes after goes on (and fails on what it does not find).
    tell(admin, run_id, "skip")
    run = run_of(admin, run_id)
    assert steps(run)["b"]["status"] == "skipped" and steps(run)["b"]["error"] == "Skipped by who debugs the run"
    assert at(run) == [] and steps(run)["c"]["status"] in ("done", "failed")
    assert [call["text"] for call in CALLS if call["action"] == "echo"][:1] == ["one"]
    # Breakpoints can be moved while the run is stopped.
    again = debug(admin, pb, stepMode=False, breakpoints=["a"])
    moved = tell(admin, again, "continue", breakpoints=["c"])
    assert moved["debug"]["breakpoints"] == ["c"]
    assert at(run_of(admin, again)) == ["c"]
    tell(admin, again, "stop")
    assert run_of(admin, again)["status"] == "stopped"


def test_the_inputs_of_a_node_and_what_later_nodes_read_can_be_changed(admin: TestClient):
    pb = three(admin)
    run_id = debug(admin, pb)
    # Other arguments for the node the run is stopped at.
    tell(admin, run_id, "step", overrides={"text": "typed"})
    run = run_of(admin, run_id)
    assert steps(run)["a"]["output"]["text"] == "typed" and steps(run)["a"]["input"]["args"]["text"] == "typed"
    # What a node gave, changed for those that come after.
    tell(admin, run_id, "step", contextPatch={"a": {"text": "patched"}})
    run = run_of(admin, run_id)
    assert steps(run)["b"]["output"]["text"] == "patched two"
    # A node that is over is run again, with other arguments; the run stays where it was stopped.
    first = next(step for step in run["steps"] if step["node"] == "a")
    tell(admin, run_id, "rerun", stepId=first["id"], overrides={"text": "again"})
    run = run_of(admin, run_id)
    assert [step["output"]["text"] for step in run["steps"] if step["node"] == "a"] == ["typed", "again"]
    assert run["debug"]["context"]["a"]["text"] == "again" and at(run) == ["c"]
    # What is not the output of a node of this run is not written.
    assert "is not changed" in tell(admin, run_id, "step", expect=400, contextPatch={"trigger": {}})["detail"]
    assert "does not hold yet" in tell(admin, run_id, "step", expect=400, contextPatch={"zzz": 1})["detail"].replace(
        "is not something this run holds yet", "does not hold yet"
    )
    assert tell(admin, run_id, "rerun", expect=409, stepId="nope")["detail"].startswith("Choose a node")
    # Breakpoints and the context are changed without moving the run.
    kept = tell(admin, run_id, "set", breakpoints=["c", "b"], contextPatch={"b": {"text": "set"}})
    assert kept["debug"]["breakpoints"] == ["c", "b"] and [where["node"] for where in kept["debug"]["at"]] == ["c"]
    assert kept["debug"]["context"]["b"] == {"text": "set"}
    assert at(run_of(admin, run_id)) == ["c"]  # a refusal changed nothing


def test_what_goes_outside_is_held_unless_one_node_is_let_through(admin: TestClient):
    pb = playbook(
        admin,
        "Blocker",
        [node("block", "action", action="test.block", args={"host": "bad.example"}), echo("after", "done")],
        [edge("start", "block"), edge("block", "after")],
    )
    held = debug(admin, pb)
    tell(admin, held, "step")
    run = run_of(admin, held)
    # As in a dry run: the node shows what it would have sent, and nobody was asked.
    assert steps(run)["block"]["status"] == "done" and run["approvals"] == []
    assert all(call["dry"] for call in CALLS if call["action"] == "block")
    CALLS.clear()
    real = debug(admin, pb)
    tell(admin, real, "step", sendForReal=True)
    run = run_of(admin, real)
    # For real, this once: the approval the node normally needs is asked first.
    assert steps(run)["block"]["waiting"] == "approval" and len(run["approvals"]) == 1 and CALLS == []
    answered = admin.post(f"{BASE}/approvals/{run['approvals'][0]['id']}", json={"answer": "approved"})
    assert answered.status_code == 200, answered.text
    worker.drain(T0)
    run = run_of(admin, real)
    assert [(call["host"], call["dry"], call["by"]) for call in CALLS] == [("bad.example", False, "admin")]
    assert steps(run)["block"]["status"] == "done" and at(run) == ["after"]
    # The node after is held again: one node was let through, not the run.
    tell(admin, real, "continue")
    assert run_of(admin, real)["status"] == "done"
    audit = admin.get("/api/audit", params={"q": "action:playbook.debug*"}).json()["entries"]
    assert {entry["action"] for entry in audit} == {"playbook.debug", "playbook.debug.real"}
    # Sending for real needs the permission to run playbooks too.
    only_debug = make_key(admin, label="d", roles=["viewer"])
    assert (
        TestClient(app).post(f"{BASE}/runs/{real}/debug", json={"action": "step"}, headers=only_debug).status_code
        == 403
    )


def test_a_draft_is_debugged_without_saving_a_version(admin: TestClient):
    created = admin.post(f"{BASE}/playbooks", json={"name": "Drafted"}).json()
    shape = {"nodes": [node("start", "trigger", manual=True), echo("a", "draft")], "edges": [edge("start", "a")]}
    assert admin.put(f"{BASE}/playbooks/{created['id']}", json={"draft": shape}).status_code == 200
    assert admin.post(f"{BASE}/playbooks/{created['id']}/debug", json={}).status_code == 400  # no saved version
    run_id = debug(admin, created["id"], draft=True)
    run = run_of(admin, run_id)
    assert run["debug"]["draft"] and at(run) == ["a"] and [n["id"] for n in run["graph"]["nodes"]] == ["start", "a"]
    tell(admin, run_id, "continue")
    assert steps(run_of(admin, run_id))["a"]["output"]["text"] == "draft"
    # A draft that cannot run says why instead of starting.
    broken = {"nodes": [node("start", "trigger", manual=True), node("x", "action", action="nope.none")], "edges": []}
    assert admin.put(f"{BASE}/playbooks/{created['id']}", json={"draft": broken}).status_code == 200
    refused = admin.post(f"{BASE}/playbooks/{created['id']}/debug", json={"draft": True})
    assert refused.status_code == 400 and refused.json()["detail"]["problems"]
    saved = three(admin, "Saved")
    assert admin.post(f"{BASE}/playbooks/{saved}/debug", json={"draft": True}).status_code == 400  # no draft


def test_debug_runs_are_their_starters_and_count_for_nothing(admin: TestClient):
    pb = three(admin, "Counted", maxRunsPerHour=1)
    builder = make_key(admin, label="b", roles=["analyst", "playbooks"])
    other = make_key(admin, label="o", roles=["analyst", "playbooks"])
    client = TestClient(app)
    run_id = debug(client, pb, headers=builder)
    second = debug(client, pb, headers=builder)  # the limit of one run an hour is not theirs
    assert run_id != second
    # A real run still starts: the debug runs did not use the hour up.
    real = start(admin, pb)
    worker.drain(T0)
    assert run_of(admin, real)["status"] == "done"
    # Listed apart, to who started them and to an admin.
    listed = admin.get(f"{BASE}/runs").json()
    assert [row["id"] for row in listed["runs"]] == [real] and listed["total"] == 1
    mine = client.get(f"{BASE}/runs", params={"debug": True}, headers=builder).json()
    assert {row["id"] for row in mine["runs"]} == {run_id, second} and all(row["debug"] for row in mine["runs"])
    assert client.get(f"{BASE}/runs", params={"debug": True}, headers=other).json()["runs"] == []
    assert len(admin.get(f"{BASE}/runs", params={"debug": True}).json()["runs"]) == 2
    assert client.get(f"{BASE}/runs/{run_id}", headers=other).status_code == 404
    assert client.post(f"{BASE}/runs/{run_id}/debug", json={"action": "stop"}, headers=other).status_code == 404
    assert admin.get(f"{BASE}/runs/{run_id}").status_code == 200
    # Not in the numbers of the playbook, of a dashboard, or of the incident.
    summary = next(row for row in admin.get(f"{BASE}/playbooks").json()["playbooks"] if row["id"] == pb)
    assert summary["lastRun"]["id"] == real
    with SessionLocal() as db:
        assert aggregate.run(db, "runs", "playbook:Counted")["total"] == 1
        # After a week they are deleted, stopped or not.
        assert debugger.prune(db, T0) == 0
        for run in db.scalars(select(Run).where(Run.debug.is_(True))):
            run.started_at = engine.iso(T0 - 8 * 86400)
        db.commit()
        assert debugger.prune(db, T0) == 2
        db.commit()
        assert db.scalars(select(Run.id)).all() == [real]
        assert db.scalars(select(RunStep.run_id).distinct()).all() == [real]

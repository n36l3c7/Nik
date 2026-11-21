"""The automation engine: how a run walks a graph, fails, waits, and is started."""

# ruff: noqa: E501 (graphs of test playbooks read better on one line)

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.automation import actions, engine, state, triggers, worker
from app.core.db import SessionLocal
from app.core.models import Approval, AutomationEvent, AutomationSchedule, Playbook, Run, RunStep
from app.main import app as fastapi_app
from tests.conftest import make_key

T0 = 1_800_000_000.0  # a fixed clock: the tests move it themselves


# --------------------------------------------------------------------------- #
# Actions of the tests                                                        #
# --------------------------------------------------------------------------- #
CALLS: list[dict] = []
FAILURES: dict[str, int] = {}


@pytest.fixture(autouse=True)
def test_actions():
    CALLS.clear()
    FAILURES.clear()

    @actions.action(
        "test.echo",
        group="Test",
        name="Echo",
        arguments=[{"name": "text", "type": "text", "required": True}, {"name": "extra", "type": "any"}],
        outputs=[{"name": "text", "type": "text"}],
    )
    def echo(call: actions.Call) -> actions.Result:
        CALLS.append({"action": "echo", **call.args, "dry": call.dry_run, "by": call.approved_by})
        return actions.Result(output={"text": call.args["text"], "extra": call.args.get("extra")})

    @actions.action(
        "test.flaky", group="Test", name="Flaky", arguments=[{"name": "key", "type": "text", "required": True}]
    )
    def flaky(call: actions.Call) -> actions.Result:
        left = FAILURES.get(call.args["key"], 0)
        CALLS.append({"action": "flaky", "key": call.args["key"]})
        if left:
            FAILURES[call.args["key"]] = left - 1
            raise actions.ActionError("The service did not answer")
        return actions.Result(output={"ok": True})

    @actions.action("test.never", group="Test", name="Never", arguments=[])
    def never(call: actions.Call) -> actions.Result:
        raise actions.ActionError("Refused by the other side", retry=False)

    @actions.action(
        "test.block",
        group="Test",
        name="Block a host",
        arguments=[{"name": "host", "type": "text", "required": True}],
        changes_outside=True,
        idempotent=False,
    )
    def block(call: actions.Call) -> actions.Result:
        CALLS.append({"action": "block", "host": call.args["host"], "by": call.approved_by, "dry": call.dry_run})
        if call.args["host"] == "lost":
            raise actions.ActionError("No answer", unknown_outcome=True)
        return actions.Result(output={"blocked": call.args["host"]}, request={"method": "POST", "host": "fw.corp"})

    yield
    for name in ("test.echo", "test.flaky", "test.never", "test.block"):
        actions.unregister(name)


# --------------------------------------------------------------------------- #
# Building playbooks                                                          #
# --------------------------------------------------------------------------- #
def node(node_id, kind, **config):
    return {"id": node_id, "kind": kind, "name": node_id, "config": config}


def edge(source, target, port=None):
    return {"from": source, "to": target, **({"port": port} if port else {})}


def echo(node_id, text, **config):
    return node(node_id, "action", action="test.echo", args={"text": text}, **config)


def playbook(admin: TestClient, name: str, nodes, edges, trigger=None, enabled=False, **settings) -> str:
    """Create a playbook, save a version of the graph and return its id."""
    created = admin.post("/api/automation/playbooks", json={"name": name})
    assert created.status_code == 201, created.text
    playbook_id = created.json()["id"]
    if settings:
        assert admin.put(f"/api/automation/playbooks/{playbook_id}", json=settings).status_code == 200
    shape = {"nodes": [node("start", "trigger", **(trigger or {"manual": True})), *nodes], "edges": edges}
    saved = admin.post(f"/api/automation/playbooks/{playbook_id}/versions", json={"graph": shape})
    assert saved.status_code == 201, saved.text
    if enabled:
        assert admin.put(f"/api/automation/playbooks/{playbook_id}/enabled", json={"enabled": True}).status_code == 200
    return playbook_id


def start(admin: TestClient, playbook_id: str, now: float = T0, **body) -> str:
    """Start a run by hand at ``now`` (the API uses the real clock: the run is re-dated)."""
    res = admin.post(f"/api/automation/playbooks/{playbook_id}/run", json=body)
    assert res.status_code == 201, res.text
    run_id = res.json()["id"]
    with SessionLocal() as db:
        run = db.get(Run, run_id)
        run.deadline = now + db.get(Playbook, run.playbook_id).max_seconds
        for step in db.scalars(select(RunStep).where(RunStep.run_id == run_id, RunStep.status == "pending")):
            step.next_at = now
        db.commit()
    return run_id


def run_of(admin: TestClient, run_id: str) -> dict:
    res = admin.get(f"/api/automation/runs/{run_id}")
    assert res.status_code == 200, res.text
    return res.json()


def steps(run: dict) -> dict[str, dict]:
    """node id → its step (the last one when a node ran more than once)."""
    return {step["node"]: step for step in run["steps"]}


def go(admin: TestClient, playbook_id: str, now: float = T0, **body) -> dict:
    run_id = start(admin, playbook_id, now, **body)
    worker.drain(now)
    return run_of(admin, run_id)


# --------------------------------------------------------------------------- #
# Walking a graph                                                             #
# --------------------------------------------------------------------------- #
def test_a_run_goes_step_by_step_and_each_reads_what_ran_before(admin: TestClient):
    pb = playbook(
        admin,
        "Linear",
        [
            echo("a", "hello {{ trigger.actor }}"),
            echo("b", "{{ a.text | upper }} / {{ run.playbook }} / {{ inputs.why }}"),
        ],
        [edge("start", "a"), edge("a", "b")],
    )
    run = go(admin, pb, inputs={"why": "test"})
    assert run["status"] == "done" and run["error"] is None and run["finishedAt"]
    assert [(s["node"], s["status"], s["port"]) for s in run["steps"]] == [
        ("start", "done", "out"),
        ("a", "done", "out"),
        ("b", "done", "out"),
    ]
    assert steps(run)["b"]["output"]["text"] == "HELLO ADMIN / Linear / test"
    assert steps(run)["a"]["input"] == {"action": "test.echo", "args": {"text": "hello admin", "extra": None}}
    assert run["trigger"] == "manual" and run["startedBy"] == "admin" and run["version"] == 1


def test_a_branch_not_taken_is_dead_and_does_not_hold_the_node_where_branches_meet(admin: TestClient):
    nodes = [
        node("check", "condition", all=[{"left": "{{ inputs.n }}", "op": "gte", "right": 5}]),
        echo("big", "big"),
        echo("small", "small"),
        echo("deeper", "after small"),
        echo("join", "joined"),
    ]
    edges = [
        edge("start", "check"),
        edge("check", "big", "yes"),
        edge("check", "small", "no"),
        edge("small", "deeper"),
        edge("big", "join"),
        edge("deeper", "join"),
    ]
    pb = playbook(admin, "Branches", nodes, edges)
    run = go(admin, pb, inputs={"n": 7})
    assert run["status"] == "done"
    assert sorted(steps(run)) == ["big", "check", "join", "start"]  # small and deeper never ran
    assert steps(run)["check"]["output"] == {"result": True} and steps(run)["check"]["port"] == "yes"
    run = go(admin, pb, inputs={"n": 1})
    assert sorted(steps(run)) == ["check", "deeper", "join", "small", "start"]
    assert [call["text"] for call in CALLS] == ["big", "joined", "small", "after small", "joined"]


def test_two_branches_run_and_the_node_after_them_waits_for_both(admin: TestClient):
    nodes = [echo("left", "L"), echo("right", "R"), echo("join", "{{ start.actor }}")]
    edges = [edge("start", "left"), edge("start", "right"), edge("left", "join"), edge("right", "join")]
    pb = playbook(admin, "Parallel", nodes, edges)
    run_id = start(admin, pb)
    worker.tick(T0)  # left and right
    assert sorted(steps(run_of(admin, run_id))) == ["join", "left", "right", "start"]
    assert steps(run_of(admin, run_id))["join"]["status"] == "pending"
    worker.drain(T0)
    run = run_of(admin, run_id)
    assert run["status"] == "done" and [s["node"] for s in run["steps"]].count("join") == 1


def test_an_end_node_finishes_the_run_and_what_was_left_is_skipped(admin: TestClient):
    nodes = [
        echo("a", "a"),
        node("stop", "end", status="failed", message="not for {{ trigger.actor }}"),
        echo("b", "b"),
    ]
    pb = playbook(admin, "Ends", nodes, [edge("start", "stop"), edge("start", "a"), edge("a", "b")])
    run = go(admin, pb)
    assert run["status"] == "failed" and run["error"] == "not for admin"
    assert steps(run)["a"]["status"] == "skipped" and "b" not in steps(run) and CALLS == []
    done = playbook(admin, "Ends well", [node("stop", "end", status="done", message="fine")], [edge("start", "stop")])
    assert go(admin, done)["status"] == "done"


# --------------------------------------------------------------------------- #
# Failing                                                                     #
# --------------------------------------------------------------------------- #
def test_a_failure_is_tried_again_with_growing_waits_then_follows_the_error_line(admin: TestClient):
    nodes = [
        node("call", "action", action="test.flaky", args={"key": "k"}, on_error={"mode": "retry", "times": 2}),
        echo("ok", "ok"),
        echo("handled", "failed with: {{ call.error }}"),
    ]
    pb = playbook(
        admin, "Retries", nodes, [edge("start", "call"), edge("call", "ok"), edge("call", "handled", "error")]
    )

    # Two failures, then it works: three tries, with waits in between.
    FAILURES["k"] = 2
    run_id = start(admin, pb)
    worker.drain(T0)
    step = steps(run_of(admin, run_id))["call"]
    assert step["status"] == "pending" and step["attempt"] == 1 and step["error"] == "The service did not answer"
    assert 4 <= step["nextAt"] - T0 <= 6  # 5 s, give or take the noise
    worker.drain(T0 + 3)
    assert steps(run_of(admin, run_id))["call"]["attempt"] == 1  # not due yet
    worker.drain(T0 + 7)
    step = steps(run_of(admin, run_id))["call"]
    assert step["attempt"] == 2 and 12 <= step["nextAt"] - (T0 + 7) <= 18  # 15 s
    worker.drain(T0 + 30)
    run = run_of(admin, run_id)
    assert run["status"] == "done" and steps(run)["call"]["attempt"] == 3 and "ok" in steps(run)

    # Fails every time: after the last try, the error line.
    FAILURES["k"] = 99
    run_id = start(admin, pb)
    for later in (0, 10, 40, 200):
        worker.drain(T0 + later)
    run = run_of(admin, run_id)
    assert (
        run["status"] == "done" and steps(run)["call"]["status"] == "failed" and steps(run)["call"]["port"] == "error"
    )
    assert steps(run)["handled"]["output"]["text"] == "failed with: The service did not answer"
    assert "ok" not in steps(run)
    assert engine.backoff(1) <= 6 and 12 <= engine.backoff(2) <= 18 and engine.backoff(30) <= 900 * 1.2


def test_a_failure_nobody_handles_fails_the_run(admin: TestClient):
    pb = playbook(
        admin,
        "Fails",
        [node("call", "action", action="test.never"), echo("after", "x")],
        [edge("start", "call"), edge("call", "after")],
    )
    run = go(admin, pb)
    assert run["status"] == "failed" and run["error"] == "call: Refused by the other side"
    assert steps(run)["call"]["attempt"] == 1 and "after" not in steps(run)
    # What cannot work is not tried again, whatever the node says.
    again = playbook(
        admin, "Fails twice",
        [node("call", "action", action="test.never", on_error={"mode": "retry", "times": 5})], [edge("start", "call")],
    )  # fmt: skip
    assert steps(go(admin, again))["call"]["attempt"] == 1
    # An expression that leads nowhere is a failure of the step, said in a sentence.
    bad = playbook(admin, "Bad path", [echo("a", "{{ trigger.nothing.here }}")], [edge("start", "a")])
    assert go(admin, bad)["error"].startswith("a: There is nothing at trigger.nothing.here")


def test_an_outside_change_with_no_answer_is_not_tried_again(admin: TestClient):
    nodes = [
        node(
            "block",
            "action",
            action="test.block",
            args={"host": "lost"},
            on_error={"mode": "retry", "times": 5},
            approval={"ask": False},
        )
    ]
    run = go(admin, playbook(admin, "Unknown outcome", nodes, [edge("start", "block")]))
    assert run["status"] == "failed" and steps(run)["block"]["attempt"] == 1
    assert run["error"] == "block: No answer (outcome unknown: it is not tried again)"


# --------------------------------------------------------------------------- #
# For each                                                                    #
# --------------------------------------------------------------------------- #
def loop_playbook(admin, name, body_config=None, **loop_config):
    nodes = [
        node("loop", "for_each", items="{{ inputs.items }}", **loop_config),
        node(
            "one", "action", **(body_config or {"action": "test.echo", "args": {"text": "{{ index }}:{{ item.name }}"}})
        ),
        echo("two", "{{ one.text | default('-') }}!"),
        echo("after", "{{ loop.count }} items, {{ loop.failed }} failed"),
        echo("handled", "loop failed"),
    ]
    edges = [
        edge("start", "loop"),
        edge("loop", "one", "each"),
        edge("one", "two"),
        edge("loop", "after", "done"),
        edge("loop", "handled", "error"),
    ]
    return playbook(admin, name, nodes, edges)


def test_for_each_runs_its_body_once_per_item_each_with_its_own_results(admin: TestClient):
    pb = loop_playbook(admin, "Loop")
    items = [{"name": f"n{i}"} for i in range(12)]
    run = go(admin, pb, inputs={"items": items})
    assert run["status"] == "done"
    loop = steps(run)["loop"]["output"]
    assert loop["count"] == 12 and loop["failed"] == 0
    # In order, whatever order the items finished in.
    assert [r["two"]["text"] for r in loop["results"]] == [f"{i}:n{i}!" for i in range(12)]
    assert steps(run)["after"]["output"]["text"] == "12 items, 0 failed"
    assert sum(1 for s in run["steps"] if s["node"] == "one") == 12
    assert sorted(s["itemIndex"] for s in run["steps"] if s["node"] == "two") == list(range(12))

    # Five at a time.
    run_id = start(admin, pb, inputs={"items": items})
    worker.tick(T0)  # the loop node
    assert sum(1 for s in run_of(admin, run_id)["steps"] if s["node"] == "one") == 5

    # Nothing to go through: straight to "done".
    empty = go(admin, pb, inputs={"items": []})
    assert steps(empty)["loop"]["output"] == {"count": 0, "failed": 0, "results": []} and "one" not in steps(empty)


def test_for_each_has_a_ceiling_and_says_what_an_item_did_wrong(admin: TestClient):
    pb = loop_playbook(admin, "Loop small", max=3)
    run = go(admin, pb, inputs={"items": [1, 2, 3, 4]})
    assert steps(run)["loop"]["error"] == "4 items, more than the 3 this loop allows"
    assert steps(run)["handled"]["status"] == "done" and "after" not in steps(run)
    assert (
        steps(go(admin, pb, inputs={"items": "not a list"}))["loop"]["error"]
        == '"For each" needs a list: this is not one'
    )

    # An item fails: the loop fails with it…
    failing = loop_playbook(admin, "Loop fails", {"action": "test.flaky", "args": {"key": "{{ item }}"}})
    FAILURES["b"] = 1
    run = go(admin, failing, inputs={"items": ["a", "b", "c"]})
    assert (
        steps(run)["loop"]["status"] == "failed"
        and steps(run)["loop"]["error"] == "Item 2: one: The service did not answer"
    )
    assert steps(run)["handled"]["status"] == "done"
    # …unless it is told to go on.
    FAILURES["b"] = 1
    lenient = loop_playbook(
        admin, "Loop goes on", {"action": "test.flaky", "args": {"key": "{{ item }}"}}, continue_on_item_error=True
    )
    run = go(admin, lenient, inputs={"items": ["a", "b", "c"]})
    out = steps(run)["loop"]["output"]
    assert (out["count"], out["failed"]) == (3, 1) and out["results"][1] == {"error": "one: The service did not answer"}
    assert steps(run)["after"]["output"]["text"] == "3 items, 1 failed"


# --------------------------------------------------------------------------- #
# Waiting                                                                     #
# --------------------------------------------------------------------------- #
def test_a_wait_holds_the_run_until_its_time(admin: TestClient):
    pb = playbook(
        admin,
        "Waits",
        [node("pause", "wait", seconds=600), echo("after", "{{ pause.waited }}")],
        [edge("start", "pause"), edge("pause", "after")],
    )
    run_id = start(admin, pb)
    worker.drain(T0)
    run = run_of(admin, run_id)
    assert (
        run["status"] == "running"
        and steps(run)["pause"]["status"] == "waiting"
        and steps(run)["pause"]["waiting"] == "wait"
    )
    worker.drain(T0 + 599)
    assert "after" not in steps(run_of(admin, run_id))
    worker.drain(T0 + 601)
    run = run_of(admin, run_id)
    assert run["status"] == "done" and steps(run)["after"]["output"]["text"] == 601


def test_wait_until_asks_again_until_the_condition_holds_or_time_runs_out(admin: TestClient):
    nodes = [
        node(
            "ready", "wait",
            until={"all": [{"left": "{{ poll.text }}", "op": "eq", "right": "go"}]},
            poll={"action": "test.echo", "args": {"text": "{{ inputs.word }}"}}, every=60, timeout=300,
        ),
        echo("after", "{{ ready.timed_out }}"),
    ]  # fmt: skip
    pb = playbook(admin, "Until", nodes, [edge("start", "ready"), edge("ready", "after")])
    assert steps(go(admin, pb, inputs={"word": "go"}))["ready"]["output"] == {"waited": 0, "timed_out": False}
    run_id = start(admin, pb, inputs={"word": "no"})
    for later in (0, 61, 122, 250):
        worker.drain(T0 + later)
        assert steps(run_of(admin, run_id))["ready"]["status"] == "waiting"
    worker.drain(T0 + 320)
    run = run_of(admin, run_id)
    assert steps(run)["ready"]["output"]["timed_out"] is True and steps(run)["after"]["output"]["text"] is True


def approvals(admin: TestClient, run_id: str) -> list[Approval]:
    with SessionLocal() as db:
        return list(db.scalars(select(Approval).where(Approval.run_id == run_id).order_by(Approval.asked_at)))


def answer(approval_id: str, verdict: str, now: float, by: str = "anna", comment: str = "") -> bool:
    with SessionLocal() as db:
        done = engine.answer(db, db.get(Approval, approval_id), verdict, by, comment, now)
        db.commit()
        return done


def ask_playbook(admin, name, **config):
    nodes = [
        node("ask", "approval", question="Block {{ inputs.host }}?", detail={"host": "{{ inputs.host }}"}, **config),
        echo("yes", "approved by {{ ask.by }}: {{ ask.comment }}"),
        echo("no", "{{ ask.answer }}"),
    ]
    return playbook(
        admin, name, nodes, [edge("start", "ask"), edge("ask", "yes", "approved"), edge("ask", "no", "refused")]
    )


def test_an_approval_stops_the_run_until_a_person_answers(admin: TestClient):
    pb = ask_playbook(admin, "Asks")
    run_id = start(admin, pb, inputs={"host": "evil.example"})
    worker.drain(T0)
    run = run_of(admin, run_id)
    assert run["status"] == "waiting" and steps(run)["ask"]["status"] == "waiting"
    (asked,) = approvals(admin, run_id)
    assert (asked.question, asked.detail, asked.status, asked.expires_at) == (
        "Block evil.example?",
        {"host": "evil.example"},
        "waiting",
        None,  # without limit by default
    )
    worker.drain(T0 + 30 * 86400)  # a month later it still waits, and the run has not timed out
    assert run_of(admin, run_id)["status"] == "waiting"

    assert answer(asked.id, "approved", T0 + 30 * 86400 + 5, comment="go") is True
    assert answer(asked.id, "refused", T0 + 30 * 86400 + 6) is False  # answered already
    worker.drain(T0 + 30 * 86400 + 5)
    run = run_of(admin, run_id)
    assert run["status"] == "done" and steps(run)["yes"]["output"]["text"] == "approved by anna: go"
    assert steps(run)["ask"]["output"]["answer"] == "approved" and "no" not in steps(run)

    refused = start(admin, pb, inputs={"host": "x"})
    worker.drain(T0)
    answer(approvals(admin, refused)[0].id, "refused", T0 + 1)
    worker.drain(T0 + 1)
    assert steps(run_of(admin, refused))["no"]["output"]["text"] == "refused"


def test_an_approval_nobody_answers_is_never_an_approval(admin: TestClient):
    for on_expire, status, answered in (
        ("skip", "done", "expired"),
        ("refuse", "done", "expired"),
        ("stop", "stopped", None),
    ):
        pb = ask_playbook(admin, f"Expires {on_expire}", wait_seconds=3600, on_expire=on_expire)
        run_id = start(admin, pb, inputs={"host": "x"})
        worker.drain(T0)
        assert approvals(admin, run_id)[0].expires_at == T0 + 3600
        worker.drain(T0 + 3599)
        assert run_of(admin, run_id)["status"] == "waiting"
        worker.drain(T0 + 3601)
        worker.drain(T0 + 3601)
        run = run_of(admin, run_id)
        assert run["status"] == status, on_expire
        assert "yes" not in steps(run)
        if answered:
            assert steps(run)["no"]["output"]["text"] == answered
        assert approvals(admin, run_id)[0].status == "expired"


def test_a_change_outside_nik_asks_first_by_default(admin: TestClient):
    nodes = [
        node("block", "action", action="test.block", args={"host": "{{ inputs.host }}"}),
        echo("after", "{{ block.blocked | default('not blocked') }}"),
    ]
    pb = playbook(admin, "Blocks", nodes, [edge("start", "block"), edge("block", "after")])
    run_id = start(admin, pb, inputs={"host": "evil.example"})
    worker.drain(T0)
    (asked,) = approvals(admin, run_id)
    assert asked.question == "block: go ahead?" and asked.detail == {
        "action": "test.block",
        "args": {"host": "evil.example"},
    }
    assert CALLS == []  # nothing left before the answer
    answer(asked.id, "approved", T0 + 60, by="bob")
    worker.drain(T0 + 60)
    run = run_of(admin, run_id)
    blocks = [call for call in CALLS if call["action"] == "block"]
    assert run["status"] == "done" and blocks == [
        {"action": "block", "host": "evil.example", "by": "bob", "dry": False}
    ]
    assert steps(run)["block"]["request"] == {"method": "POST", "host": "fw.corp"}

    # Refused: the action does not run and the run stops there; it has not failed.
    refused = start(admin, pb, inputs={"host": "other"})
    worker.drain(T0)
    answer(approvals(admin, refused)[0].id, "refused", T0 + 1, by="bob")
    worker.drain(T0 + 1)
    run = run_of(admin, refused)
    assert run["status"] == "stopped" and steps(run)["block"]["error"] == "Refused by bob"
    assert sum(1 for call in CALLS if call["action"] == "block") == 1 and "after" not in steps(run)

    # The node can say not to ask; the playbook can say not to ask by default.
    direct = playbook(
        admin, "Blocks at once",
        [node("block", "action", action="test.block", args={"host": "h"}, approval={"ask": False})], [edge("start", "block")],
    )  # fmt: skip
    assert go(admin, direct)["status"] == "done" and CALLS[-1]["by"] is None
    trusted = playbook(
        admin,
        "Trusted",
        [node("block", "action", action="test.block", args={"host": "t"})],
        [edge("start", "block")],
        approvalDefault=False,
    )
    assert go(admin, trusted)["status"] == "done"
    # And an action that changes nothing outside can be made to ask.
    careful = playbook(
        admin,
        "Careful",
        [
            echo("a", "x", approval={"ask": True, "wait_seconds": 60, "on_expire": "skip"}),
            echo("b", "{{ a.skipped | default(false) }}"),
        ],
        [edge("start", "a"), edge("a", "b")],
    )
    run_id = start(admin, careful)
    worker.drain(T0)
    worker.drain(T0 + 61)
    worker.drain(T0 + 61)
    run = run_of(admin, run_id)
    assert (
        steps(run)["a"]["status"] == "skipped" and steps(run)["b"]["output"]["text"] is True
    )  # skipped, and it went on


def test_a_dry_run_asks_nobody_and_tells_the_actions_so(admin: TestClient):
    nodes = [
        node("ask", "approval", question="ok?"),
        node("block", "action", action="test.block", args={"host": "h"}),
    ]
    pb = playbook(
        admin,
        "Dry",
        nodes,
        [edge("start", "ask"), edge("ask", "block", "approved")],
        trigger={"event": "incident.created"},
    )
    run = go(admin, pb, dryRun=True)
    assert run["status"] == "done" and run["dryRun"] is True
    assert steps(run)["ask"]["output"]["by"] == "dry run" and CALLS == [
        {"action": "block", "host": "h", "by": None, "dry": True}
    ]
    # Not by hand for real: its trigger is an event.
    assert (
        admin.post(f"/api/automation/playbooks/{pb}/run", json={}).json()["detail"]
        == "This playbook is not meant to be run by hand"
    )


# --------------------------------------------------------------------------- #
# Stopping, deadlines, the switch, a restart                                  #
# --------------------------------------------------------------------------- #
def test_a_run_is_stopped_times_out_and_pauses_with_the_general_switch(admin: TestClient):
    pb = playbook(
        admin,
        "Long",
        [node("pause", "wait", seconds=3600), echo("after", "x")],
        [edge("start", "pause"), edge("pause", "after")],
        maxSeconds=7200,
    )
    run_id = start(admin, pb)
    worker.drain(T0)
    stopped = admin.post(f"/api/automation/runs/{run_id}/stop").json()
    assert stopped["status"] == "stopped" and stopped["error"] == "Stopped by admin"
    assert steps(run_of(admin, run_id))["pause"]["status"] == "skipped"
    worker.drain(T0 + 4000)
    assert "after" not in steps(run_of(admin, run_id))
    assert admin.post(f"/api/automation/runs/{run_id}/stop").json()["status"] == "stopped"  # again: nothing

    # Longer than the playbook allows.
    slow = playbook(admin, "Too long", [node("pause", "wait", seconds=3600)], [edge("start", "pause")], maxSeconds=600)
    run_id = start(admin, slow)
    worker.drain(T0)
    worker.drain(T0 + 601)
    run = run_of(admin, run_id)
    assert run["status"] == "failed" and run["error"] == "The run took longer than the playbook allows"

    # The general switch: nothing moves while it is off, and nothing is lost.
    run_id = start(admin, pb)
    assert admin.put("/api/automation/state", json={"enabled": False}).json()["enabled"] is False
    assert worker.drain(T0) == 0 and steps(run_of(admin, run_id))["pause"]["status"] == "pending"
    assert admin.post(f"/api/automation/playbooks/{pb}/run", json={}).status_code == 409
    admin.put("/api/automation/state", json={"enabled": True})
    worker.drain(T0)
    assert steps(run_of(admin, run_id))["pause"]["status"] == "waiting"
    actions_logged = [e["action"] for e in admin.get("/api/audit?q=action:automation.switch").json()["entries"]]
    assert actions_logged == ["automation.switch", "automation.switch"]


def test_the_time_spent_waiting_for_a_person_does_not_count(admin: TestClient):
    nodes = [node("ask", "approval", question="ok?"), node("pause", "wait", seconds=300)]
    pb = playbook(admin, "Patient", nodes, [edge("start", "ask"), edge("ask", "pause", "approved")], maxSeconds=600)
    run_id = start(admin, pb)
    worker.drain(T0)
    answer(approvals(admin, run_id)[0].id, "approved", T0 + 5000)  # long after the 600 s
    worker.drain(T0 + 5000)
    assert run_of(admin, run_id)["status"] == "running"
    worker.drain(T0 + 5301)
    assert run_of(admin, run_id)["status"] == "done"


def test_a_run_survives_the_worker_dying_in_the_middle_of_a_step(admin: TestClient):
    pb = playbook(admin, "Survives", [echo("a", "a"), echo("b", "b")], [edge("start", "a"), edge("a", "b")])
    run_id = start(admin, pb)
    with SessionLocal() as db:
        (claimed,) = worker.claim_steps(db, T0, 10, holder="a-worker-that-dies")
    step = steps(run_of(admin, run_id))["a"]
    assert step["status"] == "running" and CALLS == []
    # The worker that holds the lease is the only one there is: a step that is running under another
    # name lost its worker, and is taken back at once (until 6.9 it waited for the time of the step).
    worker.drain(T0 + 30)
    run = run_of(admin, run_id)
    assert run["status"] == "done" and [c["text"] for c in CALLS] == ["a", "b"]

    # A change outside whose worker died before the call began: nothing had left, so it is made, once.
    # (A worker that died after it began the call: tests/test_restarts_engine.py.)
    outside = playbook(
        admin,
        "Outside",
        [node("block", "action", action="test.block", args={"host": "h"}, approval={"ask": False})],
        [edge("start", "block")],
    )
    run_id = start(admin, outside)
    with SessionLocal() as db:
        worker.claim_steps(db, T0, 10, holder="a-worker-that-dies")
    worker.drain(T0 + 200)
    run = run_of(admin, run_id)
    assert run["status"] == "done" and [call["host"] for call in CALLS if call["action"] == "block"] == ["h"]

    # Two workers never both schedule: the second does not get the lease.
    with SessionLocal() as db:
        later = T0 + 10_000  # after the lease this test took for its own passes
        assert worker.acquire(db, "one", later) is True
        assert worker.acquire(db, "two", later + 1) is False
        assert worker.acquire(db, "two", later + worker.LEASE_SECONDS + 1) is True
        worker.release(db, "two")


def test_results_are_cut_and_carry_the_classes_of_what_went_in(admin: TestClient):
    pb = playbook(
        admin,
        "Big",
        [echo("a", "{{ inputs.big }}"), echo("b", "{{ a.text | length }}")],
        [edge("start", "a"), edge("a", "b")],
    )
    run = go(admin, pb, inputs={"big": "x" * (engine.MAX_OUTPUT + 10)})
    assert (
        steps(run)["a"]["output"]["truncated"] is True and run["status"] == "failed"
    )  # b reads what is no longer there

    classed = playbook(
        admin,
        "Classes",
        [echo("a", "to {{ trigger.actor }}"), echo("b", "{{ a.text }}")],
        [edge("start", "a"), edge("a", "b")],
    )
    run_id = start(admin, classed)
    worker.drain(T0)
    with SessionLocal() as db:
        held = db.get(Run, run_id).context_classes
    assert held["trigger"]["actor"] == ["private_value"]
    assert held["a"] == {"": ["private_value"]} and held["b"] == {"": ["private_value"]}  # it travels on


# --------------------------------------------------------------------------- #
# Playbooks that run playbooks                                                #
# --------------------------------------------------------------------------- #
def test_a_playbook_runs_another_and_reads_what_it_gives(admin: TestClient):
    child_nodes = [echo("work", "{{ inputs.word }} from {{ trigger.actor }}")]
    child = admin.post("/api/automation/playbooks", json={"name": "Child"}).json()["id"]
    shape = {
        "nodes": [node("start", "trigger", manual=True), *child_nodes],
        "edges": [edge("start", "work")],
        "inputs": [{"name": "word", "type": "text"}],
        "outputs": [{"name": "said", "from": "{{ work.text }}"}],
    }
    assert admin.post(f"/api/automation/playbooks/{child}/versions", json={"graph": shape}).status_code == 201
    parent = playbook(
        admin, "Parent",
        [node("call", "playbook", playbook="Child", args={"word": "hi"}), echo("after", "{{ call.result.said }}")],
        [edge("start", "call"), edge("call", "after")],
    )  # fmt: skip
    run = go(admin, parent)
    assert run["status"] == "done" and steps(run)["after"]["output"]["text"] == "hi from admin"
    runs = admin.get("/api/automation/runs").json()["runs"]
    child_run = next(r for r in runs if r["playbook"] == "Child")
    assert child_run["parentRunId"] == run["id"] and child_run["status"] == "done"

    # A child that fails fails the step that waits for it.
    bad = admin.post("/api/automation/playbooks", json={"name": "Bad child"}).json()["id"]
    shape = {
        "nodes": [node("start", "trigger", manual=True), node("x", "action", action="test.never")],
        "edges": [edge("start", "x")],
    }
    admin.post(f"/api/automation/playbooks/{bad}/versions", json={"graph": shape})
    caller = playbook(admin, "Calls bad", [node("call", "playbook", playbook="Bad child")], [edge("start", "call")])
    assert go(admin, caller)["error"] == "call: The playbook it ran ended failed"
    # Stopping the parent stops the child it waits for.
    slow = admin.post("/api/automation/playbooks", json={"name": "Slow child"}).json()["id"]
    shape = {
        "nodes": [node("start", "trigger", manual=True), node("p", "wait", seconds=600)],
        "edges": [edge("start", "p")],
    }
    admin.post(f"/api/automation/playbooks/{slow}/versions", json={"graph": shape})
    waits = playbook(admin, "Calls slow", [node("call", "playbook", playbook="Slow child")], [edge("start", "call")])
    run_id = start(admin, waits)
    worker.drain(T0)
    admin.post(f"/api/automation/runs/{run_id}/stop")
    statuses = {r["playbook"]: r["status"] for r in admin.get("/api/automation/runs").json()["runs"]}
    assert statuses["Calls slow"] == "stopped" and statuses["Slow child"] == "stopped"


# --------------------------------------------------------------------------- #
# Triggers                                                                    #
# --------------------------------------------------------------------------- #
def incident(admin: TestClient, incident_id: str, **fields) -> None:
    doc = {"id": incident_id, "name": incident_id, "data": {}, **fields}
    assert admin.post("/api/incidents", json=doc).status_code == 201


def runs_of(admin: TestClient, playbook_id: str) -> list[dict]:
    return admin.get(f"/api/automation/runs?playbook={playbook_id}").json()["runs"]


def test_an_incident_event_starts_the_playbooks_that_wait_for_it(admin: TestClient):
    high = {
        "event": "incident.created",
        "conditions": {"all": [{"left": "{{ trigger.incident.severity }}", "op": "in", "right": ["high", "critical"]}]},
    }
    pb = playbook(
        admin,
        "On high",
        [echo("a", "{{ trigger.incident.name }} is {{ start.incident.severity }}")],
        [edge("start", "a")],
        trigger=high,
        enabled=True,
    )
    off = playbook(admin, "Off", [echo("a", "x")], [edge("start", "a")], trigger={"event": "incident.created"})
    incident(admin, "i1", severity="high", host="WKS-1")
    incident(admin, "i2", severity="low")
    with SessionLocal() as db:
        events = db.scalars(select(AutomationEvent).order_by(AutomationEvent.created_at)).all()
        assert [(e.kind, e.object_kind, e.object_id, e.done) for e in events] == [
            ("incident.created", "incident", "i1", False),
            ("incident.created", "incident", "i2", False),
        ]
        assert events[0].payload["data"]["incident"]["host"] == "WKS-1"
        assert events[0].payload["classes"]["incident.host"] == ["private_value"]
    worker.drain()
    (run,) = runs_of(admin, pb)
    assert (run["trigger"], run["incidentId"], run["status"], run["startedBy"]) == (
        "incident.created",
        "i1",
        "done",
        "nik-automation",
    )
    assert steps(run_of(admin, run["id"]))["a"]["output"]["text"] == "i1 is high"
    assert runs_of(admin, off) == []  # not turned on
    with SessionLocal() as db:
        assert all(e.done for e in db.scalars(select(AutomationEvent)))

    # An update says what changed, and a trigger can ask for it.
    changed = {
        "event": "incident.updated",
        "conditions": {"all": [{"left": "{{ trigger.changed }}", "op": "contains", "right": "status"}]},
    }
    on_status = playbook(
        admin,
        "On status",
        [echo("a", "{{ trigger.incident.status }}")],
        [edge("start", "a")],
        trigger=changed,
        enabled=True,
    )
    admin.patch("/api/incidents/i1", json={"severity": "critical"})
    admin.patch("/api/incidents/i1", json={"status": "closed"})
    admin.patch("/api/incidents/i1", json={"status": "closed"})  # nothing changed: no event
    worker.drain()
    (run,) = runs_of(admin, on_status)
    assert steps(run_of(admin, run["id"]))["a"]["output"]["text"] == "closed"


def test_limits_keep_a_playbook_from_running_away(admin: TestClient, monkeypatch):
    trigger = {"event": "incident.updated"}
    slow = playbook(
        admin,
        "One at a time",
        [node("pause", "wait", seconds=600)],
        [edge("start", "pause")],
        trigger=trigger,
        enabled=True,
    )
    incident(admin, "i1")
    for status_value in ("in_progress", "closed", "open"):
        admin.patch("/api/incidents/i1", json={"status": status_value})
    worker.drain()
    assert len(runs_of(admin, slow)) == 1  # one run at a time for the same object
    incident(admin, "i2")
    admin.patch("/api/incidents/i2", json={"status": "closed"})
    worker.drain()
    assert len(runs_of(admin, slow)) == 2  # another object

    # A ceiling for the whole server: two runs are in progress.
    other = playbook(admin, "Other", [echo("a", "x")], [edge("start", "a")])
    monkeypatch.setattr(triggers.settings, "AUTOMATION_MAX_ACTIVE_RUNS", 2)
    refused = admin.post(f"/api/automation/playbooks/{other}/run", json={})
    assert refused.status_code == 429 and refused.json()["detail"] == "Too many runs are in progress on this server"
    monkeypatch.setattr(triggers.settings, "AUTOMATION_MAX_ACTIVE_RUNS", 200)

    # Runs per hour.
    busy = playbook(
        admin,
        "Busy",
        [echo("a", "x")],
        [edge("start", "a")],
        trigger={"manual": True},
        maxRunsPerHour=2,
        onePerObject=False,
    )
    assert go(admin, busy)["status"] == "done" and go(admin, busy)["status"] == "done"
    refused = admin.post(f"/api/automation/playbooks/{busy}/run", json={})
    assert refused.status_code == 429 and refused.json()["detail"] == "The playbook reached its runs per hour"


def test_a_playbook_never_starts_on_what_its_own_run_did(admin: TestClient):
    """incident updated → the playbook updates the incident → incident updated → …"""

    @actions.action(
        "test.touch", group="Test", name="Touch", arguments=[{"name": "id", "type": "text", "required": True}]
    )
    def touch(call: actions.Call) -> actions.Result:
        from app.core.models import Incident

        row = call.db.get(Incident, call.args["id"])
        row.severity = "critical" if row.severity != "critical" else "high"
        triggers.incident_changed(call.db, row, "incident.updated", ["severity"])
        return actions.Result(output={})

    try:
        trigger = {"event": "incident.updated"}
        touches = [node("touch", "action", action="test.touch", args={"id": "{{ trigger.incident.id }}"})]
        first = playbook(
            admin, "Loops", touches, [edge("start", "touch")], trigger=trigger, enabled=True, onePerObject=False
        )
        incident(admin, "i1")
        admin.patch("/api/incidents/i1", json={"status": "closed"})
        for _ in range(20):
            worker.drain()
        assert len(runs_of(admin, first)) == 1  # its own change did not start it again

        # Two playbooks that set each other off stop after a few rounds.
        second = playbook(
            admin, "Loops too", touches, [edge("start", "touch")], trigger=trigger, enabled=True, onePerObject=False
        )
        admin.patch("/api/incidents/i1", json={"status": "open"})
        for _ in range(40):
            worker.drain()
        total = len(runs_of(admin, first)) + len(runs_of(admin, second))
        assert 3 <= total <= 2 + 2 * (triggers.MAX_DEPTH + 2)
        with SessionLocal() as db:
            assert all(e.done for e in db.scalars(select(AutomationEvent)))
    finally:
        actions.unregister("test.touch")


def test_a_schedule_fires_at_its_time_and_not_for_what_it_missed(admin: TestClient, monkeypatch):
    now = {"t": 1_794_800_000.0}  # 2026-11-16T03:33:20Z, a Monday
    monkeypatch.setattr("app.routers.automation.time.time", lambda: now["t"])
    trigger = {"cron": "30 6 * * 1", "timezone": "Europe/Rome"}
    pb = playbook(
        admin,
        "Weekly",
        [echo("a", "{{ trigger.cron }} at {{ trigger.at }}")],
        [edge("start", "a")],
        trigger=trigger,
        enabled=True,
    )
    with SessionLocal() as db:
        row = db.scalars(select(AutomationSchedule)).one()
        assert row.next_at == 1_794_807_000.0  # 05:30 UTC the same Monday
    worker.drain(now["t"] + 60)
    assert runs_of(admin, pb) == []
    worker.drain(1_794_807_001.0)
    (run,) = runs_of(admin, pb)
    assert run["trigger"] == "schedule" and steps(run_of(admin, run["id"]))["a"]["output"]["text"].startswith(
        "30 6 * * 1 at 2026-11-16T05:30"
    )
    # Three weeks later: one firing, not three.
    worker.drain(1_794_807_000.0 + 21 * 86400 + 5)
    assert len(runs_of(admin, pb)) == 2
    # Turned off: the schedule goes; on again: counted from now.
    admin.put(f"/api/automation/playbooks/{pb}/enabled", json={"enabled": False})
    with SessionLocal() as db:
        assert db.scalars(select(AutomationSchedule)).all() == []


# --------------------------------------------------------------------------- #
# The API                                                                     #
# --------------------------------------------------------------------------- #
def test_playbooks_are_drafts_and_versions(admin: TestClient):
    created = admin.post("/api/automation/playbooks", json={"name": "  Triage  ", "description": "d"}).json()
    pb = created["id"]
    assert (created["name"], created["enabled"], created["version"], created["hasDraft"]) == (
        "Triage",
        False,
        None,
        True,
    )
    assert created["egressMode"] == "listed" and created["dataAllow"] == [] and created["approvalDefault"] is True
    assert (
        admin.post("/api/automation/playbooks", json={"name": "triage"}).json()["detail"]
        == "A playbook with this name exists already"
    )
    assert (
        admin.put(f"/api/automation/playbooks/{pb}/enabled", json={"enabled": True}).status_code == 400
    )  # no version yet

    # A draft may be anything; a version must be valid, and says what is not.
    broken = {
        "nodes": [node("start", "trigger", manual=True), node("a", "action", action="test.echo")],
        "edges": [edge("start", "a")],
    }
    assert admin.put(f"/api/automation/playbooks/{pb}", json={"draft": broken}).json()["draft"] == broken
    refused = admin.post(f"/api/automation/playbooks/{pb}/versions", json={})
    assert refused.status_code == 422
    assert refused.json()["problems"] == [{"message": '"text" is required', "node": "a", "field": "args.text"}]
    assert admin.post(f"/api/automation/playbooks/{pb}/validate", json={}).json()["problems"][0]["node"] == "a"
    good = {**broken, "nodes": [broken["nodes"][0], echo("a", "one")]}
    saved = admin.post(f"/api/automation/playbooks/{pb}/versions", json={"graph": good, "note": "first"}).json()
    assert (saved["version"], saved["draft"], saved["graph"]) == (1, None, good)
    second = {**good, "nodes": [good["nodes"][0], echo("a", "two")]}
    admin.post(f"/api/automation/playbooks/{pb}/versions", json={"graph": second})

    # A run finishes with the version it started with.
    run_id = start(admin, pb)
    third = {**good, "nodes": [good["nodes"][0], echo("a", "three")]}
    admin.post(f"/api/automation/playbooks/{pb}/versions", json={"graph": third})
    worker.drain(T0)
    run = run_of(admin, run_id)
    assert run["version"] == 2 and steps(run)["a"]["output"]["text"] == "two" and run["graph"] == second

    listed = admin.get(f"/api/automation/playbooks/{pb}/versions").json()
    assert listed["current"] == 3 and [(v["version"], v["note"]) for v in listed["versions"]] == [
        (3, ""),
        (2, ""),
        (1, "first"),
    ]
    # Restoring an old version is a new version: history is not rewritten.
    restored = admin.post(f"/api/automation/playbooks/{pb}/versions/1/restore").json()
    assert restored["version"] == 4 and restored["graph"] == good
    assert admin.get(f"/api/automation/playbooks/{pb}/versions/4").json()["note"] == "Restored from version 1"
    assert admin.post(f"/api/automation/playbooks/{pb}/versions/9/restore").status_code == 404

    summary = next(p for p in admin.get("/api/automation/playbooks").json()["playbooks"] if p["id"] == pb)
    assert summary["trigger"] == "by hand" and summary["lastRun"]["status"] == "done" and summary["week"]["done"] == 1

    # Export and import: the graph and the limits travel; what it may reach and send does not.
    exported = admin.get(f"/api/automation/playbooks/{pb}/export").json()
    assert exported["type"] == "playbook" and "egressHosts" not in exported["playbook"]
    imported = admin.post("/api/automation/playbooks/import", json={"playbook": exported["playbook"]}).json()
    assert (imported["name"], imported["enabled"], imported["version"], imported["problems"]) == (
        "Triage (2)",
        False,
        None,
        [],
    )
    assert imported["draft"] == good and imported["egressMode"] == "listed"
    missing = {
        **exported["playbook"],
        "graph": {**good, "nodes": [good["nodes"][0], node("a", "action", action="gone.away")]},
    }
    assert (
        admin.post("/api/automation/playbooks/import", json={"playbook": missing}).json()["problems"][0]["message"]
        == "This action does not exist"
    )
    assert admin.post("/api/automation/playbooks/import", json={"playbook": {"name": "x"}}).status_code == 400

    # Deleting: not with a run in progress; then everything of it goes.
    waiting = playbook(admin, "Waiting", [node("p", "wait", seconds=600)], [edge("start", "p")])
    run_id = start(admin, waiting)
    worker.drain(T0)
    assert admin.delete(f"/api/automation/playbooks/{waiting}").status_code == 409
    admin.post(f"/api/automation/runs/{run_id}/stop")
    assert admin.delete(f"/api/automation/playbooks/{waiting}").status_code == 204
    assert admin.get(f"/api/automation/runs/{run_id}").status_code == 404
    with SessionLocal() as db:
        assert db.scalars(select(RunStep).where(RunStep.run_id == run_id)).all() == []

    logged = {e["action"] for e in admin.get("/api/audit?q=action:playbook.*").json()["entries"]}
    assert logged == {
        "playbook.create",
        "playbook.version",
        "playbook.run",
        "playbook.import",
        "playbook.stop",
        "playbook.delete",
    }


def test_who_may_do_what_with_playbooks(admin: TestClient):
    pb = playbook(admin, "Mine", [echo("a", "x")], [edge("start", "a")])
    analyst = make_key(admin, label="an", roles=["analyst"])
    builder = make_key(admin, label="pb", roles=["playbooks"])
    viewer = make_key(admin, label="vi", roles=["viewer"])
    caller = TestClient(fastapi_app)

    def status(key, method, path, **json):
        body = json if method != "GET" else None
        return caller.request(method, f"/api/automation{path}", headers=key, json=body).status_code

    # An analyst runs, reads runs and stops; does not build.
    assert status(analyst, "GET", "/playbooks") == 200 and status(analyst, "GET", "/catalog") == 200
    assert status(analyst, "POST", f"/playbooks/{pb}/run") == 201
    assert status(analyst, "GET", "/runs") == 200
    assert status(analyst, "POST", "/playbooks", name="x") == 403
    assert status(analyst, "PUT", f"/playbooks/{pb}", description="x") == 403
    assert status(analyst, "POST", f"/playbooks/{pb}/versions") == 403
    assert status(analyst, "PUT", f"/playbooks/{pb}/enabled", enabled=True) == 403
    assert status(analyst, "DELETE", f"/playbooks/{pb}") == 403
    # The playbooks role builds, without being an admin; the general switch is the admin's.
    assert status(builder, "POST", "/playbooks", name="Built") == 201
    assert status(builder, "PUT", f"/playbooks/{pb}/enabled", enabled=True) == 200
    assert status(builder, "GET", "/state") == 200 and status(builder, "PUT", "/state", enabled=False) == 403
    assert caller.get("/api/incidents", headers=builder).status_code == 403  # and reads no incident
    # A viewer has nothing to do here.
    assert status(viewer, "GET", "/playbooks") == 403 and status(viewer, "GET", "/runs") == 403

    catalog = caller.get("/api/automation/catalog", headers=analyst).json()
    by_id = {entry["id"]: entry for entry in catalog["nodes"]}
    assert by_id["flow.condition"]["group"] == "Flow" and by_id["test.block"]["changesOutside"] is True
    assert by_id["test.echo"]["arguments"][0] == {"name": "text", "type": "text", "required": True}
    assert catalog["events"][:2] == ["incident.created", "incident.updated"] and catalog["ports"]["condition"] == [
        "yes",
        "no",
    ]


def test_with_the_worker_off_nothing_is_recorded(admin: TestClient, monkeypatch):
    monkeypatch.setattr(triggers.settings, "AUTOMATION_WORKER", "off")
    incident(admin, "i1")
    with SessionLocal() as db:
        assert db.scalars(select(AutomationEvent)).all() == []
        assert state.worker_alive(db, T0) is False
        state.beat(db, T0)
        assert state.worker_alive(db, T0 + 30) is True and state.worker_alive(db, T0 + 61) is False


# --------------------------------------------------------------------------- #
# Approvals and the runs of an incident, through the API                      #
# --------------------------------------------------------------------------- #
def test_approvals_are_listed_and_answered_through_the_api(admin: TestClient):
    incident(admin, "inc-ask")
    pb = ask_playbook(admin, "Asks on an incident")
    run_id = start(admin, pb, objectKind="incident", objectId="inc-ask", inputs={"host": "evil.example"})
    other = start(admin, pb, inputs={"host": "other.example"})
    worker.drain(T0)

    listed = admin.get("/api/automation/approvals").json()
    assert listed["waiting"] == 2 and len(listed["approvals"]) == 2
    mine = next(item for item in listed["approvals"] if item["runId"] == run_id)
    assert (mine["question"], mine["detail"], mine["status"], mine["incidentId"], mine["node"], mine["inline"]) == (
        "Block evil.example?",
        {"host": "evil.example"},
        "waiting",
        "inc-ask",
        "ask",
        False,
    )
    assert mine["playbook"] == "Asks on an incident" and mine["expiresAt"] is None
    # Those of one incident; the run shows its own; the incident shows its runs and what waits.
    assert [item["id"] for item in admin.get("/api/automation/approvals?incident=inc-ask").json()["approvals"]] == [
        mine["id"]
    ]
    assert [item["id"] for item in run_of(admin, run_id)["approvals"]] == [mine["id"]]
    on_incident = admin.get("/api/incidents/inc-ask/runs").json()
    assert [run["id"] for run in on_incident["runs"]] == [run_id]
    assert [item["id"] for item in on_incident["approvals"]] == [mine["id"]]
    assert admin.get("/api/incidents/nope/runs").status_code == 404

    # An answer is approved or refused, once; the run goes on by it.
    assert admin.post(f"/api/automation/approvals/{mine['id']}", json={"answer": "maybe"}).status_code == 422
    assert admin.post("/api/automation/approvals/nope", json={"answer": "approved"}).status_code == 404
    answered = admin.post(f"/api/automation/approvals/{mine['id']}", json={"answer": "approved", "comment": " go "})
    assert answered.status_code == 200, answered.text
    assert (answered.json()["status"], answered.json()["answeredBy"], answered.json()["comment"]) == (
        "approved",
        "admin",
        "go",
    )
    again = admin.post(f"/api/automation/approvals/{mine['id']}", json={"answer": "refused"})
    assert again.status_code == 409 and "answered already" in again.json()["detail"]
    worker.drain(T0 + 1)
    run = run_of(admin, run_id)
    assert run["status"] == "done" and steps(run)["yes"]["output"]["text"] == "approved by admin: go"

    assert admin.get("/api/automation/approvals").json()["waiting"] == 1
    assert [item["status"] for item in admin.get("/api/automation/approvals?status=approved").json()["approvals"]] == [
        "approved"
    ]
    assert len(admin.get("/api/automation/approvals?status=all").json()["approvals"]) == 2
    # Who answered is in the audit log, on the incident.
    entries = admin.get("/api/audit").json()["entries"]
    approved = next(entry for entry in entries if entry["action"] == "playbook.approve")
    assert approved["actor"] == "admin" and approved["incidentId"] == "inc-ask"
    assert 'Approved "Block evil.example?"' in approved["details"]

    # Refusing is the other answer.
    waiting = admin.get("/api/automation/approvals").json()["approvals"][0]
    assert admin.post(f"/api/automation/approvals/{waiting['id']}", json={"answer": "refused"}).status_code == 200
    worker.drain(T0 + 2)
    assert steps(run_of(admin, other))["no"]["output"]["text"] == "refused"


def test_answering_an_approval_needs_the_right_to_run_playbooks(admin: TestClient):
    pb = ask_playbook(admin, "Asks a viewer")
    run_id = start(admin, pb, inputs={"host": "x"})
    worker.drain(T0)
    approval_id = approvals(admin, run_id)[0].id
    viewer = make_key(admin, roles=["viewer"])
    analyst = make_key(admin, roles=["analyst"])
    with TestClient(fastapi_app) as other:
        assert other.get("/api/automation/approvals", headers=viewer).status_code == 403
        refused = other.post(f"/api/automation/approvals/{approval_id}", json={"answer": "approved"}, headers=viewer)
        assert refused.status_code == 403
        assert other.get("/api/automation/approvals", headers=analyst).json()["waiting"] == 1
        done = other.post(f"/api/automation/approvals/{approval_id}", json={"answer": "approved"}, headers=analyst)
        assert done.status_code == 200 and done.json()["answeredBy"] == "api:test"

"""Playbooks across a restart: a step cut between *started* and *done*, by what it was doing.

A worker "dies" here when an action raises ``Killed``: not an error of the step (nothing catches
it), the pass ends where it is and nothing more is written, as when the process is killed. What
it had committed before stays: the claim, and the mark of a call when one was about to leave.
The worker that comes next has another name and takes the lease when it has run out.
"""

# ruff: noqa: E501 (graphs of test playbooks read better on one line)

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.automation import actions, engine, schedules, triggers, worker
from app.core import leases
from app.core.db import SessionLocal
from app.core.models import AutomationEvent, AutomationSchedule, Lease, Notification, Run, RunStep
from tests.conftest import make_key
from tests.test_automation_engine import (  # noqa: F401 - test_actions is a fixture
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

LATER = T0 + worker.LEASE_SECONDS + 1  # the lease of the worker that died has run out
SENT: list[str] = []
KILL: list[str] = []


class Killed(BaseException):
    """The process stopped here."""


@pytest.fixture(autouse=True)
def calls_outside():
    """Three commands, one of each class: one that only reads, one that changes something and may
    be repeated, one that changes something and may not. Each counts what it sends."""
    SENT.clear()
    KILL.clear()

    def send(name: str, call: actions.Call) -> actions.Result:
        SENT.append(name)
        if KILL and KILL[0] == name:
            KILL.pop(0)
            raise Killed
        return actions.Result(output={"sent": name}, request={"method": "POST", "host": "edr.corp"})

    actions.action("test.read", group="Test", name="Read")(lambda call: send("read", call))
    actions.action("test.isolate", group="Test", name="Isolate", changes_outside=True, idempotent=True)(
        lambda call: send("isolate", call)
    )
    actions.action("test.ticket", group="Test", name="Open a ticket", changes_outside=True, idempotent=False)(
        lambda call: send("ticket", call)
    )
    yield
    for name in ("test.read", "test.isolate", "test.ticket"):
        actions.unregister(name)


def one(admin: TestClient, action: str, name: str = "Cut") -> str:
    """A playbook of one outside call and a step after it."""
    nodes = [node("call", "action", action=f"test.{action}", args={}, approval={"ask": False}), echo("after", "after")]
    return playbook(admin, name, nodes, [edge("start", "call"), edge("call", "after")])


def die_in(admin: TestClient, playbook_id: str, action: str) -> tuple[str, str]:
    """Start a run and kill the first worker while the action is out: (run id, step id)."""
    run_id = start(admin, playbook_id)
    KILL.append(action)
    with pytest.raises(Killed):
        worker.tick(T0, holder="first")
    step = steps(run_of(admin, run_id))["call"]
    assert step["status"] == "running"
    return run_id, step["id"]


def passes(now: float, holder: str = "second", limit: int = 20) -> None:
    """The worker that came next works until nothing is due."""
    for _ in range(limit):
        done = worker.tick(now, holder=holder)
        if not done["steps"] and not done["runs"]:
            return
    raise AssertionError("the worker never came to rest")


# --------------------------------------------------------------------------- #
# Started and not done                                                        #
# --------------------------------------------------------------------------- #
def test_a_command_that_only_reads_is_done_again(admin: TestClient):
    run_id, _step = die_in(admin, one(admin, "read"), "read")
    with SessionLocal() as db:
        assert (
            db.scalars(select(RunStep.calling_at).where(RunStep.run_id == run_id, RunStep.node_id == "call")).one()
            is None
        )
    passes(LATER)
    run = run_of(admin, run_id)
    assert run["status"] == "done" and SENT == ["read", "read"]
    assert steps(run)["call"]["attempt"] == 1  # the try that was cut does not count
    assert [line["what"] for line in steps(run)["call"]["restarts"]] == ["interrupted", "again"]
    assert [call["text"] for call in CALLS] == ["after"]  # what comes after ran once


def test_a_command_that_changes_and_may_be_repeated_is_done_again(admin: TestClient):
    run_id, step_id = die_in(admin, one(admin, "isolate"), "isolate")
    with SessionLocal() as db:
        # Started, in a commit of its own, before the call left.
        assert db.get(RunStep, step_id).calling_at == T0
    passes(LATER)
    run = run_of(admin, run_id)
    assert run["status"] == "done" and SENT == ["isolate", "isolate"]
    assert steps(run)["call"]["attempt"] == 1 and steps(run)["call"]["output"] == {"sent": "isolate"}


def test_a_command_that_may_not_be_repeated_is_not_and_the_run_waits_for_a_person(admin: TestClient):
    run_id, step_id = die_in(admin, one(admin, "ticket"), "ticket")
    passes(LATER)
    passes(LATER + 600)
    run = run_of(admin, run_id)
    step = steps(run)["call"]
    assert SENT == ["ticket"]  # never sent twice
    assert run["status"] == "waiting" and run["interrupted"] is True
    assert step["status"] == "interrupted"
    assert step["error"] == "Interrupted by a restart: it is not known whether this happened"
    assert [line["what"] for line in step["restarts"]] == ["interrupted", "waiting"]
    assert "after" not in steps(run) and CALLS == []
    # Whoever owns the run is told, once however many passes go by.
    with SessionLocal() as db:
        told = db.scalars(select(Notification).where(Notification.kind == "run")).all()
    assert [(note.username, note.link) for note in told] == [("admin", f"/automation/runs/{run_id}")]
    assert "it is not known whether it happened" in told[0].text
    # It is among the runs that wait, and found by its own filter.
    listed = admin.get("/api/automation/runs?status=interrupted").json()
    assert [found["id"] for found in listed["runs"]] == [run_id] and listed["runs"][0]["interrupted"] is True
    assert admin.get("/api/automation/runs?status=running").json()["runs"] == []
    # Time does not fail a run that waits for a person.
    passes(LATER + 100_000)
    assert run_of(admin, run_id)["status"] == "waiting"


def answer(admin: TestClient, run_id: str, step_id: str, said: str, **more) -> dict:
    res = admin.post(f"/api/automation/runs/{run_id}/steps/{step_id}/resolve", json={"answer": said}, **more)
    assert res.status_code == 200, res.text
    return res.json()


def test_it_happened_the_run_goes_on_without_repeating_it(admin: TestClient):
    run_id, step_id = die_in(admin, one(admin, "ticket"), "ticket")
    passes(LATER)
    said = answer(admin, run_id, step_id, "happened")
    assert said["status"] == "running" and said["interrupted"] is False
    passes(LATER + 5)
    run = run_of(admin, run_id)
    step = steps(run)["call"]
    assert run["status"] == "done" and SENT == ["ticket"] and [call["text"] for call in CALLS] == ["after"]
    assert step["status"] == "done" and step["port"] == "out"
    assert step["output"]["interrupted"] is True and step["output"]["resolved"] == "happened"
    assert step["restarts"][-1]["what"] == "happened" and step["restarts"][-1]["by"] == "admin"
    entry = admin.get("/api/audit?q=action:playbook.resolve").json()["entries"][0]
    assert "admin said that it happened: the run goes on" in entry["details"]
    # Answered: a second answer has nothing to answer.
    again = admin.post(f"/api/automation/runs/{run_id}/steps/{step_id}/resolve", json={"answer": "again"})
    assert again.status_code == 409 and SENT == ["ticket"]


def test_it_did_not_happen_the_step_is_done_again(admin: TestClient):
    run_id, step_id = die_in(admin, one(admin, "ticket"), "ticket")
    passes(LATER)
    answer(admin, run_id, step_id, "again")
    passes(LATER + 5)
    run = run_of(admin, run_id)
    assert run["status"] == "done" and SENT == ["ticket", "ticket"]
    assert steps(run)["call"]["output"] == {"sent": "ticket"} and steps(run)["call"]["attempt"] == 1
    assert [line["what"] for line in steps(run)["call"]["restarts"]] == ["interrupted", "waiting", "again"]


def test_stop_the_run_ends_there(admin: TestClient):
    run_id, step_id = die_in(admin, one(admin, "ticket"), "ticket")
    passes(LATER)
    said = answer(admin, run_id, step_id, "stop")
    assert said["status"] == "stopped" and "a step a restart interrupted" in said["error"]
    passes(LATER + 5)
    assert SENT == ["ticket"] and CALLS == []
    assert steps(run_of(admin, run_id))["call"]["status"] == "skipped"


def test_who_may_not_run_playbooks_does_not_answer(admin: TestClient):
    run_id, step_id = die_in(admin, one(admin, "ticket"), "ticket")
    passes(LATER)
    viewer = make_key(admin, roles=["viewer"])
    url = f"/api/automation/runs/{run_id}/steps/{step_id}/resolve"
    assert admin.post(url, json={"answer": "again"}, headers=viewer).status_code == 403
    assert admin.post(url, json={"answer": "perhaps"}).status_code == 422
    assert admin.post(f"/api/automation/runs/{run_id}/steps/nope/resolve", json={"answer": "again"}).status_code == 404
    assert steps(run_of(admin, run_id))["call"]["status"] == "interrupted"


def test_a_step_that_was_claimed_and_never_began_its_call_is_simply_done(admin: TestClient):
    run_id = start(admin, one(admin, "ticket"))
    with SessionLocal() as db:
        assert leases.take(db, worker.LEASE, "first", worker.LEASE_SECONDS, T0)
        worker.claim_steps(db, T0, 10, holder="first")  # and the worker dies before it does anything
    passes(LATER)
    run = run_of(admin, run_id)
    assert run["status"] == "done" and SENT == ["ticket"]  # nothing had left: sent once, now


def test_a_worker_that_comes_back_late_applies_nothing(admin: TestClient):
    run_id, step_id = die_in(admin, one(admin, "isolate"), "isolate")
    passes(LATER)
    assert run_of(admin, run_id)["status"] == "done" and SENT == ["isolate", "isolate"]
    # The first worker was only frozen: it goes on with the step it had claimed.
    with SessionLocal() as db:
        engine.execute(db, step_id, LATER + 10, "first")
    assert SENT == ["isolate", "isolate"]
    # And a step taken back and claimed by the second worker is not the first one's to do either.
    with SessionLocal() as db:
        leases.release(db, worker.LEASE, "second")
    run_id, step_id = die_in(admin, one(admin, "read", "Cut twice"), "read")
    with SessionLocal() as db:
        assert worker.acquire(db, "second", LATER + 100)
        assert worker.reclaim(db, LATER + 100, "second") == 1
        assert worker.reclaim(db, LATER + 100, "second") == 0  # taken back once
        worker.claim_steps(db, LATER + 100, 10, holder="second")
        engine.execute(db, step_id, LATER + 100, "first")
        assert db.get(RunStep, step_id).status == "running" and SENT[-1] == "read" and SENT.count("read") == 1


def test_two_workers_do_not_both_take_a_step_back(admin: TestClient):
    run_id, step_id = die_in(admin, one(admin, "ticket"), "ticket")
    with SessionLocal() as one_db, SessionLocal() as other_db:
        first = engine.take_back(one_db, one_db.get(RunStep, step_id), LATER)
        one_db.commit()
        second = engine.take_back(other_db, other_db.get(RunStep, step_id), LATER)
        other_db.commit()
    assert (first, second) == ("interrupted", "skipped")
    with SessionLocal() as db:
        assert len(db.scalars(select(Notification).where(Notification.kind == "run")).all()) == 1


def test_a_step_that_stops_its_worker_every_time_is_not_started_for_ever(admin: TestClient):
    run_id = start(admin, one(admin, "read"))
    now = T0
    for number in range(engine.MAX_RESTARTS):
        KILL.append("read")
        with pytest.raises(Killed):
            worker.tick(now, holder=f"worker-{number}")
        now += worker.LEASE_SECONDS + 1
    passes(now, holder="the-last")
    run = run_of(admin, run_id)
    assert SENT == ["read"] * engine.MAX_RESTARTS  # not a fourth time
    assert run["status"] == "failed"
    assert run["error"].startswith(f"call: Interrupted by a restart {engine.MAX_RESTARTS} times while it ran")


def test_a_stop_that_was_asked_for_is_not_counted_against_the_step(admin: TestClient):
    """Three upgrades in a row while a slow step runs: the step did not take its worker down."""
    from app.automation import state

    run_id = start(admin, one(admin, "read"))
    now = T0
    for number in range(engine.MAX_RESTARTS + 1):
        name = f"worker-{number}"
        with SessionLocal() as db:
            assert worker.acquire(db, name, now)
            worker.reclaim(db, now, name)
            (step_id,) = worker.claim_steps(db, now, 10, holder=name)
            # Asked to stop with the step still in flight: it says so, and gives its lease back.
            state.write(db, stopped={"holder": name, "at": now})
            db.commit()
            worker.release(db, name)
        now += 5
    passes(now, holder="the-last")
    run = run_of(admin, run_id)
    assert run["status"] == "done" and SENT == ["read"]
    cuts = [line for line in steps(run)["call"]["restarts"] if line["what"] == "interrupted"]
    assert len(cuts) == engine.MAX_RESTARTS + 1 and all(line["asked"] for line in cuts)


def test_a_step_in_flight_under_this_worker_is_left_alone_until_its_time(admin: TestClient):
    run_id = start(admin, one(admin, "read"))
    with SessionLocal() as db:
        (step_id,) = worker.claim_steps(db, T0, 10, holder="second")
        worker._in_flight.add(step_id)
        assert worker.reclaim(db, T0 + 10_000, "second") == 0  # its thread runs it, however long
        worker._in_flight.clear()
        assert worker.reclaim(db, T0 + 30, "second") == 0  # no thread, but within its time
        assert worker.reclaim(db, T0 + 10_000, "second") == 1  # its thread died
    passes(T0 + 10_000)
    assert run_of(admin, run_id)["status"] == "done"


def test_steps_running_when_the_server_was_upgraded_are_asked_about_not_repeated(admin: TestClient):
    """What migration 0053 leaves: an action that was running under 6.8 carries the mark."""
    run_id = start(admin, one(admin, "ticket"))
    with SessionLocal() as db:
        (step_id,) = worker.claim_steps(db, T0, 10, holder="the-worker-of-6.8")
        db.get(RunStep, step_id).calling_at = T0
        db.commit()
    passes(LATER)
    assert steps(run_of(admin, run_id))["call"]["status"] == "interrupted" and SENT == []


# --------------------------------------------------------------------------- #
# Events and schedules                                                        #
# --------------------------------------------------------------------------- #
def test_an_event_never_starts_the_same_playbook_twice(admin: TestClient):
    trigger = {"event": "incident.created"}
    pb = playbook(admin, "On a new incident", [echo("a", "seen")], [edge("start", "a")], trigger=trigger, enabled=True)
    assert admin.post("/api/incidents", json={"id": "inc1", "name": "inc1", "data": {}}).status_code == 201
    with SessionLocal() as db:
        (event,) = db.scalars(select(AutomationEvent).where(AutomationEvent.kind == "incident.created")).all()
        # The event is in the transaction of the change: it is there exactly when the incident is.
        assert event.done is False and event.object_id == "inc1"
        event_id = event.id
        assert len(triggers.handle_event(db, event, T0)) == 1
        db.commit()  # the runs are committed, and the worker dies before the event is marked done
    with SessionLocal() as db:
        event = db.get(AutomationEvent, event_id)
        assert event.done is False
        assert triggers.handle_event(db, event, T0 + 1) == []
        db.commit()
        runs = db.scalars(select(Run).where(Run.playbook_id == pb)).all()
        assert [run.event_key for run in runs] == [f"{event_id}:{pb}"]
        # And the database itself refuses a second one, whatever went wrong before it.
        db.add(
            Run(
                id="x" * 32,
                playbook_id=pb,
                version=1,
                status="running",
                started_at=engine.iso(T0),
                event_key=runs[0].event_key,
            )
        )
        with pytest.raises(IntegrityError):
            db.flush()
        db.rollback()
    # The worker as it normally goes: the runs and the mark of done are one commit.
    passes(T0 + 2, holder=worker.HOLDER)
    with SessionLocal() as db:
        # Marked done (and, being of a day long before the clock of this test, swept away with the old ones).
        assert db.scalars(select(AutomationEvent).where(AutomationEvent.done.is_(False))).all() == []
        assert len(db.scalars(select(Run).where(Run.playbook_id == pb)).all()) == 1


def test_a_schedule_that_passed_while_the_server_was_down_runs_once(admin: TestClient):
    trigger = {"cron": "0 * * * *", "timezone": "UTC"}
    pb = playbook(
        admin,
        "Hourly",
        [echo("a", "{{ trigger.missed }} missed, late {{ trigger.late_seconds }}")],
        [edge("start", "a")],
        trigger=trigger,
        enabled=True,
    )
    week = 7 * 86400
    with SessionLocal() as db:
        row = db.scalars(select(AutomationSchedule).where(AutomationSchedule.playbook_id == pb)).one()
        row.next_at = due = schedules.next_after("0 * * * *", "UTC", T0)
        db.commit()
    now = due + week + 60  # the server was down a week
    passes(now, holder=worker.HOLDER)
    passes(now + 1, holder=worker.HOLDER)
    with SessionLocal() as db:
        runs = db.scalars(select(Run).where(Run.playbook_id == pb)).all()
        row = db.scalars(select(AutomationSchedule).where(AutomationSchedule.playbook_id == pb)).one()
        assert len(runs) == 1  # one run, not a week of them
        payload = runs[0].context["trigger"]
        assert payload["due"] == engine.iso(due) and payload["late_seconds"] == week + 60 and payload["missed"] == 168
        assert now < row.next_at <= now + 3600 and row.skipped == 168
    assert [call["text"] for call in CALLS] == [f"168 missed, late {week + 60}"]
    # On time, nothing is missed and nothing is late.
    passes(row.next_at, holder=worker.HOLDER)
    assert CALLS[-1]["text"] == "0 missed, late 0"


def test_the_count_of_missed_firings_is_bounded():
    year = 366 * 86400
    assert schedules.missed_between("*/5 * * * *", "UTC", T0, T0 + year) == schedules.MISSED_MAX
    assert schedules.missed_between("*/5 * * * *", "UTC", T0, T0 + 60) == 0


# --------------------------------------------------------------------------- #
# Leases                                                                      #
# --------------------------------------------------------------------------- #
def test_a_lease_is_taken_without_an_error_and_given_back(client: TestClient):
    with SessionLocal() as db:
        assert leases.take(db, "a-loop", "one", 30, T0) is True
        assert leases.take(db, "a-loop", "one", 30, T0 + 10) is True  # renewed
        assert db.get(Lease, "a-loop").expires_at == T0 + 40
        # Held by another: no row changes, nothing is raised, and the session goes on as it was.
        assert leases.take(db, "a-loop", "two", 30, T0 + 20) is False
        assert db.get(Lease, "a-loop").holder == "one" and leases.holder_of(db, "a-loop", T0 + 20) == "one"
        # After a hard stop nobody gives it back: it runs out, and the next process has it.
        assert leases.holder_of(db, "a-loop", T0 + 41) == ""
        assert leases.take(db, "a-loop", "two", 30, T0 + 41) is True
        leases.release(db, "a-loop", "one")  # not its own any more: nothing happens
        assert db.get(Lease, "a-loop").holder == "two"
        leases.release(db, "a-loop", "two")
        assert db.get(Lease, "a-loop") is None


def test_a_process_that_stops_gives_back_every_lease_it_took(client: TestClient):
    with SessionLocal() as db:
        assert worker.acquire(db, "me", T0) and leases.take(db, "another-loop", "me", 120, T0)
        db.add(Lease(name="theirs", holder="another-process", expires_at=T0 + 120))
        db.commit()
    assert {("automation", "me"), ("another-loop", "me")} <= set(leases.held())
    assert leases.release_all() >= 2
    with SessionLocal() as db:
        left = {row.name: row.holder for row in db.scalars(select(Lease))}
    assert "automation" not in left and "another-loop" not in left and left["theirs"] == "another-process"
    assert leases.release_all() >= 0  # nothing left to give: no error


def test_the_worker_that_is_asked_to_stop_lets_what_is_in_flight_finish_and_lets_go(admin: TestClient, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor

    waits: list[float] = []

    def pause(seconds: float) -> None:
        waits.append(seconds)
        if len(waits) == 3:
            worker._in_flight.clear()  # the step ends during the grace

    worker._in_flight.add("a-step")
    assert worker.finish_in_flight(ThreadPoolExecutor(max_workers=1), grace=5.0, pause=pause) == 0
    assert len(waits) == 3
    # One that does not end is waited for the grace and no longer.
    waits.clear()
    worker._in_flight.add("a-slow-step")
    assert worker.finish_in_flight(ThreadPoolExecutor(max_workers=1), grace=1.0, pause=waits.append) == 1
    assert 4 <= len(waits) <= 6
    worker._in_flight.clear()

    # The loop: asked to stop, it passes no more, and its lease is given back before it returns.
    passed: list[float] = []
    monkeypatch.setattr(worker, "tick", lambda pool=None: (passed.append(1), worker._stopping.set()))
    with SessionLocal() as db:
        assert worker.acquire(db)
    worker.loop()
    assert passed == [1]
    with SessionLocal() as db:
        assert db.get(Lease, worker.LEASE) is None


def test_the_playbook_the_tests_use_is_there(admin: TestClient):
    """The three commands are what the rules read: only what a command says of itself decides."""
    with SessionLocal() as db:
        specs = {name: actions.lookup(db, f"test.{name}") for name in ("read", "isolate", "ticket")}
    assert [engine.safe_to_repeat(specs[name]) for name in ("read", "isolate", "ticket")] == [True, True, False]
    assert engine.safe_to_repeat(None) is True


def test_a_script_whose_sandbox_was_away_is_taken_again_by_itself(admin: TestClient, monkeypatch):
    from app.automation import scripts

    with SessionLocal() as db:
        scripts.seed(db)
        db.commit()
    away, ran = [2], []

    def sandbox(db, name, version, args, run):
        if away[0]:
            away[0] -= 1
            raise engine.StepFailed("The sandbox could not be reached", retry=True, away=True)
        ran.append(name)
        return {"domains": []}, ""

    monkeypatch.setattr(engine, "script_runner", sandbox)
    calc = node("calc", "script", script="ExtractDomains", script_version=1, args={"text": "x"})
    pb = playbook(admin, "Computes", [calc, echo("after", "after")], [edge("start", "calc"), edge("calc", "after")])
    run_id = start(admin, pb)
    passes(T0, holder=worker.HOLDER)
    step = steps(run_of(admin, run_id))["calc"]
    # The node allows one try, and the sandbox being away is not one: it waits a little, and longer.
    assert (step["status"], step["attempt"], step["nextAt"]) == ("pending", 0, T0 + engine.AWAY_WAIT)
    passes(T0 + engine.AWAY_WAIT, holder=worker.HOLDER)
    assert steps(run_of(admin, run_id))["calc"]["nextAt"] == T0 + engine.AWAY_WAIT + 2 * engine.AWAY_WAIT
    passes(T0 + 3 * engine.AWAY_WAIT, holder=worker.HOLDER)
    run = run_of(admin, run_id)
    assert run["status"] == "done" and ran == ["ExtractDomains"] and steps(run)["calc"]["attempt"] == 1
    assert [line["what"] for line in steps(run)["calc"]["restarts"]] == ["away", "away"]

    # A sandbox that does not come back: the step fails as it always did, after about a minute.
    away[0] = 99
    run_id = start(admin, pb, now=T0 + 1000)
    now = T0 + 1000
    for _ in range(engine.MAX_RESTARTS + 2):
        passes(now, holder=worker.HOLDER)
        now += 4 * engine.AWAY_WAIT
    run = run_of(admin, run_id)
    assert run["status"] == "failed" and run["error"] == "calc: The sandbox could not be reached"
    assert [line["what"] for line in steps(run)["calc"]["restarts"]] == ["away"] * engine.MAX_RESTARTS


# --------------------------------------------------------------------------- #
# The database goes away under the work                                       #
# --------------------------------------------------------------------------- #
def gone() -> Exception:
    from sqlalchemy.exc import OperationalError

    return OperationalError("SELECT 1", {}, Exception("terminating connection due to administrator command"))


def test_the_database_going_away_under_a_step_is_not_a_failure_of_the_step(admin: TestClient, monkeypatch):
    def flaky(action: str):
        spec = actions.get(f"test.{action}")
        fell = []

        def run(call: actions.Call) -> actions.Result:
            result = spec.run(call)
            if not fell:
                fell.append(1)
                raise gone()  # the call was made, and what it gave cannot be kept
            return result

        monkeypatch.setitem(actions._REGISTRY, f"test.{action}", actions.Spec(**{**spec.__dict__, "run": run}))

    # A command that only reads: the step is neither failed nor lost, and is done again.
    flaky("read")
    reads = start(admin, one(admin, "read"))
    worker.tick(T0, holder="first")
    step = steps(run_of(admin, reads))["call"]
    assert (step["status"], step["error"]) == ("running", None) and run_of(admin, reads)["status"] == "running"
    with SessionLocal() as db:
        # Its thread ended without writing: with a pool of threads that is known half a minute later.
        assert worker.reclaim(db, T0 + engine.RECLAIM_GRACE - 1, "first", threads=True) == 0
        assert worker.reclaim(db, T0 + engine.RECLAIM_GRACE + 1, "first", threads=True) == 1
    passes(T0 + engine.RECLAIM_GRACE + 1, holder="first")
    run = run_of(admin, reads)
    assert run["status"] == "done" and SENT == ["read", "read"]

    # A command that may not be repeated had made its call: a person is asked, as after a restart.
    SENT.clear()
    flaky("ticket")
    tickets = start(admin, one(admin, "ticket", "Cut again"), now=T0 + 1000)
    worker.tick(T0 + 1000, holder="first")
    assert steps(run_of(admin, tickets))["call"]["status"] == "running"
    passes(T0 + 2000, holder="first")  # without a pool: when the step is past its time
    run = run_of(admin, tickets)
    assert (run["status"], run["interrupted"], SENT) == ("waiting", True, ["ticket"])


def test_the_database_going_away_under_an_event_leaves_the_event_for_the_next_pass(admin: TestClient, monkeypatch):
    trigger = {"event": "incident.created"}
    pb = playbook(admin, "On a new incident", [echo("a", "seen")], [edge("start", "a")], trigger=trigger, enabled=True)
    assert admin.post("/api/incidents", json={"id": "inc1", "name": "inc1", "data": {}}).status_code == 201
    handle, fell = triggers.handle_event, []

    def falls_once(db, event, now):
        if not fell:
            fell.append(1)
            raise gone()
        return handle(db, event, now)

    monkeypatch.setattr(triggers, "handle_event", falls_once)
    with SessionLocal() as db:
        with pytest.raises(type(gone())):
            worker.take_events(db, T0)
        db.rollback()
        # Not marked done for an error that was not its own: it starts its playbook at the next pass.
        assert [event.done for event in db.scalars(select(AutomationEvent))] == [False]
        assert worker.take_events(db, T0 + 1) == 1
        assert len(db.scalars(select(Run).where(Run.playbook_id == pb)).all()) == 1


# --------------------------------------------------------------------------- #
# An HTTP request node that says it is safe to repeat                         #
# --------------------------------------------------------------------------- #
@pytest.fixture()
def http_out(monkeypatch):
    """The HTTP request action, with what it sends counted in the place of the network."""
    import dataclasses

    spec = actions.lookup(None, "http.request")

    def send(call: actions.Call) -> actions.Result:
        name = str(call.args.get("method") or "GET").upper()
        SENT.append(name)
        if KILL and KILL[0] == name:
            KILL.pop(0)
            raise Killed
        return actions.Result(output={"status": 200}, request={"method": name, "host": "edr.corp"})

    monkeypatch.setitem(actions._REGISTRY, "http.request", dataclasses.replace(spec, run=send))


def request_node(admin: TestClient, method: str, name: str, **config) -> str:
    call = node(
        "call",
        "action",
        action="http.request",
        args={"method": method, "url": "https://edr.corp/tickets"},
        approval={"ask": False},
        **config,
    )
    return playbook(admin, name, [call, echo("after", "after")], [edge("start", "call"), edge("call", "after")])


def test_a_request_that_is_not_a_get_is_not_sent_again_unless_its_node_says_it_is_safe(admin: TestClient, http_out):
    # As built: a POST cut by a restart waits for a person.
    run_id, _step = die_in(admin, request_node(admin, "POST", "Plain"), "POST")
    passes(LATER)
    assert SENT == ["POST"] and steps(run_of(admin, run_id))["call"]["status"] == "interrupted"


def test_safe_to_repeat_turned_off_is_as_if_it_was_never_said(admin: TestClient, http_out):
    run_id, _step = die_in(admin, request_node(admin, "POST", "Off", safe_to_repeat=False), "POST")
    passes(LATER)
    assert SENT == ["POST"] and steps(run_of(admin, run_id))["call"]["status"] == "interrupted"


def test_a_request_whose_node_says_safe_to_repeat_is_sent_again_after_a_restart(admin: TestClient, http_out):
    run_id, step_id = die_in(admin, request_node(admin, "POST", "Safe", safe_to_repeat=True), "POST")
    with SessionLocal() as db:
        assert db.get(RunStep, step_id).calling_at == T0  # it changes something outside: marked all the same
    passes(LATER)
    run = run_of(admin, run_id)
    assert run["status"] == "done" and SENT == ["POST", "POST"]
    assert [line["what"] for line in steps(run)["call"]["restarts"]] == ["interrupted", "again"]
    assert steps(run)["call"]["attempt"] == 1 and [call["text"] for call in CALLS] == ["after"]


def test_a_get_never_needed_the_tick(admin: TestClient, http_out):
    run_id, _step = die_in(admin, request_node(admin, "GET", "Read"), "GET")
    passes(LATER)
    assert run_of(admin, run_id)["status"] == "done" and SENT == ["GET", "GET"]


def test_safe_to_repeat_is_a_setting_of_the_http_request_node_alone(admin: TestClient):
    from app.automation import engine

    ticket = actions.lookup(None, "test.ticket")
    assert engine.safe_to_repeat(ticket, {"safe_to_repeat": True}) is False, "a connector says it in the connector"
    request = actions.lookup(None, "http.request")
    assert (
        engine.safe_to_repeat(request, {}) is False and engine.safe_to_repeat(request, {"safe_to_repeat": 1}) is False
    )
    assert engine.safe_to_repeat(request, {"safe_to_repeat": True}) is True
    made = admin.post("/api/automation/playbooks", json={"name": "Elsewhere"}).json()
    shape = {
        "nodes": [
            node("start", "trigger", manual=True),
            node("call", "action", action="test.ticket", args={}, safe_to_repeat=True),
            node(
                "other",
                "action",
                action="http.request",
                args={"method": "POST", "url": "https://edr.corp/x"},
                safe_to_repeat="yes",
            ),
        ],
        "edges": [edge("start", "call"), edge("call", "other")],
    }
    refused = admin.post(f"/api/automation/playbooks/{made['id']}/versions", json={"graph": shape})
    assert refused.status_code == 422, refused.text
    said = {problem["node"]: problem["message"] for problem in refused.json()["problems"]}
    assert said == {"call": 'Only an HTTP request has "Safe to repeat"', "other": '"Safe to repeat" is on or off'}

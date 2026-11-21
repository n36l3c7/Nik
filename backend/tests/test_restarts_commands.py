"""What a connector says of doing a command twice, the key it sends for that, and the timers
that ran out while the server was stopped."""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.automation import actions, connector_actions, engine
from app.automation import connectors as cn
from app.core.db import SessionLocal
from app.core.models import AutomationEvent, Incident
from tests.test_connector_runtime import Wire, connector, runtime
from tests.test_tasks import person
from tests.test_timers import incident, shown, sla, tick

PAY = """\
- name: pay
  changes_outside: true
  idempotent: false
  idempotency_key: true
  arguments: [{ name: amount, type: number, required: true }]
  request:
    method: POST
    path: /payments
    headers: { Idempotency-Key: "{{ idempotency.key }}" }
    json: { amount: "{{ args.amount }}" }
- name: open-ticket
  changes_outside: true
  idempotent: false
  request: { method: POST, path: /tickets, json: { title: a ticket } }
- name: isolate
  changes_outside: true
  request: { method: POST, path: /isolate }
- name: look
  request: { method: GET, path: /look }
"""


def test_a_command_says_whether_a_second_try_does_harm():
    found = connector(PAY)
    safe = {command.name: command.safe_to_repeat for command in found.commands}
    # Only reads; sets a state (the default says twice is as once); makes a new thing; sends a key.
    assert safe == {"look": True, "isolate": True, "open-ticket": False, "pay": True}
    specs = {command.name: connector_actions._spec(found, command) for command in found.commands}
    assert [engine.safe_to_repeat(specs[name]) for name in ("look", "isolate", "open-ticket", "pay")] == [
        True,
        True,
        False,
        True,
    ]
    assert specs["pay"].changes_outside is True  # it still asks a person first, and is held in a dry run


def problems_of(commands: str) -> list[str]:
    with pytest.raises(cn.ConnectorError) as refused:
        connector(commands)
    return [problem.message for problem in refused.value.problems]


def test_a_command_that_promises_a_key_must_send_it():
    lying = PAY.replace('    headers: { Idempotency-Key: "{{ idempotency.key }}" }\n', "")
    assert any(
        '"idempotency_key: true" is for a command that sends {{ idempotency.key }}' in line
        for line in problems_of(lying)
    )
    # The key is for what is sent: it is not read back from an answer.
    leaking = PAY + '  outputs: { key: "{{ idempotency.key }}" }\n'
    assert any('"idempotency" cannot be read in what is read from the answer' in line for line in problems_of(leaking))


def test_every_try_of_a_step_sends_the_same_key_and_another_step_another():
    found = connector(PAY)
    run, other = SimpleNamespace(id="run-1"), SimpleNamespace(id="run-2")

    def call(run, step_id: str) -> actions.Call:
        return actions.Call(
            db=None,
            args={},
            classes=frozenset(),
            arg_classes={},
            dry_run=False,
            run=run,
            playbook=None,
            step_id=step_id,
        )

    first = connector_actions.idempotency_key(call(run, "step-1"), "pay")
    assert first == connector_actions.idempotency_key(call(run, "step-1"), "pay")  # a retry, a try after a restart
    assert len(first) == 32 and all(letter in "0123456789abcdef" for letter in first)
    others = {
        connector_actions.idempotency_key(call(run, "step-2"), "pay"),
        connector_actions.idempotency_key(call(other, "step-1"), "pay"),
        connector_actions.idempotency_key(call(run, "step-1"), "refund"),
    }
    assert len(others) == 3 and first not in others
    # Run by hand, with no step: a key of its own each time.
    by_hand = {connector_actions.idempotency_key(call(None, ""), "pay") for _ in range(3)}
    assert len(by_hand) == 3

    # The runtime sends what it was given, in the header the file names.
    wire = Wire().answer(200, {"ok": True}).answer(200, {"ok": True})
    for _ in range(2):
        held = runtime(found, wire)
        held.idempotency_key = first
        held.run("pay", {"amount": 10})
    assert [sent["headers"]["Idempotency-Key"] for sent in wire.sent] == [first, first]


def test_a_timer_that_ran_out_while_the_server_was_stopped_fires_late_with_its_real_time(admin: TestClient):
    person(admin, "anna", ["analyst"])
    sla(admin, [{"field": "time_to_contain", "minutes": 60}])
    incident(admin, assignee="anna")
    with SessionLocal() as db:
        started = db.get(Incident, "i1").fields["time_to_contain"]["started_at"]
    # The hour ran out while the worker was stopped; it is back two hours after that.
    assert tick(started + 3 * 3600) == 1
    assert tick(started + 3 * 3600 + 60) == 0  # once, however late
    # Its time is when it ran out, not when the worker came back and found it.
    ran_out = datetime.fromtimestamp(started + 3600, timezone.utc)
    assert shown(admin)["time_to_contain"]["breachedAt"] == ran_out.isoformat()
    room = admin.get("/api/incidents/i1/war-room").json()["entries"]
    since = ran_out.strftime("%Y-%m-%d %H:%M UTC")
    assert [entry["body"]["text"] for entry in room if entry["kind"] == "system"] == [
        f"Time to contain is past its time (60 min), since {since}: it was noticed late"
    ]
    with SessionLocal() as db:
        (event,) = db.scalars(select(AutomationEvent).where(AutomationEvent.kind == "sla.breached")).all()
        # What playbooks read says how late it is: an hour allowed, three counted.
        assert event.payload["data"]["timer"]["due_minutes"] == 60
        assert event.payload["data"]["timer"]["elapsed_minutes"] == 180


def test_a_fetch_cut_in_the_middle_of_a_cycle_goes_on_and_no_alert_becomes_two_incidents(
    admin: TestClient, outside, monkeypatch
):
    from app import fetch
    from app.core.models import Connection, FetchedItem
    from tests.test_fetch import incidents, mapped, radar

    class Killed(BaseException):
        """The process stopped here."""

    connection = radar(admin, outside)
    mapped(admin)
    admin.put(f"/api/fetch/{connection['id']}", json={"enabled": True})
    ingest, made = fetch.ingest, []

    def dies_after_the_first(*args, **kwargs):
        if len(made) == 1:
            raise Killed
        made.append(1)
        return ingest(*args, **kwargs)

    monkeypatch.setattr(fetch, "ingest", dies_after_the_first)
    with pytest.raises(Killed):
        fetch.run(connection["id"])
    # One alert became an incident, in a commit of its own; the place of the cycle did not move.
    assert sorted(incidents(admin)) == ["Emotet on WKS-01"]
    with SessionLocal() as db:
        assert [item.item_id for item in db.scalars(select(FetchedItem))] == ["A-1"]
        assert "last_time" not in (db.get(Connection, connection["id"]).fetch_state or {})
    # The worker that starts next runs the cycle again from where the last whole one reached: what
    # was made is found by its id and left alone, the rest is made.
    monkeypatch.setattr(fetch, "ingest", ingest)
    fetch.run(connection["id"])
    fetch.run(connection["id"])
    assert sorted(incidents(admin)) == ["Emotet on WKS-01", "Phishing page opened", "Port scan"]
    with SessionLocal() as db:
        assert sorted(item.item_id for item in db.scalars(select(FetchedItem))) == ["A-1", "A-2", "A-3"]


def test_two_steps_that_use_a_key_for_the_first_time_at_once_both_count(admin: TestClient, outside, monkeypatch):
    from app.automation import instance_keys
    from app.core.models import InstanceKeyUse
    from tests.test_fetch import radar

    connection_id = radar(admin, outside)["id"]
    with SessionLocal() as one:
        instance_keys._use(one, connection_id, "main")
        one.commit()
    with SessionLocal() as two:
        # The second step looked before the first one committed: it saw no row, and adds one.
        looked, really = [], two.get

        def not_yet(entity, ident, **more):
            looked.append(ident)
            return None if len(looked) == 1 else really(entity, ident, **more)

        monkeypatch.setattr(two, "get", not_yet)
        row = instance_keys._use(two, connection_id, "main")
        assert row is not None and len(looked) == 2  # no error: the row that is there is the one
        row.total = 2
        two.commit()
    with SessionLocal() as db:
        assert [(found.key_id, found.total) for found in db.scalars(select(InstanceKeyUse))] == [("main", 2)]


def test_every_shipped_command_that_changes_something_says_whether_it_may_be_repeated():
    """After a restart a command that says nothing is done again: for one that changes another system
    that must be a decision written in its file, never the default."""
    from pathlib import Path

    import yaml

    from tests.vendor import REPO_PACKS

    seed = Path(cn.__file__).resolve().parent / "seed" / "connectors"
    files = sorted(REPO_PACKS.glob("*/connectors/*/connector.yml")) + sorted(seed.glob("*/connector.yml"))
    assert len(files) > 20
    silent = [
        f"{path.parent.name}: {command['name']}"
        for path in files
        for command in yaml.safe_load(path.read_text(encoding="utf-8")).get("commands") or []
        if command.get("changes_outside") is True and "idempotent" not in command and not command.get("idempotency_key")
    ]
    assert silent == []

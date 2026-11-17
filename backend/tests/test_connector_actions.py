"""Connector commands as nodes of a playbook: the connection, the guard, dry runs, commands that wait."""

from __future__ import annotations

import json
import textwrap

import pytest
from fastapi.testclient import TestClient

from app.automation import connector_actions as ca
from app.automation import connectors as cn
from app.automation import worker
from app.core.db import SessionLocal
from app.core.models import Connection, Connector, RunStep
from app.core.security import now_iso
from tests.test_automation_engine import T0, edge, go, incident, node, playbook, run_of, start, steps

ACME = textwrap.dedent(
    """\
    name: Acme Desk
    id: acme
    version: 2
    description: Tickets in Acme Desk.
    configuration:
      - { name: url, type: url, required: true }
      - { name: credentials, type: basic }
    base_url: "{{ config.url }}"
    test:
      request: { method: GET, path: /me }
    commands:
      - name: create-ticket
        description: Open a ticket.
        changes_outside: true
        idempotent: false
        arguments:
          - { name: title, type: text, required: true }
          - { name: urgency, type: choice, choices: ["1", "2"], default: "2" }
        request:
          method: POST
          path: /tickets
          json: { title: "{{ args.title }}", urgency: "{{ args.urgency }}" }
        success: { status: 201 }
        outputs: { number: "{{ response.number }}" }
        sample: { number: T-0000 }
      - name: get-ticket
        arguments: [{ name: number, type: text, required: true }]
        request: { method: GET, path: "/tickets/{{ args.number }}" }
        outputs: { state: "{{ response.state }}" }
      - name: close-and-wait
        changes_outside: true
        arguments: [{ name: number, type: text, required: true }]
        steps:
          - name: close
            request: { method: POST, path: "/tickets/{{ args.number }}/close", json: {} }
          - name: closed
            request: { method: GET, path: "/jobs/{{ steps.close.response.job }}" }
            poll:
              until: { all: [{ left: "{{ response.state }}", op: eq, right: done }] }
              every: 10
              timeout: 120
        outputs: { job: "{{ steps.close.response.job }}", state: "{{ steps.closed.response.state }}" }
    """
)


@pytest.fixture()
def acme(admin: TestClient, outside):
    """The connector installed, a connection to it, and its host answering."""
    outside.host("desk.example.com", "93.184.215.20")
    with SessionLocal() as db:
        ca.install(db, ACME, "admin")
        connection = Connection(
            id="c" * 32,
            name="Acme production",
            connector_id="acme",
            config={"url": "https://desk.example.com/api"},
            created_at=now_iso(),
            updated_at=now_iso(),
        )
        ca.store_secrets(connection, {"username": "svc", "password": "s3cret-pass"})
        db.add(connection)
        db.commit()
    return outside


def command(node_id: str, name: str, connection: str = "Acme production", **args):
    return node(node_id, "action", action=f"acme.{name}", connection=connection, args=args, approval={"ask": False})


def test_the_commands_of_an_installed_connector_are_in_the_library(admin: TestClient, acme):
    entries = {entry["id"]: entry for entry in admin.get("/api/automation/catalog").json()["nodes"]}
    create = entries["acme.create-ticket"]
    assert (create["group"], create["name"], create["changesOutside"]) == ("Acme Desk", "create-ticket", True)
    assert (create["connector"], create["connectorVersion"], create["needsConnection"]) == ("acme", 2, True)
    assert [argument["name"] for argument in create["arguments"]] == ["title", "urgency"]
    assert create["outputs"] == [{"name": "number", "type": "any", "description": ""}]
    assert "acme.get-ticket" in entries and "acme.nope" not in entries
    # A graph is checked against them like against any action.
    wrong = admin.post("/api/automation/playbooks", json={"name": "Wrong"}).json()["id"]
    shape = {
        "nodes": [node("start", "trigger", manual=True), command("a", "create-ticket")],
        "edges": [edge("start", "a")],
    }
    found = admin.post(f"/api/automation/playbooks/{wrong}/validate", json={"graph": shape}).json()["problems"]
    assert [problem["message"] for problem in found] == ['"title" is required']


def test_a_command_goes_to_its_connection_with_its_credentials(admin: TestClient, acme):
    acme.answer("desk.example.com", 201, {"number": "T-41"}, path="/api/tickets")
    pb = playbook(
        admin,
        "Opens a ticket",
        [command("open", "create-ticket", title="Phishing: {{ inputs.what }}")],
        [edge("start", "open")],
    )
    run = go(admin, pb, inputs={"what": "invoice"})
    step = steps(run)["open"]
    assert run["status"] == "done" and step["output"] == {"number": "T-41"}
    (sent,) = acme.requests
    assert (sent["method"], sent["host"], sent["path"]) == ("POST", "desk.example.com", "/api/tickets")
    assert json.loads(sent["body"]) == {"title": "Phishing: invoice", "urgency": "2"}  # the default of the argument
    assert sent["headers"]["Authorization"].startswith("Basic ")
    # The step says where it went, through which connection; never the credentials.
    assert step["request"]["connection"] == "Acme production" and step["request"]["status"] == 201
    assert "s3cret-pass" not in json.dumps(run)
    # The host of the connection is reached although the playbook lists no host: the connection is the permission.
    assert admin.get(f"/api/automation/playbooks/{pb}").json()["egressHosts"] == []


def test_a_node_needs_a_connection_that_exists(admin: TestClient, acme):
    # A version is not saved while a node names a connection that is not there.
    draft = admin.post("/api/automation/playbooks", json={"name": "No such connection"}).json()["id"]
    shape = {
        "nodes": [
            node("start", "trigger", manual=True),
            command("open", "create-ticket", connection="Acme test", title="x"),
        ],
        "edges": [edge("start", "open")],
    }
    refused = admin.post(f"/api/automation/playbooks/{draft}/versions", json={"graph": shape})
    assert refused.status_code == 422
    assert refused.json()["problems"] == [
        {"message": "This connection does not exist", "node": "open", "field": "connection"}
    ]
    # With one connection only, a node that names none uses it.
    one = playbook(
        admin, "The only one", [command("open", "get-ticket", connection="", number="T-1")], [edge("start", "open")]
    )
    acme.answer("desk.example.com", 200, {"state": "open"}, path="/api/tickets/T-1")
    assert steps(go(admin, one))["open"]["output"] == {"state": "open"}
    with SessionLocal() as db:
        db.add(
            Connection(
                id="d" * 32,
                name="Acme test",
                connector_id="acme",
                config={"url": "https://desk.example.com/t"},
                created_at=now_iso(),
                updated_at=now_iso(),
            )
        )
        db.commit()
    # With two it must choose: the version that ran is now refused at its step, and a new one at saving.
    assert steps(go(admin, one))["open"]["error"].startswith("Choose a connection")
    shape["nodes"][1]["config"]["connection"] = ""
    again = admin.post(f"/api/automation/playbooks/{draft}/versions", json={"graph": shape})
    assert again.json()["problems"][0]["message"] == "Choose the connection to send through"
    # A connection deleted after the version was saved: the step says which one is missing.
    shape["nodes"][1]["config"]["connection"] = "Acme test"
    assert admin.post(f"/api/automation/playbooks/{draft}/versions", json={"graph": shape}).status_code == 201
    with SessionLocal() as db:
        db.delete(db.get(Connection, "d" * 32))
        db.commit()
    acme.requests.clear()
    run = go(admin, draft)
    assert run["status"] == "failed" and acme.requests == []
    assert (
        steps(run)["open"]["error"]
        == 'The connection "Acme test" does not exist: Acme Desk needs one to know where to send'
    )


def test_a_dry_run_sends_nothing_and_gives_the_sample(admin: TestClient, acme):
    pb = playbook(
        admin,
        "Dry",
        [command("open", "create-ticket", title="x"), command("read", "get-ticket", number="{{ open.number }}")],
        [edge("start", "open"), edge("open", "read")],
    )
    run = go(admin, pb, dryRun=True)
    assert run["status"] == "done" and acme.requests == []
    assert steps(run)["open"]["output"] == {"number": "T-0000"}  # the sample of the command
    assert steps(run)["open"]["request"] == {
        "method": "POST",
        "host": "desk.example.com",
        "path": "/api/tickets",
        "dry_run": True,
        "held": steps(run)["open"]["request"]["held"],
        "connection": "Acme production",
    }
    # A command without a sample gives its outputs empty, so that what follows can still be read.
    assert steps(run)["read"]["output"] == {"state": None}
    assert steps(run)["read"]["request"]["path"] == "/api/tickets/T-0000"


def test_the_data_guard_judges_what_a_command_would_send(admin: TestClient, acme):
    incident(admin, "inc-guard", name="Laptop of Mario Rossi")
    acme.answer("desk.example.com", 201, {"number": "T-42"}, path="/api/tickets")
    pb = playbook(
        admin,
        "Leaks a name",
        [command("open", "create-ticket", title="{{ trigger.incident.name }}")],
        [edge("start", "open")],
    )
    run = go(admin, pb, objectKind="incident", objectId="inc-guard")
    # The name of an incident is a class that is closed until an admin opens it for the playbook.
    assert run["status"] == "failed" and acme.requests == []
    assert steps(run)["open"]["error"].startswith("Held back: incident names and tickets.")
    opened = admin.put(
        f"/api/automation/playbooks/{pb}/data-allow",
        json={"class": "incident_text", "allow": True, "acknowledged": True, "confirmName": "Leaks a name"},
    )
    assert opened.status_code == 200
    assert go(admin, pb, objectKind="incident", objectId="inc-guard")["status"] == "done"
    assert json.loads(acme.requests[0]["body"])["title"] == "Laptop of Mario Rossi"


def test_a_refusal_is_not_tried_again_and_an_unknown_outcome_is_said(admin: TestClient, acme):
    acme.answer("desk.example.com", 422, {"error": "no"}, path="/api/tickets")
    retrying = {"on_error": {"mode": "retry", "times": 3}}
    pb = playbook(
        admin,
        "Refused",
        [
            {
                **command("open", "create-ticket", title="x"),
                "config": {**command("open", "create-ticket", title="x")["config"], **retrying},
            }
        ],
        [edge("start", "open")],
    )
    run = go(admin, pb)
    assert run["status"] == "failed" and steps(run)["open"]["error"] == "Acme Desk answered 422"
    assert steps(run)["open"]["attempt"] == 1 and len(acme.requests) == 1
    # A 503 on a command that changes something and is not idempotent: the other side may have acted.
    acme.requests.clear()
    acme.answer("desk.example.com", 503, {}, path="/api/tickets")
    run = go(admin, pb)
    assert "outcome unknown: it is not tried again" in steps(run)["open"]["error"] and len(acme.requests) == 1


def test_a_command_that_waits_gives_the_step_back_and_goes_on_later(admin: TestClient, acme):
    state = {"value": "running"}
    acme.answer("desk.example.com", 200, {"job": "j-7"}, path="/api/tickets/T-9/close")
    acme.answers.append(
        lambda method, host, path, headers, body: (
            (200, {"content-type": "application/json"}, json.dumps({"state": state["value"]}).encode())
            if path == "/api/jobs/j-7"
            else None
        )
    )
    pb = playbook(admin, "Closes", [command("close", "close-and-wait", number="T-9")], [edge("start", "close")])
    run_id = start(admin, pb)
    worker.drain(T0)
    step = steps(run_of(admin, run_id))["close"]
    assert step["status"] == "waiting" and step["nextAt"] is not None and step["output"] is None
    assert [sent["path"] for sent in acme.requests] == ["/api/tickets/T-9/close", "/api/jobs/j-7"]
    worker.drain(T0 + 5)  # not yet
    assert len(acme.requests) == 2
    # The close is not sent again: the command goes on from its poll.
    state["value"] = "done"
    with SessionLocal() as db:
        waiting = db.get(RunStep, step["id"])
        waiting.next_at = T0 + 10
        db.commit()
    worker.drain(T0 + 10)
    run = run_of(admin, run_id)
    assert run["status"] == "done" and steps(run)["close"]["output"] == {"job": "j-7", "state": "done"}
    assert [sent["path"] for sent in acme.requests] == ["/api/tickets/T-9/close", "/api/jobs/j-7", "/api/jobs/j-7"]


def test_installing_replaces_a_connector_and_versions_only_go_up(admin: TestClient):
    with SessionLocal() as db:
        row, connector = ca.install(db, ACME, "anna")
        assert (row.id, row.version, row.builtin, row.created_by) == ("acme", 2, False, "anna")
        assert ca.secret_names(connector) == ["username", "password"]
        assert ca.host_of(connector, {"url": "https://Desk.Example.com:8443/api"}) == "desk.example.com:8443"
        assert ca.host_of(connector, {"url": "https://desk.example.com/api"}) == "desk.example.com"
        assert ca.host_of(connector, {}) is None
        newer = ACME.replace("version: 2", "version: 3").replace("Tickets in Acme Desk.", "Tickets.")
        row, _ = ca.install(db, newer, "bruno")
        assert (row.version, row.updated_by, row.created_by) == (3, "bruno", "anna")
        with pytest.raises(cn.ConnectorError) as caught:
            ca.install(db, ACME, "anna")
        assert "Version 3 is installed" in caught.value.problems[0].message
        with pytest.raises(cn.ConnectorError):
            ca.install(db, "name: x\n", "anna")
        assert db.get(Connector, "acme").version == 3
        db.rollback()

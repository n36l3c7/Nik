"""The command line of the War Room: reading a line, running a command, reputation."""

from __future__ import annotations

import dataclasses
import textwrap

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import commands
from app.automation import connector_actions as ca
from app.automation import worker
from app.core.db import SessionLocal
from app.core.models import Connection, Playbook, PlaybookVersion, Run
from app.core.security import now_iso
from app.enrichment import service
from tests.conftest import make_key
from tests.test_automation_engine import test_actions  # noqa: F401 - a fixture
from tests.test_fields import incident
from tests.test_war_room import room

IP = "185.220.101.47"


def typed(admin: TestClient, line: str, incident_id: str = "i1", **more):
    return admin.post(f"/api/incidents/{incident_id}/war-room/command", json={"line": line, **more})


def ran(admin: TestClient, line: str, **more) -> dict:
    """Type a command, let the engine run it, and give back the entry of its result."""
    answer = typed(admin, line, **more)
    assert answer.status_code == 201, answer.text
    worker.drain()
    entries = room(admin)
    result = next(entry for entry in entries if entry["parentId"] == answer.json()["id"])
    return admin.get(f"/api/incidents/i1/war-room/{result['id']}").json()


# --------------------------------------------------------------------------- #
# Reading a line                                                              #
# --------------------------------------------------------------------------- #
def test_a_line_is_a_note_a_slash_command_or_a_command():
    assert commands.parse("  Called the user.  ") == commands.Parsed(kind="note", text="Called the user.")
    assert commands.parse("/note It was a test") == commands.Parsed(kind="slash", name="note", text="It was a test")
    assert commands.parse("/assign @anna").text == "@anna" and commands.parse("/CLOSE").name == "close"
    parsed = commands.parse('!servicenow-get-incident number=INC001 using="ServiceNow prod" raw=true extend=tmp')
    assert (parsed.kind, parsed.name, parsed.args) == ("command", "servicenow-get-incident", {"number": "INC001"})
    assert (parsed.using, parsed.raw, parsed.extend) == ("ServiceNow prod", True, "tmp")
    # A quoted value keeps its spaces; a JSON between backticks is what it says; an expression is one word.
    parsed = commands.parse(
        """!x a="two words" b='it''s' c=`{"k": [1, 2]}`"""
        """ d=${context.Mail[0].Subject} e={{ incident.name | upper }} f=1,2"""
    )
    assert parsed.args == {
        "a": "two words",
        "b": "it",
        "c": {"k": [1, 2]},
        "d": "${context.Mail[0].Subject}",
        "e": "{{ incident.name | upper }}",
        "f": "1,2",
    }
    assert parsed.positional == ["s"]  # what followed the closed quote
    assert commands.parse("!ip 185.220.101.47").positional == ["185.220.101.47"]
    assert commands.parse(r'!x a="say \"hi\""').args == {"a": 'say "hi"'}
    wrong = {
        "": "Nothing was written",
        "   ": "Nothing was written",
        "/dance": "A / command is one of: /note, /assign, /close, /task",
        "!": "After ! comes the name of a command",
        "! ip": "After ! comes the name of a command",
        '!x a="open': "A quote is not closed",
        "!x a=`{bad`": "What is between ` ` is not valid JSON",
        "!x a=${context.x": "An expression is not closed: } is missing",
        "!x a=1 a=2": '"a" is given twice',
        "!x a= b=1": '"a=" has no value',
    }
    for line, why in wrong.items():
        with pytest.raises(commands.CommandError) as caught:
            commands.parse(line)
        assert caught.value.message == why, line


# --------------------------------------------------------------------------- #
# Notes and slash commands                                                    #
# --------------------------------------------------------------------------- #
def test_plain_text_and_slash_commands(admin: TestClient):
    incident(admin)
    note = typed(admin, "Called the user.")
    assert note.status_code == 201 and note.json()["kind"] == "note"
    assert typed(admin, "/note The laptop is in the safe.").json()["body"]["text"] == "The laptop is in the safe."
    assert [n["text"] for n in admin.get("/api/incidents/i1").json()["notes"]] == [
        "Called the user.",
        "The laptop is in the safe.",
    ]
    assigned = typed(admin, "/assign @admin")
    assert assigned.status_code == 201 and assigned.json()["action"] == "assigned"
    assert admin.get("/api/incidents/i1").json()["assignee"] == "admin"
    assert room(admin)[-1]["body"]["text"] == "admin assigned the incident to admin"
    assert typed(admin, "/assign @nobody").json()["detail"] == "Owner: there is no account called nobody"
    assert (
        typed(admin, "/assign").status_code == 201 and admin.get("/api/incidents/i1").json().get("assignee", "") == ""
    )
    assert typed(admin, "/close").json() == {"action": "close"}
    assert typed(admin, "/task Call the bank").json()["action"] == "task"
    assert typed(admin, "/task").json()["detail"].startswith("/task is followed by what to do")
    assert typed(admin, "/note").json()["detail"] == "/note is followed by the note"
    assert typed(admin, "/dance").status_code == 400 and typed(admin, "x", "nope").status_code == 404

    # A viewer reads the War Room and writes nothing in it; an analyst writes and runs.
    viewer = make_key(admin, label="v", roles=["viewer"])
    for line in ("A note", "/assign @admin", "!ip 8.8.8.8"):
        refused = admin.post("/api/incidents/i1/war-room/command", headers=viewer, json={"line": line})
        assert refused.status_code == 403, line
    builder = make_key(admin, label="b", roles=["viewer", "playbooks"])
    assert admin.post("/api/incidents/i1/war-room/command", headers=builder, json={"line": "A note"}).status_code == 403
    assert (
        admin.post(
            "/api/incidents/i1/war-room/command", headers=builder, json={"line": "!test-echo text=x"}
        ).status_code
        == 201
    )


# --------------------------------------------------------------------------- #
# Commands                                                                    #
# --------------------------------------------------------------------------- #
def test_a_command_is_a_run_of_one_node_and_its_result_is_under_it(admin: TestClient):
    incident(admin, severity="high")
    detail = ran(admin, "!test-echo text=${incident.name} extra={{ incident.severity | upper }}")
    assert detail["kind"] == "result" and detail["body"]["adhoc"] is True and detail["body"]["what"] == "test.echo"
    assert detail["step"]["output"] == {"text": "Laptop of finance", "extra": "HIGH"}
    listed = room(admin, show="commands")
    assert [entry["body"]["line"] for entry in listed] == [
        "!test-echo text=${incident.name} extra={{ incident.severity | upper }}"
    ]
    assert listed[0]["author"] == "admin" and listed[0]["runId"] == detail["runId"]
    with SessionLocal() as db:
        run = db.get(Run, detail["runId"])
        assert (run.trigger["kind"], run.incident_id, run.started_by, run.status) == ("adhoc", "i1", "admin", "done")
        # It ran as the playbook of the War Room, which is never listed, opened or turned on.
        playbook = db.get(Playbook, commands.ADHOC_ID)
        assert (playbook.enabled, playbook.egress_mode, playbook.data_allow, playbook.approval_default) == (
            False,
            "listed",
            [],
            False,
        )
        assert db.scalar(select(PlaybookVersion.note).where(PlaybookVersion.playbook_id == playbook.id)).startswith(
            "!test-echo"
        )
    assert commands.ADHOC_NAME not in [p["name"] for p in admin.get("/api/automation/playbooks").json()["playbooks"]]
    assert admin.get(f"/api/automation/playbooks/{commands.ADHOC_ID}").status_code == 404
    assert (
        admin.put(f"/api/automation/playbooks/{commands.ADHOC_ID}/enabled", json={"enabled": True}).status_code == 404
    )
    assert any(e["action"] == "warroom.command" for e in admin.get("/api/audit").json()["entries"])

    # The first argument can be given without its name; a number, a list and yes/no are read as such.
    assert ran(admin, "!test-echo hello")["step"]["output"]["text"] == "hello"
    assert ran(admin, "!nik-add-tags indicators=evil.example tags=c2,phishing")["step"]["output"] == {"tagged": 1}

    def refused(line: str) -> str:
        answer = typed(admin, line)
        assert answer.status_code == 400, answer.text
        return answer.json()["detail"]

    assert refused("!no-such-thing x=1") == 'There is no command called "no-such-thing": type ! to see those there are'
    assert refused("!test-echo colour=red") == '"colour" is not an argument of this command: text, extra'
    assert refused("!test-echo") == "Needed: text="
    assert refused("!test-echo a b") == "A value with no name is the first argument: give the others as name=value"
    assert refused("!test-echo x text=y") == '"text" is given twice'
    assert refused("!test-echo text=x using=Desk") == "test-echo uses no instance: using= does not apply"
    # A command that fails says so under its line.
    failed = ran(admin, "!test-never")
    assert failed["kind"] == "error" and failed["body"]["error"] == "Refused by the other side"

    # With automation stopped nothing is started.
    admin.put("/api/automation/state", json={"enabled": False})
    assert typed(admin, "!test-echo text=x").status_code == 409
    admin.put("/api/automation/state", json={"enabled": True})


def test_a_command_that_changes_something_outside_asks_first(admin: TestClient):
    incident(admin)
    asked = typed(admin, "!test-block host=evil.example")
    assert asked.status_code == 409
    assert asked.json() == {
        "detail": "test-block changes something outside Nik: confirm to run it",
        "needsConfirm": True,
        "command": "test-block",
    }
    assert room(admin) == []  # nothing was written, nothing ran
    done = ran(admin, "!test-block host=evil.example", confirm=True)
    assert done["step"]["output"] == {"blocked": "evil.example"}


DESK = textwrap.dedent(
    """\
    name: Acme Desk
    id: acme-desk
    version: 1
    configuration:
      - { name: url, type: url, required: true }
      - { name: credentials, type: basic }
    base_url: "{{ config.url }}"
    commands:
      - name: get-ticket
        arguments:
          - { name: number, type: text, required: true }
          - { name: full, type: bool }
        request: { method: GET, path: "/tickets/{{ args.number }}", query: { full: "{{ args.full }}" } }
        outputs: { state: "{{ response.state }}" }
        context:
          - path: Ticket
            value: { ID: "{{ response.id }}", Number: "{{ args.number }}", Status: "{{ response.state }}" }
      - name: check-ip
        reputation: ip
        arguments: [{ name: address, type: text, required: true }]
        request: { method: GET, path: "/intel/{{ args.address }}" }
        outputs: { verdict: "{{ response.verdict }}", summary: "{{ response.note }}" }
    """
)


@pytest.fixture()
def desk(admin: TestClient, outside):
    outside.host("desk.example.com", "93.184.215.20")
    outside.host("desk2.example.com", "93.184.215.21")
    with SessionLocal() as db:
        ca.install(db, DESK, "admin")
        for index, (name, host) in enumerate((("Desk", "desk.example.com"), ("Desk test", "desk2.example.com"))):
            row = Connection(
                id=f"{index}" * 32,
                name=name,
                connector_id="acme-desk",
                config={"url": f"https://{host}"},
                created_at=now_iso(),
                updated_at=now_iso(),
            )
            ca.store_secrets(row, {"username": "svc", "password": "s3cret-pass"})
            db.add(row)
        db.commit()
    return outside


def test_a_command_of_a_connector_names_its_connection_and_writes_to_the_context(admin: TestClient, desk):
    incident(admin)
    desk.answer("desk.example.com", 200, {"id": "t-9", "state": "open"}, path="/tickets/T-9")
    # A connector id may hold a dash; with two connections, which one is asked.
    # An instance that is off is not one a command can use.
    with SessionLocal() as db:
        for row in db.scalars(select(Connection)):
            row.enabled = row.name != "Desk test"
        db.commit()
    refused = typed(admin, '!acme-desk-get-ticket number=T-1 using="Desk test"').json()["detail"]
    assert refused.startswith("There is no such instance")
    with SessionLocal() as db:
        for row in db.scalars(select(Connection)):
            row.enabled = True
        db.commit()
    which = typed(admin, "!acme-desk-get-ticket number=T-9")
    assert which.json()["detail"] == 'Which connection? using="Desk" or using="Desk test"'
    assert typed(admin, "!acme-desk-get-ticket number=T-9 using=Nope").json()["detail"] == (
        "There is no such instance: Desk, Desk test"
    )
    detail = ran(admin, "!acme-desk-get-ticket T-9 full=yes using=desk")
    assert detail["author"] == "connector:acme-desk" and detail["step"]["output"] == {"state": "open"}
    assert detail["step"]["request"]["connection"] == "Desk" and "full=true" in str(desk.requests[-1]["path"])
    assert "written to the context: Ticket:t-9" in detail["step"]["log"]
    context = admin.get("/api/incidents/i1/context").json()
    assert context["context"]["Ticket"] == [{"ID": "t-9", "Number": "T-9", "Status": "open"}]
    assert context["provenance"]["Ticket:t-9"]["source"] == "connector:acme-desk"

    # extend= keeps the result out of the context.
    desk.answer("desk.example.com", 200, {"id": "t-10", "state": "new"}, path="/tickets/T-10")
    kept = ran(admin, "!acme-desk-get-ticket number=T-10 using=Desk extend=tmp")
    assert kept["step"]["output"] == {"state": "new"} and "written to the context" not in (kept["step"]["log"] or "")
    assert len(admin.get("/api/incidents/i1/context").json()["context"]["Ticket"]) == 1

    # The library, as the command line completes it.
    listed = admin.get("/api/automation/catalog?prefix=acme").json()["commands"]
    assert [item["name"] for item in listed] == ["acme-desk-check-ip", "acme-desk-get-ticket"]
    assert listed[1]["needsConnection"] is True and listed[1]["arguments"][0]["name"] == "number"
    every = {item["name"] for item in admin.get("/api/automation/catalog").json()["commands"]}
    assert {"ip", "domain", "url", "file", "email", "nik-add-note", "test-echo"} <= every
    assert "nik-reputation" not in every and not any(name.startswith("flow") for name in every)


def test_a_reputation_command_asks_nik_s_sources_and_the_connectors_that_look_it_up(
    admin: TestClient, desk, monkeypatch
):
    service.limiter.reset()
    incident(admin)
    fake = dataclasses.replace(
        service.BY_ID["virustotal"], lookup=lambda *a: {"verdict": "malicious", "summary": "7 engines"}, interval=0
    )

    def check_now(db, kind, value, shared, force=False):
        service.lookup_one(db, fake, kind, value, None)
        return {"results": [], "skipped": [{"provider": "otx", "label": "OTX", "reason": "no key"}]}

    monkeypatch.setattr(service, "check_now", check_now)
    desk.answer("desk.example.com", 200, {"verdict": "Suspicious", "note": "seen twice"}, path=f"/intel/{IP}")
    desk.answer("desk2.example.com", 500, {}, path=f"/intel/{IP}")
    detail = ran(admin, f"!ip {IP}")
    out = detail["step"]["output"]
    assert (out["kind"], out["value"], out["verdict"]) == ("ip", IP, "malicious") and out["score"] >= 50
    by_source = {item["source"]: item for item in out["sources"]}
    assert by_source["Acme Desk (Desk)"] == {
        "source": "Acme Desk (Desk)",
        "verdict": "suspicious",
        "summary": "seen twice",
    }
    assert any(item["verdict"] == "malicious" and item["summary"] == "7 engines" for item in out["sources"])
    reasons = {item["source"]: item["reason"] for item in out["skipped"]}
    assert reasons["OTX"] == "no key" and "Acme Desk (Desk test)" in reasons
    # One verdict for the indicator, in the context of the incident.
    context = admin.get("/api/incidents/i1/context").json()["context"]
    assert context["IP"] == [{"Address": IP, "Verdict": "malicious", "Score": out["score"]}]

    # What was looked up is an indicator of the incident from then on, once.
    def held():
        return {(i["type"], i["value"]): i for i in admin.get("/api/incidents/i1/iocs").json()["iocs"]}

    assert held()[("ip", IP)]["sources"] == ["warroom"]
    again = typed(admin, f"!ip {IP}")
    assert again.status_code == 201 and "indicator" not in again.json()
    worker.drain()
    assert held()[("ip", IP)]["count"] == 1
    added = typed(admin, "!url https://Evil.example.net/a?b=1")
    assert added.json()["indicator"] == {"type": "url", "value": "https://Evil.example.net/a?b=1"}
    worker.drain()
    assert ("url", "https://Evil.example.net/a?b=1") in held() and ("domain", "evil.example.net") in held()
    hashed = typed(admin, "!file " + "AB" * 16)
    assert hashed.json()["indicator"] == {"type": "md5", "value": "ab" * 16}
    worker.drain()
    # What is not an indicator, or is written with an expression, adds nothing.
    for line in ("!domain not_a_domain", "!file invoice.exe", "!ip {{ incident.host }}"):
        assert "indicator" not in typed(admin, line).json(), line
    worker.drain()
    doc = admin.get("/api/incidents/i1").json()
    assert [(e["type"], e["source"], e["by"]) for e in doc["data"]["iocs"]["manual"]] == [
        ("ip", "warroom", "admin"),
        ("url", "warroom", "admin"),
        ("md5", "warroom", "admin"),
    ]

    # An address of the inside is never sent, to Nik's sources or to a connector.
    sent = len(desk.requests)
    inside = ran(admin, "!ip 10.1.2.3")["step"]["output"]
    assert inside["verdict"] == "" and len(desk.requests) == sent
    assert inside["skipped"][0]["source"] == "reputation sources"
    assert any(item["source"].startswith("Acme Desk") for item in inside["skipped"])

    # A file is told by its hash; what is not an indicator of the kind is said.
    assert ran(admin, "!file " + "a" * 64)["step"]["output"]["kind"] == "sha256"
    assert ran(admin, "!file invoice.exe")["body"]["error"] == "That is not a file hash (MD5, SHA-1 or SHA-256)"
    assert ran(admin, "!domain not_a_domain")["body"]["error"].startswith("That is not a domain")
    assert typed(admin, "!ip").json()["detail"] == "!ip takes one value: !ip <what to look up>"
    assert typed(admin, "!ip 8.8.8.8 extra=1").status_code == 400
    service.limiter.reset()

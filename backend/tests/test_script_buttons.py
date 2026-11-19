"""Script buttons: what a press would run, running it, an argument that holds several values, who may."""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy import select

from app import buttons
from app.automation import worker
from app.core.db import SessionLocal
from app.core.models import Incident, Run
from tests.conftest import make_key
from tests.test_automation_scripts import make_script
from tests.test_fields import field, incident, put
from tests.test_war_room import room

BLOCK = {
    "code": (
        "def main(args):\n"
        "    if args.get('url') == 'http://bad.example/b':\n"
        "        raise ValueError('the gateway refused it')\n"
        "    print('blocking', args.get('address'), args.get('url'))\n"
        "    return {'blocked': args.get('address'), 'url': args.get('url'), 'why': args.get('reason')}\n"
    ),
    "arguments": [
        {"name": "address", "type": "text", "required": True, "description": "The sender"},
        {"name": "url", "type": "text"},
        {"name": "reason", "type": "text", "required": True},
        {"name": "times", "type": "number"},
    ],
    "outputs": [{"name": "blocked", "type": "text"}],
    "test": {"args": {"address": "a@b.example", "reason": "test"}},
}
TEMPLATES = {"address": "{{ sender_address }}", "url": "{{ urls_in_mail }}"}
URLS = ["http://bad.example/a", "http://bad.example/b", "http://bad.example/c"]


def prepared(admin: TestClient) -> None:
    make_script(admin, "BlockSender", BLOCK)
    field(admin, "sender_address", label="Sender address")
    field(admin, "urls_in_mail", "tags", label="URLs in the mail")
    incident(admin, host="WS-0231", username="anna")
    assert put(admin, {"sender_address": "billing@inv0ice.example"}).status_code == 200


def plan(admin: TestClient, headers=None, **body) -> dict:
    answer = admin.post("/api/incidents/i1/script-buttons/plan", headers=headers, json=body)
    assert answer.status_code == 200, answer.text
    return answer.json()


def press(admin: TestClient, **body):
    return admin.post("/api/incidents/i1/script-buttons/run", json={"label": "Block the sender", **body})


def test_the_scripts_a_button_can_run_are_those_with_a_saved_version(admin: TestClient, sandbox):
    make_script(admin, "BlockSender", BLOCK)
    assert admin.post("/api/automation/scripts", json={"name": "OnlyADraft"}).status_code == 201
    listed = admin.get("/api/script-buttons/scripts").json()
    by_name = {item["name"]: item for item in listed["scripts"]}
    assert list(by_name) == ["BlockSender"]  # a draft is not in the library: a button cannot run it
    assert [argument["name"] for argument in by_name["BlockSender"]["arguments"]] == [
        "address",
        "url",
        "reason",
        "times",
    ]
    assert by_name["BlockSender"]["version"] == 1
    # Who arranges the pages of a type chooses a script; who only reads does not see them.
    viewer = make_key(admin, label="v", roles=["viewer"])
    assert admin.get("/api/script-buttons/scripts", headers=viewer).status_code == 403
    analyst = make_key(admin, label="an", roles=["analyst"])
    assert admin.get("/api/script-buttons/scripts", headers=analyst).status_code == 200


def test_a_press_is_planned_on_the_server_from_the_incident(admin: TestClient, sandbox):
    prepared(admin)
    planned = plan(admin, script="BlockSender", args=TEMPLATES)
    by_name = {argument["name"]: argument for argument in planned["arguments"]}
    # A template is filled from the field, and says which; an empty field is asked, and says why.
    assert by_name["address"]["state"] == "filled" and by_name["address"]["value"] == "billing@inv0ice.example"
    assert by_name["address"]["source"] == {"field": "sender_address", "label": "Sender address"}
    assert (
        by_name["url"]["state"] == "ask" and by_name["url"]["problem"] == "URLs in the mail is empty on this incident"
    )
    assert by_name["reason"]["state"] == "ask" and "problem" not in by_name["reason"]
    assert (planned["runs"], planned["each"], planned["missing"]) == (1, None, ["reason"])
    assert (planned["script"], planned["version"], planned["warnAbove"]) == ("BlockSender", 1, 50)

    # The incident itself, by the names people use; text around an expression; a name that is not one.
    planned = plan(
        admin,
        script="BlockSender",
        args={
            "address": "{{ incident.user }}@{{ incident.host | lower }}",
            "url": "{{ incident.url }}",
            "reason": "{{ sender_adress }}",
            "times": "{{ incident.number }}",
        },
    )
    by_name = {argument["name"]: argument for argument in planned["arguments"]}
    assert by_name["address"]["value"] == "anna@ws-0231" and by_name["address"]["source"] is None
    assert by_name["url"]["value"] == "/incident/i1" and by_name["times"]["value"] == 1
    assert by_name["times"]["source"] == {"field": "incident.number", "label": "Number"}
    assert by_name["reason"]["problem"] == '"sender_adress" is not a name that can be read here'

    # A script with no saved version, and one that is not there.
    assert admin.post("/api/automation/scripts", json={"name": "OnlyADraft"}).status_code == 201
    refused = admin.post("/api/incidents/i1/script-buttons/plan", json={"script": "OnlyADraft"})
    assert refused.status_code == 400 and refused.json()["detail"].startswith("OnlyADraft has no saved version")
    assert admin.post("/api/incidents/i1/script-buttons/plan", json={"script": "Gone"}).status_code == 404
    assert admin.post("/api/incidents/nope/script-buttons/plan", json={"script": "BlockSender"}).status_code == 404


def test_a_press_runs_the_script_and_is_written_in_the_war_room_and_the_audit_log(admin: TestClient, sandbox):
    prepared(admin)
    # What is required and was neither filled nor typed stops the press.
    refused = press(admin, script="BlockSender", args=TEMPLATES)
    assert refused.status_code == 400 and refused.json()["detail"] == "Needed: reason"
    # A number is typed as text and reaches the script as a number.
    wrong = press(admin, script="BlockSender", args=TEMPLATES, values={"reason": "x", "times": "often"})
    assert wrong.status_code == 400 and wrong.json()["detail"] == "times is a number"

    # What the page says an argument holds is not trusted: a value sent for a filled argument is ignored.
    answer = press(
        admin,
        script="BlockSender",
        args=TEMPLATES,
        values={"reason": "Invoice {{ incident.name }}", "times": "2", "address": "someone@else.example"},
        expect=1,
    )
    assert answer.status_code == 201, answer.text
    started = answer.json()
    assert (started["script"], started["total"], len(started["runs"])) == ("BlockSender", 1, 1)
    run_id, entry_id = started["runs"][0]["runId"], started["runs"][0]["entryId"]

    # The run is a command of the War Room that nobody typed, with its arguments.
    entry = next(item for item in room(admin, show="commands") if item["id"] == entry_id)
    assert entry["author"] == "admin" and entry["body"]["button"] == "Block the sender"
    assert entry["body"]["line"] == (
        '!BlockSender address=billing@inv0ice.example reason="Invoice {{ incident.name }}" times=`2`'
    )
    following = admin.post("/api/incidents/i1/script-buttons/status", json={"runs": [run_id]}).json()["runs"]
    assert following == [{"runId": run_id, "status": "running"}]

    worker.drain()
    following = admin.post("/api/incidents/i1/script-buttons/status", json={"runs": [run_id, "nope"]}).json()["runs"]
    assert len(following) == 1 and following[0]["status"] == "done" and following[0]["durationMs"] >= 0
    # What was typed is data: an expression in it is not read. The result is under the command.
    assert sandbox[-1]["args"] == {
        "address": "billing@inv0ice.example",
        "reason": "Invoice {{ incident.name }}",
        "times": 2,
    }
    result = next(item for item in room(admin) if item["parentId"] == entry_id)
    detail = admin.get(f"/api/incidents/i1/war-room/{result['id']}").json()
    assert detail["kind"] == "result" and detail["body"]["what"] == "BlockSender"
    assert detail["step"]["output"]["blocked"] == "billing@inv0ice.example"
    assert "blocking billing@inv0ice.example" in detail["step"]["log"]
    with SessionLocal() as db:
        run = db.get(Run, run_id)
        assert (run.trigger["kind"], run.incident_id, run.started_by, run.status) == ("adhoc", "i1", "admin", "done")
    audited = [e for e in admin.get("/api/audit?incidentId=i1").json()["entries"] if e["action"] == "button.run"]
    assert [(e["actor"], e["details"], e["target"]) for e in audited] == [
        ("admin", 'Pressed "Block the sender": ran BlockSender', "BlockSender")
    ]

    # The dialog showed one run; the incident now holds three addresses: the press is not started blind.
    assert put(admin, {"urls_in_mail": URLS}).status_code == 200
    stale = press(admin, script="BlockSender", args=TEMPLATES, values={"reason": "x"}, expect=1)
    assert stale.status_code == 409 and "this would now make 3 runs, not 1" in stale.json()["detail"]


def test_a_field_that_holds_several_values_runs_the_script_once_for_each(admin: TestClient, sandbox):
    prepared(admin)
    assert put(admin, {"urls_in_mail": URLS}).status_code == 200
    planned = plan(admin, script="BlockSender", args=TEMPLATES, values={"reason": "Invoice lure"})
    by_name = {argument["name"]: argument for argument in planned["arguments"]}
    assert (planned["runs"], planned["each"], planned["items"], planned["missing"]) == (3, "url", URLS, [])
    assert (by_name["url"]["state"], by_name["url"]["count"]) == ("filled", 3)
    assert by_name["url"]["source"]["label"] == "URLs in the mail"

    answer = press(admin, script="BlockSender", args=TEMPLATES, values={"reason": "Invoice lure"}, expect=3)
    assert answer.status_code == 201, answer.text
    started = answer.json()["runs"]
    assert [(run["index"], run["item"]) for run in started] == list(enumerate(URLS))
    worker.drain()
    ids = [run["runId"] for run in started]
    following = admin.post("/api/incidents/i1/script-buttons/status", json={"runs": ids}).json()["runs"]
    assert [item["status"] for item in following] == ["done", "failed", "done"]
    assert "the gateway refused it" in following[1]["error"]
    # Each run is its own command, with the value it ran for, and its own line of the audit log.
    lines = [item["body"]["line"] for item in room(admin, show="commands")]
    assert lines == [f'!BlockSender address=billing@inv0ice.example reason="Invoice lure" url={url}' for url in URLS]
    audited = [e["details"] for e in admin.get("/api/audit?incidentId=i1").json()["entries"]]
    assert 'Pressed "Block the sender": ran BlockSender for http://bad.example/b (2 of 3)' in audited
    assert len([line for line in audited if line.startswith('Pressed "Block the sender"')]) == 3

    # The failed one is run again alone.
    again = press(admin, script="BlockSender", args=TEMPLATES, values={"reason": "Invoice lure"}, expect=3, only=[1])
    assert again.status_code == 201 and [run["index"] for run in again.json()["runs"]] == [1]
    assert again.json()["total"] == 3

    # One value alone is that value; a list for an argument that is one keeps the type the script declared.
    assert put(admin, {"urls_in_mail": URLS[:1]}).status_code == 200
    planned = plan(admin, script="BlockSender", args=TEMPLATES)
    assert planned["runs"] == 1 and planned["arguments"][1]["value"] == URLS[0]
    with SessionLocal() as db:
        row = db.get(Incident, "i1")
        declared = {"name": "urls", "type": "list"}
        assert buttons._shaped(declared, "a") == ["a"] and buttons._shaped({"type": "text"}, "a") == "a"
        # Two arguments that hold several values: nobody could tell which go together.
        assert put(admin, {"urls_in_mail": URLS, "affected_hosts": ["a", "b"]}).status_code == 200
        db.refresh(row)
        try:
            buttons.plan(db, row, "BlockSender", {"url": "{{ urls_in_mail }}", "address": "{{ affected_hosts }}"})
        except buttons.ButtonError as error:
            assert error.message.startswith("Two arguments hold several values (address, url)")
        else:
            raise AssertionError("two lists were accepted")
        # Joined into one text, the second is one value again.
        joined = buttons.plan(
            db, row, "BlockSender", {"url": "{{ urls_in_mail }}", "address": '{{ affected_hosts | join(", ") }}'}
        )
        assert len(joined.runs) == 3 and joined.runs[0]["address"] == "a, b"


def test_who_may_press_a_button(admin: TestClient, sandbox):
    prepared(admin)
    body = {"script": "BlockSender", "args": TEMPLATES, "values": {"reason": "x"}}
    # Reading an incident is not running scripts on it, whatever else the account may do.
    for roles in (["viewer"], ["viewer", "rules"]):
        key = make_key(admin, label="-".join(roles), roles=roles)
        for route in ("plan", "run"):
            refused = admin.post(f"/api/incidents/i1/script-buttons/{route}", headers=key, json=body)
            assert refused.status_code == 403, (roles, route)
        assert admin.post("/api/incidents/i1/script-buttons/status", headers=key, json={"runs": []}).status_code == 403
    # Who runs playbooks and reads no incident is told so.
    builder = make_key(admin, label="b", roles=["playbooks"])
    refused = admin.post("/api/incidents/i1/script-buttons/plan", headers=builder, json=body)
    assert refused.status_code == 403 and refused.json()["detail"] == "Your roles do not include reading incidents"
    # An analyst reads incidents and runs scripts.
    analyst = make_key(admin, label="an", roles=["analyst"])
    assert admin.post("/api/incidents/i1/script-buttons/run", headers=analyst, json=body).status_code == 201
    # With automation stopped nothing starts.
    assert admin.put("/api/automation/state", json={"enabled": False}).status_code == 200
    stopped = admin.post("/api/incidents/i1/script-buttons/run", headers=analyst, json=body)
    assert stopped.status_code == 409 and stopped.json()["detail"].startswith("Automation is stopped")
    with SessionLocal() as db:
        assert len(db.scalars(select(Run).where(Run.incident_id == "i1")).all()) == 1


def test_the_line_of_a_run_reads_back_as_the_command_it_is():
    line = buttons.command_line("Say", {"a": "one", "b": "two words", "c": 'a "quote"', "d": [1, 2], "e": True})
    assert line == '!Say a=one b="two words" c="a \\"quote\\"" d=`[1, 2]` e=`true`'
    from app import commands

    parsed = commands.parse(line)
    assert parsed.args == {"a": "one", "b": "two words", "c": 'a "quote"', "d": [1, 2], "e": True}

"""The context of an incident: paths, the merge by key, provenance, what playbooks read and write."""

from __future__ import annotations

import textwrap

import pytest
from fastapi.testclient import TestClient

from app import context as ctx
from app.automation import connector_actions as ca
from app.automation import connectors as cn
from app.core.db import SessionLocal
from app.core.models import Connection, Incident, IncidentContext
from app.core.security import now_iso
from tests.conftest import make_key
from tests.test_automation_engine import (  # noqa: F401 - test_actions is a fixture
    edge,
    go,
    node,
    playbook,
    steps,
    test_actions,
)
from tests.test_fields import incident
from tests.test_mail import no_dns, phishing_message  # noqa: F401 - no_dns is a fixture
from tests.test_malware import fake_pe


def write(incident_id: str, writes: list, source: str = "run:r1") -> list[str]:
    with SessionLocal() as db:
        touched = ctx.apply(db, db.get(Incident, incident_id), writes, source)
        db.commit()
        return touched


def held(admin: TestClient, incident_id: str = "i1") -> dict:
    answer = admin.get(f"/api/incidents/{incident_id}/context")
    assert answer.status_code == 200, answer.text
    return answer.json()


# --------------------------------------------------------------------------- #
# Paths                                                                       #
# --------------------------------------------------------------------------- #
def test_a_context_path_has_three_forms_and_nothing_else_is_parsed():
    assert ctx.parse("Ticket") == ctx.Path(kind="entity", entity="Ticket")
    assert ctx.parse("Ticket(val.ID == obj.ID)").keys == ("ID",)
    assert ctx.parse("Process(val.PID == obj.PID && val.Host == obj.Host)").keys == ("PID", "Host")
    assert ctx.parse("Ticket.Status").sub == ("Status",)
    assert ctx.parse("ext.servicenow.sys_class") == ctx.Path(kind="ext", connector="servicenow", name="sys_class")
    assert ctx.parse("incident.severity") == ctx.Path(kind="field", name="severity")
    wrong = {
        "ticket": "is not a context path",
        "Tickets": "is not a context path",
        "Ticket(val.ID == obj.Number)": "is written val.<Key> == obj.<Key>",
        "Ticket(val.ID == 'x')": "is written val.<Key> == obj.<Key>",
        "Ticket(val.ID == obj.ID || val.Number == obj.Number)": "is written val.<Key> == obj.<Key>",
        "Ticket(val.Colour == obj.Colour)": "Ticket has no key called Colour",
        "Ticket.Colour": "Ticket has no key called Colour",
        "Ticket.Status.Deep": "goes too deep",
        "Ticket(val.ID == obj.ID).Status": "takes no key expression",
        "ext.servicenow": "is not a context path",
        "File[0].Name": "is not a context path",
        "__class__": "is not a context path",
    }
    for path, why in wrong.items():
        assert why in (ctx.problem(path) or ""), path
    assert ctx.problem("File(val.SHA256 == obj.SHA256)") is None


def test_objects_are_appended_merged_by_their_key_and_set(admin: TestClient):
    incident(admin)
    ticket = {"ID": "abc", "Number": "INC001", "System": "ServiceNow", "Status": "New"}
    assert write("i1", [("Ticket", ticket)]) == ["Ticket:abc"]
    # The same key again: merged over the item, not added beside it. The default key of the entity is used.
    write("i1", [("Ticket", {"ID": "abc", "Status": "In progress", "URL": "https://sn.example/abc"})])
    write("i1", [("Ticket(val.Number == obj.Number)", {"Number": "INC001", "Status": "Resolved"})])
    found = held(admin)
    assert found["context"]["Ticket"] == [
        {"ID": "abc", "Number": "INC001", "System": "ServiceNow", "Status": "Resolved", "URL": "https://sn.example/abc"}
    ]
    assert found["version"] == 3 and found["provenance"]["Ticket:abc"]["source"] == "run:r1"
    # A key on the one item there is.
    write("i1", [("Ticket.Status", "Closed")])
    assert held(admin)["context"]["Ticket"][0]["Status"] == "Closed"
    # A list is each of its objects; one without the key of the entity is appended as it is.
    write("i1", [("IP", [{"Address": "185.220.101.47", "Verdict": "malicious"}, {"Address": "8.8.8.8"}])])
    write("i1", [("IP", {"Address": "8.8.8.8", "Geo": "US"}), ("Rule", {"ID": "r-1"}), ("Rule", {"ID": "r-1"})])
    found = held(admin)["context"]
    assert found["IP"] == [{"Address": "185.220.101.47", "Verdict": "malicious"}, {"Address": "8.8.8.8", "Geo": "US"}]
    assert found["Rule"] == [{"ID": "r-1"}, {"ID": "r-1"}]  # no Name: nothing to tell them apart by
    # What a connector knows beyond the schema.
    write("i1", [("ext.servicenow.sys_class", "incident")], "connector:servicenow")
    found = held(admin)
    assert found["context"]["ext"] == {"servicenow": {"sys_class": "incident"}}
    assert found["provenance"]["ext.servicenow.sys_class"]["source"] == "connector:servicenow"
    assert set(found["schema"]) == set(ctx.ENTITIES) and found["schema"]["Process"]["key"] == ["PID", "Host"]

    def refused(writes: list) -> str:
        with SessionLocal() as db, pytest.raises(ctx.ContextError) as caught:
            ctx.apply(db, db.get(Incident, "i1"), writes, "run:r1")
        return caught.value.message

    assert refused([("Ticket", {"ID": "x", "Priority": 1})]).startswith("Ticket has no key called Priority")
    assert refused([("Ticket", "INC001")]).startswith("Ticket takes objects with the keys")
    assert refused([("IP.Verdict", "x")]) == "IP.Verdict sets a key on the one IP there is: there are 2"
    assert refused([("Ticket(val.Number == obj.Number)", {"ID": "z"})]) == "What goes to Ticket lacks its key: Number"
    assert refused([("ext.acme.blob", "x" * 4_100_000)]).startswith("The context of an incident holds 4 MB at most")
    assert held(admin)["version"] == found["version"]  # nothing of a refused write was kept


def test_a_write_to_a_field_goes_through_the_registry(admin: TestClient):
    incident(admin)
    assert write("i1", [("incident.severity", "high"), ("Ticket", {"ID": "t1"})]) == ["field:severity", "Ticket:t1"]
    assert admin.get("/api/incidents/i1").json()["severity"] == "high"
    with SessionLocal() as db, pytest.raises(ctx.ContextError) as caught:
        ctx.apply(db, db.get(Incident, "i1"), [("incident.severity", "apocalyptic")], "run:r1")
    assert caught.value.message == "Severity is one of: low, medium, high, critical"


def test_who_set_a_value_decides_whether_a_connector_may_replace_it():
    assert ctx.may_overwrite(None, "connector:jira")
    assert ctx.may_overwrite("connector:jira", "connector:jira")
    assert ctx.may_overwrite("connector:servicenow", "connector:jira")  # another connector
    assert ctx.may_overwrite("run:abc", "connector:jira")
    assert not ctx.may_overwrite("user:anna", "connector:jira")  # a person edited it
    assert not ctx.may_overwrite("nik", "connector:jira")  # Nik's own analysis
    assert ctx.may_overwrite("user:anna", "connector:jira", authoritative=True)


def test_two_writers_do_not_lose_each_others_work(admin: TestClient):
    incident(admin)
    write("i1", [("Ticket", {"ID": "a"})])
    with SessionLocal() as first, SessionLocal() as second:
        # The second reads, the first writes and commits, then the second writes: it reads again.
        second.get(IncidentContext, "i1")
        ctx.apply(first, first.get(Incident, "i1"), [("Ticket", {"ID": "b"})], "run:r1")
        first.commit()
        ctx.apply(second, second.get(Incident, "i1"), [("Ticket", {"ID": "c"})], "run:r2")
        second.commit()
    assert [item["ID"] for item in held(admin)["context"]["Ticket"]] == ["a", "b", "c"]


# --------------------------------------------------------------------------- #
# Nik's own analysis                                                          #
# --------------------------------------------------------------------------- #
def test_what_nik_analysed_for_an_incident_is_in_its_context(admin: TestClient, no_dns):  # noqa: F811
    incident(admin)
    sample = admin.post("/api/incidents/i1/samples", files={"file": ("invoice.exe", fake_pe())})
    assert sample.status_code in (200, 201), sample.text
    mail = admin.post("/api/incidents/i1/mails", files={"file": ("reported.eml", phishing_message())})
    assert mail.status_code in (200, 201), mail.text
    found = held(admin)
    (file,) = found["context"]["File"]
    assert file["Name"] == "invoice.exe" and len(file["SHA256"]) == 64 and file["Size"] > 0
    (message,) = found["context"]["Mail"]
    assert message["Verdict"] in ("phishing", "suspicious") and "@" in message["From"] and message["MessageID"]
    assert found["provenance"][f"File:{file['SHA256']}"]["source"] == "nik"
    # Saving the incident again writes nothing new.
    version = found["version"]
    admin.patch("/api/incidents/i1", json={"host": "WKS-1"})
    admin.patch(
        "/api/incidents/i1", content='{"data": {"x": 1}}', headers={"Content-Type": "application/merge-patch+json"}
    )
    assert held(admin)["version"] == version
    # The fields of the incident are read beside it, by the names of the registry.
    assert held(admin)["incident"]["host"] == "WKS-1" and held(admin)["incident"]["type"] == "unclassified"

    # For the accounts that run playbooks; it goes with the incident.
    assert (
        admin.get("/api/incidents/i1/context", headers=make_key(admin, label="v", roles=["viewer"])).status_code == 403
    )
    assert admin.get("/api/incidents/nope/context").status_code == 404
    assert admin.delete("/api/incidents/i1").status_code == 204
    with SessionLocal() as db:
        assert db.get(IncidentContext, "i1") is None


# --------------------------------------------------------------------------- #
# Playbooks                                                                   #
# --------------------------------------------------------------------------- #
DESK = textwrap.dedent(
    """\
    name: Acme Desk
    id: acme
    version: 1
    configuration:
      - { name: url, type: url, required: true }
      - { name: credentials, type: basic }
    base_url: "{{ config.url }}"
    commands:
      - name: create-ticket
        changes_outside: true
        arguments: [{ name: title, type: text, required: true }]
        request: { method: POST, path: /tickets, json: { title: "{{ args.title }}" } }
        success: { status: 201 }
        outputs: { number: "{{ response.number }}" }
        context:
          - path: Ticket(val.ID == obj.ID)
            value:
              ID: "{{ response.id }}"
              Number: "{{ response.number }}"
              System: Acme Desk
              Status: "{{ response.state }}"
              URL: "{{ config.url }}/tickets/{{ response.number }}"
          - path: ext.acme.queue
            value: "{{ response.queue }}"
          - path: incident.ticket
            value: "{{ response.number }}"
        sample: { number: T-0000 }
    """
)


@pytest.fixture()
def desk(admin: TestClient, outside):
    outside.host("desk.example.com", "93.184.215.20")
    with SessionLocal() as db:
        ca.install(db, DESK, "admin")
        row = Connection(
            id="c" * 32,
            name="Desk",
            connector_id="acme",
            config={"url": "https://desk.example.com"},
            created_at=now_iso(),
            updated_at=now_iso(),
        )
        ca.store_secrets(row, {"username": "svc", "password": "s3cret-pass"})
        db.add(row)
        db.commit()
    return outside


def test_a_command_writes_what_it_declares_and_the_next_step_reads_it(admin: TestClient, desk):
    incident(admin, severity="high")
    desk.answer(
        "desk.example.com", 201, {"id": "t-77", "number": "T-77", "state": "open", "queue": "SOC"}, path="/tickets"
    )
    opened = node(
        "open",
        "action",
        action="acme.create-ticket",
        connection="Desk",
        approval={"ask": False},
        args={"title": "{{ incident.name }} ({{ incident.severity }})"},
    )
    read = node(
        "read",
        "action",
        action="test.echo",
        args={
            "text": "{{ context.Ticket[0].Number }} in {{ context.ext.acme.queue }}, ticket {{ incident.ticket }}",
            "extra": "{{ context.Ticket | length }}",
        },
    )
    pb = playbook(admin, "Ticket", [opened, read], [edge("start", "open"), edge("open", "read")])
    opening = admin.put(
        f"/api/automation/playbooks/{pb}/data-allow",
        json={"class": "incident_text", "allow": True, "acknowledged": True, "confirmName": "Ticket"},
    )
    assert opening.status_code == 200

    # A dry run writes nothing to the context.
    tried = go(admin, pb, objectKind="incident", objectId="i1", dryRun=True)
    assert tried["status"] == "failed" and held(admin)["context"] == {}  # nothing there for the next step to read
    run = go(admin, pb, objectKind="incident", objectId="i1")
    assert run["status"] == "done", {name: step.get("error") for name, step in steps(run).items()}
    done = steps(run)
    assert done["open"]["input"]["args"]["title"] == "Laptop of finance (high)"
    assert "written to the context: field:ticket, Ticket:t-77, ext.acme.queue" in done["open"]["log"]
    assert done["read"]["output"] == {"text": "T-77 in SOC, ticket T-77", "extra": 1}
    found = held(admin)
    assert found["context"]["Ticket"] == [
        {
            "ID": "t-77",
            "Number": "T-77",
            "System": "Acme Desk",
            "Status": "open",
            "URL": "https://desk.example.com/tickets/T-77",
        }
    ]
    # Who set it: the connector; and the field, through the registry.
    assert found["provenance"]["Ticket:t-77"]["source"] == "connector:acme"
    assert found["incident"]["ticket"] == "T-77"
    # Run again with the same ticket: the item is merged, not doubled.
    again = go(admin, pb, objectKind="incident", objectId="i1")
    assert again["status"] == "done" and len(held(admin)["context"]["Ticket"]) == 1

    # With no incident there is no context: the step is done, and nothing is written.
    alone = playbook(
        admin, "Alone", [{**opened, "config": {**opened["config"], "args": {"title": "x"}}}], [edge("start", "open")]
    )
    assert go(admin, alone)["status"] == "done"


def test_a_connector_file_is_checked_for_where_its_results_go():
    def problems(context_yaml: str) -> list[str]:
        text = DESK.replace(
            DESK[DESK.index("    context:") : DESK.index("    sample:")],
            "    context:\n" + textwrap.indent(textwrap.dedent(context_yaml), "      "),
        )
        try:
            cn.load(text)
        except cn.ConnectorError as error:
            return [problem.message for problem in error.problems]
        return []

    assert problems("- { path: Ticket, value: { ID: '{{ response.id }}' } }\n") == []
    assert "is not a context path" in problems("- { path: Tickets, value: 1 }\n")[0]
    assert problems("- { path: ext.other.thing, value: 1 }\n") == [
        "A connector writes under ext.acme, not under ext.other"
    ]
    assert problems("- { path: Ticket, value: { ID: '{{ secret.password }}' } }\n")
    assert problems("- { path: Ticket, value: { ID: '{{ nope.id }}' } }\n")


def test_a_script_says_where_an_output_goes(admin: TestClient, sandbox):
    incident(admin)
    draft = {
        "code": (
            "def main(args):\n"
            "    hosts = [{'Name': name, 'OS': 'Windows'} for name in args['names']]\n"
            "    return {'hosts': hosts, 'count': len(hosts)}\n"
        ),
        "arguments": [{"name": "names", "type": "list", "required": True}],
        "outputs": [
            {"name": "hosts", "type": "list", "context_path": "Host(val.Name == obj.Name)"},
            {"name": "count", "type": "number"},
        ],
        "test": {"args": {"names": ["a"]}},
    }
    made = admin.post("/api/automation/scripts", json={"name": "HostsFromNames"})
    assert made.status_code == 201, made.text
    script_id = made.json()["id"]
    assert admin.put(f"/api/automation/scripts/{script_id}", json={"draft": draft}).status_code == 200
    saved = admin.post(f"/api/automation/scripts/{script_id}/versions", json={})
    assert saved.status_code == 201, saved.text
    version = saved.json()["version"]
    step = node("hosts", "script", script="HostsFromNames", script_version=version, args={"names": ["WKS-1", "SRV-2"]})
    pb = playbook(admin, "Hosts", [step], [edge("start", "hosts")])
    run = go(admin, pb, objectKind="incident", objectId="i1")
    assert run["status"] == "done", steps(run)["hosts"].get("error")
    found = held(admin)
    assert found["context"]["Host"] == [{"Name": "WKS-1", "OS": "Windows"}, {"Name": "SRV-2", "OS": "Windows"}]
    assert found["provenance"]["Host:WKS-1"]["source"] == f"run:{run['id']}"

    # A path that is not one is told when the script is saved.
    wrong = {**draft, "outputs": [{"name": "hosts", "type": "list", "context_path": "Hosts"}]}
    admin.put(f"/api/automation/scripts/{script_id}", json={"draft": wrong})
    refused = admin.post(f"/api/automation/scripts/{script_id}/versions", json={})
    assert refused.status_code != 201 and "hosts" in refused.text and "is not a context path" in refused.text

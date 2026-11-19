"""Classifiers and mappers: what a fetched item becomes, and what goes back."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.automation import expressions as ex
from tests import vendor
from tests.conftest import make_key
from tests.test_connectors_api import connect, install
from tests.test_fields import field, incident

ITEM = {
    "id": "T-77",
    "threatInfo": {"threatName": "Emotet.dll", "confidenceLevel": "malicious", "createdAt": "2026-11-16T08:30:00Z"},
    "agent": {"computerName": "WKS-FINANCE-01", "uuid": "a-1", "user": "m.rossi"},
    "priority": 2,
    "score": 81,
    "url": "https://console.example/threats/T-77",
    "tags": ["finance", "q4"],
}

INCOMING = [
    {"to": "name", "from": "{{ item.threatInfo.threatName }} on {{ item.agent.computerName }}"},
    {"to": "severity", "from": "{{ item.score | severity }}", "authoritative": True},
    {"to": "host", "from": "{{ item.agent.computerName }}"},
    {"to": "source_id", "from": "{{ item.id }}"},
    {"to": "incident.occurred", "from": "{{ item.threatInfo.createdAt }}"},
    {"to": "labels", "from": "{{ item.tags }}"},
    {"to": "ticket", "from": "{{ item.nothing.here }}"},
    {"to": "Alert(val.ID == obj.ID)", "from": {"ID": "{{ item.id }}", "Name": "{{ item.threatInfo.threatName }}"}},
    {"to": "ext.acme.agent_uuid", "from": "{{ item.agent.uuid }}"},
]


def tried(admin: TestClient, **body) -> dict:
    answer = admin.post("/api/mappers/try", json={"connectorId": "acme", "direction": "incoming", **body})
    assert answer.status_code == 200, answer.text
    return answer.json()


def refused(admin: TestClient, rules: list, direction: str = "incoming") -> str:
    answer = admin.put("/api/mappers", json={"connectorId": "acme", "direction": direction, "rules": rules})
    assert answer.status_code == 400, answer.text
    return answer.json()["detail"]


def test_two_filters_read_what_other_products_say():
    def render(template: str, **values):
        return ex.render(template, ex.Scope(values=values)).data

    # A severity in words, on a scale of five either way up, or out of a hundred.
    assert [render("{{ v | severity }}", v=v) for v in ("Critical", "moderate", "INFO", "", "purple")] == [
        "critical",
        "medium",
        "low",
        "",
        "",
    ]
    assert [render("{{ v | severity }}", v=v) for v in (1, 3, 4, 5)] == ["low", "medium", "high", "critical"]
    assert [render("{{ v | severity('inverse') }}", v=v) for v in (1, 2, 3, 5)] == ["critical", "high", "medium", "low"]
    assert [render("{{ v | severity }}", v=v) for v in (10, 30, 60, 81, "97")] == [
        "low",
        "medium",
        "high",
        "critical",
        "critical",
    ]
    # A part of a text by a pattern: the whole match, a group by number or by name, nothing when it finds none.
    assert render("{{ v | regex_extract('INC[0-9]+') }}", v="re: INC0012345 opened") == "INC0012345"
    assert render("{{ v | regex_extract('user=([a-z.]+)', 1) }}", v="host=x user=m.rossi") == "m.rossi"
    assert (
        render("{{ v | regex_extract('(?P<host>[A-Z0-9-]+)\\\\.corp', 'host') }}", v="WKS-01.corp.example") == "WKS-01"
    )
    assert render("{{ v | regex_extract('nothing') }}", v="abc") == ""
    for wrong in ("{{ v | regex_extract('(') }}", "{{ v | regex_extract('a', 3) }}"):
        try:
            render(wrong, v="abc")
        except ex.ExpressionError as error:
            assert "cannot be applied" in error.message
        else:
            raise AssertionError("refused")


def test_an_incoming_mapper_turns_an_item_into_fields_and_context(admin: TestClient):
    install(admin)
    field(admin, "badge_number", "number")
    made = tried(admin, rules=INCOMING, item=ITEM)
    assert made["fields"] == {
        "name": "Emotet.dll on WKS-FINANCE-01",
        "severity": "critical",
        "host": "WKS-FINANCE-01",
        "source_id": "T-77",
        "occurred": "2026-11-16T08:30:00Z",
        "labels": ["finance", "q4"],
    }
    assert made["authoritative"] == ["severity"] and made["problems"] == [] and made["missing"] == []
    assert made["context"] == [
        {"path": "Alert(val.ID == obj.ID)", "value": {"ID": "T-77", "Name": "Emotet.dll"}},
        {"path": "ext.acme.agent_uuid", "value": "a-1"},
    ]
    # A value the field refuses is a problem to show; the rest goes on.
    partly = tried(
        admin,
        rules=[
            {"to": "severity", "from": "{{ item.threatInfo.confidenceLevel }}"},
            {"to": "badge_number", "from": "{{ item.agent.user }}"},
            {"to": "host", "from": "{{ item.agent.computerName }}"},
        ],
        item=ITEM,
    )
    assert partly["fields"] == {"host": "WKS-FINANCE-01"} and len(partly["problems"]) == 2
    assert "Severity" in partly["problems"][0] and "badge_number is a number" in partly["problems"][1]

    # What is saved is checked: where it writes, what it reads.
    assert refused(admin, [{"to": "colour", "from": "x"}]).startswith(
        '"colour" is not a field of incidents nor a context'
    )
    assert refused(admin, [{"to": "type", "from": "x"}]) == '"type" is not a field a mapper sets'
    assert refused(admin, [{"to": "time_to_close", "from": "x"}]) == '"time_to_close" is not a field a mapper sets'
    assert refused(admin, [{"to": "ext.other.x", "from": "y"}]) == "A mapper of acme writes under ext.acme"
    assert refused(admin, [{"to": "host", "from": "{{ incident.host }}"}]) == (
        'Rule 1: "incident" cannot be read here, only item'
    )
    assert refused(admin, [{"to": "host", "from": "{{ item.x "}]).startswith("Rule 1: The expression is not closed")
    assert refused(admin, [{"to": "host", "from": "a"}, {"to": "incident.host", "from": "b"}]) == (
        'Rule 2: "host" is written twice'
    )
    assert refused(admin, [{"to": "host"}]) == "Rule 1 needs where its value comes from"
    assert refused(admin, [{"from": "x"}]) == "Rule 1 needs what it writes to"


def test_mappers_are_kept_by_connector_direction_and_type(admin: TestClient):
    install(admin)
    made = admin.post("/api/incident-types", json={"name": "Endpoint alert"})
    assert made.status_code == 201, made.text
    type_id = made.json()["id"]
    field(admin, "agent_group", allTypes=False)
    admin.put(
        f"/api/incident-types/{type_id}",
        json={"fields": [{"name": "agent_group", "required": True}]},
    )

    every = admin.put("/api/mappers", json={"connectorId": "acme", "direction": "incoming", "rules": INCOMING[:3]})
    assert every.status_code == 200, every.text
    assert (every.json()["incidentType"], len(every.json()["rules"])) == ("*", 3)
    own = admin.put(
        "/api/mappers",
        json={
            "connectorId": "acme",
            "direction": "incoming",
            "incidentType": type_id,
            "rules": [{"to": "name", "from": "Endpoint: {{ item.threatInfo.threatName }}"}],
        },
    )
    assert own.status_code == 200, own.text
    # Saved again, it replaces the one there.
    again = admin.put("/api/mappers", json={"connectorId": "acme", "direction": "incoming", "rules": INCOMING[:2]})
    assert again.json()["id"] == every.json()["id"] and len(again.json()["rules"]) == 2
    listed = admin.get("/api/mappers", params={"connector": "acme"}).json()["mappers"]
    assert sorted((row["direction"], row["incidentType"]) for row in listed) == [
        ("incoming", "*"),
        ("incoming", type_id),
    ]
    # Tried with the saved rules: the type's own mapper for its type, the general one otherwise.
    assert tried(admin, incidentType=type_id, item=ITEM)["fields"] == {"name": "Endpoint: Emotet.dll"}
    assert tried(admin, item=ITEM)["fields"]["severity"] == "critical"
    # A field the type needs that nothing gives is said.
    assert tried(admin, incidentType=type_id, item=ITEM)["missing"] == ["agent_group"]

    # Nik's side of the editor: the fields a mapper may set for the type, those it needs first.
    targets = admin.get("/api/mappers/targets", params={"type": type_id}).json()
    names = [item["name"] for item in targets["fields"]]
    assert names[0] == "agent_group" and targets["fields"][0]["required"] is True
    assert "source_id" in names and "type" not in names and "time_to_close" not in names and "created" not in names
    assert "agent_group" not in [item["name"] for item in admin.get("/api/mappers/targets").json()["fields"]]
    assert {
        "entity": "Ticket",
        "keys": ["ID", "Number", "System", "URL", "Status"],
        "path": "Ticket(val.ID == obj.ID)",
    } in (targets["context"])

    assert (
        admin.put("/api/mappers", json={"connectorId": "nope", "direction": "incoming", "rules": []}).status_code == 404
    )
    bad_type = {"connectorId": "acme", "direction": "incoming", "incidentType": "nope", "rules": []}
    assert admin.put("/api/mappers", json=bad_type).status_code == 400
    assert admin.delete(f"/api/mappers/{own.json()['id']}").status_code == 204
    assert admin.delete(f"/api/mappers/{own.json()['id']}").status_code == 404
    analyst = make_key(admin, label="a", roles=["analyst"])
    assert admin.get("/api/mappers", headers=analyst).status_code == 403


def test_an_outgoing_mapper_says_what_goes_to_the_other_side(admin: TestClient):
    install(admin)
    incident(admin, severity="high", host="WKS-FINANCE-01")
    rules = [
        {"to": "short_description", "from": "{{ incident.name }} ({{ incident.severity }})"},
        {"to": "urgency", "from": "{{ incident.severity | map(high='1', medium='2') }}"},
        {"to": "cmdb_ci", "from": "{{ incident.host }}"},
        {"to": "assigned_to", "from": "{{ incident.owner }}"},
        {"to": "category", "from": "security"},
    ]
    saved = admin.put("/api/mappers", json={"connectorId": "acme", "direction": "outgoing", "rules": rules})
    assert saved.status_code == 200, saved.text
    sent = admin.post(
        "/api/mappers/try", json={"connectorId": "acme", "direction": "outgoing", "incidentId": "i1"}
    ).json()["sent"]
    # What has no value (nobody owns the incident) sends nothing for its name.
    assert sent == {
        "short_description": "Laptop of finance (high)",
        "urgency": "1",
        "cmdb_ci": "WKS-FINANCE-01",
        "category": "security",
    }
    assert refused(admin, [{"to": "x", "from": "{{ item.id }}"}], "outgoing") == (
        'Rule 1: "item" cannot be read here, only context, incident, mirror'
    )
    missing = admin.post("/api/mappers/try", json={"connectorId": "acme", "direction": "outgoing", "incidentId": "no"})
    assert missing.status_code == 404


def test_a_classifier_chooses_the_type_of_incident_an_item_becomes(admin: TestClient):
    install(admin)
    connection = connect(admin)
    url = f"/api/classifiers/{connection['id']}"
    assert admin.get(url).json() == {
        "connectionId": connection["id"],
        "rules": [],
        "defaultType": None,
        "updatedAt": None,
        "updatedBy": "",
    }
    rules = [
        {
            "when": {"all": [{"left": "{{ item.threatInfo.threatName }}", "op": "matches", "right": "(?i)phish"}]},
            "type": "phishing",
        },
        {"when": {"any": [{"left": "{{ item.score }}", "op": "gte", "right": 80}]}, "type": "malware"},
    ]
    saved = admin.put(url, json={"rules": rules, "defaultType": "unclassified"})
    assert saved.status_code == 200, saved.text
    assert saved.json()["defaultType"] == "unclassified" and saved.json()["updatedBy"] == "admin"

    def becomes(item) -> str | None:
        answer = admin.post("/api/classifiers/try", json={"rules": rules, "defaultType": "unclassified", "item": item})
        assert answer.status_code == 200, answer.text
        return answer.json()["type"]

    assert becomes(ITEM) == "malware"
    assert becomes({"threatInfo": {"threatName": "Phishing page"}, "score": 99}) == "phishing"  # the first that holds
    assert becomes({"score": 5}) == "unclassified"
    assert becomes("not an object") == "unclassified"  # a rule that cannot be judged does not hold

    def wrong(body: dict) -> str:
        answer = admin.put(url, json=body)
        assert answer.status_code == 400, answer.text
        return answer.json()["detail"]

    assert wrong({"rules": [{"when": rules[0]["when"], "type": "nope"}]}) == 'There is no type of incident "nope"'
    assert wrong({"rules": [{"when": {}, "type": "malware"}]}).startswith("Rule 1: a condition is")
    assert wrong(
        {"rules": [{"when": {"all": [{"left": "{{ incident.x }}", "op": "eq", "right": 1}]}, "type": "malware"}]}
    ) == ('Rule 1: "incident" cannot be read here, only item')
    assert wrong({"rules": [], "defaultType": "nope"}) == 'There is no type of incident "nope"'
    assert admin.get("/api/classifiers/nope").status_code == 404


def test_the_shipped_connectors_come_with_their_mappers(admin: TestClient):
    from sqlalchemy import select

    from app import mapping
    from app.automation import connector_actions
    from app.core.db import SessionLocal
    from app.core.models import Mapper

    with SessionLocal() as db:
        connector_actions.seed(db)
        db.flush()
        assert mapping.seed(db) >= 1  # the Mail connector
        db.commit()
        assert vendor.install(db) == len(vendor.folders())
        assert mapping.seed(db) == 0  # nothing changed: nothing is written again
        row = db.scalars(
            select(Mapper).where(Mapper.connector_id == "servicenow", Mapper.direction == "incoming")
        ).one()
        assert row.incident_type == mapping.ANY_TYPE
    # A mapper someone saved is theirs: a release does not take it back.
    mine = [{"to": "name", "from": "{{ item.number }}"}]
    saved = admin.put("/api/mappers", json={"connectorId": "servicenow", "direction": "incoming", "rules": mine})
    assert saved.status_code == 200, saved.text
    with SessionLocal() as db:
        assert mapping.seed(db) == 0
        row = db.scalars(
            select(Mapper).where(Mapper.connector_id == "servicenow", Mapper.direction == "incoming")
        ).one()
        assert not row.builtin and [rule["from"] for rule in row.rules] == ["{{ item.number }}"]

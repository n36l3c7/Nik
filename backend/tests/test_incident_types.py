"""Incident types: the shipped ones, a type of your own, its layout, closing, and the incident routes."""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy import select

from app import incident_types as types
from app.core.db import SessionLocal
from app.core.models import Incident, IncidentType
from tests.conftest import make_key
from tests.test_fields import field, incident, put


def make(admin: TestClient, **body) -> dict:
    made = admin.post("/api/incident-types", json=body)
    assert made.status_code == 201, made.text
    return made.json()


def refused(admin: TestClient, method: str, url: str, **body) -> str:
    answer = admin.request(method, url, json=body)
    assert answer.status_code == 400, answer.text
    return answer.json()["detail"]


def test_seven_types_ship_and_unclassified_is_the_type_of_what_has_none(admin: TestClient):
    incident(admin)
    listed = admin.get("/api/incident-types").json()
    names = [item["name"] for item in listed["types"]]
    assert names[0] == "Unclassified" and sorted(names[1:]) == names[1:]
    assert set(names) == {
        "Unclassified",
        "Phishing",
        "Malware",
        "Network intrusion",
        "Data leak",
        "Access abuse",
        "Vulnerability",
    }
    assert "summary" in listed["tabs"] and "slate" in listed["colours"]
    by_id = {item["id"]: item for item in listed["types"]}
    unclassified = by_id["unclassified"]
    assert unclassified["builtin"] and unclassified["incidents"] == 1 and unclassified["fields"] == []
    # Every shipped type has a side panel (the "key" section) and reasons to close with.
    for item in listed["types"]:
        keys = [section for section in item["layout"]["sections"] if section["key"]]
        assert len(keys) == 1 and "status" in keys[0]["fields"], item["name"]
        assert item["closeReasons"] and item["customLayout"] is True, item["name"]
    assert "Awareness test" in by_id["phishing"]["closeReasons"]
    assert admin.get("/api/incidents/i1").json()["type"] == "unclassified"

    # Seeding again adds nothing; a shipped type that was changed or deleted is the team's.
    assert admin.put("/api/incident-types/malware", json={"description": "Ours"}).status_code == 200
    assert admin.delete("/api/incident-types/vulnerability").status_code == 204
    with SessionLocal() as db:
        assert types.seed(db) == 1  # only the one that was deleted: a release cannot know it was meant
        db.rollback()
        assert db.get(IncidentType, "malware").description == "Ours"
    assert (
        admin.delete("/api/incident-types/unclassified").json()["detail"].startswith("Unclassified cannot be deleted")
    )


def test_a_type_of_your_own_with_fields_and_a_layout(admin: TestClient):
    field(admin, "campaign", label="Campaign", allTypes=False)
    field(admin, "users_hit", "number", label="Users hit", allTypes=False)
    field(admin, "site", label="Site")  # on every type
    made = make(
        admin,
        name="Business e-mail compromise",
        colour="violet",
        fields=[{"name": "campaign", "required": True}, {"name": "users_hit", "requiredOnClose": True}],
    )
    assert made["id"] == "business-e-mail-compromise" and made["builtin"] is False
    assert made["fields"] == [
        {"name": "campaign", "required": True, "requiredOnClose": False},
        {"name": "users_hit", "required": False, "requiredOnClose": True},
    ]
    # No layout was given: one is made from its fields, with those that are on every type.
    assert made["customLayout"] is False
    assert made["layout"]["sections"][-1] == {
        "id": "fields",
        "title": "More",
        "key": False,
        "columns": 2,
        "fields": ["campaign", "users_hit", "site"],
    }
    assert made["closeReasons"] == list(types.CLOSE_REASONS)
    url = f"/api/incident-types/{made['id']}"

    layout = {
        "sections": [
            {"id": "key", "title": "Key facts", "key": True, "fields": ["status", "severity", "campaign"]},
            {"title": "Reach", "columns": 2, "fields": ["users_hit", "site", "affected_users"]},
        ],
        "tabs": ["summary", "mail", "iocs"],
        "hidden": ["eventlogs", "browser"],
    }
    saved = admin.put(url, json={"layout": layout, "closeReasons": ["Recovered", "Recovered", "No loss"]}).json()
    assert saved["customLayout"] is True and saved["closeReasons"] == ["Recovered", "No loss"]
    assert [section["id"] for section in saved["layout"]["sections"]] == ["key", "s2"]
    assert saved["layout"]["sections"][1]["columns"] == 2 and saved["layout"]["tabs"] == ["summary", "mail", "iocs"]
    assert saved["fields"] == made["fields"]  # left out of the change: kept

    assert refused(admin, "POST", "/api/incident-types", name="phishing") == "There is a type with this name already"
    assert refused(admin, "POST", "/api/incident-types", name=" ") == "A type needs a name"
    assert refused(admin, "PUT", url, colour="mauve").startswith("A colour is one of")
    assert refused(admin, "PUT", url, fields=[{"name": "nope"}]) == 'There is no field of incidents called "nope"'
    assert refused(admin, "PUT", url, fields=[{"name": "severity"}]) == (
        "Severity is a system field: every type has it already"
    )
    assert refused(admin, "PUT", url, fields=[{"name": "campaign"}, {"name": "campaign"}]) == "Campaign is listed twice"
    assert refused(admin, "PUT", url, layout={"sections": [{"fields": ["status"]}, {"fields": ["status"]}]}) == (
        "Status is in two sections"
    )
    assert refused(admin, "PUT", url, layout={"sections": [{"key": True}, {"key": True}]}) == (
        "One section at most is the side panel"
    )
    assert refused(admin, "PUT", url, layout={"tabs": ["cinema"]}).startswith('There is no tab called "cinema"')
    assert refused(admin, "PUT", url, layout={"hidden": ["summary"]}).startswith("The Summary cannot be hidden")
    assert refused(admin, "PUT", url, autoRun=True) == "To run by itself a type needs its playbook"
    assert refused(admin, "PUT", url, defaultPlaybookId="nope") == "The playbook of the type does not exist"
    assert refused(admin, "PUT", url, visibleToRoles=["wizard"]) == "The roles that see a type are roles that exist"

    # A field in a section must be of the type; one taken off the type leaves its sections.
    other = make(admin, name="Other")
    assert (
        refused(admin, "PUT", f"/api/incident-types/{other['id']}", layout={"sections": [{"fields": ["campaign"]}]})
        == "Campaign is in a section but is not a field of this type: add it to the type"
    )
    trimmed = admin.put(url, json={"fields": [{"name": "users_hit"}]}).json()
    assert trimmed["layout"]["sections"][0]["fields"] == ["status", "severity"]
    assert admin.put(url, json={"layout": None}).json()["customLayout"] is False

    # Who may.
    analyst = make_key(admin, label="an", roles=["analyst"])
    assert admin.get("/api/incident-types", headers=analyst).status_code == 200
    assert admin.post("/api/incident-types", headers=analyst, json={"name": "Mine"}).status_code == 403
    assert admin.put(url, headers=analyst, json={"name": "x"}).status_code == 403
    assert admin.delete(url, headers=analyst).status_code == 403
    assert admin.get("/api/incident-types/nope").status_code == 404


def test_an_incident_takes_a_type_and_keeps_what_another_type_does_not_show(admin: TestClient):
    field(admin, "campaign", label="Campaign", allTypes=False)
    bec = make(admin, name="BEC", fields=[{"name": "campaign"}])
    # Created with a type and its fields, in the document as a client sends it.
    doc = {"id": "i1", "name": "CEO fraud", "data": {}, "type": bec["id"], "fields": {"campaign": "Q4", "tlp": "amber"}}
    made = admin.post("/api/incidents", json=doc)
    assert made.status_code == 201, made.text
    assert made.json()["type"] == "bec" and made.json()["fields"] == {"campaign": "Q4", "tlp": "amber"}
    with SessionLocal() as db:
        row = db.get(Incident, "i1")
        # Kept beside the document, never in it.
        assert row.type_id == "bec" and "fields" not in row.doc and "type" not in row.doc
    listed = admin.get("/api/incidents").json()["incidents"]
    assert listed[0]["type"] == "bec" and listed[0]["fields"]["campaign"] == "Q4"
    assert admin.get("/api/incident-types/bec").json()["incidents"] == 1

    # A wrong value refuses the creation, and the change of a document.
    bad = admin.post("/api/incidents", json={"id": "i2", "name": "x", "data": {}, "fields": {"nope": 1}})
    assert bad.status_code == 400 and admin.get("/api/incidents/i2").status_code == 404
    merge = {"Content-Type": "application/merge-patch+json"}
    assert admin.patch("/api/incidents/i1", content='{"fields": {"tlp": "purple"}}', headers=merge).status_code == 400

    # A merge patch changes a field, clears one with null, and the rest of the document with it.
    patched = admin.patch(
        "/api/incidents/i1", content='{"fields": {"campaign": "Q1", "tlp": null}, "host": "WKS-9"}', headers=merge
    )
    assert patched.status_code == 200, patched.text
    assert patched.json()["fields"] == {"campaign": "Q1"} and patched.json()["host"] == "WKS-9"
    only = admin.patch("/api/incidents/i1", json={"type": "phishing"})
    assert only.status_code == 200 and only.json()["type"] == "phishing"
    # Phishing does not list "campaign": the value stays in storage and cannot be written meanwhile.
    assert only.json()["fields"] == {"campaign": "Q1"}
    assert put(admin, {"campaign": "Q2"}).status_code == 400
    assert admin.patch("/api/incidents/i1", json={"type": "bec"}).json()["type"] == "bec"
    assert put(admin, {"campaign": "Q2"}).status_code == 200

    # Deleting a type moves its incidents, with their values.
    assert admin.delete("/api/incident-types/bec?moveTo=bec").status_code == 400
    assert admin.delete("/api/incident-types/bec?moveTo=malware").status_code == 204
    assert admin.get("/api/incidents/i1").json()["type"] == "malware"
    assert admin.get("/api/incidents/i1").json()["fields"] == {"campaign": "Q2"}
    assert admin.delete("/api/incident-types/malware").status_code == 204
    assert admin.get("/api/incidents/i1").json()["type"] == "unclassified"


def test_closing_asks_for_what_the_type_wants_on_closing(admin: TestClient):
    field(admin, "root_cause", label="Root cause", allTypes=False)
    field(admin, "campaign", label="Campaign", allTypes=False)
    kind = make(
        admin,
        name="Outage",
        fields=[{"name": "root_cause", "requiredOnClose": True}, {"name": "campaign", "required": True}],
        closeReasons=["Fixed", "Not ours"],
    )
    incident(admin, type=kind["id"], fields={"campaign": "x"})
    wanted = "To close this incident, fill in: Root cause"
    # Whichever way it is closed: by its fields, or by the document.
    assert put(admin, {"status": "closed"}).json()["detail"] == wanted
    by_doc = admin.patch("/api/incidents/i1", json={"status": "closed"})
    assert by_doc.status_code == 400 and by_doc.json()["detail"] == wanted
    assert admin.get("/api/incidents/i1").json().get("status", "open") != "closed"
    assert (
        put(admin, {"status": "closed", "root_cause": "A bad rule", "close_reason": "Whatever"}).json()["detail"]
        == "The close reason is one of: Fixed, Not ours"
    )

    closed = put(
        admin, {"status": "closed", "root_cause": "A bad rule", "close_reason": "Fixed", "close_notes": "Rule fixed"}
    )
    assert closed.status_code == 200, closed.text
    held = closed.json()["fields"]
    assert held["closed"] and (held["close_reason"], held["close_notes"]) == ("Fixed", "Rule fixed")
    with SessionLocal() as db:
        assert db.scalars(select(Incident.closed_at)).one()
    # Opened again by the document: the moment it was closed goes.
    assert admin.patch("/api/incidents/i1", json={"status": "open"}).status_code == 200
    assert "closed" not in admin.get("/api/incidents/i1/fields").json()["fields"]
    # A field the type always wants cannot be emptied.
    assert put(admin, {"campaign": None}).json()["detail"] == "A required field cannot be emptied: Campaign"

    # An incident with no type closes as it always did.
    incident(admin, "i2")
    assert admin.patch("/api/incidents/i2", json={"status": "closed"}).status_code == 200


def test_a_type_can_be_for_some_roles_only(admin: TestClient):
    make(admin, name="Insider", visibleToRoles=["audit"])
    analyst = make_key(admin, label="an", roles=["analyst"])
    auditor = make_key(admin, label="au", roles=["viewer", "audit"])

    def names(headers) -> set[str]:
        return {item["name"] for item in admin.get("/api/incident-types", headers=headers).json()["types"]}

    assert "Insider" not in names(analyst) and "Insider" in names(auditor) and "Insider" in names(None)
    assert admin.get("/api/incident-types/insider", headers=analyst).status_code == 404
    assert admin.get("/api/incident-types/insider", headers=auditor).status_code == 200

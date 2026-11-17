"""The field registry: system fields, custom fields, and the one writer of an incident's fields."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import fields as registry
from app.core.db import SessionLocal
from app.core.models import AutomationEvent, Field, Incident, IncidentType
from app.core.security import now_iso
from tests.conftest import make_key


def incident(admin: TestClient, incident_id: str = "i1", **more) -> None:
    doc = {"id": incident_id, "name": "Laptop of finance", "data": {}, **more}
    assert admin.post("/api/incidents", json=doc).status_code == 201


def field(admin: TestClient, name: str, kind: str = "text", **more) -> dict:
    made = admin.post("/api/fields", json={"name": name, "type": kind, "allTypes": True, **more})
    assert made.status_code == 201, made.text
    return made.json()


def put(admin: TestClient, changes: dict, incident_id: str = "i1", **more):
    return admin.patch(f"/api/incidents/{incident_id}/fields", json={"changes": changes, **more})


def test_the_system_fields_are_there_and_cannot_be_deleted_or_retyped(admin: TestClient):
    listed = admin.get("/api/fields").json()
    names = [item["name"] for item in listed["fields"]]
    assert names == list(registry.SYSTEM_FIELDS)  # in their order, nothing else yet
    by_name = {item["name"]: item for item in listed["fields"]}
    assert by_name["status"]["options"] == {"choices": ["open", "in_progress", "closed"]}
    assert by_name["owner"]["type"] == "user" and by_name["id"]["writable"] is False
    assert all(item["system"] and item["allTypes"] for item in listed["fields"])
    assert "list" in listed["types"] and "timer" in listed["types"]

    assert admin.delete("/api/fields/severity").json()["detail"] == "A system field cannot be deleted"
    relabelled = admin.patch("/api/fields/owner", json={"label": "Handler"})
    assert relabelled.status_code == 200 and relabelled.json()["label"] == "Handler"
    refused = admin.patch("/api/fields/severity", json={"options": {"choices": ["bad", "worse"]}})
    assert refused.json()["detail"] == "Of a system field only the label and the description can change"
    assert admin.post("/api/fields", json={"name": "severity"}).json()["detail"] == (
        "There is a field with this name already"
    )
    # Seeding again (another start of the server) adds nothing and keeps the new label.
    with SessionLocal() as db:
        assert registry.seed(db) == 0
        assert db.scalars(select(Field).where(Field.name == "owner")).one().label == "Handler"


def test_a_custom_field_has_a_name_for_ever_and_a_type_with_its_options(admin: TestClient):
    made = field(
        admin, "business_unit", "choice", label="Business unit", options={"choices": ["Retail", "Retail", "IT"]}
    )
    assert (made["name"], made["label"], made["system"]) == ("business_unit", "Business unit", False)
    assert made["options"] == {"choices": ["Retail", "IT"]} and made["createdBy"] == "admin"

    def refused(body: dict) -> str:
        answer = admin.post("/api/fields", json=body)
        assert answer.status_code == 400, answer.text
        return answer.json()["detail"]

    assert refused({"name": "Business Unit"}).startswith("A name is a lower-case letter")
    assert refused({"name": "x"}).startswith("A name is a lower-case letter")
    assert refused({"name": "business_unit"}) == "There is a field with this name already"
    assert refused({"name": "colour", "type": "rainbow"}).startswith("A type is one of: text, long_text")
    assert refused({"name": "colour", "type": "choice"}) == "A choice needs its choices: a list of texts"
    assert refused({"name": "rows", "type": "list"}) == "A list needs its columns: 1 to 20"
    assert refused({"name": "rows", "type": "list", "options": {"columns": [{"name": "A B"}]}}).startswith(
        "A column's name is"
    )
    assert refused({"name": "thing", "appliesTo": "playbook"}) == "A field is of an incident, an indicator or a task"

    # The label, the description and the choices can change; the name and the type cannot be sent at all.
    changed = admin.patch(
        "/api/fields/business_unit", json={"label": "Unit", "options": {"choices": ["Retail", "IT", "Legal"]}}
    ).json()
    assert changed["label"] == "Unit" and changed["options"]["choices"] == ["Retail", "IT", "Legal"]
    assert admin.patch("/api/fields/business_unit", json={"options": {}}).status_code == 400
    assert admin.get("/api/fields/nope").status_code == 404

    # Who may: reading is for whoever reads incidents, changing for who configures them.
    analyst = make_key(admin, label="an", roles=["analyst"])
    assert admin.get("/api/fields", headers=analyst).status_code == 200
    assert admin.post("/api/fields", headers=analyst, json={"name": "mine"}).status_code == 403
    assert admin.patch("/api/fields/business_unit", headers=analyst, json={"label": "x"}).status_code == 403
    assert admin.delete("/api/fields/business_unit", headers=analyst).status_code == 403
    actions = [entry["action"] for entry in admin.get("/api/audit").json()["entries"]]
    assert "field.create" in actions and "field.update" in actions


def test_values_are_checked_against_the_registry_and_coerced(admin: TestClient):
    incident(admin)
    field(admin, "business_unit", "choice", options={"choices": ["Retail", "IT"]})
    field(admin, "users_hit", "number")
    field(admin, "contained", "bool")
    field(admin, "detected", "date")
    field(admin, "systems", "tags")
    field(admin, "vectors", "multi_choice", options={"choices": ["mail", "web", "usb"]})
    field(admin, "advisory", "url")
    field(admin, "handler", "user")
    field(admin, "c2", "indicator")
    field(admin, "extra", "json")
    field(
        admin,
        "accounts",
        "list",
        options={"columns": [{"name": "user", "type": "text"}, {"name": "admin", "type": "bool"}]},
    )

    saved = put(
        admin,
        {
            "business_unit": "IT",
            "users_hit": "12",
            "contained": "yes",
            "detected": "2026-11-17T10:30:00+01:00",
            "systems": "WKS-1, SRV-2, WKS-1",
            "vectors": ["mail", "web"],
            "advisory": "https://example.org/advisory/7",
            "handler": "ADMIN",
            "c2": {"type": "domain", "value": "Evil.Example."},
            "extra": {"anything": [1, 2]},
            "accounts": [{"user": "anna", "admin": "true"}, {"user": "bo"}],
        },
    )
    assert saved.status_code == 200, saved.text
    body = saved.json()
    assert body["rev"] == 1 and len(body["changed"]) == 11
    held = body["fields"]
    assert held["users_hit"] == 12 and held["contained"] is True
    assert held["detected"] == "2026-11-17T09:30:00Z"  # stored as UTC
    assert held["systems"] == ["WKS-1", "SRV-2"] and held["vectors"] == ["mail", "web"]
    assert held["handler"] == "admin"  # the account as it is written
    assert held["c2"] == {"type": "domain", "value": "evil.example"}
    assert held["accounts"] == [{"user": "anna", "admin": True}, {"user": "bo"}]
    assert admin.get("/api/incidents/i1/fields").json()["fields"]["business_unit"] == "IT"

    def refused(changes: dict) -> str:
        answer = put(admin, changes)
        assert answer.status_code == 400, answer.text
        return answer.json()["detail"]

    assert refused({"business_unit": "Legal"}) == "business_unit is one of: Retail, IT"
    assert refused({"users_hit": "many"}) == "users_hit is a number"
    assert refused({"users_hit": float("inf")} if False else {"users_hit": "nan"}) == "users_hit is a number"
    assert refused({"contained": "maybe"}) == "contained is true or false"
    assert refused({"detected": "yesterday"}).startswith("detected is a date")
    assert refused({"vectors": ["mail", "fax"]}) == "vectors is one of: mail, web, usb"
    assert refused({"advisory": "javascript:alert(1)"}) == "advisory is an http:// or https:// address"
    assert refused({"handler": "nobody"}) == "handler: there is no account called nobody"
    assert refused({"c2": "evil.example"}) == "c2 is an indicator: a type and a value"
    assert refused({"accounts": [{"user": "x", "shoe": 1}]}) == "accounts: a row has the columns user, admin"
    assert refused({"accounts": [{"user": "x"}] * 501}) == "accounts is a list of rows, 500 at most"
    assert refused({"extra": "x" * 70_000}) == "extra is larger than 64 kB"
    assert refused({"systems": [str(n) for n in range(101)]}).startswith("systems holds 100 values at most")
    # One name for one thing: a name the registry does not know is refused, and nothing of the change is kept.
    assert refused({"users_hit": 3, "bussiness_unit": "IT"}) == (
        'There is no field called "bussiness_unit": fields are made in Settings'
    )
    assert admin.get("/api/incidents/i1/fields").json()["fields"]["users_hit"] == 12

    # null clears; the same value again changes nothing; a stale revision is told.
    cleared = put(admin, {"users_hit": None, "business_unit": "IT"}).json()
    assert cleared["changed"] == ["users_hit"] and "users_hit" not in cleared["fields"] and cleared["rev"] == 2
    assert put(admin, {"business_unit": "IT"}).json() == {**admin.get("/api/incidents/i1/fields").json(), "changed": []}
    stale = put(admin, {"business_unit": "Retail"}, ifRev=1)
    assert stale.status_code == 409 and stale.json()["detail"].startswith("The fields were changed by someone else")
    assert put(admin, {"business_unit": "Retail"}, ifRev=2).status_code == 200
    assert put(admin, {}).status_code == 400 and put(admin, {"x": 1}, "nope").status_code == 404


def test_system_fields_are_written_where_they_always_lived(admin: TestClient):
    incident(admin, severity="low")
    with SessionLocal() as db:
        db.query(AutomationEvent).delete()
        db.commit()
    saved = put(
        admin, {"severity": "high", "owner": "admin", "ticket": "INC-7", "status": "in_progress", "tlp": "amber"}
    )
    assert saved.status_code == 200, saved.text
    assert sorted(saved.json()["changed"]) == ["owner", "severity", "status", "ticket", "tlp"]
    doc = admin.get("/api/incidents/i1").json()
    assert (doc["severity"], doc["assignee"], doc["ticketId"], doc["status"]) == (
        "high",
        "admin",
        "INC-7",
        "in_progress",
    )
    with SessionLocal() as db:
        row = db.get(Incident, "i1")
        # The columns the lists read follow, and what has no column of its own is in "fields".
        assert (row.severity, row.assignee, row.ticket_id, row.status) == ("high", "admin", "INC-7", "in_progress")
        assert row.fields == {"tlp": "amber"} and row.fields_rev == 1
        (event,) = db.scalars(select(AutomationEvent)).all()
        # A playbook is told with the names it has always known, and with the names of the registry.
        assert event.kind == "incident.updated"
        assert {"severity", "assignee", "owner", "ticketId", "ticket", "status", "tlp"} <= set(
            event.payload["data"]["changed"]
        )
    listed = admin.get("/api/incidents?q=severity:high").json()
    assert [item["id"] for item in listed["incidents"]] == ["i1"]

    def refused(changes: dict) -> str:
        answer = put(admin, changes)
        assert answer.status_code == 400, answer.text
        return answer.json()["detail"]

    assert refused({"severity": "apocalyptic"}) == "Severity is one of: low, medium, high, critical"
    assert (
        refused({"id": "other"}) == "Id cannot be set" and refused({"created": "2026-01-01"}) == "Created cannot be set"
    )
    assert refused({"name": ""}) == "An incident needs a name"
    assert refused({"type": "no-such-type"}) == "There is no such type of incident"

    # Closing stamps the moment, opening again clears it.
    closed = put(admin, {"status": "closed", "close_reason": "False positive"}).json()["fields"]
    assert closed["closed"] and closed["close_reason"] == "False positive"
    again = put(admin, {"status": "open"}).json()["fields"]
    assert "closed" not in again and again["status"] == "open"
    entries = [e["details"] for e in admin.get("/api/audit").json()["entries"] if e["action"] == "incident.field"]
    assert "Set Severity: low → high" in entries and "Set Status: closed → open" in entries


def test_a_custom_field_belongs_to_the_types_that_list_it(admin: TestClient):
    incident(admin)
    made = admin.post("/api/fields", json={"name": "campaign", "label": "Campaign"})
    assert made.status_code == 201 and made.json()["allTypes"] is False
    assert put(admin, {"campaign": "Q4 invoices"}).json()["detail"] == (
        'Campaign is not a field of the type "Unclassified"'
    )
    with SessionLocal() as db:
        db.add(
            IncidentType(
                id="phishing",
                name="Phishing",
                fields=[{"name": "campaign", "required": False, "required_on_close": False}],
                created_at=now_iso(),
                updated_at=now_iso(),
            )
        )
        db.commit()
    assert put(admin, {"type": "phishing", "campaign": "Q4 invoices"}).json()["changed"] == ["type", "campaign"]
    assert admin.get("/api/incidents/i1/fields").json()["type"] == "phishing"
    used = admin.get("/api/fields/campaign").json()["usedBy"]
    assert used == {"types": ["Phishing"], "incidents": 1}
    assert admin.delete("/api/fields/campaign").json()["detail"] == "Used by the types: Phishing"

    # Back to no type: the value is kept in storage, and cannot be written while the type does not list it.
    assert put(admin, {"type": "unclassified"}).json()["type"] == "unclassified"
    assert admin.get("/api/incidents/i1/fields").json()["fields"]["campaign"] == "Q4 invoices"
    assert put(admin, {"campaign": "other"}).status_code == 400
    with SessionLocal() as db:
        db.delete(db.get(IncidentType, "phishing"))
        db.commit()
    assert admin.delete("/api/fields/campaign").json()["detail"] == "1 incident(s) hold a value of this field"
    with SessionLocal() as db:
        row = db.get(Incident, "i1")
        row.fields = {}
        db.commit()
    assert admin.delete("/api/fields/campaign").status_code == 204
    assert admin.get("/api/fields/campaign").status_code == 404


@pytest.mark.parametrize(
    ("kind", "options", "value", "stored"),
    [
        ("text", {}, 42, "42"),
        ("long_text", {}, "a\nb", "a\nb"),
        ("number", {}, 1.5, 1.5),
        ("number", {}, "7.0", 7),
        ("bool", {}, 0, False),
        ("date", {}, 1_800_000_000, "2027-01-15T08:00:00Z"),
        ("date", {}, "2026-11-17", "2026-11-17T00:00:00Z"),
        ("timer", {}, "2026-11-17T10:00:00Z", "2026-11-17T10:00:00Z"),
        ("role", {}, "analyst", "analyst"),
        ("tags", {}, [" a ", "b", "a", ""], ["a", "b"]),
        ("text", {}, "", None),
        ("number", {}, None, None),
    ],
)
def test_each_type_stores_a_value_its_own_way(client: TestClient, kind, options, value, stored):
    with SessionLocal() as db:
        assert registry.coerce(db, "f", kind, options, value) == stored


def test_what_no_type_accepts(client: TestClient):
    with SessionLocal() as db:
        for kind, value in (("text", {"a": 1}), ("text", "x" * 1001), ("role", "automation"), ("number", True)):
            with pytest.raises(registry.FieldError):
                registry.coerce(db, "f", kind, {}, value)

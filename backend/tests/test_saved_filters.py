"""Saved filters of the incident list, and what the list gives its quick view."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.incident_quick import counts
from app.main import app
from tests.conftest import make_key


def saved(client: TestClient, headers=None, **body) -> dict:
    answer = client.post("/api/filters", json={"name": "Mine", "query": "status:open", **body}, headers=headers)
    assert answer.status_code == 201, answer.text
    return answer.json()


def listed(client: TestClient, headers=None) -> dict:
    answer = client.get("/api/filters", headers=headers)
    assert answer.status_code == 200, answer.text
    return answer.json()


def analyst(admin: TestClient, label: str = "ana") -> tuple[TestClient, dict]:
    return TestClient(app), make_key(admin, label=label, roles=["analyst"])


def test_a_filter_keeps_the_query_the_sort_and_the_columns(admin: TestClient):
    made = saved(
        admin,
        name="  My   open ones ",
        query=" status:open severity:>=high ",
        sort={"key": "severity", "dir": "desc"},
        columns=["number", "name", "severity", "name", " "],
    )
    assert made["name"] == "My open ones" and made["query"] == "status:open severity:>=high"
    assert made["sort"] == {"key": "severity", "dir": "desc"} and made["columns"] == ["number", "name", "severity"]
    assert made["owner"] == "admin" and made["mine"] and not made["shared"] and made["entity"] == "incidents"
    assert listed(admin) == {"filters": [made], "default": None}
    # What is left out of a change stays; a sort can be taken away.
    changed = admin.put(f"/api/filters/{made['id']}", json={"name": "Open, high"}).json()
    assert changed["name"] == "Open, high" and changed["query"] == made["query"] and changed["sort"] == made["sort"]
    cleared = admin.put(f"/api/filters/{made['id']}", json={"sort": None, "query": ""}).json()
    assert cleared["sort"] is None and cleared["query"] == "" and cleared["columns"] == made["columns"]
    assert admin.delete(f"/api/filters/{made['id']}").status_code == 204
    assert listed(admin)["filters"] == []


def test_a_query_that_cannot_be_read_is_refused_with_the_reason(admin: TestClient):
    answer = admin.post("/api/filters", json={"name": "Broken", "query": "status:(open"})
    assert answer.status_code == 422 and answer.json()["query"]["position"] >= 0 and answer.json()["detail"]
    unknown = admin.post("/api/filters", json={"name": "Broken", "query": "sevrity:high"})
    assert unknown.status_code == 422 and "severity" in unknown.json()["detail"]
    made = saved(admin)
    assert admin.put(f"/api/filters/{made['id']}", json={"query": '"unclosed'}).status_code == 422
    assert listed(admin)["filters"][0]["query"] == "status:open"


def test_a_filter_on_a_custom_field_is_kept_and_says_so_when_the_field_is_gone(admin: TestClient):
    from tests.test_fields import field

    field(admin, "customer")
    field(admin, "region", "choice", options={"choices": ["EMEA", "APAC"]})
    made = saved(admin, name="Acme", query="customer:acme !region:APAC field.customer:*", columns=["name", "customer"])
    assert made["query"] == "customer:acme !region:APAC field.customer:*"
    # It is read as the list reads it: a choice the field does not have is refused when it is saved.
    wrong = admin.put(f"/api/filters/{made['id']}", json={"query": "region:mars"})
    assert wrong.status_code == 422 and wrong.json()["detail"] == '"region" is one of: EMEA, APAC'
    # The field is deleted: the filter is still there, and the list says which field it names.
    assert admin.delete("/api/fields/customer").status_code == 204
    assert listed(admin)["filters"][0]["query"] == made["query"]
    asked = admin.get("/api/incidents", params={"view": "summary", "q": made["query"]})
    assert asked.status_code == 422 and asked.json()["query"]["code"] == "unknown_field"
    assert asked.json()["detail"].startswith('"customer" is not a field of incidents')
    again = admin.put(f"/api/filters/{made['id']}", json={"query": made["query"]})
    assert again.status_code == 422 and '"customer"' in again.json()["detail"]
    assert admin.put(f"/api/filters/{made['id']}", json={"query": "!region:APAC"}).status_code == 200


def test_what_a_filter_is_made_of_is_checked(admin: TestClient):
    def refused(**body) -> str:
        answer = admin.post("/api/filters", json={"name": "No", **body})
        assert answer.status_code == 400, answer.text
        return answer.json()["detail"]

    assert "name" in refused(name="   ")
    assert "incidents" in refused(entity="artifacts")
    assert "asc or desc" in refused(sort={"key": "name", "dir": "up"})
    assert "column" in refused(sort={"dir": "asc"})
    saved(admin, name="Twice")
    again = admin.post("/api/filters", json={"name": "twice"})
    assert again.status_code == 409 and "already" in again.json()["detail"]
    other = saved(admin, name="Other")
    assert admin.put(f"/api/filters/{other['id']}", json={"name": "TWICE"}).status_code == 409
    assert admin.put(f"/api/filters/{other['id']}", json={"name": "other"}).status_code == 200  # its own name


def test_a_filter_is_its_owners_until_an_admin_shares_it(admin: TestClient):
    ana, key = analyst(admin)
    hers = saved(ana, key, name="Hers")
    mine = saved(admin, name="Unassigned, high", query='owner:"" severity:>=high')
    # Each sees their own, and what is not theirs does not exist for them.
    assert [row["name"] for row in listed(ana, key)["filters"]] == ["Hers"]
    assert ana.get("/api/filters", headers=key).json()["filters"][0]["owner"] == "api:ana"
    assert ana.put(f"/api/filters/{mine['id']}", json={"name": "Taken"}, headers=key).status_code == 404
    assert admin.delete(f"/api/filters/{hers['id']}").status_code == 404
    # Sharing is an administrator's.
    assert ana.put(f"/api/filters/{hers['id']}/sharing", json={"shared": True}, headers=key).status_code == 403
    shared = admin.put(f"/api/filters/{mine['id']}/sharing", json={"shared": True}).json()
    assert shared["shared"] and shared["mine"]
    seen = listed(ana, key)["filters"]
    assert [(row["name"], row["mine"], row["shared"]) for row in seen] == [
        ("Hers", True, False),
        ("Unassigned, high", False, True),
    ]
    # A shared filter of someone else is read, not changed.
    refused = ana.put(f"/api/filters/{mine['id']}", json={"query": ""}, headers=key)
    assert refused.status_code == 403 and "admin's" in refused.json()["detail"]
    assert ana.delete(f"/api/filters/{mine['id']}", headers=key).status_code == 403
    actions = [entry["action"] for entry in admin.get("/api/audit").json()["entries"]]
    assert "filter.share" in actions
    # Taken back: the others no longer see it.
    assert not admin.put(f"/api/filters/{mine['id']}/sharing", json={"shared": False}).json()["shared"]
    assert [row["name"] for row in listed(ana, key)["filters"]] == ["Hers"]


def test_each_person_chooses_one_default_and_a_deleted_filter_clears_it(admin: TestClient):
    ana, key = analyst(admin)
    first, second = saved(admin, name="First"), saved(admin, name="Second")
    assert admin.put("/api/filters/default/incidents", json={"filterId": first["id"]}).json() == {
        "default": first["id"]
    }
    assert admin.put("/api/filters/default/incidents", json={"filterId": second["id"]}).status_code == 200
    assert listed(admin)["default"] == second["id"]  # one at most
    # A filter that is not shared cannot be someone else's default; a shared one can.
    assert ana.put("/api/filters/default/incidents", json={"filterId": second["id"]}, headers=key).status_code == 404
    admin.put(f"/api/filters/{second['id']}/sharing", json={"shared": True})
    assert ana.put("/api/filters/default/incidents", json={"filterId": second["id"]}, headers=key).status_code == 200
    assert listed(ana, key)["default"] == second["id"] and listed(admin)["default"] == second["id"]
    # No longer shared: her default goes, its owner's stays.
    admin.put(f"/api/filters/{second['id']}/sharing", json={"shared": False})
    assert listed(ana, key)["default"] is None and listed(admin)["default"] == second["id"]
    # Deleted: the default of whoever had it goes with it.
    assert admin.delete(f"/api/filters/{second['id']}").status_code == 204
    assert listed(admin)["default"] is None
    admin.put("/api/filters/default/incidents", json={"filterId": first["id"]})
    assert admin.delete("/api/filters/default/incidents").status_code == 204
    assert listed(admin) == {"filters": [first], "default": None}
    assert admin.put("/api/filters/default/artifacts", json={"filterId": first["id"]}).status_code == 400


def test_the_filters_of_an_account_follow_its_new_name(admin: TestClient):
    created = admin.post("/api/users", json={"username": "rita", "password": "password1", "roles": ["analyst"]})
    assert created.status_code == 201, created.text
    rita = TestClient(app)
    assert rita.post("/api/auth/login", json={"username": "rita", "password": "password1"}).status_code == 200
    hers = saved(rita, name="Hers")
    rita.put("/api/filters/default/incidents", json={"filterId": hers["id"]})
    user_id = next(user["id"] for user in admin.get("/api/users").json()["users"] if user["username"] == "rita")
    assert admin.patch(f"/api/users/{user_id}", json={"username": "margherita"}).status_code == 200
    again = listed(rita)
    assert [(row["name"], row["owner"], row["mine"]) for row in again["filters"]] == [("Hers", "margherita", True)]
    assert again["default"] == hers["id"]


# --------------------------------------------------------------------------- #
# What the list reads of an incident                                          #
# --------------------------------------------------------------------------- #
DOC = {
    "id": "inc-quick",
    "name": "WKS-1 - rossi",
    "host": "WKS-1",
    "username": "rossi",
    "createdAt": "2026-11-19T09:00:00.000Z",
    "updatedAt": "2026-11-19T09:00:00.000Z",
    "createdBy": "admin",
    "flags": {"a": {"key": "a"}, "b": {"key": "b"}},
    "notes": [{"id": "n1", "text": "Sender blocked on the gateway", "createdAt": "2026-11-19T09:52:00.000Z"}],
    "data": {
        "browser": {
            "browsers": {
                "chrome": {
                    "profiles": {
                        "Default": {"history": [{}, {}, {}], "downloads": [{}], "bookmarks": [{}, {}]},
                        "Work": {"history": [{}]},
                    }
                }
            }
        },
        "commands": {"shells": {"bash": {"commands": [{}, {}]}, "powershell": {"commands": [{}]}}},
        "endpoint": {"categories": {"execution": {"sources": {"bam": {"records": [{}, {}, {}, {}]}}}}},
    },
}


def test_the_numbers_of_the_evidence_are_counted_without_trusting_the_shape():
    assert counts(DOC) == {
        "browserEvents": 5,
        "commands": 3,
        "endpointArtifacts": 4,
        "flagged": 2,
        "bookmarks": 2,
        "notes": 1,
    }
    empty = {"browserEvents": 0, "commands": 0, "endpointArtifacts": 0, "flagged": 0, "bookmarks": 0, "notes": 0}
    assert counts(None) == empty
    assert counts({"data": {"browser": {"browsers": []}, "commands": "x"}, "flags": [], "notes": {}}) == empty


def test_the_quick_view_reads_an_incident_without_its_evidence(admin: TestClient):
    assert admin.post("/api/incidents", json=DOC).status_code == 201
    assert admin.patch("/api/incidents/inc-quick/fields", json={"changes": {"category": "phishing"}}).status_code == 200
    for text in ("first", "second", "third"):
        assert admin.post("/api/incidents/inc-quick/war-room", json={"text": text}).status_code == 201
    quick = admin.get("/api/incidents/inc-quick/quick")
    assert quick.status_code == 200, quick.text
    body = quick.json()
    assert body["id"] == "inc-quick" and body["number"] == 1 and body["type"] == "unclassified"
    assert body["fields"]["category"] == "phishing" and body["createdBy"] == "admin"
    assert body["counts"]["browserEvents"] == 5 and body["counts"]["notes"] == 4
    # The last three lines of the War Room, oldest first; nothing of the evidence.
    assert [entry["body"]["text"] for entry in body["last"]] == ["first", "second", "third"]
    assert isinstance(body["timers"], list) and "data" not in body
    assert admin.get("/api/incidents/nothing/quick").status_code == 404


def test_the_list_gives_the_fields_its_columns_ask_for(admin: TestClient):
    assert admin.post("/api/incidents", json=DOC).status_code == 201
    admin.patch("/api/incidents/inc-quick/fields", json={"changes": {"category": "phishing", "phase": "triage"}})
    plain = admin.get("/api/incidents?view=summary").json()["incidents"][0]
    assert "fields" not in plain
    rows = admin.get("/api/incidents?view=summary&fields=category,, nothing ,category").json()["incidents"]
    assert rows[0]["fields"] == {"category": "phishing"}
    assert {key: rows[0][key] for key in plain} == plain and "data" not in rows[0]
    # A query narrows it as it narrows the plain list.
    assert admin.get('/api/incidents?view=summary&fields=phase&q=host:"nothing"').json()["incidents"] == []

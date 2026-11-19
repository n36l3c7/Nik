"""The number of an incident (5.0): given at creation, never used twice, beside the uuid."""

from __future__ import annotations

from fastapi.testclient import TestClient


def _create(admin: TestClient, **doc) -> dict:
    answer = admin.post("/api/incidents", json={"name": "one", **doc})
    assert answer.status_code == 201, answer.text
    return answer.json()


def test_an_incident_gets_the_next_number_and_keeps_it(admin: TestClient):
    first = _create(admin, id="aaaa-1", name="first")
    second = _create(admin, id="aaaa-2", name="second")
    # The id is the uuid, named so too; the number is beside it.
    assert first["id"] == first["uuid"] == "aaaa-1"
    assert second["number"] == first["number"] + 1

    shown = admin.get("/api/incidents/aaaa-2").json()
    assert (shown["id"], shown["uuid"], shown["number"]) == ("aaaa-2", "aaaa-2", second["number"])
    rows = {row["id"]: row for row in admin.get("/api/incidents?view=summary").json()["incidents"]}
    assert rows["aaaa-1"]["number"] == first["number"] and rows["aaaa-2"]["number"] == second["number"]
    full = {row["id"]: row for row in admin.get("/api/incidents").json()["incidents"]}
    assert full["aaaa-2"]["number"] == second["number"]

    # A change of the document does not change it, whatever the document says.
    etag = admin.get("/api/incidents/aaaa-2").headers["ETag"]
    patched = admin.patch(
        "/api/incidents/aaaa-2",
        json={"name": "renamed", "number": 999},
        headers={"If-Match": etag, "Content-Type": "application/merge-patch+json"},
    )
    assert patched.status_code == 200, patched.text
    assert admin.get("/api/incidents/aaaa-2").json()["number"] == second["number"]
    # Saving the same incident again (an upsert) keeps its number.
    again = _create(admin, id="aaaa-2", name="saved again")
    assert again["number"] == second["number"]

    # A number is not given twice, also when the incident that had it is gone.
    assert admin.delete("/api/incidents/aaaa-2").status_code == 204
    third = _create(admin, id="aaaa-3", name="third")
    assert third["number"] == second["number"] + 1


def test_an_incident_is_found_by_its_number(admin: TestClient):
    made = _create(admin, id="bbbb-1", name="by number")
    found = admin.get(f"/api/incidents/by-number/{made['number']}")
    assert found.status_code == 200
    assert found.json() == {"id": "bbbb-1", "uuid": "bbbb-1", "number": made["number"], "name": "by number"}
    assert admin.get("/api/incidents/by-number/99999").status_code == 404
    assert admin.get("/api/incidents/by-number/abc").status_code == 422

    # In a query: number:N, and with the comparisons of a number.
    other = _create(admin, id="bbbb-2", name="another")
    ids = lambda q: {row["id"] for row in admin.get("/api/incidents", params={"q": q}).json()["incidents"]}  # noqa: E731
    assert ids(f"number:{made['number']}") == {"bbbb-1"}
    assert ids(f"no:>{made['number']}") == {"bbbb-2"}
    assert ids(f"number IN ({made['number']}, {other['number']})") == {"bbbb-1", "bbbb-2"}
    assert ids(f"!number:{made['number']}") == {"bbbb-2"}
    assert ids("uuid:bbbb-2") == {"bbbb-2"}


def test_an_incident_of_another_nik_gets_a_number_of_this_one(admin: TestClient):
    _create(admin, id="cccc-1")
    arrived = _create(admin, id="cccc-2", name="from elsewhere", number=4242, uuid="not-kept")
    assert arrived["number"] != 4242 and arrived["importedNumber"] == 4242
    assert arrived["uuid"] == "cccc-2"
    # The next one goes on from this Nik's own count, not from the number that came.
    assert _create(admin, id="cccc-3")["number"] == arrived["number"] + 1


def test_a_backup_gives_every_incident_the_number_it_had(admin: TestClient):
    first = _create(admin, id="dddd-1", name="first")
    second = _create(admin, id="dddd-2", name="second")
    admin.delete("/api/incidents/dddd-1")
    third = _create(admin, id="dddd-3", name="third")

    backup = admin.get("/api/backup/export").json()
    numbers = {doc["id"]: doc["number"] for doc in backup["incidents"]}
    assert numbers == {"dddd-2": second["number"], "dddd-3": third["number"]}
    # One incident of an older backup has no number: it gets one after the others.
    backup["incidents"].append({"id": "dddd-old", "name": "from 4.x"})
    assert admin.post("/api/backup/import", json=backup).status_code == 200
    admin.post("/api/auth/login", json={"username": "admin", "password": "supersecret"})
    restored = {row["id"]: row["number"] for row in admin.get("/api/incidents?view=summary").json()["incidents"]}
    assert restored["dddd-2"] == second["number"] and restored["dddd-3"] == third["number"]
    assert restored["dddd-old"] > third["number"]
    assert first["number"] not in restored.values()
    assert _create(admin, id="dddd-4")["number"] == restored["dddd-old"] + 1

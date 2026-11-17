"""The War Room of an incident: notes, what playbooks did, evidence."""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.automation import worker
from app.core.db import SessionLocal
from app.core.models import RunStep, WarRoomEntry
from tests.conftest import make_key
from tests.test_automation_engine import (  # noqa: F401 - test_actions is a fixture
    T0,
    edge,
    go,
    node,
    playbook,
    test_actions,
)
from tests.test_fields import incident


def room(admin: TestClient, incident_id: str = "i1", **params) -> list[dict]:
    answer = admin.get(f"/api/incidents/{incident_id}/war-room", params=params)
    assert answer.status_code == 200, answer.text
    return answer.json()["entries"]


def test_notes_are_the_notes_of_the_incident_wherever_they_were_written(admin: TestClient):
    incident(admin)
    # A note written the way it always was: in the document, through the notes API.
    old = admin.post("/api/incidents/i1/notes", json={"text": "Called the user."}).json()
    # A note written in the War Room.
    new = admin.post("/api/incidents/i1/war-room", json={"text": "  Laptop collected.  ", "tags": ["Chain", "chain"]})
    assert new.status_code == 201, new.text
    written = new.json()
    assert (written["kind"], written["author"], written["tags"]) == ("note", "admin", ["chain"])
    assert written["body"]["text"] == "Laptop collected." and written["body"]["noteId"]

    listed = room(admin)
    assert [entry["body"]["text"] for entry in listed] == ["Called the user.", "Laptop collected."]  # oldest first
    assert listed[0]["id"] == f"note-{old['id']}"  # no entry of its own: read from the document
    # Both are notes of the incident: its document holds the two, once each.
    notes = admin.get("/api/incidents/i1").json()["notes"]
    assert [note["text"] for note in notes] == ["Called the user.", "Laptop collected."]

    # Edited or deleted where notes are edited, the War Room follows.
    admin.patch(f"/api/incidents/i1/notes/{written['body']['noteId']}", json={"text": "Laptop collected at 10:40."})
    assert room(admin)[1]["body"] == {
        "text": "Laptop collected at 10:40.",
        "noteId": written["body"]["noteId"],
        "automation": False,
        "edited": True,
    }
    assert admin.delete(f"/api/incidents/i1/notes/{written['body']['noteId']}").status_code == 204
    assert [entry["body"]["text"] for entry in room(admin)] == ["Called the user."]

    assert admin.post("/api/incidents/i1/war-room", json={"text": "   "}).status_code == 400
    assert admin.post("/api/incidents/nope/war-room", json={"text": "x"}).status_code == 404
    viewer = make_key(admin, label="v", roles=["viewer"])
    assert admin.get("/api/incidents/i1/war-room", headers=viewer).status_code == 200
    assert admin.post("/api/incidents/i1/war-room", headers=viewer, json={"text": "x"}).status_code == 403


def test_what_a_playbook_does_on_an_incident_is_in_its_war_room(admin: TestClient):
    incident(admin)
    nodes = [
        node("say", "action", action="test.echo", args={"text": "hello {{ incident.name }}"}),
        node("ask", "approval", question="Go on?"),
        node("note", "action", action="nik.add-note", args={"text": "Done by the playbook"}),
        node("boom", "action", action="test.never", args={}),
    ]
    edges = [edge("start", "say"), edge("say", "ask"), edge("ask", "note", "approved"), edge("note", "boom")]
    pb = playbook(admin, "Works", nodes, edges)

    # A dry run changes nothing, and leaves no line.
    go(admin, pb, objectKind="incident", objectId="i1", dryRun=True)
    assert room(admin) == []

    run = go(admin, pb, objectKind="incident", objectId="i1")
    assert run["status"] == "waiting"
    (asked,) = admin.get("/api/automation/approvals").json()["approvals"]
    admin.post(f"/api/automation/approvals/{asked['id']}", json={"answer": "approved", "comment": "fine"})
    with SessionLocal() as db:
        for step in db.scalars(select(RunStep).where(RunStep.run_id == run["id"], RunStep.status == "pending")):
            step.next_at = T0
        db.commit()
    worker.drain(T0)

    listed = room(admin)
    kinds = [(entry["kind"], entry["author"]) for entry in listed]
    assert ("result", "nik-automation") in kinds and ("approval", "admin") in kinds
    assert ("error", "nik-automation") in kinds
    said = next(entry for entry in listed if entry["body"].get("title") == "say")
    assert said["body"] == {"title": "say", "what": "test.echo", "playbook": "Works"} and said["runId"] == run["id"]
    answered = next(entry for entry in listed if entry["kind"] == "approval")
    assert answered["body"] == {"question": "Go on?", "answer": "approved", "comment": "fine", "playbook": "Works"}
    failed = next(entry for entry in listed if entry["kind"] == "error")
    assert failed["body"]["error"] == "Refused by the other side"
    # The note the playbook wrote is the incident's note, marked as automation, with the run that wrote it.
    by_playbook = next(entry for entry in listed if entry["kind"] == "note")
    assert by_playbook["body"]["automation"] is True and by_playbook["runId"] == run["id"]

    # Opened, an entry shows what its step got, gave and sent: read from the step, not copied.
    detail = admin.get(f"/api/incidents/i1/war-room/{said['id']}").json()
    assert detail["step"]["output"] == {"text": "hello Laptop of finance", "extra": None}
    assert detail["step"]["input"]["args"]["text"] == "hello Laptop of finance"
    assert detail["step"]["playbook"] == "Works"
    assert admin.get(f"/api/incidents/i1/war-room/{by_playbook['id']}").json()["step"] is None
    assert admin.get("/api/incidents/i1/war-room/nope").status_code == 404

    # The chips of the stream.
    assert {entry["kind"] for entry in room(admin, show="notes")} == {"note"}
    assert {entry["kind"] for entry in room(admin, show="automation")} == {"result", "approval", "error"}
    assert room(admin, show="commands") == []
    assert [entry["kind"] for entry in room(admin, author="admin")] == ["approval"]
    assert len(room(admin, limit=2)) == 2 and room(admin, limit=2)[-1]["id"] == listed[-1]["id"]
    assert all(entry["at"] < listed[-1]["at"] for entry in room(admin, before=listed[-1]["at"]))

    # A playbook that works on no incident writes in no War Room.
    lone = [node("say", "action", action="test.echo", args={"text": "x"})]
    go(admin, playbook(admin, "Alone", lone, [edge("start", "say")]))
    with SessionLocal() as db:
        assert {row.incident_id for row in db.scalars(select(WarRoomEntry))} == {"i1"}

    # It goes with the incident.
    assert admin.delete("/api/incidents/i1").status_code == 204
    with SessionLocal() as db:
        assert db.scalars(select(WarRoomEntry)).all() == []


def test_an_entry_is_marked_as_evidence_and_found_among_it(admin: TestClient):
    incident(admin)
    old = admin.post("/api/incidents/i1/notes", json={"text": "The user confirmed the click."}).json()
    written = admin.post("/api/incidents/i1/war-room", json={"text": "Screenshot taken."}).json()
    assert room(admin, show="evidence") == []

    # A note that has no entry of its own gets one when it is tagged.
    marked = admin.put(f"/api/incidents/i1/war-room/note-{old['id']}/tags", json={"tags": ["evidence", "User"]})
    assert marked.status_code == 200, marked.text
    assert marked.json()["tags"] == ["evidence", "user"]
    assert marked.json()["body"]["text"] == "The user confirmed the click."
    assert [entry["body"]["text"] for entry in room(admin, show="evidence")] == ["The user confirmed the click."]
    assert [entry["body"]["text"] for entry in room(admin, tag="user")] == ["The user confirmed the click."]
    # It is still listed once, where it was.
    assert [entry["body"]["text"] for entry in room(admin)] == ["The user confirmed the click.", "Screenshot taken."]

    url = f"/api/incidents/i1/war-room/{written['id']}/tags"
    admin.put(url, json={"tags": ["evidence"]})
    assert len(room(admin, show="evidence")) == 2
    admin.put(url, json={"tags": []})
    assert len(room(admin, show="evidence")) == 1
    actions = [entry["action"] for entry in admin.get("/api/audit").json()["entries"]]
    assert actions.count("warroom.evidence") == 2
    assert admin.put("/api/incidents/i1/war-room/nope/tags", json={"tags": ["evidence"]}).status_code == 404
    viewer = make_key(admin, label="v", roles=["viewer"])
    assert admin.put(url, headers=viewer, json={"tags": []}).status_code == 403

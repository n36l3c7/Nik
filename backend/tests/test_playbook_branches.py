"""Branches of a playbook (5.2): worked on beside the version in use, then pushed over it."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app as fastapi_app
from tests.conftest import make_key
from tests.test_automation_engine import edge, node, playbook, test_actions  # noqa: F401 - a fixture

BASE = "/api/automation/playbooks"


def note(text: str) -> dict:
    return node("say", "action", action="test.echo", args={"text": text})


def graph_of(text: str) -> dict:
    return {"nodes": [node("start", "trigger", manual=True), note(text)], "edges": [edge("start", "say")]}


def test_a_branch_is_made_worked_on_and_pushed_over_the_version_in_use(admin: TestClient, test_actions):  # noqa: F811
    pb = playbook(admin, "Branched", [note("one")], [edge("start", "say")])
    url = f"{BASE}/{pb}"
    assert admin.get(url).json()["branches"] == [] and admin.get(url).json()["version"] == 1

    made = admin.post(f"{url}/branches", json={"name": "  louder   words "})
    assert made.status_code == 201, made.text
    branch = made.json()
    assert (branch["name"], branch["baseVersion"], branch["behind"], branch["createdBy"]) == (
        "louder words",
        1,
        False,
        "admin",
    )
    assert branch["graph"] == admin.get(url).json()["graph"]  # a copy of the version in use
    # The list of playbooks names the branches of each, without their graphs.
    listed = {row["id"]: row for row in admin.get(BASE).json()["playbooks"]}
    assert [(item["name"], item["createdBy"]) for item in listed[pb]["branches"]] == [("louder words", "admin")]
    assert "graph" not in listed[pb]["branches"][0]
    assert all(row["branches"] == [] for key, row in listed.items() if key != pb)
    for bad in ("main", "Draft", "   ", "louder WORDS"):
        assert admin.post(f"{url}/branches", json={"name": bad}).status_code in (400, 422), bad

    # Saved as it is edited: it need not be valid, and nothing a run uses changes.
    broken = {"nodes": [node("start", "trigger", manual=True), note("two")], "edges": []}
    saved = admin.put(f"{url}/branches/{branch['id']}", json={"graph": broken})
    assert saved.status_code == 200 and saved.json()["graph"] == broken
    assert admin.get(url).json()["version"] == 1
    refused = admin.post(f"{url}/branches/{branch['id']}/push", json={})
    assert refused.status_code == 422 and refused.json()["problems"]

    admin.put(f"{url}/branches/{branch['id']}", json={"graph": graph_of("two")})
    pushed = admin.post(f"{url}/branches/{branch['id']}/push", json={})
    assert pushed.status_code == 200, pushed.text
    after = pushed.json()
    assert after["version"] == 2 and after["graph"] == graph_of("two")
    assert after["branches"][0]["baseVersion"] == 2 and after["branches"][0]["behind"] is False
    versions = admin.get(f"{url}/versions").json()["versions"]
    assert versions[0]["note"] == 'From the branch "louder words"'

    # The branch of another branch starts where that one did.
    twin = admin.post(f"{url}/branches", json={"name": "twin", "from": branch["id"]}).json()
    assert twin["graph"] == graph_of("two") and twin["baseVersion"] == 2
    assert [b["name"] for b in admin.get(f"{url}/branches").json()["branches"]] == ["louder words", "twin"]
    assert admin.delete(f"{url}/branches/{twin['id']}").status_code == 204
    assert admin.get(f"{url}/branches/{twin['id']}").status_code == 404
    assert admin.get(f"{BASE}/nope/branches").status_code == 404


def test_a_push_says_when_the_playbook_moved_on_and_overwrites_only_when_told(admin: TestClient, test_actions):  # noqa: F811
    pb = playbook(admin, "Moved", [note("one")], [edge("start", "say")])
    url = f"{BASE}/{pb}"
    branch = admin.post(f"{url}/branches", json={"name": "mine", "graph": graph_of("mine")}).json()
    # Someone saves a version meanwhile.
    assert admin.post(f"{url}/versions", json={"graph": graph_of("theirs")}).status_code == 201
    assert admin.get(f"{url}/branches").json()["branches"][0]["behind"] is True

    held = admin.post(f"{url}/branches/{branch['id']}/push", json={})
    assert held.status_code == 409
    assert (held.json()["moved"], held.json()["baseVersion"], held.json()["currentVersion"]) == (True, 1, 2)
    assert admin.get(url).json()["graph"] == graph_of("theirs")

    forced = admin.post(f"{url}/branches/{branch['id']}/push", json={"overwrite": True, "note": "Mine wins"})
    assert forced.status_code == 200 and forced.json()["version"] == 3
    assert forced.json()["graph"] == graph_of("mine")
    assert admin.get(f"{url}/versions").json()["versions"][0]["note"] == "Mine wins"
    # What was there is a version still: nothing is lost.
    assert admin.get(f"{url}/versions/2").json()["graph"] == graph_of("theirs")


def test_a_branch_is_seen_by_who_edits_playbooks_and_changed_by_its_author(admin: TestClient, test_actions):  # noqa: F811
    pb = playbook(admin, "Shared", [note("one")], [edge("start", "say")])
    url = f"{BASE}/{pb}"
    branch = admin.post(f"{url}/branches", json={"name": "admins"}).json()
    builder = make_key(admin, label="builder", roles=["playbooks", "analyst"])
    runner = make_key(admin, label="runner", roles=["analyst"])
    with TestClient(fastapi_app) as other:
        assert other.get(f"{url}/branches", headers=runner).status_code == 403
        seen = other.get(f"{url}/branches/{branch['id']}", headers=builder)
        assert seen.status_code == 200 and seen.json()["graph"]
        for call in (
            other.put(f"{url}/branches/{branch['id']}", headers=builder, json={"graph": graph_of("x")}),
            other.post(f"{url}/branches/{branch['id']}/push", headers=builder, json={}),
            other.delete(f"{url}/branches/{branch['id']}", headers=builder),
        ):
            assert call.status_code == 403 and "make one of your own" in call.json()["detail"]
        # One of their own, from it; an admin may change anybody's.
        own = other.post(f"{url}/branches", headers=builder, json={"name": "builders", "from": branch["id"]})
        assert own.status_code == 201 and own.json()["createdBy"] == "api:builder"
    assert admin.put(f"{url}/branches/{own.json()['id']}", json={"name": "renamed"}).json()["name"] == "renamed"
    audit = admin.get("/api/audit", params={"q": "action:playbook.branch"}).json()["entries"]
    assert len(audit) == 2
    # Deleting the playbook takes its branches.
    assert admin.delete(url).status_code == 204


def test_a_draft_is_thrown_away_and_a_playbook_that_is_only_a_draft_is_deleted(admin: TestClient, test_actions):  # noqa: F811
    pb = playbook(admin, "Drafted", [note("one")], [edge("start", "say")])
    url = f"{BASE}/{pb}"
    admin.put(url, json={"draft": graph_of("half done")})
    assert admin.get(url).json()["draft"] == graph_of("half done")
    assert admin.delete(f"{url}/draft").status_code == 204
    assert admin.get(url).json()["draft"] is None and admin.get(url).json()["graph"]["nodes"]
    assert admin.delete(f"{url}/draft").status_code == 204  # nothing to throw away: nothing happens

    fresh = admin.post(BASE, json={"name": "Never saved"}).json()
    admin.put(f"{BASE}/{fresh['id']}", json={"draft": graph_of("x")})
    only = admin.delete(f"{BASE}/{fresh['id']}/draft")
    assert only.status_code == 409 and "delete the playbook instead" in only.json()["detail"]
    assert admin.delete(f"{BASE}/{fresh['id']}").status_code == 204


def test_the_corners_of_a_connection_are_part_of_the_graph(admin: TestClient, test_actions):  # noqa: F811
    """A line routed by hand (5.2): its corners are kept with the edge, and checked as a drawing."""
    pb = playbook(admin, "Routed", [note("one")], [edge("start", "say")])
    url = f"{BASE}/{pb}"
    shape = graph_of("two")
    shape["edges"][0]["points"] = [{"x": 40, "y": 120}, {"x": 200, "y": 120.5}]
    saved = admin.post(f"{url}/versions", json={"graph": shape})
    assert saved.status_code == 201, saved.text
    assert saved.json()["graph"]["edges"][0]["points"] == shape["edges"][0]["points"]
    for bad in (
        [{"x": 1}],
        [{"x": "1", "y": 2}],
        [{"x": 1, "y": 2, "z": 3}],
        [{"x": True, "y": 2}],
        "here",
        [{"x": 1, "y": 2}] * 21,
        [{"x": 1e9, "y": 0}],
    ):
        shape["edges"][0]["points"] = bad
        refused = admin.post(f"{url}/versions", json={"graph": shape})
        assert refused.status_code == 422 and "corners of an edge" in refused.json()["detail"], bad

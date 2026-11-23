"""The playbooks Nik ships: added once and off, importable as files, and each
one walked to its end in a dry run. The two actions written for them."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.automation import connector_actions, scripts, shipped, state, worker
from app.core.db import SessionLocal
from app.core.models import Connection, IocCheck, Playbook, Run, RunStep
from app.core.security import now_iso
from tests import vendor
from tests.test_automation_engine import (  # noqa: F401 - test_actions is a fixture
    T0,
    edge,
    go,
    node,
    playbook,
    run_of,
    start,
    steps,
    test_actions,
)
from tests.test_mail import no_dns, phishing_message  # noqa: F401 - no_dns is a fixture

IP = "185.220.101.47"
# The playbooks Nik ships and the ones of the packs of vendors (packs/<id>/playbooks).
FILES = {**dict(shipped.files()), **vendor.playbooks()}
NAMES = {
    "phishing-triage": "Phishing triage",
    "recheck-watched-lists": "Weekly re-check of the watched lists",
    "block-malicious-indicator": "Malicious indicator to a block list",
    "incident-to-ticket": "Incident to ticketing",
    "storage-low-notice": "Disk almost full notice",
    "mail-attachments": "Analyse the attachments of an e-mail",
}


@pytest.fixture()
def library(admin: TestClient):
    """What a server has when it starts: the shipped scripts, connectors and playbooks."""
    with SessionLocal() as db:
        scripts.seed(db)
        connector_actions.seed(db)
        db.flush()
        added = shipped.seed(db)
        db.commit()
        added += vendor.install(db)  # two of them bring a playbook
    return added


def by_name(admin: TestClient) -> dict[str, dict]:
    return {row["name"]: row for row in admin.get("/api/automation/playbooks").json()["playbooks"]}


def detail(admin: TestClient, name: str) -> dict:
    return admin.get(f"/api/automation/playbooks/{by_name(admin)[name]['id']}").json()


def connection(connector_id: str, name: str, config: dict, secrets: dict) -> None:
    with SessionLocal() as db:
        row = Connection(
            id=(connector_id.replace("-", "") + "0" * 32)[:32],
            name=name,
            connector_id=connector_id,
            config=config,
            created_at=now_iso(),
            updated_at=now_iso(),
        )
        connector_actions.store_secrets(row, secrets)
        db.add(row)
        db.commit()


def errors(run: dict) -> dict:
    """What each step that failed said, for the message of an assertion."""
    return {name: (step["status"], step.get("error")) for name, step in steps(run).items() if step.get("error")}


def dry(admin: TestClient, playbook_id: str, **body) -> dict:
    return go(admin, playbook_id, dryRun=True, **body)


# --------------------------------------------------------------------------- #
# Shipping                                                                    #
# --------------------------------------------------------------------------- #
def test_six_playbooks_ship_and_each_file_is_a_playbook_as_export_writes_it():
    assert {key: source["name"] for key, source in FILES.items()} == NAMES
    for path in sorted([*shipped.SEED_DIR.glob("*.json"), *vendor.REPO_PACKS.glob("*/playbooks/*.json")]):
        doc = json.loads(path.read_text(encoding="utf-8"))
        assert (doc["app"], doc["type"], doc["version"]) == ("Nik", "playbook", 1), path.name
        held = doc["playbook"]
        assert set(held) == {
            "name",
            "description",
            "graph",
            "maxRunsPerHour",
            "onePerObject",
            "maxSeconds",
            "approvalDefault",
        }, path.name
        assert 80 < len(held["description"]) <= 2000 and held["approvalDefault"] is True, path.name
        # Each can be tried by hand, and says so.
        trigger = next(n for n in held["graph"]["nodes"] if n["kind"] == "trigger")
        assert trigger["config"].get("manual") is True, path.name
        assert all(n.get("name") and "position" in n for n in held["graph"]["nodes"]), path.name


def test_they_are_added_once_and_off_and_are_the_teams_from_then_on(admin: TestClient, library):
    # Four are part of Nik; two come with the pack of the product they are about.
    assert library == 4 + len(vendor.folders())
    listed = by_name(admin)
    assert set(NAMES.values()) <= set(listed)
    own = {source["name"] for _key, source in shipped.files()}
    assert len(own) == 4
    assert all(listed[name]["builtin"] == (name in own) and not listed[name]["enabled"] for name in NAMES.values())
    # What needs nothing chosen has a version and can be turned on; the other is a draft that says what
    # is missing. A node of a connector with no instance yet is not something to choose: it sends through
    # the one that is on when it runs.
    ready = {name for name in NAMES.values() if listed[name]["version"] == 1}
    assert ready == {
        "Phishing triage",
        "Weekly re-check of the watched lists",
        "Disk almost full notice",
        "Analyse the attachments of an e-mail",
        "Incident to ticketing",
    }
    row = listed["Malicious indicator to a block list"]
    assert row["version"] is None and row["hasDraft"] is True
    refused = admin.put(f"/api/automation/playbooks/{row['id']}/enabled", json={"enabled": True})
    assert refused.status_code == 400
    problems = admin.post(f"/api/automation/playbooks/{row['id']}/versions", json={}).json()["problems"]
    assert '"repository" is required' in {problem["message"] for problem in problems}
    # A schedule that is off fires nothing.
    worker.drain(T0 + 14 * 86400)
    with SessionLocal() as db:
        assert db.scalars(select(Run)).all() == []

    # Again (another start of the server): nothing to add, and nothing overwritten.
    triage = listed["Phishing triage"]["id"]
    assert admin.put(f"/api/automation/playbooks/{triage}", json={"name": "Our triage"}).status_code == 200
    assert admin.delete(f"/api/automation/playbooks/{listed['Disk almost full notice']['id']}").status_code == 204
    with SessionLocal() as db:
        assert shipped.seed(db) == 0
        db.commit()
        assert sorted(state.read(db)["shippedPlaybooks"]) == sorted(key for key, _source in shipped.files())
    after = by_name(admin)
    assert "Our triage" in after and "Phishing triage" not in after and "Disk almost full notice" not in after


def test_a_name_already_taken_is_left_to_whoever_took_it(admin: TestClient):
    mine = playbook(admin, "phishing TRIAGE", [], [])
    with SessionLocal() as db:
        scripts.seed(db)
        connector_actions.seed(db)
        db.flush()
        assert shipped.seed(db) == 3
        # No description sends to a place of Settings that is gone.
        for shipped_row in db.scalars(select(Playbook).where(Playbook.builtin.is_(True))).all():
            assert "Settings, Connections" not in shipped_row.description
            assert "Settings, Automation" not in shipped_row.description
        db.commit()
        assert shipped.seed(db) == 0
    rows = [row for name, row in by_name(admin).items() if name.lower() == "phishing triage"]
    assert [row["id"] for row in rows] == [mine] and rows[0]["builtin"] is False


def test_each_file_is_imported_by_hand_like_any_other(admin: TestClient):
    with SessionLocal() as db:
        scripts.seed(db)
        connector_actions.seed(db)
        for text, _connector in vendor.connectors():
            connector_actions.install(db, text, "admin")
        db.commit()
    for key, source in FILES.items():
        made = admin.post("/api/automation/playbooks/import", json={"playbook": source})
        assert made.status_code == 201, (key, made.text)
        body = made.json()
        assert body["name"] == NAMES[key] and body["enabled"] is False and body["version"] is None
        # The script nodes took the version each script has here.
        for item in body["draft"]["nodes"]:
            if item["kind"] == "script":
                assert isinstance(item["config"]["script_version"], int), (key, item["id"])
        messages = {problem["message"] for problem in body["problems"]}
        if key == "block-malicious-indicator":
            assert '"repository" is required' in messages, key
        else:
            assert messages == set(), key


# --------------------------------------------------------------------------- #
# Dry runs                                                                    #
# --------------------------------------------------------------------------- #
def test_phishing_triage_in_a_dry_run(admin: TestClient, library, sandbox, no_dns):  # noqa: F811
    mail = admin.post("/api/artifacts/mails", files={"file": ("reported.eml", phishing_message())}).json()
    pb = by_name(admin)["Phishing triage"]["id"]
    run = dry(admin, pb, objectKind="artifact", objectId=mail["id"])
    assert run["status"] == "done", errors(run)
    done = steps(run)
    assert [done[name]["status"] for name in ("open", "link", "hosts", "note", "ask", "watch")] == ["done"] * 6
    assert done["open"]["request"]["would"] == "create an incident"
    assert done["open"]["request"]["title"].startswith("Phishing: ")
    assert done["open"]["input"]["args"]["severity"] in ("high", "medium")
    assert done["link"]["request"] == {"would": "link the artifact", "artifact": mail["id"]}
    hosts = done["hosts"]["output"]
    assert hosts["count"] == len(hosts["domains"]) > 0
    # The note is defanged: nobody opens an address from it by mistake.
    text = done["note"]["input"]["args"]["text"]
    assert "[.]" in text and "http://" not in text and "https://" not in text
    assert done["watch"]["request"]["would"] == 'add to the list "Phishing senders"'
    # Nothing was changed: no incident, no list.
    assert "Phishing:" not in admin.get("/api/incidents").text
    assert admin.get("/api/iocs/lists").json()["lists"] == []


def test_phishing_triage_for_real_opens_the_incident_and_asks_before_watching(
    admin: TestClient,
    library,
    sandbox,
    no_dns,  # noqa: F811
):
    pb = by_name(admin)["Phishing triage"]["id"]
    assert admin.put(f"/api/automation/playbooks/{pb}/enabled", json={"enabled": True}).status_code == 200
    mail = admin.post("/api/artifacts/mails", files={"file": ("reported.eml", phishing_message())}).json()
    worker.drain()
    (run,) = admin.get(f"/api/automation/runs?playbook={pb}").json()["runs"]
    assert (run["trigger"], run["status"], run["artifactId"]) == ("mail.analysed", "waiting", mail["id"])
    done = steps(run_of(admin, run["id"]))
    incident_id = done["open"]["output"]["incident"]["id"]
    linked = admin.get(f"/api/artifacts/{mail['id']}").json()["incidents"]
    assert [item["id"] for item in linked] == [incident_id]
    waiting = admin.get("/api/automation/approvals").json()["approvals"]
    assert waiting[0]["question"].startswith("Watch the sender's domain ")
    # Linking the e-mail to the incident it opened does not start the triage again.
    assert len(admin.get(f"/api/automation/runs?playbook={pb}").json()["runs"]) == 1


def test_the_weekly_recheck_in_a_dry_run(admin: TestClient, library, sandbox):
    admin.post("/api/iocs", json={"text": IP, "list": {"name": "AsyncRAT C2", "watch": True}})
    admin.post("/api/iocs", json={"text": "198.51.100.7", "list": {"name": "Not watched"}})
    row = by_name(admin)["Weekly re-check of the watched lists"]
    assert row["trigger"] == "schedule 30 6 * * 1, by hand"
    run = dry(admin, row["id"])
    assert run["status"] == "done", errors(run)
    done = steps(run)
    assert done["lists"]["output"]["names"] == ["AsyncRAT C2"]
    assert done["each"]["output"]["count"] == 1 and done["each"]["output"]["failed"] == 0
    check = done["check"]
    assert check["request"]["would"] == 'check the list "AsyncRAT C2" again'
    assert check["output"]["before"] == check["output"]["after"] == [{"type": "ip", "value": IP, "verdict": ""}]
    # Nothing was asked, so nothing changed and no report is sent.
    assert done["changes"]["output"]["changed"] == [] and "report" not in done
    with SessionLocal() as db:
        assert db.scalars(select(IocCheck)).all() == []


SMTP = {"host": "smtp.example.org", "port": 587, "security": "starttls", "username": "", "sender": "nik@example.org"}


def test_the_report_of_a_recheck_says_what_changed(admin: TestClient, library, sandbox, outside):
    """The shipped graph with the check's answers put in by hand: the comparison, the condition, the message."""
    with SessionLocal() as db:
        vendor.source(db, "shodan")  # a source that is on: there is someone to ask
    outside.host("smtp.example.org", "93.184.215.25")
    assert admin.put("/api/automation/settings", json={"smtp": SMTP}).status_code == 200
    admin.post("/api/iocs", json={"text": f"{IP}\nevil.example", "list": {"name": "AsyncRAT C2", "watch": True}})
    pb = by_name(admin)["Weekly re-check of the watched lists"]["id"]
    assert (
        admin.put(
            f"/api/automation/playbooks/{pb}/egress", json={"mode": "listed", "hosts": ["example.org"]}
        ).status_code
        == 200
    )

    def answers(db, shared, budget_seconds=60.0, max_calls=300):
        """The enrichment worker: one source says the address is malicious."""
        for check in db.scalars(select(IocCheck).where(IocCheck.status == "running")).all():
            vendor.said(db, "virustotal", "ip", IP, "malicious", "7 engines")
            check.status, check.pending, check.done = "done", [], check.total
        db.commit()

    run_id = start(admin, pb)
    worker.drain(T0)
    step = steps(run_of(admin, run_id))["check"]
    assert step["status"] == "waiting"  # the sources are being asked: the step is called again later
    with SessionLocal() as db:
        (check,) = db.scalars(select(IocCheck)).all()
        assert (check.label, check.created_by) == ("AsyncRAT C2", "nik-automation")
        answers(db, {})
    worker.drain(T0 + 60)
    run = run_of(admin, run_id)
    done = steps(run)
    assert done["check"]["status"] == "done" and done["check"]["output"]["finished"] is True
    assert {"type": "ip", "value": IP, "verdict": "malicious"} in done["check"]["output"]["after"]
    assert [item["value"] for item in done["changes"]["output"]["worse"]] == [IP]
    # The message leaves (indicators and verdicts always may), defanged, and names the list.
    assert run["status"] == "done", errors(run)
    (mail,) = outside.mails
    assert (mail["to"], mail["subject"]) == ("soc@example.org", 'Nik: the watched list "AsyncRAT C2" changed')
    assert "185[.]220[.]101[.]47" in mail["text"] and IP not in mail["text"]
    assert "Became suspicious or malicious (1):" in mail["text"] and "No longer flagged (0):" in mail["text"]


def test_the_block_list_in_a_dry_run(admin: TestClient, library, outside):
    outside.host("api.bitbucket.org", "104.192.141.1")
    connection(
        "bitbucket-cloud",
        "Block lists",
        {"workspace": "acme-sec"},
        {"username": "soc@example.org", "password": "an-api-token"},
    )
    row = by_name(admin)["Malicious indicator to a block list"]
    shape = detail(admin, row["name"])["draft"]
    for item in shape["nodes"]:
        if item["id"] in ("read", "write"):
            item["config"]["connection"] = "Block lists"
            item["config"]["args"]["repository"] = "edl"
    saved = admin.post(f"/api/automation/playbooks/{row['id']}/versions", json={"graph": shape})
    assert saved.status_code == 201, saved.text
    assert saved.json()["runsOn"] == "indicator"
    admin.post("/api/iocs", json={"text": "evil.example"})
    run = dry(admin, row["id"], objectKind="indicator", objectId="domain:evil.example")
    assert run["status"] == "done", errors(run)
    done = steps(run)
    assert outside.requests == []
    read = done["read"]["request"]
    assert (read["method"], read["host"], read["connection"]) == ("GET", "api.bitbucket.org", "Block lists")
    assert read["path"] == "/2.0/repositories/acme-sec/edl/src/main/lists/blocked.txt"
    write = done["write"]
    assert write["request"]["method"] == "POST" and write["request"]["path"] == "/2.0/repositories/acme-sec/edl/src"
    assert write["input"]["args"]["content"].endswith("evil.example\n")
    assert write["input"]["args"]["message"].startswith("Block evil.example")
    assert done["keep"]["request"]["would"] == 'add to the list "Blocked"'
    # For real the commit would wait for a person: the playbook asks before a change outside.
    assert detail(admin, row["name"])["approvalDefault"] is True
    assert next(n for n in shape["nodes"] if n["id"] == "write")["config"].get("approval") is None


def test_the_block_list_adds_a_line_once(admin: TestClient, library, outside):
    """For real: the file is read, the address is added with a commit after a person approves, and not twice."""
    outside.host("api.bitbucket.org", "104.192.141.1")
    connection(
        "bitbucket-cloud", "Block lists", {"workspace": "acme-sec"}, {"username": "soc@example.org", "password": "t"}
    )
    row = by_name(admin)["Malicious indicator to a block list"]
    shape = detail(admin, row["name"])["draft"]
    for item in shape["nodes"]:
        if item["id"] in ("read", "write"):
            item["config"]["connection"] = "Block lists"
            item["config"]["args"]["repository"] = "edl"
    assert admin.post(f"/api/automation/playbooks/{row['id']}/versions", json={"graph": shape}).status_code == 201
    file_path = "/2.0/repositories/acme-sec/edl/src/main/lists/blocked.txt"
    outside.answer("api.bitbucket.org", 200, body=b"old.example\n", path=file_path)
    outside.answer("api.bitbucket.org", 201, body=b"", path="/2.0/repositories/acme-sec/edl/src")
    admin.post("/api/iocs", json={"text": "evil.example"})

    run_id = start(admin, row["id"], objectKind="indicator", objectId="domain:evil.example")
    worker.drain(T0)
    assert run_of(admin, run_id)["status"] == "waiting"
    (asked,) = admin.get("/api/automation/approvals").json()["approvals"]
    assert admin.post(f"/api/automation/approvals/{asked['id']}", json={"answer": "approved"}).status_code == 200
    with SessionLocal() as db:
        for step in db.scalars(select(RunStep).where(RunStep.run_id == run_id, RunStep.status == "pending")):
            step.next_at = T0
        db.commit()
    worker.drain(T0)
    run = run_of(admin, run_id)
    assert run["status"] == "done", errors(run)
    posted = [r for r in outside.requests if r["method"] == "POST"]
    assert len(posted) == 1
    body = posted[0]["body"].decode() if isinstance(posted[0]["body"], bytes) else str(posted[0]["body"])
    assert "old.example%0Aevil.example%0A" in body and "branch=main" in body
    lists = {item["name"]: item for item in admin.get("/api/iocs/lists").json()["lists"]}
    assert lists["Blocked"]["count"] == 1

    # Already in the file: nothing is written.
    outside.answer("api.bitbucket.org", 200, body=b"old.example\nevil.example\n", path=file_path)
    again = go(admin, row["id"], objectKind="indicator", objectId="domain:evil.example")
    assert again["status"] == "done" and "write" not in steps(again)
    assert len([r for r in outside.requests if r["method"] == "POST"]) == 1


def test_incident_to_ticketing_in_a_dry_run(admin: TestClient, library, outside):
    outside.host("acme.service-now.com", "148.139.1.1")
    connection(
        "servicenow",
        "ServiceNow",
        {"url": "https://acme.service-now.com"},
        {"username": "nik", "password": "a-password"},
    )
    row = by_name(admin)["Incident to ticketing"]
    shape = detail(admin, row["name"])["graph"]
    next(n for n in shape["nodes"] if n["id"] == "ticket")["config"]["connection"] = "ServiceNow"
    saved = admin.post(f"/api/automation/playbooks/{row['id']}/versions", json={"graph": shape})
    assert saved.status_code == 201, saved.text
    doc = {"id": "inc-9", "name": "Ransom note on FILESRV-02", "severity": "critical", "data": {}}
    assert admin.post("/api/incidents", json=doc).status_code == 201

    # The ticket carries the incident's name: held back until an admin opens that class for this playbook.
    held = dry(admin, row["id"], objectKind="incident", objectId="inc-9")
    assert held["status"] == "failed" and steps(held)["ticket"]["request"]["held"]["held"] == ["incident_text"]
    assert steps(held)["ticket"]["error"].startswith("Held back: incident names and tickets.")
    opened = admin.put(
        f"/api/automation/playbooks/{row['id']}/data-allow",
        json={"class": "incident_text", "allow": True, "acknowledged": True, "confirmName": row["name"]},
    )
    assert opened.status_code == 200, opened.text

    run = dry(admin, row["id"], objectKind="incident", objectId="inc-9")
    assert run["status"] == "done", errors(run)
    done = steps(run)
    ticket = done["ticket"]
    assert (ticket["request"]["method"], ticket["request"]["host"]) == ("POST", "acme.service-now.com")
    assert ticket["request"]["path"] == "/api/now/table/incident" and ticket["request"]["held"]["held"] == []
    assert ticket["input"]["args"]["short_description"] == "Ransom note on FILESRV-02"
    assert (ticket["input"]["args"]["urgency"], ticket["input"]["args"]["impact"]) == ("1", "1")
    assert ticket["output"]["number"] == "INC0000001"  # the sample of the command
    assert done["number"]["input"]["args"] == {"incident": "inc-9", "field": "ticketId", "value": "INC0000001"}
    assert done["note"]["input"]["args"]["text"].startswith("ServiceNow INC0000001: https://")
    assert outside.requests == []
    assert admin.get("/api/incidents/inc-9").json().get("ticketId") in (None, "")


def test_the_disk_notice_in_a_dry_run(admin: TestClient, library, outside):
    pb = by_name(admin)["Disk almost full notice"]["id"]
    # As shipped there is no instance of the Mail connector: the step says to add one.
    refused = dry(admin, pb)
    assert refused["status"] == "failed"
    assert steps(refused)["notice"]["error"].startswith("No instance of Mail listener / sender is on: add one")
    # One instance, named by nobody: the node sends through it. Its recipient is a placeholder nobody listed.
    outside.host("smtp.example.org", "93.184.215.25")
    assert admin.put("/api/automation/settings", json={"smtp": SMTP}).status_code == 200
    with SessionLocal() as db:
        assert connector_actions.adopt_smtp(db) is True
        db.commit()
    refused = dry(admin, pb)
    assert steps(refused)["notice"]["error"].startswith("example.org is not among the hosts this playbook may reach")
    assert (
        admin.put(
            f"/api/automation/playbooks/{pb}/egress", json={"mode": "listed", "hosts": ["example.org"]}
        ).status_code
        == 200
    )
    run = dry(admin, pb)
    assert run["status"] == "done", errors(run)
    assert steps(run)["notice"]["request"]["connection"] == "Mail (from Settings)"

    # Started by the event, the message says how much is left.
    assert admin.put(f"/api/automation/playbooks/{pb}/enabled", json={"enabled": True}).status_code == 200
    from collections import namedtuple

    Disk = namedtuple("Disk", "total used free")
    with SessionLocal() as db:
        assert worker.storage_low(db, T0, usage=lambda path: Disk(2000, 1900, 100)) is True
    worker.drain()
    (last,) = [
        r for r in admin.get(f"/api/automation/runs?playbook={pb}").json()["runs"] if r["trigger"] == "storage.low"
    ]
    assert last["status"] == "done", errors(run_of(admin, last["id"]))
    (mail,) = outside.mails
    assert mail["subject"] == "Nik: 5.0% of the evidence disk is free"
    assert "100 bytes free of 2000 (5.0%)" in mail["text"]


# --------------------------------------------------------------------------- #
# The actions written for them                                                #
# --------------------------------------------------------------------------- #
def test_the_lists_of_the_library_are_read_by_a_playbook(admin: TestClient):
    admin.post("/api/iocs", json={"text": f"{IP}\nevil.example", "list": {"name": "Watched", "watch": True}})
    admin.post("/api/iocs", json={"text": "198.51.100.7", "list": {"name": "Other"}})
    pb = playbook(
        admin,
        "Lists",
        [
            node("every", "action", action="nik.get-ioc-lists", args={}),
            node("watched", "action", action="nik.get-ioc-lists", args={"watched": True}),
        ],
        [edge("start", "every"), edge("every", "watched")],
    )
    done = steps(go(admin, pb))
    assert done["every"]["output"]["names"] == ["Other", "Watched"] and done["every"]["output"]["count"] == 2
    (only,) = done["watched"]["output"]["lists"]
    assert (only["name"], only["watched"], only["count"]) == ("Watched", True, 2)


def test_a_recheck_waits_for_its_answers_but_not_for_ever(admin: TestClient):
    with SessionLocal() as db:
        vendor.source(db, "shodan")  # a source that is on, and that nobody asks here: the worker is not running
    admin.post("/api/iocs", json={"text": IP, "list": {"name": "Watched", "watch": True}})
    pb = playbook(
        admin,
        "Recheck",
        [node("check", "action", action="nik.recheck-list", args={"list": "{{ inputs.list }}", "wait_minutes": 2})],
        [edge("start", "check")],
    )
    missing = go(admin, pb, inputs={"list": "No such list"})
    assert steps(missing)["check"]["error"] == "There is no list with this name"

    # The sources are asked in the background; a check that does not end in the time given lets the
    # playbook go on with what is there.
    run_id = start(admin, pb, inputs={"list": "Watched"})
    worker.drain(T0)
    assert steps(run_of(admin, run_id))["check"]["status"] == "waiting"
    worker.drain(T0 + 45)
    assert steps(run_of(admin, run_id))["check"]["status"] == "waiting"
    worker.drain(T0 + 200)
    out = steps(run_of(admin, run_id))["check"]
    assert (
        out["status"] == "done"
        and out["output"]["finished"] is False
        and out["output"]["asked"] == 1
        and out["output"]["total"] == 1
    )
    assert out["output"]["before"] == out["output"]["after"]


def test_the_attachments_of_an_e_mail_in_a_dry_run_and_for_real(admin: TestClient, library, no_dns):  # noqa: F811
    from app import artifact_jobs

    mail = admin.post("/api/artifacts/mails", files={"file": ("reported.eml", phishing_message())}).json()
    row = by_name(admin)["Analyse the attachments of an e-mail"]
    assert row["trigger"] == "mail.analysed, by hand"
    run = dry(admin, row["id"], objectKind="artifact", objectId=mail["id"])
    assert run["status"] == "done", errors(run)
    done = steps(run)
    assert done["each"]["output"]["count"] == 2 and done["each"]["output"]["failed"] == 0
    assert done["take"]["request"]["would"] == "add the attachment"
    assert done["analyse"]["request"]["would"] == "analyse the artifact"
    # Nothing was kept and nothing was started.
    assert [item["kind"] for item in admin.get("/api/artifacts").json()["artifacts"]] == ["mail"]

    run_id = start(admin, row["id"], objectKind="artifact", objectId=mail["id"])
    for index in range(8):
        worker.drain(T0 + index * 5)
        artifact_jobs.run_due(threads=False)
    run = run_of(admin, run_id)
    assert run["status"] == "done", errors(run)
    assert steps(run)["each"]["output"] == {**steps(run)["each"]["output"], "count": 2, "failed": 0}
    # Each attachment is a file of its own, taken out of the e-mail.
    shown = admin.get(f"/api/artifacts/{mail['id']}").json()
    assert sorted(child["name"] for child in shown["children"]) == ["Fattura.zip", "attached-message.eml"]
    assert all(child["relation"] == "attachment" and child["kind"] == "file" for child in shown["children"])

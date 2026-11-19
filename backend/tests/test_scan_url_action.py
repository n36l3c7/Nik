"""The playbook node that scans an address: it asks, the API process visits, the node reads the verdict."""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy import select

from app import urlscan, urlscan_queue
from app.automation import engine, worker
from app.core.config import settings
from app.core.db import SessionLocal
from app.core.models import AutomationEvent, UrlScan
from tests.test_automation_engine import (  # noqa: F401 - test_actions is a fixture
    T0,
    edge,
    go,
    incident,
    node,
    playbook,
    run_of,
    start,
    steps,
    test_actions,
)
from tests.test_urls import PHISH, SESSION, browser  # noqa: F401 - browser is a fixture

SHORT = "https://bit.ly/3xQ9a"


def scan(url: str = "hxxps://bit[.]ly/3xQ9a", **config):
    args = config.pop("args", {})
    return node("scan", "action", action="nik.scan-url", args={"url": url, **args}, **config)


def scanning(admin: TestClient, name: str = "Scans", **kwargs) -> str:
    return playbook(admin, name, [scan(**kwargs)], [edge("start", "scan")])


def later(admin: TestClient, run_id: str, now: float) -> dict:
    worker.drain(now)
    return run_of(admin, run_id)


def test_a_playbook_scans_an_address_without_holding_a_worker_and_reads_the_verdict(admin: TestClient, browser):  # noqa: F811
    incident(admin, "i1")
    pb = scanning(admin)
    run_id = start(admin, pb, objectKind="incident", objectId="i1")

    # The step asks for the scan and gives itself back: nothing was visited by the worker of playbooks.
    waiting = later(admin, run_id, T0)
    assert waiting["status"] == "running" and steps(waiting)["scan"]["status"] == "waiting"
    assert steps(waiting)["scan"]["log"] == "Scanning bit.ly/3xQ9a" and browser == []
    with SessionLocal() as db:
        row = db.get(UrlScan, urlscan.scan_id(SHORT))
        assert row.status == "queued" and row.created_by == "nik-automation"
        assert row.result[urlscan_queue.MARK]["run"] == run_id
    # Already in the incident, as a scan that is not finished.
    refs = admin.get("/api/incidents/i1").json()["data"]["urls"]["scans"]
    assert [(ref["url"], ref["status"]) for ref in refs] == [(SHORT, "queued")]
    # Asked again before the visit: it still waits.
    assert steps(later(admin, run_id, T0 + 5))["scan"]["status"] == "waiting"

    # The API process takes what was asked for and visits, as it does for an analyst.
    assert urlscan_queue.run_due() == 1 and urlscan_queue.run_due() == 0
    assert ("open", "nik-automation", True, SHORT) in browser and ("act", "inspect") in browser
    assert ("close", SESSION) in browser
    # What the scan set off says which run caused it: a playbook that waits for scans does not loop on its own.
    with SessionLocal() as db:
        events = db.scalars(select(AutomationEvent).where(AutomationEvent.kind == "url.analysed")).all()
        assert [event.payload["caused_by_run"] for event in events] == [run_id]

    done = later(admin, run_id, T0 + 10)
    assert done["status"] == "done"
    output = steps(done)["scan"]["output"]
    scan_id = urlscan.scan_id(SHORT)
    assert output["scanned"] is True and output["verdict"] == "phishing" and output["score"] >= 70
    assert output["url"] == SHORT and output["final_url"] == PHISH
    assert output["redirected"] is True and output["redirects"] == 1
    assert output["title"].startswith("Log in") and output["password_form"] is True
    assert output["scan"] == scan_id and output["artifact"] == f"url-{scan_id}"
    assert output["page"] == f"/artifact/url-{scan_id}"
    assert {"type": "domain", "value": "login-paypa1.top"} in output["indicators"]
    assert {"type": "ip", "value": "203.0.113.10"} in output["indicators"]
    assert output["findings"] and all(isinstance(text, str) and text for text in output["findings"])
    assert output["summary"].startswith("phishing (score ") and "login-paypa1.top/signin" in output["summary"]
    assert "reached from bit.ly/3xQ9a" in output["summary"] and "asks for a password" in output["summary"]

    # The incident holds the scan with its verdict and its indicators; the artifact is there.
    doc = admin.get("/api/incidents/i1").json()
    assert [(ref["id"], ref["verdict"]) for ref in doc["data"]["urls"]["scans"]] == [(scan_id, "phishing")]
    values = {item["value"] for item in admin.get("/api/incidents/i1/iocs").json()["iocs"]}
    assert {"login-paypa1.top", "203.0.113.10"} <= values
    assert admin.get(f"/api/artifacts/url-{scan_id}").json()["verdict"] == "phishing"
    entry = admin.get("/api/audit?q=Scan of").json()["entries"][0]
    assert entry["actor"] == "nik-automation" and entry["action"] == "url.scan"
    assert entry["details"].startswith('Scan of bit.ly/3xQ9a (playbook "Scans", run ') and entry["incidentId"] == "i1"


def test_a_scan_nik_holds_is_given_at_once_unless_the_node_asks_for_another_visit(admin: TestClient, browser):  # noqa: F811
    pb = scanning(admin)
    run_id = start(admin, pb)
    worker.drain(T0)
    urlscan_queue.run_due()
    first = later(admin, run_id, T0 + 5)
    assert first["status"] == "done" and browser.count(("act", "inspect")) == 1
    # No incident: the scan is an artifact on its own.
    scan_id = urlscan.scan_id(SHORT)
    assert admin.get(f"/api/artifacts/url-{scan_id}").json()["incidents"] == []

    # The same address in another run: the scan that is there, in one step, without a visit.
    again = go(admin, pb, T0 + 100)
    assert again["status"] == "done" and steps(again)["scan"]["output"]["verdict"] == "phishing"
    assert urlscan_queue.run_due() == 0 and browser.count(("act", "inspect")) == 1
    assert admin.get("/api/audit?q=already known").json()["entries"][0]["action"] == "url.scan"

    # "again": the address is visited once more.
    fresh = scanning(admin, "Scans again", args={"again": True})
    run_id = start(admin, fresh, T0 + 200)
    assert steps(later(admin, run_id, T0 + 200))["scan"]["status"] == "waiting"
    assert urlscan_queue.run_due() == 1 and browser.count(("act", "inspect")) == 2
    assert later(admin, run_id, T0 + 205)["status"] == "done"


def test_without_the_isolated_browser_the_step_fails_and_says_so(admin: TestClient, monkeypatch):
    monkeypatch.setattr(settings, "BROWSER_URL", "")
    run_id = start(admin, scanning(admin))
    worker.drain(T0)
    assert urlscan_queue.run_due() == 1
    failed = later(admin, run_id, T0 + 5)
    assert failed["status"] == "failed"
    assert (
        steps(failed)["scan"]["error"]
        == "The isolated browser is not configured (BROWSER_URL): the address was not visited."
    )


def test_a_scan_nobody_takes_fails_the_step_after_five_minutes(admin: TestClient):
    run_id = start(admin, scanning(admin))
    worker.drain(T0)
    assert steps(later(admin, run_id, T0 + 299))["scan"]["status"] == "waiting"
    failed = later(admin, run_id, T0 + 310)
    assert failed["status"] == "failed"
    assert steps(failed)["scan"]["error"].startswith("The scan did not end in 5 minutes")


def test_what_may_not_be_scanned_is_refused_before_anything_is_asked(admin: TestClient, browser):  # noqa: F811
    for bad, why in (
        ("http://10.0.0.5/admin", "Not scanned: a private or reserved address."),
        ("http://intranet/", "Not scanned: an internal name."),
        ("ftp://example.com/x", "Only http and https addresses can be scanned."),
    ):
        run = go(admin, scanning(admin, f"Refused {bad}", url=bad))
        assert run["status"] == "failed" and steps(run)["scan"]["error"] == why, bad
    with SessionLocal() as db:
        assert db.scalars(select(UrlScan)).all() == []
    assert urlscan_queue.run_due() == 0 and browser == []


def test_the_data_guard_decides_what_address_leaves(admin: TestClient, browser):  # noqa: F811
    # An address that carries a person's e-mail address: held, unless an admin opened the class.
    tracked = "https://login-paypa1.top/signin?u=anna.rossi@contoso.example"
    pb = scanning(admin, "Tracked", url=tracked)
    run = go(admin, pb)
    assert run["status"] == "failed" and steps(run)["scan"]["error"].startswith("Held back: 1 × e-mail addresses")
    assert steps(run)["scan"]["request"]["held"]["held"] == ["email_address"]
    with SessionLocal() as db:
        assert db.scalars(select(UrlScan)).all() == []

    # An allowlisted address is your own: held too.
    shared = admin.get("/api/settings").json()
    assert admin.put("/api/settings", json={**shared, "iocAllowlist": ["portal.example.org"]}).status_code == 200
    run = go(admin, scanning(admin, "Own", url="https://portal.example.org/login"))
    assert run["status"] == "failed" and "allowlisted" in steps(run)["scan"]["request"]["held"]["held"]

    # "held: drop" on the node: the step goes on, and says the address was not visited.
    run = go(admin, scanning(admin, "Lenient", url=tracked, held="drop"))
    output = steps(run)["scan"]["output"]
    assert run["status"] == "done" and output["scanned"] is False and output["verdict"] == ""
    assert output["summary"] == "Not scanned: the data guard held the address back"
    assert urlscan_queue.run_due() == 0 and browser == []

    # Opened for the playbook by an admin: the address is scanned.
    opened = admin.put(
        f"/api/automation/playbooks/{pb}/data-allow",
        json={"class": "email_address", "acknowledged": True, "confirmName": "Tracked"},
    )
    assert opened.status_code == 200, opened.text
    run_id = start(admin, pb)
    assert steps(later(admin, run_id, T0))["scan"]["status"] == "waiting"
    assert urlscan_queue.run_due() == 1
    assert later(admin, run_id, T0 + 5)["status"] == "done"


def test_a_dry_run_scans_nothing_and_gives_a_sample(admin: TestClient, browser):  # noqa: F811
    incident(admin, "i1")
    run = go(admin, scanning(admin), objectKind="incident", objectId="i1", dryRun=True)
    assert run["status"] == "done"
    step = steps(run)["scan"]
    scan_id = urlscan.scan_id(SHORT)
    assert step["output"] == {
        "scanned": False,
        "verdict": "",
        "score": 0,
        "url": SHORT,
        "final_url": SHORT,
        "redirected": False,
        "redirects": 0,
        "title": "",
        "password_form": False,
        "findings": [],
        "indicators": [],
        "scan": scan_id,
        "artifact": f"url-{scan_id}",
        "page": f"/artifact/url-{scan_id}",
        "summary": "Dry run: the address was not visited",
    }
    assert step["request"]["would"] == "scan the address" and step["request"]["url"] == "bit.ly/3xQ9a"
    with SessionLocal() as db:
        assert db.scalars(select(UrlScan)).all() == []
    assert admin.get("/api/incidents/i1").json()["data"].get("urls") in (None, {}, {"scans": []})
    assert urlscan_queue.run_due() == 0 and browser == []


def test_the_api_process_takes_only_what_a_playbook_asked_for_and_each_scan_once(admin: TestClient, browser):  # noqa: F811
    with SessionLocal() as db:
        # A scan the interface queued: its own background task runs it, not this queue.
        row = urlscan.register(db, "https://example.org/", "anna")
        row.result = {"startedAt": engine.iso(T0)}
        db.commit()
        assert urlscan_queue.take(db) is None
    run_id = start(admin, scanning(admin))
    worker.drain(T0)
    with SessionLocal() as one, SessionLocal() as two:
        taken = urlscan_queue.take(one)
        assert taken is not None and taken[0] == urlscan.scan_id(SHORT) and taken[1]["run"] == run_id
        assert urlscan_queue.take(two) is None  # another process, a moment later: it is taken
    assert browser == []


def test_the_node_is_in_the_library_of_the_editor(admin: TestClient):
    nodes = {entry["id"]: entry for entry in admin.get("/api/automation/catalog").json()["nodes"]}
    entry = nodes["nik.scan-url"]
    assert entry["group"] == "Nik" and entry["name"] == "Scan an address" and entry["changesOutside"] is False
    assert [argument["name"] for argument in entry["arguments"]] == ["url", "incident", "again"]
    assert {"verdict", "final_url", "redirected", "indicators", "artifact", "summary"} <= {
        output["name"] for output in entry["outputs"]
    }

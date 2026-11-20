"""The data guard on the look-ups made outside playbooks: "Check now", the checks in bulk, the worker.

A value that passes the rule of the look-ups is judged by the data guard on
what it carries, against the classes an administrator opened for all such
look-ups: none at first. A playbook's look-up keeps to what was opened for
the playbook. The sources are the packs of the repository, answering through
the fake outside of ``conftest.py``, as in ``test_enrichment.py``.
"""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy import select

from app import ioc_library as lib
from app.core.db import SessionLocal
from app.core.models import Enrichment, IocCheck
from app.enrichment import service
from tests.conftest import make_key
from tests.test_enrichment import _incident, by_source, expire, turn_on

PLAIN = "http://evil.example.com/gate.php"
CARRIES = "https://portal.example-corp.it/reset?user=mario.rossi@example-corp.it"
EMAILS = {"id": "email_address", "label": "E-mail addresses"}
OURS = {"id": "private_value", "label": "Internal names and addresses"}
LISTED = {"id": "allowlisted", "label": "Allowlisted indicators"}


def post_check(admin: TestClient, kind: str, value: str, force: bool = False) -> dict:
    r = admin.post("/api/enrichment/check", json={"type": kind, "value": value, "force": force})
    assert r.status_code == 200, r.text
    return r.json()


def detail(admin: TestClient, kind: str, value: str) -> dict:
    r = admin.get("/api/enrichment", params={"type": kind, "value": value})
    assert r.status_code == 200, r.text
    return r.json()


def set_class(admin: TestClient, name: str, allow: bool = True, **more) -> dict:
    labels = {EMAILS["id"]: EMAILS["label"], OURS["id"]: OURS["label"], LISTED["id"]: LISTED["label"]}
    body = {"class": name, "allow": allow, "acknowledged": True, "confirmName": labels.get(name, ""), **more}
    r = admin.put("/api/enrichment/guard", json=body)
    assert r.status_code == 200, r.text
    return {item["id"]: item["open"] for item in r.json()["guard"]}


def sent(outside, text: str) -> list[dict]:
    """The requests that carried a text, in their address or in what they posted."""
    return [
        request for request in outside.requests if text in request["path"] or text.encode() in (request["body"] or b"")
    ]


def audited(admin: TestClient, action: str) -> list[str]:
    found = admin.get("/api/audit?q=" + action.split(".")[0]).json()
    entries = found.get("entries", found if isinstance(found, list) else [])
    return [entry["details"] for entry in entries if entry["action"] == action]


# --------------------------------------------------------------------------- #
# Check now                                                                   #
# --------------------------------------------------------------------------- #
def test_check_now_is_held_until_an_admin_opens_the_class_and_held_again_when_it_is_closed(admin: TestClient, outside):
    turn_on(outside, "urlscan")
    # Nothing is opened on a server that never set it: every class is offered closed, in the guard's words.
    listed = admin.get("/api/enrichment/sources").json()["guard"]
    assert [(item["id"], item["label"], item["open"]) for item in listed] == [
        ("email_address", "E-mail addresses", False),
        ("private_value", "Internal names and addresses", False),
        ("allowlisted", "Allowlisted indicators", False),
    ]
    assert all(item["warning"] and item["example"].startswith("In an indicator:") for item in listed)
    assert admin.get("/api/settings").json()["enrichment"]["guardOpen"] == []

    # A link that carries an e-mail address: held, said as it is, and no source is asked at all.
    held = post_check(admin, "url", CARRIES)
    value = held["value"]
    assert held["held"]["classes"] == [EMAILS] and held["blocked"] is None
    assert held["held"]["reason"].startswith("Held back: e-mail addresses. A look-up may not send them")
    assert held["results"] == [] and held["skipped"] == [] and held["summary"] is None
    assert outside.requests == []
    with SessionLocal() as db:
        assert db.scalars(select(Enrichment)).all() == []  # not an error, not an answer: nothing is stored
    seen = detail(admin, "url", value)
    assert seen["held"]["classes"] == [EMAILS] and seen["providers"] == ["urlscan"] and seen["refresh"] == []
    assert audited(admin, "enrichment.held") == [f"The data guard held the look-up of url {value}: e-mail addresses"]
    # Asked for with "force", it is held the same.
    assert post_check(admin, "url", value, force=True)["held"] and outside.requests == []
    # A link that carries nothing of the kind is looked up as before.
    plain = post_check(admin, "url", PLAIN)
    assert plain["held"] is None and set(by_source(plain)) == {"urlscan"} and len(outside.requests) == 1

    # Opening asks twice: the box, and the name of the class as it is written.
    for wrong in (
        {"acknowledged": False},
        {"confirmName": "e-mail addresses"},
        {"confirmName": ""},
    ):
        body = {"class": "email_address", "allow": True, "acknowledged": True, "confirmName": EMAILS["label"], **wrong}
        refused = admin.put("/api/enrichment/guard", json=body)
        assert refused.status_code == 400 and "ticking the box" in refused.json()["detail"]
    # A class an indicator cannot carry, and TLP:RED data, are not offered and cannot be opened.
    for never in ("subject", "tlp_red", "mail_body", "nothing"):
        body = {"class": never, "allow": True, "acknowledged": True, "confirmName": never}
        assert admin.put("/api/enrichment/guard", json=body).status_code == 400
    assert post_check(admin, "url", value)["held"] and len(outside.requests) == 1

    assert set_class(admin, "email_address") == {"email_address": True, "private_value": False, "allowlisted": False}
    assert audited(admin, "enrichment.guard.open") == [
        "Look-ups made outside playbooks may send e-mail addresses to the sources: urlscan.io"
    ]
    assert set_class(admin, "email_address")["email_address"] and len(audited(admin, "enrichment.guard.open")) == 1
    # Opened: the same button looks it up.
    looked = post_check(admin, "url", value)
    assert looked["held"] is None and by_source(looked)["urlscan"]["status"] == "done"
    assert len(sent(outside, "mario.rossi")) == 1 and len(outside.requests) == 2

    # Closed again: held again, and the answer that was stored stays, expired or not, and is not refreshed.
    assert not set_class(admin, "email_address", allow=False)["email_address"]
    assert audited(admin, "enrichment.guard.close") == [
        "Look-ups made outside playbooks may no longer send e-mail addresses"
    ]
    expire()
    seen = detail(admin, "url", value)
    assert seen["held"]["classes"] == [EMAILS] and seen["refresh"] == []
    assert by_source(seen)["urlscan"]["verdict"] == by_source(looked)["urlscan"]["verdict"]
    assert by_source(post_check(admin, "url", value, force=True))["urlscan"]["status"] == "done"
    assert len(outside.requests) == 2


def test_the_setting_is_the_admins_and_is_not_saved_with_the_other_settings(admin: TestClient, outside):
    turn_on(outside, "urlscan")
    analyst = make_key(admin, roles=["analyst"])
    body = {"class": "email_address", "allow": True, "acknowledged": True, "confirmName": EMAILS["label"]}
    with TestClient(admin.app) as other:
        assert other.put("/api/enrichment/guard", headers=analyst, json=body).status_code == 403
        assert other.put("/api/enrichment/guard", json=body).status_code == 401
        # Anyone who reads the sources reads what is open.
        assert other.get("/api/enrichment/sources", headers=analyst).json()["guard"][0]["open"] is False
    # Saving the settings of the look-ups opens nothing, whatever is sent with them.
    shared = admin.get("/api/settings").json()
    shared["enrichment"]["guardOpen"] = ["email_address", "private_value"]
    saved = admin.put("/api/settings", json=shared)
    assert saved.status_code == 200 and saved.json()["enrichment"]["guardOpen"] == []
    assert post_check(admin, "url", CARRIES)["held"] and outside.requests == []
    # And once a class is open, saving the others leaves it open.
    set_class(admin, "email_address")
    shared = admin.get("/api/settings").json()
    shared["enrichment"]["retentionDays"]["url"] = 90
    shared["enrichment"].pop("guardOpen")
    saved = admin.put("/api/settings", json=shared).json()["enrichment"]
    assert saved["guardOpen"] == ["email_address"] and saved["retentionDays"]["url"] == 90
    assert post_check(admin, "url", CARRIES)["held"] is None and len(outside.requests) == 1


def test_own_domains_and_the_allowlist_say_what_a_value_is(admin: TestClient, outside):
    turn_on(outside, "urlscan")
    # Nobody said the domain is ours: its name leaves, and the link is held for the address only.
    assert post_check(admin, "domain", "portal.example-corp.it")["held"] is None
    assert post_check(admin, "url", CARRIES)["held"]["classes"] == [EMAILS]
    before = len(outside.requests)
    # An administrator makes it ours (Settings, Mail analysis: own domains): names under it are held.
    mail = {"orgDomains": ["Example-Corp.it"], "trustedAuthServers": []}
    assert admin.put("/api/settings", json={"mail": mail}).status_code == 200
    domain = post_check(admin, "domain", "portal.example-corp.it", force=True)
    assert domain["held"]["classes"] == [OURS]
    assert domain["held"]["reason"].startswith("Held back: internal names and addresses.")
    assert by_source(domain)["urlscan"]["status"] == "done"  # what was answered before stays
    assert post_check(admin, "url", CARRIES)["held"]["classes"] == [EMAILS, OURS]
    # One of the two opened is not enough.
    set_class(admin, "email_address")
    assert post_check(admin, "url", CARRIES)["held"]["classes"] == [OURS]
    assert len(outside.requests) == before
    set_class(admin, "private_value")
    assert post_check(admin, "url", CARRIES)["held"] is None and len(outside.requests) == before + 1

    # A link that names an allowlisted domain is held by the guard; the allowlisted domain itself is
    # the rule's, which no setting loosens.
    redirect = "https://evil.example.com/r?to=https://sso.ourpartner.example/login"
    assert post_check(admin, "url", redirect)["held"] is None
    assert admin.put("/api/settings", json={"iocAllowlist": ["ourpartner.example"]}).status_code == 200
    assert post_check(admin, "url", redirect, force=True)["held"]["classes"] == [LISTED]
    refused = admin.post("/api/enrichment/check", json={"type": "domain", "value": "sso.ourpartner.example"})
    assert refused.status_code == 422 and "allowlist" in refused.json()["detail"]
    set_class(admin, "allowlisted")
    assert post_check(admin, "url", redirect, force=True)["held"] is None
    assert (
        admin.post("/api/enrichment/check", json={"type": "domain", "value": "sso.ourpartner.example"}).status_code
        == 422
    )
    assert detail(admin, "domain", "sso.ourpartner.example")["held"] is None  # said by the rule, once
    # Off the allowlist again, the value is what it was: nothing holds it, with every class closed.
    for name in ("email_address", "private_value", "allowlisted"):
        set_class(admin, name, allow=False)
    assert admin.put("/api/settings", json={"iocAllowlist": []}).status_code == 200
    assert detail(admin, "url", redirect)["held"] is None
    # A digest, an address: nothing the guard holds.
    judged = service.judge(admin.get("/api/settings").json())
    assert service.held("sha256", "a" * 64, judged) is None and service.held("ip", "185.220.101.47", judged) is None
    assert service.held("url", "https://evil.example.com/?next=10.0.0.5", judged)["classes"] == [OURS]


# --------------------------------------------------------------------------- #
# The automatic look-ups                                                      #
# --------------------------------------------------------------------------- #
def test_the_automatic_look_ups_leave_a_held_value_alone_until_its_class_is_opened(admin: TestClient, outside):
    turn_on(outside, "urlscan")
    key = make_key(admin)
    _incident(admin, key, "g1", "curl https://files.example.net/dl?for=anna.bianchi@example.org -o /tmp/x")
    iocs = admin.get("/api/incidents/g1/iocs", headers=key).json()["iocs"]
    (url,) = [item["value"] for item in iocs if item["type"] == "url"]
    assert "anna.bianchi@example.org" in url
    shared = admin.get("/api/settings").json()
    shared["enrichment"]["auto"]["url"] = True
    assert admin.put("/api/settings", json=shared).status_code == 200

    def a_pass() -> int:
        with SessionLocal() as db:
            return service.run_cycle(db, admin.get("/api/settings").json(), budget_seconds=5)

    # The domain of the link is asked about; the link, which carries an address, is not.
    first = a_pass()
    assert first >= 1 and sent(outside, "anna.bianchi") == []
    with SessionLocal() as db:
        assert db.scalars(select(Enrichment).where(Enrichment.type == "url")).all() == []
    # Not tried again pass after pass, and nothing is stored to try again.
    assert (a_pass(), a_pass()) == (0, 0) and len(outside.requests) == first
    # The list of indicators says it where the verdict would be.
    with SessionLocal() as db:
        (row,) = lib.library(db, admin.get("/api/settings").json(), only={("url", url)})
        assert row["held"].startswith("Held back: e-mail addresses.") and row["neverSent"] is None
        (plain,) = lib.library(db, admin.get("/api/settings").json(), only={("domain", "files.example.net")})
        assert plain["held"] is None
    # Opened: the next pass asks, once.
    set_class(admin, "email_address")
    assert a_pass() == 1 and len(sent(outside, "anna.bianchi")) == 1
    assert a_pass() == 0
    with SessionLocal() as db:
        (row,) = lib.library(db, admin.get("/api/settings").json(), only={("url", url)})
        assert row["held"] is None and row["verdict"]


# --------------------------------------------------------------------------- #
# In bulk                                                                     #
# --------------------------------------------------------------------------- #
def test_a_check_in_bulk_counts_what_is_held_and_does_not_ask_about_it(admin: TestClient, outside):
    turn_on(outside, "urlscan")
    added = admin.post(
        "/api/iocs", json={"items": [{"value": PLAIN}, {"value": CARRIES}, {"value": "http://10.0.0.8/x"}]}
    )
    assert added.status_code == 201, added.text
    rows = {row["value"]: row for row in admin.get("/api/iocs?type=url").json()["iocs"]}
    carries = next(value for value in rows if "mario.rossi" in value)
    assert rows[carries]["held"] and not rows[carries]["neverSent"]
    assert rows[PLAIN]["held"] is None and rows["http://10.0.0.8/x"]["neverSent"]
    scope = {"items": [{"type": "url", "value": value} for value in rows]}

    # What it would cost says how many are held, apart from what is never sent.
    plan = admin.post("/api/iocs/check", json={"scope": scope, "dryRun": True}).json()["plan"]
    assert (plan["total"], plan["toAsk"], plan["held"], plan["neverSent"]) == (3, 1, 1, 1)
    started = admin.post("/api/iocs/check", json={"scope": scope}).json()
    assert started["plan"]["held"] == 1 and started["check"]["message"] == "1 held back by the data guard: not asked."
    with SessionLocal() as db:
        assert service.run_checks(db, admin.get("/api/settings").json(), budget_seconds=5) == 1
    done = admin.get(f"/api/iocs/checks/{started['check']['id']}").json()
    assert (done["status"], done["done"], done["total"]) == ("done", 1, 1)
    assert done["message"] == "1 held back by the data guard: not asked."
    assert sent(outside, "mario.rossi") == [] and len(outside.requests) == 1

    # Opened, a check asks about it; closed while the check waits for its turn, it is not asked.
    set_class(admin, "email_address")
    plan = admin.post("/api/iocs/check", json={"scope": scope, "dryRun": True}).json()["plan"]
    assert (plan["toAsk"], plan["held"], plan["reused"]) == (1, 0, 1)
    queued = admin.post("/api/iocs/check", json={"scope": scope}).json()["check"]
    assert (queued["status"], queued["total"], queued["message"]) == ("running", 1, "")
    set_class(admin, "email_address", allow=False)
    with SessionLocal() as db:
        assert service.run_checks(db, admin.get("/api/settings").json(), budget_seconds=5) == 0
        row = db.get(IocCheck, queued["id"])
        assert (row.status, row.pending, row.message) == ("done", [], "1 held back by the data guard: not asked.")
    assert sent(outside, "mario.rossi") == []
    # Opened again, it is asked.
    set_class(admin, "email_address")
    admin.post("/api/iocs/check", json={"scope": scope})
    with SessionLocal() as db:
        assert service.run_checks(db, admin.get("/api/settings").json(), budget_seconds=5) == 1
    assert len(sent(outside, "mario.rossi")) == 1


# --------------------------------------------------------------------------- #
# A playbook's look-up keeps to the playbook                                  #
# --------------------------------------------------------------------------- #
def test_what_is_opened_for_the_look_ups_and_what_is_opened_for_a_playbook_do_not_mix(admin: TestClient, outside):
    from tests.test_automation_engine import edge, go, incident, node, playbook, steps

    turn_on(outside, "urlscan")
    incident(admin, "inc-guard")

    def look_up(name: str, value: str) -> tuple[str, dict]:
        pb = playbook(
            admin,
            name,
            [node("rep", "action", action="nik.reputation", args={"kind": "url", "value": value})],
            [edge("start", "rep")],
        )
        return pb, steps(go(admin, pb, objectKind="incident", objectId="inc-guard"))["rep"]["output"]

    # Opened for the look-ups outside playbooks: a playbook that opened nothing is held as before.
    set_class(admin, "email_address")
    pb, out = look_up("Looks up a link", CARRIES)
    assert [item["source"] for item in out["skipped"]] == ["reputation sources"]
    assert out["skipped"][0]["reason"].startswith("Held back: 1 × e-mail addresses. This playbook may not send them")
    assert out["sources"] == [] and outside.requests == []
    # While "Check now" on the same value asks.
    assert post_check(admin, "url", CARRIES)["held"] is None and len(outside.requests) == 1

    # Opened for a playbook only: its look-up asks, and "Check now" is held.
    set_class(admin, "email_address", allow=False)
    other = "https://files.example.net/dl?for=anna.bianchi@example.org"
    pb, out = look_up("Looks up another link", other)
    assert out["skipped"][0]["reason"].startswith("Held back: 1 × e-mail addresses") and len(outside.requests) == 1
    opened = {"class": "email_address", "allow": True, "acknowledged": True, "confirmName": "Looks up another link"}
    assert admin.put(f"/api/automation/playbooks/{pb}/data-allow", json=opened).status_code == 200
    out = steps(go(admin, pb, objectKind="incident", objectId="inc-guard"))["rep"]["output"]
    assert out["skipped"] == [] and [item["source"] for item in out["sources"]] == ["urlscan.io"]
    assert len(sent(outside, "anna.bianchi")) == 1 and len(outside.requests) == 2
    # The global setting is as it was, and holds the look-up made by hand.
    assert admin.get("/api/settings").json()["enrichment"]["guardOpen"] == []
    held = post_check(admin, "url", out["value"], force=True)
    assert held["held"]["classes"] == [EMAILS] and len(outside.requests) == 2
    assert by_source(held)["urlscan"]["status"] == "done"  # what the playbook's look-up stored is shown

"""What a playbook does inside Nik, where it may send, and what it may send."""

# ruff: noqa: E501 (graphs of test playbooks read better on one line)

from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.automation import egress, guard, worker
from app.automation import expressions as ex
from app.core.db import SessionLocal
from app.core.models import AuditEntry, Incident, IocList, IocListItem, IocRecord, Setting, User
from app.main import app as fastapi_app
from tests.conftest import make_key
from tests.test_automation_engine import T0, edge, go, incident, node, playbook, run_of, start, steps


def act(node_id, action, approval=None, **args):
    config = {"action": action, "args": args}
    if approval is not None:
        config["approval"] = approval
    return node(node_id, "action", **config)


# --------------------------------------------------------------------------- #
# Egress: where a request may go                                              #
# --------------------------------------------------------------------------- #
LISTED = egress.Policy(mode="listed", hosts=frozenset({"api.example.com", "fw.corp:4434", "intranet.corp"}))
ANY = egress.Policy(mode="any", hosts=frozenset({"intranet.corp"}))


def refused(policy, url, **kwargs) -> str:
    with pytest.raises(egress.EgressError) as caught:
        egress.destination(policy, url, **kwargs)
    assert caught.value.refused is True
    return caught.value.message


def test_a_listed_playbook_reaches_its_hosts_and_no_other(outside):
    outside.host("api.example.com", "93.184.215.10")
    outside.host("other.example.com", "93.184.215.11")
    outside.host("fw.corp", "93.184.215.12")
    assert egress.destination(LISTED, "https://API.Example.com/v1/x?a=1") == (
        "https",
        "api.example.com",
        443,
        "/v1/x?a=1",
        "93.184.215.10",
    )
    assert (
        refused(LISTED, "https://other.example.com/")
        == "other.example.com is not among the hosts this playbook may reach"
    )
    assert refused(LISTED, "https://evil-api.example.com/").endswith("may reach")  # an exact name, not a suffix
    # A host listed with a port is that port only.
    assert egress.destination(LISTED, "https://fw.corp:4434/api")[2] == 4434
    assert refused(LISTED, "https://fw.corp/api").endswith("may reach")
    assert egress.destination(ANY, "https://other.example.com/")[1] == "other.example.com"

    assert (
        refused(LISTED, "http://api.example.com/") == "Plain http is refused: use https, or allow http on the instance"
    )
    assert egress.destination(LISTED, "http://api.example.com/", allow_http=True)[0] == "http"
    assert refused(LISTED, "ftp://api.example.com/") == "Only https addresses can be reached"
    assert refused(LISTED, "https://user:pw@api.example.com/") == "An address with a user name in it is refused"
    assert refused(LISTED, "https:///nothing") == "The address names no host"
    assert refused(LISTED, "https://api.example.com/" + "a" * 9000) == "The address is too long"
    with pytest.raises(egress.EgressError) as caught:
        egress.destination(ANY, "https://nowhere.example.com/")
    assert caught.value.message == "nowhere.example.com could not be resolved" and caught.value.refused is False


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.5",
        "172.16.3.4",
        "192.168.1.1",
        "169.254.169.254",
        "169.254.1.1",
        "0.0.0.0",
        "::1",
        "fe80::1",
        "fc00::1",
        "::ffff:10.0.0.1",
        "224.0.0.1",
        "100.64.0.1",
        "100.100.100.200",
    ],
)
def test_an_address_inside_is_never_reached_by_accident(outside, address):
    """Whatever the mode: a name that resolves inside is refused unless that very host is listed."""
    outside.host("rebind.example.com", address)
    outside.host("intranet.corp", address)
    message = refused(ANY, "https://rebind.example.com/")
    assert message == "rebind.example.com is an address inside the network: it is reached only when the host is listed"
    # One good address among several does not make the name safe.
    outside.host("mixed.example.com", "93.184.215.5", address)
    assert refused(ANY, "https://mixed.example.com/").endswith("is listed")
    # Listed by name: an internal firewall manager is reachable because someone wrote its name.
    assert egress.destination(ANY, "https://intranet.corp/")[4] == address
    assert egress.destination(LISTED, "https://intranet.corp/")[4] == address
    literal = f"[{address}]" if ":" in address else address
    assert refused(ANY, f"https://{literal}/").endswith("is listed") or "inside" in refused(ANY, f"https://{literal}/")
    assert egress.is_inside(address) is True


def test_a_request_goes_to_the_address_that_was_checked_and_follows_checked_redirects(outside):
    outside.host("api.example.com", "93.184.215.10")
    outside.host("cdn.example.com", "93.184.215.20")
    outside.host("inside.example.com", "10.0.0.9")
    outside.answer("api.example.com", json={"ok": True}, path="/v1/items")
    policy = egress.Policy(mode="any")

    answer = egress.request(
        policy,
        "post",
        "https://api.example.com/v1/items",
        headers={"Authorization": "Bearer s3cret"},
        query={"a": 1, "skip": None, "b": ["x", "y"]},
        json={"n": 1},
    )
    assert answer.status == 200 and answer.json() == {"ok": True} and answer.text == '{"ok": true}'
    sent = outside.requests[-1]
    # Resolved once, checked, and connected to: no second resolution to rebind.
    assert (sent["address"], sent["host"], sent["path"], sent["method"]) == (
        "93.184.215.10",
        "api.example.com",
        "/v1/items?a=1&b=x&b=y",
        "POST",
    )
    assert sent["body"] == b'{"n": 1}' and sent["headers"]["Content-Type"] == "application/json"
    # What is recorded for the step: no query, no header, no secret.
    assert (
        answer.record["method"] == "POST"
        and answer.record["host"] == "api.example.com"
        and answer.record["path"] == "/v1/items"
    )
    assert answer.record["status"] == 200 and "s3cret" not in str(answer.record) and "a=1" not in str(answer.record)

    # A redirect to another host: followed, checked again, and the credentials stay behind.
    outside.answer("api.example.com", status=302, headers={"location": "https://cdn.example.com/file"}, path="/moved")
    outside.answer("cdn.example.com", body=b"data", path="/file")
    answer = egress.request(
        policy,
        "GET",
        "https://api.example.com/moved",
        headers={"Authorization": "Bearer s3cret", "X-Api-Key": "k", "X-Trace": "t"},
    )
    assert answer.body == b"data" and answer.record["redirects"] == 1 and answer.json() is None
    assert "Authorization" not in outside.requests[-1]["headers"] and "X-Api-Key" not in outside.requests[-1]["headers"]
    assert outside.requests[-1]["headers"]["X-Trace"] == "t"
    # A redirect to an address inside is refused like a first request.
    outside.answer("api.example.com", status=302, headers={"location": "https://inside.example.com/"}, path="/inside")
    with pytest.raises(egress.EgressError) as caught:
        egress.request(policy, "GET", "https://api.example.com/inside")
    assert caught.value.refused and "inside the network" in caught.value.message
    # A POST redirected with 303 becomes a GET without its body.
    outside.answer("api.example.com", status=303, headers={"location": "/done"}, path="/submit")
    outside.answer("api.example.com", body=b"ok", path="/done")
    egress.request(policy, "POST", "https://api.example.com/submit", json={"x": 1})
    assert (outside.requests[-1]["method"], outside.requests[-1]["body"]) == ("GET", None)
    # Three redirects at most.
    outside.answer("api.example.com", status=302, headers={"location": "/loop"}, path="/loop")
    with pytest.raises(egress.EgressError) as caught:
        egress.request(policy, "GET", "https://api.example.com/loop")
    assert caught.value.message == "Too many redirects"
    assert sum(1 for r in outside.requests if r["path"] == "/loop") == 4

    for bad in (dict(method="TRACE"), dict(headers={"X": "a\r\nInjected: 1"})):
        with pytest.raises(egress.EgressError) as caught:
            egress.request(policy, bad.pop("method", "GET"), "https://api.example.com/", **bad)
        assert caught.value.refused


def test_hosts_are_cleaned_before_they_are_listed():
    assert egress.clean_host(" API.Example.COM. ") == "api.example.com"
    assert egress.clean_host("fw.corp:4434") == "fw.corp:4434" and egress.clean_host("10.1.2.3") == "10.1.2.3"
    assert egress.clean_host("bücher.example") == "xn--bcher-kva.example"
    for bad in ("", "a b", "http://x", "x/y", "user@x", "x:99999", "x:port", "a..b", "x" * 300):
        assert egress.clean_host(bad) is None, bad


def test_no_other_module_of_the_package_opens_a_socket():
    """Everything that leaves goes through egress.py: nothing else imports a network library."""
    package = Path(egress.__file__).parent
    forbidden = re.compile(
        r"^\s*(?:import|from)\s+(socket|http\.client|http|urllib\.request|urllib3|requests|httpx|smtplib|imaplib|poplib|ftplib|telnetlib|asyncio)\b",
        re.M,
    )
    for path in sorted(package.glob("*.py")):
        if path.name == "egress.py":
            continue
        found = forbidden.findall(path.read_text(encoding="utf-8"))
        assert not found, f"{path.name} imports {found}"
    source = (package / "egress.py").read_text(encoding="utf-8")
    assert "verify_mode" not in source and "CERT_NONE" not in source and "check_hostname = False" not in source


# --------------------------------------------------------------------------- #
# The data guard                                                              #
# --------------------------------------------------------------------------- #
CONTEXT = guard.Context(
    internal_domains=frozenset({"corp.example"}),
    allowlisted=lambda kind, value: (kind, value) in {("domain", "partner.example"), ("ip", "198.51.100.7")},
)


def test_some_classes_always_leave_and_every_other_is_held_until_opened():
    decision = guard.check(
        {"sha256": "ab" * 32, "verdict": "malicious"}, frozenset({"hash", "verdict", "nik_id"}), [], CONTEXT
    )
    assert decision.allowed and decision.held == frozenset()
    for name in guard.CLASSES:
        held = guard.check("x", frozenset({name}), [], CONTEXT)
        assert held.held == {name} and not held.allowed, name
        assert guard.check("x", frozenset({name}), [name], CONTEXT).allowed, name
    # Opening one class opens that one.
    mixed = guard.check("x", frozenset({"email_address", "mail_body", "hash"}), ["email_address"], CONTEXT)
    assert mixed.held == {"mail_body"}
    assert guard.SENSITIVE == {"mail_body", "attachment", "sample", "tlp_red"}
    assert guard.ALWAYS.isdisjoint(guard.CLASSES)


def test_the_scan_is_a_second_net_that_can_only_add():
    def held(payload, classes=(), opened=()):
        return sorted(guard.check(payload, frozenset(classes), opened, CONTEXT).held)

    assert held("nothing to see") == []
    assert held({"to": "Eve <eve@evil.example>", "note": "hi"}) == ["email_address"]
    assert held(["see 10.1.2.3", {"deep": ["192.168.0.1 and 127.0.0.1"]}]) == ["private_value"]
    assert held("host srv01.corp.example answered") == ["private_value"]  # under the organisation's own domains
    assert held("corp.example.attacker.net is not ours") == []
    assert held("seen at partner.example and 198.51.100.7") == ["allowlisted"]
    assert held("8.8.8.8 and example.org") == []
    assert held({"key 10.0.0.1": "x"}) == ["private_value"]  # keys are read too
    # Tagged and scanned classes add up; an opened class is not held however it was found.
    assert held("eve@evil.example", ["subject"]) == ["email_address", "subject"]
    assert held("eve@evil.example", ["subject"], ["email_address", "subject"]) == []
    decision = guard.check("a@b.example, c@d.example, 10.0.0.1", frozenset(), [], CONTEXT)
    assert decision.counts == {"email_address": 2, "private_value": 1}
    assert decision.sentence() == (
        "Held back: 2 × e-mail addresses, 1 × internal names and addresses. "
        "This playbook may not send them: an admin can open them for it"
    )
    assert "eve" not in guard.check("eve@evil.example", frozenset(), [], CONTEXT).sentence()  # never the value itself
    # What is past the first megabyte is not scanned: the tags are what counts there.
    assert held("x" * guard.SCAN_LIMIT + " eve@evil.example") == []


def test_drop_sends_without_what_is_held():
    payload = {
        "to": "eve@evil.example",
        "hosts": ["8.8.8.8", "10.0.0.1", "example.org"],
        "n": 3,
        "nested": {"who": "a@b.example", "ok": "fine"},
    }
    assert guard.drop(payload, CONTEXT, []) == {
        "to": None,
        "hosts": ["8.8.8.8", "example.org"],
        "n": 3,
        "nested": {"who": None, "ok": "fine"},
    }
    assert guard.drop(payload, CONTEXT, ["email_address", "private_value"]) == payload
    assert guard.drop("eve@evil.example", CONTEXT, []) is None


def test_classes_follow_a_value_from_the_trigger_to_the_way_out(admin: TestClient, outside):
    """An incident's host is an internal name wherever it ends up: in a URL, a body, through a filter."""
    outside.host("siem.example.com")
    outside.answer("siem.example.com", json={"id": 7})
    incident(admin, "i1", host="WKS-FINANCE-01", severity="high")
    post = act(
        "send",
        "http.request",
        approval={"ask": False},
        method="POST",
        url="https://siem.example.com/events",
        json={"host": "{{ trigger.incident.host | lower }}", "severity": "{{ trigger.incident.severity }}"},
    )
    pb = playbook(admin, "Sends", [post], [edge("start", "send")])
    assert (
        admin.put(
            f"/api/automation/playbooks/{pb}/egress", json={"mode": "listed", "hosts": ["siem.example.com"]}
        ).status_code
        == 200
    )

    run = go(admin, pb, objectKind="incident", objectId="i1")
    assert run["status"] == "failed" and outside.requests == []  # nothing left
    assert (
        steps(run)["send"]["error"]
        == "Held back: internal names and addresses. This playbook may not send them: an admin can open them for it"
    )
    assert steps(run)["send"]["request"] == {
        "held": {"classes": ["private_value", "verdict"], "held": ["private_value"], "counts": {}}
    }

    # An admin opens the class for this playbook: now it leaves, and the step says what left where.
    opened = admin.put(
        f"/api/automation/playbooks/{pb}/data-allow",
        json={"class": "private_value", "acknowledged": True, "confirmName": "Sends"},
    )
    assert opened.json()["dataAllow"] == ["private_value"]
    run = go(admin, pb, objectKind="incident", objectId="i1")
    assert run["status"] == "done" and outside.requests[-1]["body"] == b'{"host": "wks-finance-01", "severity": "high"}'
    request = steps(run)["send"]["request"]
    assert (request["method"], request["host"], request["path"], request["status"]) == (
        "POST",
        "siem.example.com",
        "/events",
        200,
    )
    assert request["held"]["held"] == [] and steps(run)["send"]["output"]["json"] == {"id": 7}

    # "held: drop" on the node: it is sent without what is held.
    admin.put(f"/api/automation/playbooks/{pb}/data-allow", json={"class": "private_value", "allow": False})
    lenient = {
        **post,
        "config": {
            **post["config"],
            "held": "drop",
            "args": {
                **post["config"]["args"],
                "json": {"note": "about {{ trigger.incident.id }}", "who": "eve@evil.example"},
            },
        },
    }
    dropping = playbook(admin, "Drops", [lenient], [edge("start", "send")])
    admin.put(f"/api/automation/playbooks/{dropping}/egress", json={"mode": "listed", "hosts": ["siem.example.com"]})
    run = go(admin, dropping, objectKind="incident", objectId="i1")
    assert run["status"] == "done" and outside.requests[-1]["body"] == b'{"note": "about i1", "who": null}'
    assert steps(run)["send"]["request"]["held"]["dropped"] is True


# --------------------------------------------------------------------------- #
# The HTTP and e-mail nodes                                                   #
# --------------------------------------------------------------------------- #
def test_the_http_node_reads_without_asking_and_asks_before_it_changes(admin: TestClient, outside):
    outside.host("api.example.com")
    outside.answer("api.example.com", json={"items": [1, 2]}, path="/v1/items")
    outside.answer("api.example.com", status=500, body=b"boom", path="/broken")
    outside.answer("api.example.com", status=404, body=b"nope", path="/missing")
    nodes = [
        act("read", "http.request", url="https://api.example.com/v1/items", query={"limit": 2}),
        act(
            "write",
            "http.request",
            method="DELETE",
            url="https://api.example.com/v1/items/{{ read.json.items | first }}",
        ),
    ]
    pb = playbook(admin, "Http", nodes, [edge("start", "read"), edge("read", "write")])

    # Not listed yet: the request is refused before it leaves, and it is not tried again.
    run = go(admin, pb)
    assert (
        run["error"] == "read: api.example.com is not among the hosts this playbook may reach"
        and outside.requests == []
    )
    admin.put(f"/api/automation/playbooks/{pb}/egress", json={"mode": "listed", "hosts": ["api.example.com"]})

    run_id = start(admin, pb)
    worker.drain(T0)
    run = run_of(admin, run_id)
    assert steps(run)["read"]["output"]["json"] == {"items": [1, 2]} and steps(run)["read"]["output"]["status"] == 200
    # The DELETE changes something on the other side: it waits for a person.
    assert run["status"] == "waiting" and steps(run)["write"]["status"] == "waiting" and len(outside.requests) == 1
    approvals = admin.get("/api/automation/runs/" + run_id).json()
    assert steps(approvals)["write"]["input"]["args"]["url"] == "https://api.example.com/v1/items/1"

    # A dry run sends nothing and shows what it would have sent. What a later step
    # needed from the answer is not there: the run says so and stops at that step.
    before = len(outside.requests)
    dry = go(admin, pb, dryRun=True)
    assert len(outside.requests) == before and steps(dry)["read"]["status"] == "done"
    assert dry["error"].startswith("write: There is nothing at read.json.items")
    assert steps(dry)["read"]["request"] == {
        "method": "GET",
        "host": "api.example.com",
        "path": "/v1/items",
        "held": {"classes": [], "held": [], "counts": {}},
        "dry_run": True,
    }

    # An answer of 400 or more is a failure (tried again only when the other side may recover).
    def one(path, **args):
        single = playbook(
            admin,
            f"Http {path} {len(args)}",
            [act("call", "http.request", url=f"https://api.example.com{path}", **args)],
            [edge("start", "call")],
        )
        admin.put(f"/api/automation/playbooks/{single}/egress", json={"mode": "listed", "hosts": ["api.example.com"]})
        return go(admin, single)

    assert one("/missing")["error"] == "call: The other side answered 404"
    assert steps(one("/broken"))["call"]["error"] == "The other side answered 500"
    lenient = one("/missing", fail_on_error=False)
    assert lenient["status"] == "done" and steps(lenient)["call"]["output"] == {
        "status": 404, "ok": False, "json": None, "text": "nope", "content_type": "",
    }  # fmt: skip


def test_the_email_node_writes_to_listed_domains_through_the_configured_server(admin: TestClient, outside):
    mail = act(
        "mail",
        "email.send",
        to="soc@corp.example, lead@corp.example",
        subject="Incident {{ trigger.incident.id }}",
        text="Severity {{ trigger.incident.severity }}",
    )
    pb = playbook(admin, "Mails", [mail], [edge("start", "mail")])
    incident(admin, "i1", severity="high", host="WKS-1")

    run = go(admin, pb, objectKind="incident", objectId="i1")
    assert (
        run["error"]
        == "mail: corp.example is not among the hosts this playbook may reach: list it to write to its addresses"
    )
    admin.put(f"/api/automation/playbooks/{pb}/egress", json={"mode": "listed", "hosts": ["corp.example"]})
    run = go(admin, pb, objectKind="incident", objectId="i1")
    assert run["error"] == (
        "mail: No instance of the Mail connector is on: add one in Settings, Connectors, to send e-mail"
    )

    smtp = {
        "host": "smtp.corp.example",
        "port": 587,
        "security": "starttls",
        "username": "nik",
        "password": "s3cret-pw",
        "sender": "nik@corp.example",
    }
    saved = admin.put("/api/automation/settings", json={"smtp": smtp}).json()
    assert saved["smtp"] == {
        "host": "smtp.corp.example",
        "port": 587,
        "security": "starttls",
        "username": "nik",
        "sender": "nik@corp.example",
        "caPem": "",
        "hasPassword": True,
    }
    with SessionLocal() as db:
        stored = db.get(Setting, 2).doc["smtp"]["password"]
    assert stored and "s3cret-pw" not in stored  # encrypted at rest, never returned
    # Saving again without a password keeps it.
    assert (
        admin.put(
            "/api/automation/settings", json={"smtp": {**smtp, "password": None, "port": 465, "security": "tls"}}
        ).json()["smtp"]["hasPassword"]
        is True
    )

    run = go(admin, pb, objectKind="incident", objectId="i1")
    assert run["status"] == "done" and steps(run)["mail"]["output"] == {"sent": True, "recipients": 2}
    assert outside.mails == [
        {"host": "smtp.corp.example", "port": 465, "from": "nik@corp.example", "to": "soc@corp.example, lead@corp.example",
         "subject": "Incident i1", "text": "Severity high\n", "login": ("nik", "s3cret-pw")}
    ]  # fmt: skip
    assert steps(run)["mail"]["request"]["method"] == "SMTP" and "s3cret" not in str(steps(run)["mail"]["request"])

    # What is said is judged like anything that leaves; the recipients are where it goes, not what is sent.
    leaky = act("mail", "email.send", to="soc@corp.example", subject="Host", text="It is {{ trigger.incident.host }}")
    leaks = playbook(admin, "Mails a host", [leaky], [edge("start", "mail")])
    admin.put(f"/api/automation/playbooks/{leaks}/egress", json={"mode": "listed", "hosts": ["corp.example"]})
    run = go(admin, leaks, objectKind="incident", objectId="i1")
    assert steps(run)["mail"]["error"].startswith("Held back: internal names and addresses") and len(outside.mails) == 1
    for bad in ("not-an-address", "a@b@c d", ""):
        broken = playbook(
            admin,
            f"Bad to {len(bad)}",
            [act("mail", "email.send", to=bad or [], subject="s", text="t")],
            [edge("start", "mail")],
        )
        assert go(admin, broken)["status"] == "failed"


def test_the_email_node_of_before_sends_through_an_instance_of_the_mail_connector(admin: TestClient, outside):
    """5.1: mail is a connector. The node of 4.x is kept for the playbooks that have it, and sends
    through an instance; the SMTP server of the settings becomes one when the server starts."""
    from app.automation import connector_actions as ca
    from app.automation import state
    from app.core.models import Connection

    with SessionLocal() as db:
        ca.seed(db)  # the connectors Nik ships, the Mail connector among them
        db.commit()
    assert admin.get("/api/automation/connectors/mail").json()["native"] == "mail"
    entries = {entry["id"]: entry for entry in admin.get("/api/automation/catalog").json()["nodes"]}
    # The old node is not offered any more; the commands of the connector are, once an instance is on.
    assert entries["email.send"]["retired"] is True
    assert entries["mail.send"]["connector"] == "mail" and entries["mail.send"]["available"] is False

    smtp = {"host": "smtp.corp.example", "port": 465, "security": "tls", "username": "nik", "password": "s3cret-pw",
            "sender": "nik@corp.example"}  # fmt: skip
    admin.put("/api/automation/settings", json={"smtp": smtp})
    with SessionLocal() as db:
        assert ca.adopt_smtp(db) is True
        db.commit()
        (row,) = db.scalars(select(Connection).where(Connection.connector_id == "mail")).all()
        assert (row.name, row.enabled, row.created_by) == ("Mail (from Settings)", True, "nik")
        assert row.config == {
            "smtp_host": "smtp.corp.example", "smtp_port": 465, "smtp_security": "tls", "sender": "nik@corp.example",
        }  # fmt: skip
        assert ca.secrets_of(row) == {"username": "nik", "password": "s3cret-pw"} and "s3cret-pw" not in row.secrets
        # Once: an instance deleted afterwards does not come back.
        assert ca.adopt_smtp(db) is False and state.read(db)["smtp_adopted"] is True
    entries = {entry["id"]: entry for entry in admin.get("/api/automation/catalog").json()["nodes"]}
    assert entries["mail.send"]["available"] is True

    old = act("mail", "email.send", to="soc@corp.example", subject="Old node", text="Still works")
    # A command that sends changes something outside and asks first by default: not here.
    new = act(
        "mail",
        "mail.send",
        approval={"ask": False},
        to="soc@corp.example",
        subject="New command",
        text="Through the connector",
    )
    for name, node_ in (("Old mail node", old), ("New mail command", new)):
        pb = playbook(admin, name, [node_], [edge("start", "mail")])
        refused = go(admin, pb)
        assert "corp.example is not among the hosts this playbook may reach" in str(refused["error"]), (name, refused)
        admin.put(f"/api/automation/playbooks/{pb}/egress", json={"mode": "listed", "hosts": ["corp.example"]})
        run = go(admin, pb)
        assert run["status"] == "done", run
        step = steps(run)["mail"]
        assert step["output"]["sent"] is True and step["output"]["recipients"] == 1
        assert step["request"]["connection"] == "Mail (from Settings)" and step["request"]["method"] == "SMTP"
        assert "s3cret" not in str(step)
    assert [(m["subject"], m["from"], m["login"]) for m in outside.mails] == [
        ("Old node", "nik@corp.example", ("nik", "s3cret-pw")),
        ("New command", "nik@corp.example", ("nik", "s3cret-pw")),
    ]

    # The instance turned off: the command says so; the old node falls back to the server of the settings.
    with SessionLocal() as db:
        db.scalars(select(Connection).where(Connection.connector_id == "mail")).one().enabled = False
        db.commit()
    pb = playbook(admin, "Off", [new], [edge("start", "mail")])
    admin.put(f"/api/automation/playbooks/{pb}/egress", json={"mode": "listed", "hosts": ["corp.example"]})
    # It names no instance and none is on: it has nowhere to send. Named, it is told that it is off.
    assert "Choose an instance" in go(admin, pb)["error"]
    named = dict(new, config={**new["config"], "connection": "Mail (from Settings)"})
    pb = playbook(admin, "Off, named", [named], [edge("start", "mail")])
    assert "is off: turn it on in Settings, Connectors" in go(admin, pb)["error"]


# --------------------------------------------------------------------------- #
# The double check                                                            #
# --------------------------------------------------------------------------- #
def test_opening_a_playbook_needs_an_admin_and_a_double_check(admin: TestClient):
    pb = playbook(admin, "Careful one", [], [])
    url = f"/api/automation/playbooks/{pb}"
    builder = make_key(admin, label="pb", roles=["playbooks", "analyst"])
    caller = TestClient(fastapi_app)
    # The playbooks role builds; it does not decide where data goes.
    assert (
        caller.put(f"{url}/egress", headers=builder, json={"mode": "listed", "hosts": ["x.example"]}).status_code == 403
    )
    assert (
        caller.put(
            f"{url}/data-allow",
            headers=builder,
            json={"class": "sample", "acknowledged": True, "confirmName": "Careful one"},
        ).status_code
        == 403
    )
    assert caller.get("/api/automation/settings", headers=builder).status_code == 403
    assert caller.get("/api/automation/data-classes", headers=builder).status_code == 200

    # Listing hosts: no double check, but cleaned.
    listed = admin.put(
        f"{url}/egress", json={"mode": "listed", "hosts": ["API.example.com.", "fw.corp:4434", "api.example.com"]}
    ).json()
    assert listed["egressHosts"] == ["api.example.com", "fw.corp:4434"] and listed["egressMode"] == "listed"
    assert admin.put(f"{url}/egress", json={"mode": "listed", "hosts": ["http://x"]}).status_code == 400

    # Any host: the box and the name, exactly.
    for body in (
        {},
        {"acknowledged": True},
        {"acknowledged": True, "confirmName": "careful one"},
        {"confirmName": "Careful one"},
    ):
        refused_ = admin.put(f"{url}/egress", json={"mode": "any", "hosts": [], **body})
        assert refused_.status_code == 400 and "typing the name" in refused_.json()["detail"], body
    opened = admin.put(
        f"{url}/egress", json={"mode": "any", "hosts": [], "acknowledged": True, "confirmName": "Careful one"}
    ).json()
    assert opened["egressMode"] == "any" and "any host" in opened["warnings"]
    # Back to listed needs no confirmation.
    assert admin.put(f"{url}/egress", json={"mode": "listed", "hosts": ["siem.corp"]}).json()["egressMode"] == "listed"

    # A class of data: the same double check to open, none to close.
    assert admin.put(f"{url}/data-allow", json={"class": "sample"}).status_code == 400
    assert (
        admin.put(
            f"{url}/data-allow", json={"class": "nope", "acknowledged": True, "confirmName": "Careful one"}
        ).status_code
        == 400
    )
    opened = admin.put(
        f"{url}/data-allow", json={"class": "sample", "acknowledged": True, "confirmName": "Careful one"}
    ).json()
    opened = admin.put(
        f"{url}/data-allow", json={"class": "email_address", "acknowledged": True, "confirmName": "Careful one"}
    ).json()
    assert opened["dataAllow"] == ["email_address", "sample"] and "data opened" in opened["warnings"]
    assert admin.put(f"{url}/data-allow", json={"class": "sample", "allow": False}).json()["dataAllow"] == [
        "email_address"
    ]

    classes = admin.get("/api/automation/data-classes").json()
    assert classes["always"] == ["hash", "nik_id", "public_indicator", "verdict"]
    assert [c["id"] for c in classes["classes"] if c["sensitive"]] == ["mail_body", "attachment", "sample", "tlp_red"]
    assert all(c["label"] and c["warning"] for c in classes["classes"])

    # Every opening and closing is in the audit log, with where the data can go.
    entries = admin.get("/api/audit?q=action:automation.*").json()["entries"]
    assert [e["action"] for e in reversed(entries)] == [
        "automation.egress.hosts", "automation.egress.open", "automation.egress.close",
        "automation.data.open", "automation.data.open", "automation.data.close",
    ]  # fmt: skip
    assert entries[2]["details"] == 'Playbook "Careful one" may send samples to: siem.corp'

    # The hosts an admin lists for every playbook.
    assert admin.put("/api/automation/settings", json={"hosts": ["Proxy.corp", "siem.corp"]}).json()["hosts"] == [
        "proxy.corp",
        "siem.corp",
    ]
    assert admin.put("/api/automation/settings", json={"hosts": ["a b"]}).status_code == 400


# --------------------------------------------------------------------------- #
# The Nik nodes                                                               #
# --------------------------------------------------------------------------- #
def test_what_a_playbook_changes_in_nik_is_signed_and_audited(admin: TestClient):
    incident(admin, "i1", severity="low", host="WKS-1")
    admin.post("/api/users", json={"username": "anna", "password": "password1"})
    nodes = [
        act("note", "nik.add-note", text="Seen by {{ run.playbook }}"),
        act("status", "nik.set-status", status="in_progress"),
        act("owner", "nik.set-assignee", assignee="anna"),
        act("sev", "nik.set-incident-field", field="severity", value="critical"),
        act("read", "nik.get-incident"),
        act(
            "last",
            "nik.add-note",
            text="Now {{ read.incident.status }} / {{ read.incident.severity }} / {{ sev.incident.assignee }}",
        ),
    ]
    order = [
        edge("start", "note"),
        edge("note", "status"),
        edge("status", "owner"),
        edge("owner", "sev"),
        edge("sev", "read"),
        edge("read", "last"),
    ]
    pb = playbook(admin, "Triage", nodes, order)
    run = go(admin, pb, objectKind="incident", objectId="i1")
    assert run["status"] == "done", run["error"]

    doc = admin.get("/api/incidents/i1").json()
    assert (doc["status"], doc["assignee"], doc["severity"]) == ("in_progress", "anna", "critical")
    first, last = doc["notes"]
    assert first["text"] == "Seen by Triage" and first["author"] == "nik-automation"
    assert first["automation"] == {"run": run["id"], "playbook": "Triage"}  # marked as made by automation
    assert last["text"] == "Now in_progress / critical / anna"

    with SessionLocal() as db:
        entries = db.scalars(
            select(AuditEntry).where(AuditEntry.actor == "nik-automation").order_by(AuditEntry.at)
        ).all()
        assert [e.action for e in entries] == [
            "note.add",
            "incident.update",
            "incident.update",
            "incident.update",
            "note.add",
        ]
        assert entries[1].details == f'Set status: open → in_progress (playbook "Triage", run {run["id"]})'
        assert all(e.incident_id == "i1" for e in entries)
        # The lists read the columns: they follow.
        row = db.get(Incident, "i1")
        assert (row.status, row.assignee, row.severity) == ("in_progress", "anna", "critical")

    # A dry run changes nothing and says what it would have done.
    before = admin.get("/api/incidents/i1").json()
    dry = go(admin, pb, objectKind="incident", objectId="i1", dryRun=True)
    assert dry["status"] == "done" and steps(dry)["status"]["request"] == {
        "would": "set status",
        "value": "in_progress",
    }
    assert admin.get("/api/incidents/i1").json()["notes"] == before["notes"]

    # What cannot be done says why, and is not tried again.
    def fails(action, **args):
        bad = playbook(admin, f"Bad {action} {len(str(args))}", [act("x", action, **args)], [edge("start", "x")])
        return go(admin, bad, objectKind="incident", objectId="i1")["error"]

    assert (
        fails("nik.set-assignee", assignee="nobody")
        == "x: There is no account with this name to assign the incident to"
    )
    assert (
        fails("nik.set-incident-field", field="severity", value="urgent")
        == "x: The severity is low, medium, high or critical"
    )
    assert fails("nik.add-note", text="  ") == "x: The note is empty"
    assert fails("nik.get-incident", incident="nope") == "x: The incident does not exist"
    orphan = playbook(admin, "No incident", [act("x", "nik.add-note", text="hi")], [edge("start", "x")])
    assert go(admin, orphan)["error"] == "x: No incident was given"


def test_a_playbook_opens_incidents_and_keeps_indicators(admin: TestClient):
    nodes = [
        act("open", "nik.create-incident", title="Phishing wave", ticketId="INC-9", host="MX-1", severity="high"),
        act(
            "add",
            "nik.add-indicators",
            indicators="see 185.220.101.47 and hxxp://evil[.]example/kit",
            tags=["phish"],
            note="from the wave",
        ),
        act(
            "list",
            "nik.add-to-ioc-list",
            list="Blocklist",
            indicators=[{"type": "ip", "value": "185.220.101.47"}, "evil.example"],
        ),
        act("tag", "nik.add-tags", indicators=["185.220.101.47"], tags=["C2", "c2"]),
        act("ask", "nik.get-indicator", value="185.220.101.47"),
        act("drop", "nik.remove-from-ioc-list", list="Blocklist", indicators=["evil.example"]),
        act(
            "note",
            "nik.add-note",
            incident="{{ open.incident.id }}",
            text="{{ ask.tags | sort | join(',') }} in {{ ask.lists | join(',') }}; {{ add.added }} added",
        ),
    ]
    order = [edge("start", "open")] + [edge(a["id"], b["id"]) for a, b in zip(nodes, nodes[1:], strict=False)]
    run = go(admin, playbook(admin, "Wave", nodes, order))
    assert run["status"] == "done", run["error"]
    created = steps(run)["open"]["output"]["incident"]
    doc = admin.get(f"/api/incidents/{created['id']}").json()
    assert (doc["name"], doc["severity"], doc["status"], doc["createdBy"], doc["host"]) == (
        "INC-9 · Phishing wave",
        "high",
        "open",
        "nik-automation",
        "MX-1",
    )
    assert doc["notes"][0]["text"] == "c2,phish in Blocklist; 2 added"
    with SessionLocal() as db:
        records = {(r.type, r.value): r for r in db.scalars(select(IocRecord))}
        assert set(records) == {
            ("ip", "185.220.101.47"),
            ("url", "http://evil.example/kit"),
            ("domain", "evil.example"),
        }
        assert sorted(records[("ip", "185.220.101.47")].tags) == ["c2", "phish"]
        blocklist = db.scalars(select(IocList).where(IocList.name == "Blocklist")).one()
        assert [
            (i.type, i.value) for i in db.scalars(select(IocListItem).where(IocListItem.list_id == blocklist.id))
        ] == [("ip", "185.220.101.47")]
    assert steps(run)["drop"]["output"] == {"removed": 1} and steps(run)["ask"]["output"]["found"] is True
    # The new incident is an event like any other: a playbook that waits for it would start.
    events = admin.get("/api/audit?q=action:incident.create").json()["entries"]
    assert events[0]["actor"] == "nik-automation" and "Wave" in events[0]["details"]


def test_the_system_account_cannot_sign_in_and_is_not_one_people_manage(admin: TestClient):
    from app.automation.nik_actions import system_user

    with SessionLocal() as db:
        first = system_user(db)
        db.commit()
        assert system_user(db).id == first.id  # made once
        assert db.scalars(select(User).where(User.username == "nik-automation")).one().roles == ["automation"]
    for password in ("", "!", "nik-automation", "password"):
        res = TestClient(fastapi_app).post("/api/auth/login", json={"username": "nik-automation", "password": password})
        assert res.status_code in (401, 403), password
    assert [u["username"] for u in admin.get("/api/users").json()["users"]] == ["admin"]
    assert "nik-automation" not in admin.get("/api/users/names").json()["names"]
    assert [u["username"] for u in admin.get("/api/backup/export").json()["users"]] == ["admin"]
    # Its name is taken: nobody signs changes as the engine.
    for name in ("nik-automation", "NIK-Automation"):
        assert admin.post("/api/users", json={"username": name, "password": "password1"}).status_code == 400
    me = admin.get("/api/auth/me").json()["user"]["id"]
    assert admin.patch(f"/api/users/{me}", json={"username": "nik-automation"}).status_code == 400
    # Its role is not one an admin can give.
    assert (
        admin.post("/api/users", json={"username": "bot", "password": "password1", "roles": ["automation"]}).status_code
        == 400
    )


def test_classes_of_what_nik_returns(admin: TestClient):
    scope = ex.Scope(
        values={"x": {"incident": {"host": "WKS-1", "id": "i1"}}},
        classes={"x": {"incident.host": ["private_value"], "incident.id": ["nik_id"]}},
    )
    assert ex.render("{{ x.incident.id }}", scope).classes == {"nik_id"}
    assert guard.check("i1", ex.render("{{ x.incident.id }}", scope).classes, [], CONTEXT).allowed
    assert not guard.check("WKS-1", ex.render("{{ x.incident }}", scope).classes, [], CONTEXT).allowed


def test_the_system_account_is_not_a_first_user(client: TestClient):
    """The worker makes its account when it starts, which may be before anyone signed up."""
    from app.automation.nik_actions import system_user

    with SessionLocal() as db:
        system_user(db)
        db.commit()
    assert client.get("/api/auth/bootstrap").json() == {"hasUsers": False}
    created = client.post("/api/users", json={"username": "admin", "password": "supersecret"})
    assert created.status_code == 201 and created.json()["user"]["roles"] == ["admin"]  # still the first run
    assert client.get("/api/auth/bootstrap").json() == {"hasUsers": True}
    client.post("/api/auth/login", json={"username": "admin", "password": "supersecret"})
    me = client.get("/api/auth/me").json()["user"]["id"]
    # And it is not "another user" that would let the only person be deleted.
    assert client.delete(f"/api/users/{me}").status_code == 400

"""Stored credentials: kept once, named by instances, read when a request is built, and nowhere else."""

from __future__ import annotations

import base64
import json
import textwrap

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.automation import actions, credentials, instance_keys
from app.automation import connector_actions as ca
from app.automation import connectors as cn
from app.automation import expressions as ex
from app.core import vault
from app.core.config import settings
from app.core.db import SessionLocal
from app.core.models import (
    AuditEntry,
    CommandAnswer,
    Connection,
    Credential,
    InstanceKeyUse,
    IntegrationKey,
    Playbook,
)
from app.core.security import now_iso
from app.enrichment import old_keys
from tests.conftest import make_key
from tests.test_automation_engine import edge, go, node, playbook, run_of, steps
from tests.test_connector_actions import acme, command  # noqa: F401 - acme is a fixture
from tests.test_debugger import debug, tell
from tests.test_enrichment import by_source, check, old_key, rated

BASE = "/api/automation"
CONNECTION = "c" * 32
VALUE = "vt-key-0123456789abcdef"
PASSWORD = "proxy-pass-0123456789"

# A product that takes its key in the address and says it back: the worst case for what a step records.
KEYED = textwrap.dedent(
    """\
    name: Keyed
    id: keyed
    version: 1
    configuration:
      - { name: api_key, type: secret }
    base_url: "https://keyed.example.com"
    commands:
      - name: export
        arguments: [{ name: what, type: text, required: true }]
        request: { method: GET, path: "/exports/{{ secret.api_key }}/{{ args.what }}" }
        outputs: { echo: "{{ response.echo }}", what: "{{ response.what }}" }
        context:
          - { path: ext.keyed.echo, value: "{{ response.echo }}" }
    ext_fields:
      - { name: echo, type: text }
    """
)


def make(admin: TestClient, name: str = "vt_key", expect: int = 201, **body) -> dict:
    sent = {"name": name, "kind": "secret", "value": VALUE, **body}
    res = admin.post(f"{BASE}/credentials", json=sent)
    assert res.status_code == expect, res.text
    return res.json()


def pair(admin: TestClient, name: str = "proxy_account", username: str = "proxy-user", **body) -> dict:
    return make(admin, name, kind="pair", username=username, value=PASSWORD, **body)


def listed(admin: TestClient) -> dict[str, dict]:
    return {row["name"]: row for row in admin.get(f"{BASE}/credentials").json()["credentials"]}


def who(headers: dict) -> tuple[str, str]:
    user, _, password = base64.b64decode(headers["Authorization"].split()[1]).decode().partition(":")
    return user, password


def use_pair(admin: TestClient, name: str = "proxy_account", connection: str = CONNECTION) -> dict:
    saved = admin.put(
        f"{BASE}/instances/{connection}",
        json={
            "secrets": {
                "username": "{{ credentials." + name + ".username }}",
                "password": "{{credentials." + name + ".password}}",  # as a person may type it
            }
        },
    )
    assert saved.status_code == 200, saved.text
    return saved.json()


@pytest.fixture()
def keyed(admin: TestClient, outside):
    """The connector whose key goes in the address, with an instance, and its host saying the key back."""
    outside.host("keyed.example.com", "93.184.215.30")
    with SessionLocal() as db:
        ca.install(db, KEYED, "admin")
        db.commit()
    made = admin.post(f"{BASE}/connectors/keyed/instances", json={"name": "Keyed one", "secrets": {}})
    assert made.status_code == 201, made.text
    outside.instance = made.json()["id"]

    def reply(method, host, path, _headers, _body):
        if host != "keyed.example.com":
            return None
        _, _, key, what = path.split("?")[0].split("/")
        return 200, {"content-type": "application/json"}, json.dumps({"echo": f"key={key}", "what": what}).encode()

    outside.answers.append(reply)
    return outside


# --------------------------------------------------------------------------- #
# The thing                                                                   #
# --------------------------------------------------------------------------- #
def test_a_credential_is_stored_encrypted_and_its_value_is_never_given_back(admin: TestClient):
    made = make(admin, title="The VirusTotal key of the SOC")
    assert (made["name"], made["kind"], made["title"]) == ("vt_key", "secret", "The VirusTotal key of the SOC")
    assert made["usedBy"] == [] and made["readable"] is True and made["updatedBy"] == "admin"
    both = pair(admin)
    assert both["kind"] == "pair" and both["username"] == "proxy-user"  # the user name is not a secret
    for body in (made, both, admin.get(f"{BASE}/credentials").json()):
        assert VALUE not in json.dumps(body) and PASSWORD not in json.dumps(body)
        assert "value" not in body and "secret" not in body
    with SessionLocal() as db:
        row = credentials.by_name(db, "vt_key")
        assert VALUE not in row.secret and vault.decrypt(row.secret) == VALUE  # as the secrets of an instance are
        assert PASSWORD not in credentials.by_name(db, "proxy_account").secret
    # The audit log says that it was made, never what it holds.
    entries = admin.get("/api/audit", params={"q": "action:credential.create"}).json()["entries"]
    assert [entry["details"] for entry in entries][::-1] == [
        'Made the credential "vt_key" (one value)',
        'Made the credential "proxy_account" (a user name and a password)',
    ]
    with SessionLocal() as db:
        everything = json.dumps([[row.details, row.target] for row in db.scalars(select(AuditEntry))])
    assert VALUE not in everything and PASSWORD not in everything


def test_what_a_credential_is_called_and_what_it_must_hold(admin: TestClient):
    make(admin)
    for name in ("Vt", "1key", "has space", "a.b", "", "x" * 41, "{{ credentials.a }}"):
        assert admin.post(f"{BASE}/credentials", json={"name": name, "value": "v"}).status_code in (400, 422), name
    for name in ("a", "vt-key-2", "proxy_1"):
        make(admin, name)
    assert make(admin, expect=400)["detail"] == 'A credential called "vt_key" exists already'
    assert make(admin, "other", kind="cert", expect=400)["detail"].startswith("A credential is a secret")
    assert make(admin, "nouser", kind="pair", expect=400)["detail"] == "The user name of a pair is needed"
    assert make(admin, "empty", value="", expect=422)
    # A credential holds a value: it does not name another one.
    assert make(admin, "loop", value="{{ credentials.vt_key }}", expect=400)["detail"].startswith("A credential holds")


def test_only_who_manages_the_instances_reads_or_changes_credentials(admin: TestClient, client: TestClient):
    made = make(admin)
    for roles in (["analyst"], ["viewer"], ["playbooks"]):
        headers = make_key(admin, label="k" + roles[0], roles=roles)
        assert client.get(f"{BASE}/credentials", headers=headers).status_code == 403, roles
        assert client.post(f"{BASE}/credentials", json={"name": "x", "value": "v"}, headers=headers).status_code == 403
        assert client.put(f"{BASE}/credentials/{made['id']}", json={"value": "v"}, headers=headers).status_code == 403
        assert client.delete(f"{BASE}/credentials/{made['id']}", headers=headers).status_code == 403
    manager = make_key(admin, label="manager", roles=["connectors"])
    assert client.get(f"{BASE}/credentials", headers=manager).status_code == 200


# --------------------------------------------------------------------------- #
# In an instance                                                              #
# --------------------------------------------------------------------------- #
def test_an_instance_names_a_credential_and_stores_the_name_not_the_value(admin: TestClient, acme):  # noqa: F811
    pair(admin)
    shown = use_pair(admin)
    assert shown["secrets"] == {"username": True, "password": True}
    assert shown["credentials"] == {
        "username": {"name": "proxy_account", "part": "username", "missing": False},
        "password": {"name": "proxy_account", "part": "password", "missing": False},
    }
    assert shown["keys"][0]["credentials"] == shown["credentials"]
    assert PASSWORD not in json.dumps(shown)
    with SessionLocal() as db:
        row = db.get(Connection, CONNECTION)
        assert ca.secrets_of(row) == {  # the reference, in its one spelling: not a copy
            "username": "{{ credentials.proxy_account.username }}",
            "password": "{{ credentials.proxy_account.password }}",
        }
        assert ca.usable_secrets(db, row) == {"username": "proxy-user", "password": PASSWORD}
    # Where it is used is said with the credential.
    assert listed(admin)["proxy_account"]["usedBy"] == [
        {
            "instance": CONNECTION,
            "name": "Acme production",
            "connector": "acme",
            "connectorName": "Acme Desk",
            "key": "main",
            "keyName": "Key 1",
            "fields": ["password", "username"],
        }
    ]


def test_a_reference_must_be_whole_exist_and_fit_the_kind(admin: TestClient, acme):  # noqa: F811
    make(admin)
    pair(admin)
    url = f"{BASE}/instances/{CONNECTION}"

    def refused(value: str) -> str:
        res = admin.put(url, json={"secrets": {"password": value}})
        assert res.status_code == 400, res.text
        return res.json()["detail"]

    assert refused("{{ credentials.nope }}") == (
        'There is no credential called "nope": make it in Settings, Credentials'
    )
    assert refused("Bearer {{ credentials.vt_key }}") == credentials.HOW  # alone in the field
    assert refused("{{ credentials.vt_key | upper }}") == credentials.HOW  # not a template
    assert refused("{{ credentials.vt_key.token }}") == credentials.HOW
    assert refused("{{ credentials.proxy_account }}").startswith('"proxy_account" is a user name and a password')
    assert refused("{{ credentials.vt_key.password }}").startswith('"vt_key" is one value')
    # A plain value of an instance is shown and sent as it is: a credential is not named there.
    wrong = admin.put(url, json={"config": {"url": "https://{{ credentials.vt_key }}.example.com"}})
    assert wrong.status_code == 400 and "is not a secret" in wrong.json()["detail"]
    # The password of a pair, or a secret, alone in a field that holds one value.
    assert admin.put(url, json={"secrets": {"password": "{{ credentials.vt_key }}"}}).status_code == 200
    with SessionLocal() as db:
        assert ca.usable_secrets(db, db.get(Connection, CONNECTION)) == {"username": "svc", "password": VALUE}


def test_a_command_goes_with_the_value_the_credential_has_now(admin: TestClient, acme):  # noqa: F811
    made = pair(admin)
    use_pair(admin)
    acme.answer("desk.example.com", 200, {"state": "open"}, path="/api/tickets/T-1")
    pb = playbook(admin, "Reads", [command("read", "get-ticket", number="T-1")], [edge("start", "read")])
    run = go(admin, pb)
    assert run["status"] == "done" and steps(run)["read"]["output"] == {"state": "open"}
    assert who(acme.requests[-1]["headers"]) == ("proxy-user", PASSWORD)
    assert PASSWORD not in json.dumps(run)
    # The value is changed in one place: the next request of every instance that names it sends the new one.
    admin.put(f"{BASE}/instances/{CONNECTION}", json={"keyPolicy": {"cacheHours": 24}})
    go(admin, pb)
    with SessionLocal() as db:
        assert db.scalars(select(CommandAnswer)).first() is not None  # an answer is kept for the instance
        db.get(Connection, CONNECTION).last_test = {"ok": True}
        db.commit()
    changed = admin.put(
        f"{BASE}/credentials/{made['id']}", json={"value": "another-pass-9876543210", "username": "other-user"}
    )
    assert changed.status_code == 200 and "another-pass" not in changed.text
    with SessionLocal() as db:
        # What was got with the old value is not kept as if the new one had got it.
        assert db.scalars(select(CommandAnswer)).first() is None
        assert db.get(Connection, CONNECTION).last_test is None
    before = len(acme.requests)
    assert go(admin, pb)["status"] == "done"
    assert len(acme.requests) == before + 1
    assert who(acme.requests[-1]["headers"]) == ("other-user", "another-pass-9876543210")
    entry = admin.get("/api/audit", params={"q": "action:credential.update"}).json()["entries"][0]
    assert entry["details"] == (
        'Changed the credential "proxy_account": its user name, its password; used by Acme production'
    )
    # A value left out stays as it is.
    admin.put(f"{BASE}/credentials/{made['id']}", json={"title": "The proxy"})
    with SessionLocal() as db:
        assert vault.decrypt(credentials.by_name(db, "proxy_account").secret) == "another-pass-9876543210"


def test_a_credential_that_is_used_is_not_deleted_and_keeps_its_name(admin: TestClient, acme):  # noqa: F811
    made = pair(admin)
    use_pair(admin)
    refused = admin.delete(f"{BASE}/credentials/{made['id']}")
    assert refused.status_code == 409
    assert refused.json()["detail"] == (
        '"proxy_account" is used by Acme production: give those instances another credential, or a typed value, first'
    )
    renamed = admin.put(f"{BASE}/credentials/{made['id']}", json={"name": "proxy2"})
    assert renamed.status_code == 409 and "keeps its name" in renamed.json()["detail"]
    assert "proxy_account" in listed(admin)
    # Typed again in the instance, nothing names it: it is renamed, then deleted.
    admin.put(f"{BASE}/instances/{CONNECTION}", json={"secrets": {"username": "svc", "password": "typed-pass-1"}})
    assert listed(admin)["proxy_account"]["usedBy"] == []
    assert admin.put(f"{BASE}/credentials/{made['id']}", json={"name": "proxy2"}).json()["name"] == "proxy2"
    assert admin.delete(f"{BASE}/credentials/{made['id']}").status_code == 204
    assert admin.delete(f"{BASE}/credentials/{made['id']}").status_code == 404
    actions_logged = [entry["action"] for entry in admin.get("/api/audit").json()["entries"]]
    assert "credential.delete" in actions_logged


def test_a_credential_that_is_missing_fails_the_step_by_its_name_and_nothing_is_sent(
    admin: TestClient,
    acme,  # noqa: F811
):
    pair(admin)
    use_pair(admin)
    with SessionLocal() as db:  # what a database put back from before it was made looks like
        db.delete(credentials.by_name(db, "proxy_account"))
        db.commit()
    pb = playbook(admin, "Reads", [command("read", "get-ticket", number="T-1")], [edge("start", "read")])
    run = go(admin, pb)
    assert run["status"] == "failed" and acme.requests == []
    assert steps(run)["read"]["error"] == (
        'The instance "Acme production" uses the credential "proxy_account", which does not exist: '
        "make it again in Settings, Credentials, or give the instance another"
    )
    # The same in a dry run and in the test of the connection; and the form says which one is missing.
    assert steps(go(admin, pb, dryRun=True))["read"]["error"].startswith('The instance "Acme production" uses')
    tested = admin.post(f"{BASE}/instances/{CONNECTION}/test").json()
    assert tested["ok"] is False and '"proxy_account", which does not exist' in tested["message"]
    shown = admin.get(f"{BASE}/instances").json()["instances"][0]
    assert shown["credentials"]["password"] == {"name": "proxy_account", "part": "password", "missing": True}


def test_a_value_never_reaches_a_run_a_dry_run_a_debug_session_or_the_audit_log(admin: TestClient, keyed):
    make(admin)
    saved = admin.put(f"{BASE}/instances/{keyed.instance}", json={"secrets": {"api_key": "{{ credentials.vt_key }}"}})
    assert saved.status_code == 200, saved.text
    read = node("read", "action", action="keyed.export", connection="Keyed one", args={"what": "full"})
    pb = playbook(admin, "Exports", [read], [edge("start", "read")])
    run = go(admin, pb)
    step = steps(run)["read"]
    assert run["status"] == "done", step
    # The request left with the value, and nothing that is kept of it says the value.
    assert keyed.requests[-1]["path"] == f"/exports/{VALUE}/full"
    assert step["request"]["path"] == "/exports/•••/full"
    assert step["output"] == {"echo": "key=•••", "what": "full"}  # even when the other side says it back
    assert VALUE not in json.dumps(run)
    dry = go(admin, pb, dryRun=True)
    assert steps(dry)["read"]["request"]["path"] == "/exports/•••/full" and VALUE not in json.dumps(dry)
    # A debug session shows what a node read and gave, and takes other arguments: never the value.
    run_id = debug(admin, pb)
    tell(admin, run_id, "continue")
    debugged = run_of(admin, run_id)
    assert debugged["status"] == "done" and VALUE not in json.dumps(debugged)
    with SessionLocal() as db:
        everything = json.dumps([[row.action, row.details, row.target] for row in db.scalars(select(AuditEntry))])
    assert VALUE not in everything
    # A failure quotes the address, not the key in it.
    keyed.answers.append(lambda *_: (500, {"content-type": "text/plain"}, f"no {VALUE} here".encode()))
    failed = go(admin, pb)
    assert failed["status"] == "failed" and VALUE not in json.dumps(failed)


# --------------------------------------------------------------------------- #
# Nowhere else                                                                #
# --------------------------------------------------------------------------- #
def test_a_playbook_cannot_read_a_credential(admin: TestClient, acme):  # noqa: F811
    make(admin)
    leak = command("open", "create-ticket", title="{{ credentials.vt_key }}")
    draft = admin.post(f"{BASE}/playbooks", json={"name": "Leaks"}).json()["id"]
    shape = {"nodes": [node("start", "trigger", manual=True), leak], "edges": [edge("start", "open")]}
    found = admin.post(f"{BASE}/playbooks/{draft}/validate", json={"graph": shape}).json()["problems"]
    assert [problem["message"] for problem in found] == [ex.CREDENTIALS_ELSEWHERE]
    assert admin.post(f"{BASE}/playbooks/{draft}/versions", json={"graph": shape}).status_code == 422
    # The engine refuses the name wherever an expression is evaluated: no scope holds the credentials.
    for values in ({}, {"trigger": {}, "inputs": {}}, {"config": {}, "args": {}, "secret": {"api_key": "x"}}):
        for text in ("{{ credentials.vt_key }}", "{{ credentials }}", "{{ credentials.vt_key | default('') }}"):
            with pytest.raises(ex.ExpressionError) as raised:
                ex.render_text(text, ex.Scope(values=values))
            assert raised.value.message == ex.CREDENTIALS_ELSEWHERE
    # Typed into a node while a run is debugged, it is the text that was typed: nothing reads it.
    safe = command("open", "create-ticket", title="safe")
    pb = playbook(admin, "Debugged", [safe], [edge("start", "open")])
    acme.answer("desk.example.com", 201, {"number": "T-1"}, path="/api/tickets")
    run_id = debug(admin, pb)
    tell(admin, run_id, "step", overrides={"title": "{{ credentials.vt_key }}"}, sendForReal=True)
    run = run_of(admin, run_id)
    assert json.loads(acme.requests[-1]["body"])["title"] == "{{ credentials.vt_key }}"
    assert VALUE not in json.dumps(run) and VALUE not in json.dumps(acme.requests, default=str)


def test_a_connector_file_cannot_read_a_credential():
    text = KEYED.replace("{{ secret.api_key }}", "{{ credentials.vt_key }}")
    with pytest.raises(cn.ConnectorError) as raised:
        cn.load(text)
    assert ex.CREDENTIALS_ELSEWHERE in [problem.message for problem in raised.value.problems]
    outputs = KEYED.replace('echo: "{{ response.echo }}", what', 'echo: "{{ credentials.vt_key }}", what')
    with pytest.raises(cn.ConnectorError) as raised:
        cn.load(outputs)
    assert ex.CREDENTIALS_ELSEWHERE in [problem.message for problem in raised.value.problems]


# --------------------------------------------------------------------------- #
# Several keys                                                                #
# --------------------------------------------------------------------------- #
def ask(playbook_id: str, at: float, connection: str = "Acme production") -> actions.Result:
    with SessionLocal() as db:
        call = actions.Call(
            db=db,
            args={"number": "T-1"},
            classes=frozenset(),
            arg_classes={},
            dry_run=False,
            run=None,
            playbook=db.get(Playbook, playbook_id),
            now=at,
            connection=connection,
        )
        result = ca.run_command("acme", "get-ticket", call)
        db.commit()
        return result


def test_keys_that_name_credentials_take_turns_and_each_instance_counts_its_own(admin: TestClient, acme):  # noqa: F811
    pair(admin)
    pair(admin, "lab_account", username="lab-user")
    saved = admin.put(
        f"{BASE}/instances/{CONNECTION}",
        json={
            "keys": [
                {
                    "name": "lab",
                    "secrets": {
                        "username": "{{ credentials.lab_account.username }}",
                        "password": "{{ credentials.lab_account.password }}",
                    },
                }
            ],
            "keyPolicy": {"mode": "each", "perMinute": 1},
        },
    )
    assert saved.status_code == 200, saved.text
    lab = saved.json()["keys"][1]
    assert lab["secrets"] == {"username": True, "password": True}
    assert lab["credentials"]["username"] == {"name": "lab_account", "part": "username", "missing": False}
    assert PASSWORD not in saved.text
    # A key cannot name a credential that is not there, as the first cannot.
    wrong = admin.put(
        f"{BASE}/instances/{CONNECTION}",
        json={"keys": [{"name": "x", "secrets": {"username": "u", "password": "{{ credentials.none.password }}"}}]},
    )
    assert wrong.status_code == 400 and 'no credential called "none"' in wrong.json()["detail"]
    # A second instance of the same connector names the same credential as its only key.
    with SessionLocal() as db:
        other = Connection(
            id="d" * 32,
            name="Acme lab",
            connector_id="acme",
            config={"url": "https://desk.example.com/api"},
            created_at=now_iso(),
            updated_at=now_iso(),
        )
        ca.store_secrets(other, {"username": "svc", "password": "s3cret-pass"})
        db.add(other)
        db.commit()
    use_pair(admin, "lab_account", connection="d" * 32)
    assert [(use["name"], use["keyName"]) for use in listed(admin)["lab_account"]["usedBy"]] == [
        ("Acme lab", "Key 1"),
        ("Acme production", "lab"),
    ]
    acme.answer("desk.example.com", 200, {"state": "open"}, path="/api/tickets/T-1")
    pb = playbook(admin, "Keys", [], [])
    now = 1_800_000_000.0
    ask(pb, now)
    ask(pb, now + 1)
    assert [who(sent["headers"])[0] for sent in acme.requests] == ["svc", "lab-user"]  # one request each
    # Both keys of the first instance are at their limit for this minute; the second instance, which
    # names the same credential, has counted nothing and asks.
    assert ask(pb, now + 2).again_at is not None
    assert ask(pb, now + 3, connection="Acme lab").output == {"state": "open"}
    assert who(acme.requests[-1]["headers"]) == ("lab-user", PASSWORD)
    with SessionLocal() as db:
        counted = {
            (row.connection_id[0], row.key_id == "main"): row.total for row in db.scalars(select(InstanceKeyUse))
        }
    assert counted == {("c", True): 1, ("c", False): 1, ("d", True): 1}
    # "Test every key" reads the credentials too.
    acme.answer("desk.example.com", 200, {}, path="/api/me")
    tested = admin.post(f"{BASE}/instances/{CONNECTION}/keys/test").json()["keys"]
    assert [key["ok"] for key in tested] == [True, True]


# --------------------------------------------------------------------------- #
# Keep as a credential                                                        #
# --------------------------------------------------------------------------- #
def test_a_typed_secret_is_kept_as_a_credential_without_typing_it_again(admin: TestClient, acme):  # noqa: F811
    url = f"{BASE}/instances/{CONNECTION}/credentials"
    kept = admin.post(url, json={"field": "password", "name": "acme_account", "title": "Acme service account"})
    assert kept.status_code == 201, kept.text
    shown = kept.json()
    # A user name and a password the instance held together are one pair.
    assert shown["credentials"] == {
        "username": {"name": "acme_account", "part": "username", "missing": False},
        "password": {"name": "acme_account", "part": "password", "missing": False},
    }
    assert "s3cret-pass" not in kept.text
    made = listed(admin)["acme_account"]
    assert (made["kind"], made["username"], made["title"]) == ("pair", "svc", "Acme service account")
    assert [use["name"] for use in made["usedBy"]] == ["Acme production"]
    with SessionLocal() as db:
        row = db.get(Connection, CONNECTION)
        assert "s3cret-pass" not in json.dumps(ca.secrets_of(row))  # moved, not copied
        assert ca.usable_secrets(db, row) == {"username": "svc", "password": "s3cret-pass"}
    entry = admin.get("/api/audit", params={"q": "action:credential.create"}).json()["entries"][0]
    assert entry["details"] == (
        'Kept what the instance "Acme production" held as the credential "acme_account" '
        "(a user name and a password): the instance names it now"
    )
    # Not twice, not under a name that is taken, not what is not there.
    assert admin.post(url, json={"field": "password", "name": "again"}).json()["detail"] == (
        "This is a stored credential already"
    )
    assert admin.post(url, json={"field": "token", "name": "again"}).status_code == 400
    assert admin.post(url, json={"field": "password", "name": "again", "key": "gone"}).status_code == 404
    # A key beside the first, one part of it: a secret, and the other part stays typed.
    lab_key = {"username": "{{ credentials.acme_account.username }}", "password": "lab-pass-123456"}
    saved = admin.put(f"{BASE}/instances/{CONNECTION}", json={"keys": [{"name": "lab", "secrets": lab_key}]}).json()
    lab = saved["keys"][1]["id"]
    taken = admin.post(url, json={"key": lab, "field": "password", "name": "acme_account"})
    assert taken.status_code == 400 and "exists already" in taken.json()["detail"]
    with SessionLocal() as db:  # nothing was moved by the refusal
        assert instance_keys.keys_of(db.get(Connection, CONNECTION))[1].secrets["password"] == "lab-pass-123456"
    one = admin.post(url, json={"key": lab, "field": "password", "name": "lab_pass"})
    assert one.status_code == 201, one.text
    assert one.json()["keys"][1]["credentials"]["password"] == {"name": "lab_pass", "part": "", "missing": False}
    assert listed(admin)["lab_pass"]["kind"] == "secret"
    with SessionLocal() as db:
        row = db.get(Connection, CONNECTION)
        assert ca.usable_secrets(db, row, instance_keys.keys_of(row)[1]) == {
            "username": "svc",
            "password": "lab-pass-123456",
        }


# --------------------------------------------------------------------------- #
# Around                                                                      #
# --------------------------------------------------------------------------- #
def test_credentials_follow_a_change_of_the_secret_key_and_stay_when_a_connector_goes(
    admin: TestClient,
    acme,  # noqa: F811
    monkeypatch,
):
    made = pair(admin)
    use_pair(admin)
    admin.put(
        f"{BASE}/instances/{CONNECTION}",
        json={"keys": [{"name": "lab", "secrets": {"username": "lab", "password": "lab-pass-123456"}}]},
    )
    old = settings.SECRET_KEY
    monkeypatch.setattr(settings, "SECRET_KEY", "a-new-secret-key-for-the-test-0123456789")
    monkeypatch.setattr(settings, "SECRET_KEY_PREVIOUS", [old])
    assert vault.reencrypt(SessionLocal) >= 3  # the instance, its other key, the credential
    monkeypatch.setattr(settings, "SECRET_KEY_PREVIOUS", [])
    with SessionLocal() as db:
        row = db.get(Connection, CONNECTION)
        assert ca.usable_secrets(db, row) == {"username": "proxy-user", "password": PASSWORD}
        assert instance_keys.keys_of(row)[1].secrets["password"] == "lab-pass-123456"
    # A value nobody can read any more is said, by the name of the credential.
    with SessionLocal() as db:
        credentials.by_name(db, "proxy_account").secret = vault.encrypt("x")[:-8] + "AAAAAAAA"
        db.commit()
    assert listed(admin)["proxy_account"]["readable"] is False
    with SessionLocal() as db, pytest.raises(ca.CommandError) as raised:
        ca.usable_secrets(db, db.get(Connection, CONNECTION))
    assert raised.value.message == (
        'The credential "proxy_account" cannot be read since SECRET_KEY changed: '
        "type its value again in Settings, Credentials"
    )
    # Credentials are the server's: removing the connector takes its instances, never a credential.
    assert admin.delete(f"{BASE}/connectors/acme").status_code == 204
    left = listed(admin)["proxy_account"]
    assert left["usedBy"] == [] and left["id"] == made["id"]
    with SessionLocal() as db:
        assert db.scalars(select(Credential)).one().name == "proxy_account"


def test_a_look_up_goes_with_a_key_that_is_a_credential(admin: TestClient, outside):
    rated(outside)
    make(admin, "rated_key", value="rated-key-from-the-store")
    saved = admin.put(f"{BASE}/instances/{'r' * 32}", json={"secrets": {"value": "{{ credentials.rated_key }}"}})
    assert saved.status_code == 200, saved.text
    outside.answer("rated.example.com", json={"verdict": "harmless", "line": "nothing"})
    found = check(admin, "ip", "185.220.102.1")
    assert by_source(found)["rated"]["status"] == "done"
    assert outside.requests[-1]["headers"]["X-Key"] == "rated-key-from-the-store"
    assert "rated-key-from-the-store" not in json.dumps(found)
    # A key kept before 6.5 that an instance has already, through a credential, needs no second home.
    with SessionLocal() as db:
        old_key(db, "virustotal", "vt-old-key-0001")
        db.commit()
    with SessionLocal() as db:
        from tests import vendor

        vendor.install_pack(db, "virustotal")
        db.commit()
    with SessionLocal() as db:
        made = db.scalars(select(Connection).where(Connection.connector_id == "virustotal")).one()
        field = old_keys.key_field(ca.parsed(made.connector_id and db.get(ca.Connector, "virustotal")))
        assert old_keys._holds(db, made, field, "vt-old-key-0001")
        db.add(
            Credential(
                id="k" * 32,
                name="vt_old",
                kind="secret",
                secret=vault.encrypt("vt-other-key-0002"),
                created_at=now_iso(),
                updated_at=now_iso(),
            )
        )
        ca.store_secrets(made, {field: "{{ credentials.vt_old }}"})
        db.commit()
        assert not old_keys._holds(db, made, field, "vt-old-key-0001")
        assert old_keys._holds(db, made, field, "vt-other-key-0002")
        assert db.query(IntegrationKey).count() == 0  # moved when the pack was installed

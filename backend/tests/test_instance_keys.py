"""Several keys for one instance: how they take turns, what happens when one is used up, the answers kept."""

from __future__ import annotations

import base64
import json

import pytest
from fastapi.testclient import TestClient

from app.automation import actions, instance_keys
from app.automation import connector_actions as ca
from app.core.db import SessionLocal
from app.core.models import CommandAnswer, Connection, InstanceKeyUse, Playbook
from tests.test_automation_engine import playbook
from tests.test_connector_actions import acme  # noqa: F401 - a fixture

BASE = "/api/automation"
CONNECTION = "c" * 32
NOW = 1_800_000_000.0  # a moment at the start of a minute, far from midnight UTC


def who(headers: dict) -> str:
    """The user a request signed in as (the connector of the tests sends basic credentials)."""
    return base64.b64decode(headers["Authorization"].split()[1]).decode().split(":")[0]


@pytest.fixture()
def desk(admin: TestClient, acme):  # noqa: F811
    """The instance of the tests with three keys, and a desk that says who asked."""
    saved = admin.put(
        f"{BASE}/instances/{CONNECTION}",
        json={
            "mainName": "personal",
            "keys": [
                {"name": "lab", "secrets": {"username": "lab", "password": "lab-secret-1"}},
                {"name": "spare", "secrets": {"username": "spare", "password": "spare-secret-1"}},
            ],
        },
    )
    assert saved.status_code == 200, saved.text
    acme.refuse: set[str] = set()
    acme.asked: list[str] = []

    def reply(method, host, path, headers, _body):
        if host != "desk.example.com" or not path.startswith("/api/tickets/"):
            return None
        user = who(headers)
        acme.asked.append(user)
        if user in acme.refuse:
            return 429, {"content-type": "application/json"}, b'{"error": "quota exceeded"}'
        return 200, {"content-type": "application/json"}, json.dumps({"state": "open", "by": user}).encode()

    acme.answers.append(reply)
    acme.playbook = playbook(admin, "Keys", [], [])
    return acme


def ask(desk, number: str = "T-1", at: float = NOW, **more) -> actions.Result:
    with SessionLocal() as db:
        call = actions.Call(
            db=db,
            args={"number": number},
            classes=frozenset(),
            arg_classes={},
            dry_run=False,
            run=None,
            playbook=db.get(Playbook, desk.playbook),
            now=at,
            connection="Acme production",
            **more,
        )
        result = ca.run_command("acme", "get-ticket", call)
        db.commit()
        return result


def policy(admin: TestClient, **changes) -> dict:
    saved = admin.put(f"{BASE}/instances/{CONNECTION}", json={"keyPolicy": changes})
    assert saved.status_code == 200, saved.text
    return saved.json()


def test_the_keys_of_an_instance_are_listed_and_never_shown(admin: TestClient, desk):
    shown = admin.get(f"{BASE}/instances").json()["instances"][0]
    assert [(key["id"] == "main", key["name"]) for key in shown["keys"]] == [
        (True, "personal"), (False, "lab"), (False, "spare")
    ]  # fmt: skip
    assert all(key["secrets"] == {"username": True, "password": True} for key in shown["keys"])
    assert "lab-secret-1" not in json.dumps(shown)
    assert shown["keyPolicy"] == {"mode": "each", "perMinute": 0, "perDay": 0, "whenExhausted": "wait", "cacheHours": 0}
    with SessionLocal() as db:
        row = db.get(Connection, CONNECTION)
        assert "lab-secret-1" not in row.extra_keys  # encrypted, like the first
        assert [key.secrets["username"] for key in instance_keys.keys_of(row)] == ["svc", "lab", "spare"]
    lab = shown["keys"][1]["id"]
    # A key keeps what it is not given; one that is left out is removed, with what was counted for it.
    assert ask(desk).output["state"] == "open"
    kept = admin.put(f"{BASE}/instances/{CONNECTION}", json={"keys": [{"id": lab, "name": "lab account"}]}).json()
    assert [key["name"] for key in kept["keys"]] == ["personal", "lab account"]
    with SessionLocal() as db:
        assert [key.secrets.get("password") for key in instance_keys.keys_of(db.get(Connection, CONNECTION))][1] == (
            "lab-secret-1"
        )
    for wrong in (
        {"keys": [{"name": "new"}]},  # a new key needs its credentials
        {"keys": [{"name": "personal", "secrets": {"username": "a", "password": "b"}}]},  # the name of the first
        {"keys": [{"id": "gone", "name": "x"}]},
        {"keys": [{"name": "x", "secrets": {"token": "t"}}]},  # not a credential of this connector
        {"keyPolicy": {"mode": "sometimes"}},
        {"keyPolicy": {"perMinute": -1}},
    ):
        assert admin.put(f"{BASE}/instances/{CONNECTION}", json=wrong).status_code == 400, wrong


def test_one_request_each_goes_round_the_keys(admin: TestClient, desk):
    policy(admin, mode="each")
    for index in range(6):
        ask(desk, at=NOW + index)
    assert desk.asked == ["svc", "lab", "spare", "svc", "lab", "spare"]
    shown = admin.get(f"{BASE}/instances").json()["instances"][0]["keys"]
    assert [key["total"] for key in shown] == [2, 2, 2]


def test_the_same_key_until_it_is_used_up_then_the_next(admin: TestClient, desk):
    policy(admin, mode="until_exhausted", perMinute=2)
    for index in range(5):
        ask(desk, at=NOW + index)
    assert desk.asked == ["svc", "svc", "lab", "lab", "spare"]
    # The next minute the key in use stays in use: the first does not take over again.
    ask(desk, at=NOW + 61)
    assert desk.asked[-1] == "spare"
    # "The first key only, the others in reserve" goes back to the first as soon as it can be used.
    policy(admin, mode="reserve", perMinute=2)
    ask(desk, at=NOW + 125)
    assert desk.asked[-1] == "svc"


def test_the_key_used_least_today_is_the_one_that_goes(admin: TestClient, desk):
    policy(admin, mode="least_used")
    with SessionLocal() as db:
        row = db.get(Connection, CONNECTION)
        keys = instance_keys.keys_of(row)
        for count, key in zip((5, 1, 3), keys, strict=True):
            for _ in range(count):
                instance_keys.used(db, row, key.id, NOW)
        db.commit()
    for index in range(3):
        ask(desk, at=NOW + index)
    assert desk.asked == ["lab", "lab", "spare"]  # 1 → 2 → 3, then the one at 3 that waited longest


def test_a_key_the_vendor_refuses_is_left_alone_and_the_next_is_tried(admin: TestClient, desk):
    policy(admin, mode="reserve")
    desk.refuse = {"svc"}
    result = ask(desk)
    assert result.output["state"] == "open" and desk.asked == ["svc", "lab"]
    assert result.request["key"] == "lab"
    # The first key is not asked again for a while, whatever the mode.
    ask(desk, at=NOW + 30)
    assert desk.asked[-1] == "lab"
    shown = admin.get(f"{BASE}/instances").json()["instances"][0]["keys"]
    assert shown[0]["total"] == 1  # what the vendor refused was a request all the same
    with SessionLocal() as db:
        assert db.get(InstanceKeyUse, (CONNECTION, "main")).exhausted_until == NOW + instance_keys.REFUSED_SECONDS
    ask(desk, at=NOW + instance_keys.REFUSED_SECONDS + 1)
    assert desk.asked[-2:] == ["svc", "lab"]  # tried again when the time is up, refused again, and the next goes

    # Every key refused: the failure is the vendor's answer, said once.
    desk.refuse = {"svc", "lab", "spare"}
    with pytest.raises(actions.ActionError) as failed:
        ask(desk, at=NOW + 4000)
    assert "429" in failed.value.message


def test_when_every_key_is_used_up_the_command_waits_or_fails(admin: TestClient, desk):
    policy(admin, mode="each", perMinute=1, whenExhausted="wait")
    for index in range(3):
        ask(desk, at=NOW + index)
    waiting = ask(desk, at=NOW + 10)
    assert waiting.output is None and waiting.again_at == NOW + 60  # the start of the next minute
    assert waiting.request["waiting"] == "keys" and len(desk.asked) == 3
    assert ask(desk, at=NOW + 60).output["state"] == "open"

    policy(admin, perMinute=0, perDay=1, whenExhausted="fail")
    with pytest.raises(actions.ActionError) as failed:
        ask(desk, at=NOW + 120)
    assert "Every key" in failed.value.message and failed.value.retry is False
    # A new day is a new count.
    assert ask(desk, at=NOW + 86_400 * 2).output["state"] == "open"


def test_an_answer_is_kept_for_the_hours_the_instance_says(admin: TestClient, desk):
    policy(admin, cacheHours=2)
    first = ask(desk, "T-7")
    again = ask(desk, "T-7", at=NOW + 3600)
    assert again.output == first.output and again.request["kept"] is True and len(desk.asked) == 1
    assert len(ask(desk, "T-8", at=NOW + 3600).output) and len(desk.asked) == 2  # other arguments, another answer
    ask(desk, "T-7", at=NOW + 2 * 3600 + 1)
    assert len(desk.asked) == 3  # too old: asked again
    # Forgetting them asks again; turning the keeping off forgets them.
    assert admin.delete(f"{BASE}/instances/{CONNECTION}/answers").json()["forgotten"] == 2
    ask(desk, "T-7", at=NOW + 2 * 3600 + 2)
    assert len(desk.asked) == 4
    policy(admin, cacheHours=0)
    with SessionLocal() as db:
        assert db.query(CommandAnswer).count() == 0
    ask(desk, "T-7", at=NOW + 2 * 3600 + 3)
    assert len(desk.asked) == 5


def test_a_command_that_changes_something_is_never_answered_from_what_was_kept(admin: TestClient, desk):
    policy(admin, cacheHours=24)
    desk.answer("desk.example.com", status=201, json={"number": "T-9"}, path="/api/tickets")
    with SessionLocal() as db:
        for _ in range(2):
            call = actions.Call(
                db=db, args={"title": "Printer", "urgency": "2"}, classes=frozenset(), arg_classes={}, dry_run=False,
                run=None, playbook=db.get(Playbook, desk.playbook), now=NOW, connection="Acme production",
            )  # fmt: skip
            assert ca.run_command("acme", "create-ticket", call).output == {"number": "T-9"}
        db.commit()
        assert db.query(CommandAnswer).count() == 0
    assert len([sent for sent in desk.requests if sent["method"] == "POST"]) == 2


def test_each_key_is_tested_on_its_own(admin: TestClient, desk):
    def me(method, host, path, headers, _body):
        if host != "desk.example.com" or path != "/api/me":
            return None
        return (401 if who(headers) == "lab" else 200), {"content-type": "application/json"}, b"{}"

    desk.answers.append(me)
    found = admin.post(f"{BASE}/instances/{CONNECTION}/keys/test").json()["keys"]
    assert [(key["name"], key["ok"]) for key in found] == [("personal", True), ("lab", False), ("spare", True)]
    with SessionLocal() as db:
        assert db.query(InstanceKeyUse).count() == 0  # a test counts against no key

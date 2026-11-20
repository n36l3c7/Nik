"""Signing in: the second factor, the waits after failures, the sessions, the administrators' networks.

The clock is the test's: nothing here sleeps. ``clock`` replaces the time
every decision of ``core/security.py`` and ``app/signin.py`` reads.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient

from app import account, signin
from app.core import client_address, security, signin_policy, totp, vault
from app.core.config import settings
from app.core.db import SessionLocal
from app.core.models import RecoveryCode, SigninAttempt, SigninTicket, UserFactor
from app.core.models import Session as SessionModel
from app.main import app as fastapi_app
from tests.conftest import ADMIN, make_key

RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # "12345678901234567890", the seed of RFC 6238 for SHA-1
OFFICE = "203.0.113.7"
ELSEWHERE = "198.51.100.23"
PROXY = "10.20.0.2"


class Clock:
    def __init__(self) -> None:
        self.now = datetime.now(timezone.utc)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **how_long) -> None:
        self.now += timedelta(**how_long)


@pytest.fixture()
def clock(monkeypatch) -> Clock:
    made = Clock()
    monkeypatch.setattr(security, "utcnow", made)
    return made


@pytest.fixture(autouse=True)
def no_rate_limit():
    """The blanket limit per address is another test's subject; here the waits are counted."""
    fastapi_app.state.limiter.enabled = False
    client_address.forget()
    yield
    fastapi_app.state.limiter.enabled = True


def holding(name: str, value: str) -> dict:
    """The header of a request that carries this cookie, whatever the browser's own jar holds."""
    return {"Cookie": f"{name}={value}"}


def browser(address: str | None = None, **headers) -> TestClient:
    """A browser of its own, connecting from ``address`` when one is given."""
    client = TestClient(fastapi_app, client=(address, 50000)) if address else TestClient(fastapi_app)
    client.headers.update(headers)
    return client


def make_user(admin: TestClient, username: str = "anna", roles: tuple[str, ...] = ("analyst",)) -> dict:
    res = admin.post("/api/users", json={"username": username, "password": "password1", "roles": list(roles)})
    assert res.status_code == 201, res.text
    return res.json()["user"]


def sign_in(client: TestClient, username: str = "anna", password: str = "password1"):
    return client.post("/api/auth/login", json={"username": username, "password": password})


def signed_in(username: str = "anna", password: str = "password1", address: str | None = None) -> TestClient:
    client = browser(address)
    res = sign_in(client, username, password)
    assert res.status_code == 200 and "user" in res.json(), res.text
    return client


def code_now(secret: str, clock: Clock | None = None, shift: int = 0) -> str:
    at = (clock.now if clock else security.utcnow()).timestamp()
    return totp.code_at(secret, totp.step_at(at) + shift)


def enrol(client: TestClient, clock: Clock | None = None) -> tuple[str, list[str]]:
    """Turn a second factor on for the signed-in client: its secret and its recovery codes."""
    started = client.post("/api/auth/second-factor/totp")
    assert started.status_code == 200, started.text
    secret = started.json()["secret"]
    done = client.post("/api/auth/second-factor/totp/confirm", json={"code": code_now(secret, clock)})
    assert done.status_code == 200, done.text
    return secret, done.json()["recoveryCodes"]


def set_policy(admin: TestClient, **values):
    res = admin.put("/api/auth/policy", json=values)
    assert res.status_code == 200, res.text
    return res.json()


def actions(admin: TestClient) -> list[str]:
    return [entry["action"] for entry in admin.get("/api/audit").json()["entries"]]


def details(admin: TestClient, action: str) -> list[str]:
    return [entry["details"] for entry in admin.get("/api/audit").json()["entries"] if entry["action"] == action]


# --------------------------------------------------------------------------- #
# TOTP                                                                        #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("at", "expected"),
    [
        (59, "94287082"),
        (1111111109, "07081804"),
        (1111111111, "14050471"),
        (1234567890, "89005924"),
        (2000000000, "69279037"),
        (20000000000, "65353130"),
    ],
)
def test_totp_gives_the_codes_of_rfc_6238(at: int, expected: str):
    assert totp.code_at(RFC_SECRET, totp.step_at(at), digits=8) == expected
    # Six digits are the last six of the same number.
    assert totp.code_at(RFC_SECRET, totp.step_at(at)) == expected[2:]


def test_totp_sha256_and_sha512_follow_the_rfc_too():
    import base64

    sha256 = base64.b32encode(b"12345678901234567890123456789012").decode()
    assert totp.code_at(sha256, totp.step_at(59), digits=8, algorithm="sha256") == "46119246"
    assert totp.code_at(sha256, totp.step_at(1111111109), digits=8, algorithm="sha256") == "68084774"
    sha512 = base64.b32encode(b"1234567890123456789012345678901234567890123456789012345678901234").decode()
    assert totp.code_at(sha512, totp.step_at(59), digits=8, algorithm="sha512") == "90693936"
    assert totp.code_at(sha512, totp.step_at(1111111109), digits=8, algorithm="sha512") == "25091201"


def test_totp_accepts_one_step_either_way_and_no_code_twice():
    at = 1_700_000_015.0
    step = totp.step_at(at)
    for shift in (-1, 0, 1):
        assert totp.verify(RFC_SECRET, totp.code_at(RFC_SECRET, step + shift), at) == step + shift
    for shift in (-3, -2, 2, 3):
        assert totp.verify(RFC_SECRET, totp.code_at(RFC_SECRET, step + shift), at) is None
    current = totp.code_at(RFC_SECRET, step)
    # The step that was accepted, and every older one, is over.
    assert totp.verify(RFC_SECRET, current, at, after=step) is None
    assert totp.verify(RFC_SECRET, totp.code_at(RFC_SECRET, step - 1), at, after=step) is None
    assert totp.verify(RFC_SECRET, totp.code_at(RFC_SECRET, step + 1), at, after=step) == step + 1
    assert totp.verify(RFC_SECRET, current, at, after=step - 1) == step


@pytest.mark.parametrize("typed", ["", "12345", "1234567", "abcdef", "１２３４５６", None, "12 34", "000000\x00"])
def test_totp_refuses_what_is_not_a_code(typed):
    assert totp.verify(RFC_SECRET, typed, 1_700_000_000.0) is None


def test_totp_reads_a_code_typed_with_spaces_and_makes_a_secret_an_app_takes():
    at = 1_700_000_000.0
    code = totp.code_at(RFC_SECRET, totp.step_at(at))
    assert totp.verify(RFC_SECRET, f" {code[:3]} {code[3:]} ", at) == totp.step_at(at)
    secret = totp.new_secret()
    assert len(secret) == 32 and secret.isalnum() and secret != totp.new_secret()
    assert totp.verify(secret, totp.code_at(secret, 5), 5 * 30) == 5
    address = totp.uri(secret, "anna b")
    assert address.startswith("otpauth://totp/Nik%3Aanna%20b?secret=" + secret) and "issuer=Nik" in address


# --------------------------------------------------------------------------- #
# Enrolment and the two steps of a sign-in                                    #
# --------------------------------------------------------------------------- #
def test_nothing_changes_for_an_account_without_a_second_factor(admin: TestClient):
    make_user(admin)
    res = sign_in(browser())
    body = res.json()
    assert res.status_code == 200 and set(body) == {"user", "session"}
    assert body["user"]["secondFactor"] is False and body["user"]["secondFactorRequired"] is False
    assert "nik_session" in res.cookies and "nik_signin" not in res.cookies


def test_a_factor_counts_only_once_a_code_confirmed_it(admin: TestClient, clock: Clock):
    make_user(admin)
    anna = signed_in()
    started = anna.post("/api/auth/second-factor/totp").json()
    assert started["uri"].startswith("otpauth://totp/Nik%3Aanna?secret=" + started["secret"])
    # Not confirmed: the account still signs in with its password alone, and nothing says a factor is there.
    assert anna.get("/api/auth/second-factor").json()["factors"] == []
    assert set(sign_in(browser()).json()) == {"user", "session"}
    wrong = anna.post("/api/auth/second-factor/totp/confirm", json={"code": "000000"})
    assert wrong.status_code == 400 and "not right" in wrong.json()["detail"]
    # Starting again replaces the secret: a code of the first one is no longer taken.
    again = anna.post("/api/auth/second-factor/totp").json()
    assert again["secret"] != started["secret"]
    old = anna.post("/api/auth/second-factor/totp/confirm", json={"code": code_now(started["secret"], clock)})
    assert old.status_code == 400
    done = anna.post("/api/auth/second-factor/totp/confirm", json={"code": code_now(again["secret"], clock)})
    assert done.status_code == 200
    state = done.json()
    assert [factor["kind"] for factor in state["factors"]] == ["totp"] and state["recoveryCodesLeft"] == 10
    assert len(state["recoveryCodes"]) == 10 and len(set(state["recoveryCodes"])) == 10
    # The secret is encrypted where it is kept, and no route gives it again.
    with SessionLocal() as db:
        row = db.scalar(sa.select(UserFactor))
        assert again["secret"] not in row.secret and vault.decrypt(row.secret) == again["secret"]
        hashes = [code.code_hash for code in db.scalars(sa.select(RecoveryCode))]
    assert all("$2b$" in stored for stored in hashes)
    assert not any(code.replace("-", "") in stored for code in state["recoveryCodes"] for stored in hashes)
    shown = anna.get("/api/auth/second-factor").json()
    assert "secret" not in str(shown) and "recoveryCodes" not in shown
    assert anna.post("/api/auth/second-factor/totp").status_code == 409
    assert anna.get("/api/auth/me").json()["user"]["secondFactor"] is True
    assert "auth.factor.on" in actions(admin)


def test_the_right_password_alone_gives_a_ticket_and_nothing_else(admin: TestClient, clock: Clock):
    make_user(admin)
    secret, _codes = enrol(signed_in(), clock)
    clock.advance(seconds=60)
    client = browser()
    first = sign_in(client)
    assert first.status_code == 200
    assert first.json() == {"secondFactor": {"kinds": ["totp"], "recoveryCodes": True, "seconds": 300}}
    assert "nik_session" not in first.cookies
    cookie = first.headers["set-cookie"].lower()
    assert (
        "nik_signin=" in cookie and "httponly" in cookie and "samesite=strict" in cookie and "path=/api/auth" in cookie
    )
    # No session: nothing answers.
    assert client.get("/api/auth/me").status_code == 401
    assert client.get("/api/incidents").status_code == 401
    assert client.get("/api/auth/second-factor").status_code == 401
    # The ticket is not a session, whatever cookie carries it.
    ticket = client.cookies.get("nik_signin")
    assert browser().get("/api/auth/me", headers=holding("nik_session", ticket)).status_code == 401
    # Without the ticket the second step is nobody's.
    assert browser().post("/api/auth/login/code", json={"code": code_now(secret, clock)}).status_code == 401

    done = client.post("/api/auth/login/code", json={"code": code_now(secret, clock)})
    assert done.status_code == 200 and done.json()["user"]["username"] == "anna"
    assert done.json()["user"]["secondFactor"] is True
    assert client.get("/api/auth/me").status_code == 200
    # The ticket is spent with the sign-in.
    with SessionLocal() as db:
        assert db.scalar(sa.select(sa.func.count()).select_from(SigninTicket)) == 0
    assert "Signed in with a second-factor code" in details(admin, "auth.login")


def test_a_ticket_runs_out_and_a_sign_out_ends_it(admin: TestClient, clock: Clock):
    make_user(admin)
    secret, _codes = enrol(signed_in(), clock)
    clock.advance(seconds=60)
    late = browser()
    sign_in(late)
    clock.advance(seconds=301)
    res = late.post("/api/auth/login/code", json={"code": code_now(secret, clock)})
    assert res.status_code == 401 and "sign in again" in res.json()["detail"]
    left = browser()
    sign_in(left)
    ticket = left.cookies.get("nik_signin")
    assert left.post("/api/auth/logout").status_code == 204
    again = browser().post(
        "/api/auth/login/code", json={"code": code_now(secret, clock)}, headers=holding("nik_signin", ticket)
    )
    assert again.status_code == 401


def test_a_code_is_taken_once_and_a_wrong_one_is_refused(admin: TestClient, clock: Clock):
    make_user(admin)
    secret, _codes = enrol(signed_in(), clock)
    # The code that confirmed the enrolment is spent: a sign-in in the same half minute needs the next.
    client = browser()
    sign_in(client)
    replay = client.post("/api/auth/login/code", json={"code": code_now(secret, clock)})
    assert replay.status_code == 401 and "used already" in replay.json()["detail"]
    clock.advance(seconds=30)
    assert client.post("/api/auth/login/code", json={"code": "12"}).status_code == 401
    good = code_now(secret, clock)
    assert client.post("/api/auth/login/code", json={"code": good}).status_code == 200
    # The same code again, from another browser that knows the password, within its window.
    other = browser()
    sign_in(other)
    assert other.post("/api/auth/login/code", json={"code": good}).status_code == 401
    # One step of tolerance: the code of the next half minute is taken, the one after is not.
    assert other.post("/api/auth/login/code", json={"code": code_now(secret, clock, shift=2)}).status_code == 401
    assert other.post("/api/auth/login/code", json={"code": code_now(secret, clock, shift=1)}).status_code == 200
    assert "auth.code.failed" in actions(admin)


def test_a_recovery_code_signs_in_once_and_says_how_many_are_left(admin: TestClient, clock: Clock):
    make_user(admin)
    _secret, codes = enrol(signed_in(), clock)
    client = browser()
    sign_in(client)
    assert client.post("/api/auth/login/code", json={"recoveryCode": "aaaa-bbbb-cccc-dddd"}).status_code == 401
    assert client.post("/api/auth/login/code", json={"recoveryCode": codes[0][:-1] + "x"}).status_code == 401
    # Typed in capitals and without the dashes: it is the same code.
    done = client.post("/api/auth/login/code", json={"recoveryCode": codes[0].replace("-", "").upper()})
    assert done.status_code == 200 and done.json()["recoveryCodesLeft"] == 9
    again = browser()
    sign_in(again)
    spent = again.post("/api/auth/login/code", json={"recoveryCode": codes[0]})
    assert spent.status_code == 401 and "used already" in spent.json()["detail"]
    assert again.post("/api/auth/login/code", json={"recoveryCode": codes[1]}).json()["recoveryCodesLeft"] == 8
    assert "Used a recovery code to sign in (9 left)" in details(admin, "auth.recovery.used")
    assert "Signed in with a recovery code, after 2 failed attempts" in details(admin, "auth.login")


def test_new_recovery_codes_end_the_old_ones_and_ask_who_it_is(admin: TestClient, clock: Clock):
    make_user(admin)
    anna = signed_in()
    secret, codes = enrol(anna, clock)
    url = "/api/auth/second-factor/recovery-codes"
    clock.advance(seconds=30)
    assert anna.post(url, json={"password": "nope", "code": code_now(secret, clock)}).status_code == 400
    assert anna.post(url, json={"password": "password1"}).status_code == 400
    assert anna.post(url, json={"password": "password1", "code": "000000"}).status_code == 400
    made = anna.post(url, json={"password": "password1", "code": code_now(secret, clock)})
    assert made.status_code == 200 and len(made.json()["recoveryCodes"]) == 10
    fresh = made.json()["recoveryCodes"]
    assert not set(fresh) & set(codes)
    client = browser()
    sign_in(client)
    assert client.post("/api/auth/login/code", json={"recoveryCode": codes[3]}).status_code == 401
    assert client.post("/api/auth/login/code", json={"recoveryCode": fresh[3]}).status_code == 200
    assert "auth.recovery.new" in actions(admin)


def test_turning_it_off_asks_the_password_and_a_code_and_ends_the_other_sessions(admin: TestClient, clock: Clock):
    make_user(admin)
    anna = signed_in()
    secret, codes = enrol(anna, clock)
    clock.advance(seconds=30)
    elsewhere = browser()
    sign_in(elsewhere)
    assert elsewhere.post("/api/auth/login/code", json={"code": code_now(secret, clock)}).status_code == 200
    clock.advance(seconds=30)
    url = "/api/auth/second-factor/off"
    assert anna.post(url, json={"password": "password1"}).status_code == 400
    assert anna.post(url, json={"password": "wrong", "code": code_now(secret, clock)}).status_code == 400
    # A recovery code stands in for the code here too, and is spent.
    off = anna.post(url, json={"password": "password1", "recoveryCode": codes[0]})
    assert off.status_code == 200 and off.json()["factors"] == [] and off.json()["recoveryCodesLeft"] == 0
    assert anna.get("/api/auth/me").json()["user"]["secondFactor"] is False
    assert elsewhere.get("/api/auth/me").status_code == 401
    with SessionLocal() as db:
        assert db.scalar(sa.select(sa.func.count()).select_from(RecoveryCode)) == 0
    assert set(sign_in(browser()).json()) == {"user", "session"}
    assert anna.post(url, json={"password": "password1"}).status_code == 409
    assert "auth.factor.off" in actions(admin)


def test_changing_the_password_asks_for_a_code_when_there_is_a_factor(admin: TestClient, clock: Clock):
    make_user(admin)
    anna = signed_in()
    secret, _codes = enrol(anna, clock)
    clock.advance(seconds=30)
    url = "/api/users/me/password"
    change = {"currentPassword": "password1", "newPassword": "a-new-secret"}
    assert anna.put(url, json=change).status_code == 400
    assert anna.put(url, json={**change, "code": "111111"}).status_code == 400
    # A password that would be refused spends no code.
    code = code_now(secret, clock)
    assert anna.put(url, json={**change, "newPassword": "short", "code": code}).status_code == 400
    assert anna.put(url, json={**change, "code": code}).status_code == 204
    assert sign_in(browser(), password="password1").status_code == 401
    assert sign_in(browser(), password="a-new-secret").json().get("secondFactor")


def test_wrong_values_when_asked_again_are_counted_like_failed_sign_ins(admin: TestClient, clock: Clock):
    make_user(admin)
    anna = signed_in()
    secret, _codes = enrol(anna, clock)
    url = "/api/auth/second-factor/off"
    for _ in range(5):
        clock.advance(seconds=30)
        assert anna.post(url, json={"password": "password1", "code": "000000"}).status_code == 400
    clock.advance(seconds=1)
    waits = anna.post(url, json={"password": "password1", "code": code_now(secret, clock)})
    assert waits.status_code == 429 and waits.headers["retry-after"] == "29"
    clock.advance(seconds=30)
    assert anna.post(url, json={"password": "password1", "code": code_now(secret, clock)}).status_code == 200


def test_changing_the_secret_key_keeps_the_second_factors(admin: TestClient, clock: Clock, monkeypatch):
    secret, _codes = enrol(admin, clock)
    old_key = settings.SECRET_KEY
    monkeypatch.setattr(settings, "SECRET_KEY", "a-new-secret-key-of-the-server-0123456789")
    # Without the old key the factor cannot be read: no code is right (the account is reset from the server).
    clock.advance(seconds=30)
    client = browser()
    assert sign_in(client, **ADMIN).json().get("secondFactor")
    assert client.post("/api/auth/login/code", json={"code": code_now(secret, clock)}).status_code == 401
    # With SECRET_KEY_PREVIOUS set for one start, it is read and written again under the new key.
    monkeypatch.setattr(settings, "SECRET_KEY_PREVIOUS", [old_key])
    assert vault.reencrypt(SessionLocal) == 1
    monkeypatch.setattr(settings, "SECRET_KEY_PREVIOUS", [])
    clock.advance(seconds=30)
    assert client.post("/api/auth/login/code", json={"code": code_now(secret, clock)}).status_code == 200


# --------------------------------------------------------------------------- #
# Required by role                                                            #
# --------------------------------------------------------------------------- #
def test_an_account_of_a_required_role_can_only_set_its_factor_up(admin: TestClient, clock: Clock):
    make_user(admin, "anna", ("analyst", "rules"))
    make_user(admin, "vera", ("viewer",))
    anna = signed_in("anna")
    assert anna.get("/api/incidents").status_code == 200
    key = make_key(admin, label="robot", roles=["analyst"])
    said = set_policy(admin, requiredRoles=["analyst"])
    assert said["policy"]["requiredRoles"] == ["analyst"] and said["mustEnrol"] is False

    # At once, on the session that was open: nothing but the enrolment answers.
    refused = anna.get("/api/incidents")
    assert refused.status_code == 403 and refused.json()["code"] == "second_factor_required"
    assert anna.post("/api/incidents", json={"id": "i1", "data": {}}).status_code == 403
    assert anna.put("/api/users/me/password", json={"currentPassword": "password1", "newPassword": "x" * 9}).json()[
        "code"
    ] == ("second_factor_required")
    assert anna.get("/api/auth/sessions").status_code == 403
    me = anna.get("/api/auth/me").json()["user"]
    assert me["secondFactorRequired"] is True and me["secondFactor"] is False
    assert anna.get("/api/auth/session").status_code == 200
    assert anna.get("/api/auth/second-factor").json()["required"] is True
    # A new sign-in is let in, to the same place.
    fresh = signed_in("anna")
    assert fresh.get("/api/incidents").json()["code"] == "second_factor_required"
    # Other roles and API keys are not concerned.
    assert signed_in("vera").get("/api/incidents").status_code == 200
    assert TestClient(fastapi_app).get("/api/incidents", headers=key).status_code == 200

    secret, _codes = enrol(anna, clock)
    assert anna.get("/api/incidents").status_code == 200
    # Turning it off is allowed, and leads straight back to setting one up.
    clock.advance(seconds=30)
    off = anna.post("/api/auth/second-factor/off", json={"password": "password1", "code": code_now(secret, clock)})
    assert off.status_code == 200
    assert anna.get("/api/incidents").json()["code"] == "second_factor_required"
    assert "auth.policy" in actions(admin)
    assert "requiredRoles: none → analyst" in details(admin, "auth.policy")[0]


def test_every_route_but_the_enrolment_refuses_an_account_that_must_enrol(admin: TestClient):
    from tests.test_permissions_matrix import EXPECTED, _url

    # Anna may do everything, so nothing else than the missing factor can be what refuses her.
    make_user(admin, "anna", ("analyst", "admin"))
    anna = signed_in("anna")
    set_policy(admin, requiredRoles=["analyst"])
    assert admin.get("/api/incidents").status_code == 200
    wrong = []
    for (method, path), expected in EXPECTED.items():
        if expected in ("public", "first-run"):
            continue
        res = anna.request(method, _url(path), json={} if method in ("POST", "PUT", "PATCH") else None)
        allowed = (method, path) in security.ENROLMENT_ROUTES
        refused = res.status_code == 403 and res.json().get("code") == "second_factor_required"
        if allowed == refused:
            wrong.append((method, path, res.status_code))
    assert not wrong, wrong


def test_requiring_it_for_admins_starts_the_enrolment_of_the_admin_who_asked(admin: TestClient, clock: Clock):
    said = set_policy(admin, requiredRoles=["admin"])
    assert said["mustEnrol"] is True
    assert admin.get("/api/users").json()["code"] == "second_factor_required"
    # Not locked out: the enrolment answers, and then everything does.
    enrol(admin, clock)
    assert admin.get("/api/users").status_code == 200
    users = admin.get("/api/users").json()["users"]
    assert users[0]["secondFactor"] is True and users[0]["secondFactorRequired"] is True


def test_the_accounts_list_says_who_has_a_factor_and_who_must(admin: TestClient, clock: Clock):
    make_user(admin, "anna")
    make_user(admin, "vera", ("viewer",))
    enrol(signed_in("vera"), clock)
    set_policy(admin, requiredRoles=["analyst"])
    shown = {
        user["username"]: (user["secondFactor"], user["secondFactorRequired"])
        for user in admin.get("/api/users").json()["users"]
    }
    assert shown == {"admin": (False, False), "anna": (False, True), "vera": (True, False)}


# --------------------------------------------------------------------------- #
# Reset by an administrator, and from the server                              #
# --------------------------------------------------------------------------- #
def test_an_admin_resets_the_factor_of_somebody_else_never_their_own_never_with_a_key(admin: TestClient, clock: Clock):
    anna_account = make_user(admin)
    anna = signed_in()
    secret, codes = enrol(anna, clock)
    url = f"/api/users/{anna_account['id']}/second-factor/reset"
    key = make_key(admin, label="adm", roles=["admin"])
    assert TestClient(fastapi_app).post(url, headers=key).status_code == 401
    make_user(admin, "vera", ("viewer",))
    assert signed_in("vera").post(url).status_code == 403
    admin_id = admin.get("/api/auth/me").json()["user"]["id"]
    enrol(admin, clock)
    own = admin.post(f"/api/users/{admin_id}/second-factor/reset")
    assert own.status_code == 400 and "recovery code" in own.json()["detail"]

    done = admin.post(url)
    assert done.status_code == 200 and done.json()["user"]["secondFactor"] is False
    assert admin.post(url).status_code == 409
    # The sessions of the account are over, its codes too; it signs in with the password and is told, once.
    assert anna.get("/api/auth/me").status_code == 401
    back = sign_in(browser())
    assert back.status_code == 200 and back.json()["notice"] == "second_factor_reset"
    assert "notice" not in sign_in(browser()).json()
    with SessionLocal() as db:
        assert (
            db.scalar(
                sa.select(sa.func.count()).select_from(RecoveryCode).where(RecoveryCode.user_id == anna_account["id"])
            )
            == 0
        )
    assert codes and secret
    entry = [e for e in admin.get("/api/audit").json()["entries"] if e["action"] == "auth.factor.reset"][0]
    assert entry["actor"] == "admin" and entry["target"] == "anna"


def test_the_server_console_resets_a_factor_and_clears_the_networks(admin: TestClient, clock: Clock, capsys):
    secret, _codes = enrol(admin, clock)
    set_policy(admin, requiredRoles=["admin"])
    assert account.main(["reset-second-factor", "nobody"]) == 1
    assert account.main(["what"]) == 2 and "reset-second-factor <username>" in capsys.readouterr().err
    assert account.main(["reset-second-factor", "ADMIN"]) == 0
    assert "is reset" in capsys.readouterr().out
    assert admin.get("/api/auth/me").status_code == 401
    back = sign_in(admin, **ADMIN)
    # The password alone signs in; the role still asks for a factor, so the account is led to set one up.
    assert back.status_code == 200 and back.json()["notice"] == "second_factor_reset"
    assert back.json()["user"]["secondFactorRequired"] is True and back.json()["user"]["secondFactor"] is False
    assert admin.get("/api/users").json()["code"] == "second_factor_required"
    enrol(admin, clock)
    assert account.main(["reset-second-factor", "admin"]) == 0
    assert account.main(["reset-second-factor", "admin"]) == 0 and "nothing to do" in capsys.readouterr().out
    assert secret

    with SessionLocal() as db:
        signin_policy.store(db, {**signin_policy.load(db), "adminNetworks": ["192.0.2.0/24"], "requiredRoles": []})
        db.commit()
    locked = browser(ELSEWHERE)
    assert sign_in(locked, **ADMIN).json()["code"] == "admin_network"
    assert account.main(["clear-admin-networks"]) == 0
    assert "192.0.2.0/24" in capsys.readouterr().out
    assert sign_in(locked, **ADMIN).status_code == 200
    assert account.main(["clear-admin-networks"]) == 0
    said = details(locked, "auth.policy")
    assert any("from the server" in line for line in said)
    assert any(entry["actor"] == "server console" for entry in locked.get("/api/audit").json()["entries"])


# --------------------------------------------------------------------------- #
# Sessions                                                                    #
# --------------------------------------------------------------------------- #
def test_a_session_ends_when_it_is_not_used_and_the_pages_own_requests_do_not_count(admin: TestClient, clock: Clock):
    make_user(admin)
    set_policy(admin, idleMinutes=30, idleMinutesAdmin=10)
    anna = signed_in()
    background = {"X-Nik-Background": "1"}
    # The page polls for an hour: every answer comes, until the half hour is over.
    for _ in range(5):
        clock.advance(minutes=5)
        assert anna.get("/api/notifications", headers=background).status_code == 200
    state = anna.get("/api/auth/session").json()
    assert state == {"idleSeconds": 1800, "idleLeft": 300, "lifetimeLeft": 12 * 3600 - 1500, "warnSeconds": 60}
    clock.advance(minutes=5, seconds=1)
    assert anna.get("/api/notifications", headers=background).status_code == 401
    assert anna.get("/api/auth/me").status_code == 401
    with SessionLocal() as db:  # a session that ended is removed, not kept
        assert db.scalar(sa.select(sa.func.count()).select_from(SessionModel)) == 1

    # The person working keeps it open: each request they cause counts.
    anna = signed_in()
    for _ in range(12):
        clock.advance(minutes=25)
        assert anna.get("/api/incidents").status_code == 200
    # Asking how long is left is not use either; saying "I am here" is.
    clock.advance(minutes=29)
    assert anna.get("/api/auth/session").json()["idleLeft"] == 60
    assert anna.post("/api/auth/session/stay").json()["idleLeft"] == 1800
    clock.advance(minutes=29)
    assert anna.get("/api/auth/session").json()["idleLeft"] == 60
    clock.advance(minutes=2)
    assert anna.get("/api/incidents").status_code == 401

    # Administrators have their own, shorter here.
    assert sign_in(admin, **ADMIN).status_code == 200
    clock.advance(minutes=9)
    assert admin.get("/api/users").status_code == 200
    clock.advance(minutes=11)
    assert admin.get("/api/users").status_code == 401


def test_a_session_ended_while_one_of_its_requests_is_under_way_is_no_error(admin: TestClient, clock: Clock):
    make_user(admin)
    anna = signed_in()
    token = anna.cookies.get("nik_session")
    with SessionLocal() as db:
        session = db.get(SessionModel, token)
        with SessionLocal() as other:  # somebody ends it meanwhile
            other.execute(sa.delete(SessionModel).where(SessionModel.token == token))
            other.commit()
        security.touch_session(db, session, last_used_at=security.utcnow().isoformat())
        assert session.last_used_at
    assert anna.get("/api/auth/me").status_code == 401


def test_a_session_ends_after_its_lifetime_however_much_it_is_used(admin: TestClient, clock: Clock):
    make_user(admin)
    anna = signed_in()
    for _ in range(23):
        clock.advance(minutes=31)
        assert anna.get("/api/incidents").status_code == 200  # 11 h 53 min of work
    clock.advance(minutes=8)
    assert anna.get("/api/incidents").status_code == 401
    # No idle limit at all: the lifetime is still there.
    again = sign_in(admin, **ADMIN)
    assert again.status_code == 200
    set_policy(admin, idleMinutes=0, idleMinutesAdmin=0, lifetimeHours=2)
    assert admin.get("/api/auth/session").json() == {
        "idleSeconds": 0,
        "idleLeft": None,
        "lifetimeLeft": 7200,
        "warnSeconds": 0,
    }
    clock.advance(minutes=119)
    assert admin.get("/api/users").status_code == 200
    clock.advance(minutes=2)
    assert admin.get("/api/users").status_code == 401


def test_a_shorter_lifetime_applies_to_the_sessions_that_are_open(admin: TestClient, clock: Clock):
    make_user(admin)
    anna = signed_in()
    clock.advance(hours=3)
    assert anna.get("/api/incidents").status_code == 200
    set_policy(admin, lifetimeHours=2)
    assert anna.get("/api/incidents").status_code == 401


def test_the_sessions_of_an_account_are_listed_and_ended(admin: TestClient, clock: Clock):
    make_user(admin)
    firefox = browser(
        OFFICE, **{"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"}
    )
    assert sign_in(firefox).status_code == 200
    clock.advance(minutes=10)
    phone = browser(ELSEWHERE, **{"User-Agent": "Mozilla/5.0 (iPhone) Safari/605.1"})
    assert sign_in(phone).status_code == 200
    clock.advance(minutes=1)
    third = signed_in()
    clock.advance(minutes=1)

    # This one first, then the last used first.
    listed = firefox.get("/api/auth/sessions").json()["sessions"]
    assert [(row["address"], row["current"]) for row in listed] == [
        (OFFICE, True),
        ("testclient", False),
        (ELSEWHERE, False),
    ]
    assert "Firefox/140.0" in listed[0]["userAgent"] and listed[0]["createdAt"] < listed[2]["createdAt"]
    assert listed[0]["lastUsedAt"] > listed[1]["lastUsedAt"] > listed[2]["lastUsedAt"]
    # Nothing in the list is the cookie.
    tokens = {client.cookies.get("nik_session") for client in (firefox, phone, third)}
    assert not any(token in str(listed) for token in tokens) and all(len(row["id"]) == 16 for row in listed)

    # Ended at once: the next request of that session is refused.
    assert firefox.delete(f"/api/auth/sessions/{listed[2]['id']}").status_code == 204
    assert phone.get("/api/auth/me").status_code == 401
    assert firefox.delete(f"/api/auth/sessions/{listed[2]['id']}").status_code == 404
    assert third.get("/api/auth/me").status_code == 200
    # Nobody ends a session of another account this way.
    assert signed_in("admin", ADMIN["password"]).delete(f"/api/auth/sessions/{listed[1]['id']}").status_code == 404
    assert firefox.post("/api/auth/sessions/end-others").json() == {"ended": 1}
    assert third.get("/api/auth/me").status_code == 401
    assert firefox.post("/api/auth/sessions/end-others").json() == {"ended": 0}
    assert [row["current"] for row in firefox.get("/api/auth/sessions").json()["sessions"]] == [True]
    # Ending one's own is signing out.
    own = firefox.get("/api/auth/sessions").json()["sessions"][0]["id"]
    assert firefox.delete(f"/api/auth/sessions/{own}").status_code == 204
    assert firefox.get("/api/auth/me").status_code == 401
    assert actions(admin).count("auth.session.end") == 3


def test_an_admin_sees_and_ends_the_sessions_of_any_account(admin: TestClient, clock: Clock):
    anna_account = make_user(admin)
    one, two = signed_in(address=OFFICE), signed_in(address=ELSEWHERE)
    url = f"/api/users/{anna_account['id']}/sessions"
    listed = admin.get(url).json()["sessions"]
    assert sorted(row["address"] for row in listed) == sorted([OFFICE, ELSEWHERE])
    assert not any(row["current"] for row in listed)
    assert signed_in().get(url).status_code == 403
    listed = admin.get(url).json()["sessions"]
    target = next(row for row in listed if row["address"] == OFFICE)
    assert admin.delete(f"{url}/{target['id']}").status_code == 204
    assert one.get("/api/auth/me").status_code == 401 and two.get("/api/auth/me").status_code == 200
    assert admin.delete(f"{url}/{target['id']}").status_code == 404
    assert admin.delete(url).json() == {"ended": 2}
    assert two.get("/api/auth/me").status_code == 401
    # On their own account the session they act from goes on.
    admin_id = admin.get("/api/auth/me").json()["user"]["id"]
    other = signed_in("admin", ADMIN["password"])
    assert admin.delete(f"/api/users/{admin_id}/sessions").json() == {"ended": 1}
    assert admin.get("/api/auth/me").status_code == 200 and other.get("/api/auth/me").status_code == 401
    assert admin.get("/api/users/nobody/sessions").status_code == 404
    assert any('of the account "anna"' in line for line in details(admin, "auth.session.end"))


def test_what_protects_an_account_ends_its_sessions_when_it_changes(admin: TestClient, clock: Clock):
    anna_account = make_user(admin)
    url = f"/api/users/{anna_account['id']}"

    def two() -> tuple[TestClient, TestClient]:
        return signed_in(), signed_in()

    # Their own password: the others end, this one goes on.
    here, there = two()
    change = {"currentPassword": "password1", "newPassword": "password1"}
    assert here.put("/api/users/me/password", json=change).status_code == 204
    assert here.get("/api/auth/me").status_code == 200 and there.get("/api/auth/me").status_code == 401
    # A password set by an admin, other roles, the account disabled: all of them end.
    for body in ({"password": "password1"}, {"roles": ["viewer"]}, {"disabled": True}):
        here, there = two()
        assert admin.patch(url, json=body).status_code == 200
        assert here.get("/api/auth/me").status_code == 401 and there.get("/api/auth/me").status_code == 401, body
    assert admin.patch(url, json={"disabled": False}).status_code == 200
    # A new name is not protection: the sessions go on.
    here, there = two()
    assert admin.patch(url, json={"username": "anna"}).status_code == 200
    assert here.get("/api/auth/me").status_code == 200
    # The second factor turned on: the others end, and this one changes its id.
    before = here.cookies.get("nik_session")
    enrol(here, clock)
    assert here.cookies.get("nik_session") != before
    assert here.get("/api/auth/me").status_code == 200 and there.get("/api/auth/me").status_code == 401
    assert browser().get("/api/auth/me", headers=holding("nik_session", before)).status_code == 401
    # An admin who changes their own roles keeps the session they do it from.
    admin_id = admin.get("/api/auth/me").json()["user"]["id"]
    other_admin = signed_in("admin", ADMIN["password"])
    assert admin.patch(f"/api/users/{admin_id}", json={"roles": ["admin", "audit"]}).status_code == 200
    assert admin.get("/api/auth/me").status_code == 200 and other_admin.get("/api/auth/me").status_code == 401


def test_a_sign_in_never_keeps_a_session_id(admin: TestClient):
    make_user(admin)
    anna = signed_in()
    first = anna.cookies.get("nik_session")
    # The same browser signs in again (the session-expired dialog, or another account): a new id, the old one dead.
    again = sign_in(anna)
    second = anna.cookies.get("nik_session")
    assert again.status_code == 200 and second != first and len(second) == 64
    assert browser().get("/api/auth/me", headers=holding("nik_session", first)).status_code == 401
    # An id an attacker planted in the browser beforehand is not the one the sign-in gives.
    planted = "f" * 64
    victim = browser()
    login = {"username": "anna", "password": "password1"}
    assert victim.post("/api/auth/login", json=login, headers=holding("nik_session", planted)).status_code == 200
    assert victim.cookies.get("nik_session") != planted
    assert browser().get("/api/auth/me", headers=holding("nik_session", planted)).status_code == 401
    # Signing out ends it on the server, not only in the browser.
    token = victim.cookies.get("nik_session")
    assert victim.post("/api/auth/logout").status_code == 204
    assert browser().get("/api/auth/me", headers=holding("nik_session", token)).status_code == 401


def test_the_cookies_are_http_only_lax_and_secure_when_the_server_says_so(admin: TestClient, clock: Clock, monkeypatch):
    make_user(admin)
    cookie = sign_in(browser()).headers["set-cookie"].lower()
    assert "nik_session=" in cookie and "httponly" in cookie and "samesite=lax" in cookie and "path=/" in cookie
    assert "max-age=43200" in cookie and "secure" not in cookie  # COOKIE_SECURE=false in the tests
    # (The test's browser speaks plain HTTP: it would not send a Secure cookie back, so it signs in first.)
    anna = signed_in()
    started = anna.post("/api/auth/second-factor/totp").json()
    set_policy(admin, lifetimeHours=2)
    monkeypatch.setattr(settings, "COOKIE_SECURE", True)
    fresh = sign_in(browser()).headers["set-cookie"].lower()
    assert "; secure" in fresh and "max-age=7200" in fresh
    confirmed = anna.post("/api/auth/second-factor/totp/confirm", json={"code": code_now(started["secret"], clock)})
    rotated = confirmed.headers["set-cookie"].lower()
    assert "nik_session=" in rotated and "httponly" in rotated and "; secure" in rotated
    ticket = sign_in(browser()).headers["set-cookie"].lower()
    assert "nik_signin=" in ticket and "httponly" in ticket and "; secure" in ticket and "max-age=300" in ticket


def test_a_request_sent_by_another_site_is_refused_before_anything_looks_at_it(admin: TestClient):
    make_user(admin)
    login = {"username": "anna", "password": "password1"}
    for site in ("cross-site", "same-site"):
        refused = browser().post("/api/auth/login", json=login, headers={"Sec-Fetch-Site": site})
        assert refused.status_code == 403 and refused.json()["code"] == "cross_site"
        assert (
            admin.post("/api/incidents", json={"id": "x", "data": {}}, headers={"Sec-Fetch-Site": site}).status_code
            == 403
        )
        assert admin.delete("/api/users/x", headers={"Sec-Fetch-Site": site}).status_code == 403
    assert admin.get("/api/incidents/x").status_code == 404  # nothing was made
    # Reading is not concerned, nor is the browser on the page itself, nor a client that is no browser.
    assert admin.get("/api/incidents", headers={"Sec-Fetch-Site": "cross-site"}).status_code == 200
    for site in ("same-origin", "none"):
        assert browser().post("/api/auth/login", json=login, headers={"Sec-Fetch-Site": site}).status_code == 200
    assert browser().post("/api/auth/login", json=login).status_code == 200
    # A webhook is called by whoever the sender is.
    hook = browser().post(f"/api/automation/hooks/{'B' * 43}", json={}, headers={"Sec-Fetch-Site": "cross-site"})
    assert hook.status_code != 403 or hook.json().get("code") != "cross_site"


# --------------------------------------------------------------------------- #
# Waits after failures                                                        #
# --------------------------------------------------------------------------- #
def test_the_wait_doubles_to_a_maximum_and_the_count_falls_back():
    policy = signin_policy.defaults()
    assert [signin.wait_after(count, policy) for count in (1, 4, 5, 6, 7, 8, 9, 10, 11, 50)] == [
        0,
        0,
        30,
        60,
        120,
        240,
        480,
        900,
        900,
        900,
    ]
    assert [signin.wait_text(seconds) for seconds in (1, 30, 89, 90, 240, 900)] == [
        "1 second",
        "30 seconds",
        "89 seconds",
        "2 minutes",
        "4 minutes",
        "15 minutes",
    ]


def test_wrong_passwords_make_the_account_wait_longer_each_time_never_for_good(admin: TestClient, clock: Clock):
    make_user(admin)
    client = browser()
    for _ in range(4):
        assert sign_in(client, password="nope").status_code == 401
    assert sign_in(client).status_code == 200  # four failures cost nothing, and the right password clears them
    assert "Signed in, after 4 failed attempts" in details(admin, "auth.login")

    for _ in range(5):
        assert sign_in(client, password="nope").status_code == 401
    waits = sign_in(client)
    assert waits.status_code == 429 and waits.headers["retry-after"] == "30"
    assert waits.json()["detail"] == "Too many failed attempts: try again in 30 seconds"
    # An attempt during the wait is not looked at and does not make it longer.
    clock.advance(seconds=20)
    assert sign_in(client, password="nope").headers["retry-after"] == "10"
    clock.advance(seconds=11)
    assert sign_in(client, password="nope").status_code == 401
    assert sign_in(client).headers["retry-after"] == "60"
    for expected in (120, 240, 480, 900, 900):
        clock.advance(seconds=int(sign_in(client).headers["retry-after"]) + 1)
        assert sign_in(client, password="nope").status_code == 401
        assert sign_in(client).headers["retry-after"] == str(expected)
    # After the longest wait the right password signs in: nothing is locked for good.
    clock.advance(seconds=901)
    assert sign_in(client).status_code == 200
    with SessionLocal() as db:
        assert db.scalar(sa.select(sa.func.count()).select_from(SigninAttempt)) == 0


def test_the_count_falls_back_with_time(admin: TestClient, clock: Clock):
    make_user(admin)
    client = browser()
    for _ in range(4):
        sign_in(client, password="nope")
    clock.advance(seconds=signin.FORGIVE_SECONDS * 2 + 1)  # two of the four are forgotten
    for _ in range(2):
        assert sign_in(client, password="nope").status_code == 401
    assert sign_in(client, password="nope").status_code == 401  # the fifth that counts
    assert sign_in(client).status_code == 429


def test_an_account_that_does_not_exist_is_answered_and_made_to_wait_like_one_that_does(
    admin: TestClient, clock: Clock, monkeypatch
):
    make_user(admin)
    checks: list[str] = []
    real = security.verify_password

    def counted(password: str, password_hash: str) -> bool:
        checks.append(password_hash)
        return real(password, password_hash)

    from app.routers import auth

    monkeypatch.setattr(auth, "verify_password", counted)
    known, ghost = browser(), browser()
    answers = []
    for client, name in ((known, "anna"), (ghost, "ghost")):
        seen = []
        for _ in range(6):
            res = client.post("/api/auth/login", json={"username": name, "password": "nope"})
            seen.append((res.status_code, res.json()["detail"], res.headers.get("retry-after")))
        answers.append(seen)
    assert answers[0] == answers[1]
    assert answers[0][0] == (401, "Invalid username or password", None) and answers[0][5][0] == 429
    # The same work each time: one bcrypt check per attempt that is looked at, none during the wait.
    assert len(checks) == 10 and all(stored.startswith("$2b$") for stored in checks)
    with SessionLocal() as db:
        keys = sorted(db.scalars(sa.select(SigninAttempt.key)))
    assert len(keys) == 2 and all(key.startswith("password:account:") for key in keys)
    assert "anna" not in str(keys) and "ghost" not in str(keys)
    # What is typed as a name is not written in the audit log unless it is an account.
    said = details(admin, "auth.failed")
    assert any('the account "anna"' in line for line in said)
    assert any("an account that does not exist" in line for line in said) and "ghost" not in str(said)


def test_failures_are_counted_per_address_too(admin: TestClient, clock: Clock):
    for name in ("a1", "a2", "a3", "a4", "a5", "a6"):
        make_user(admin, name)
    attacker = browser(ELSEWHERE)
    for name in ("a1", "a2", "a3", "a4", "a5"):
        assert sign_in(attacker, name, "nope").status_code == 401  # one guess per account: no account waits
    waits = sign_in(attacker, "a6")
    assert waits.status_code == 429 and waits.headers["retry-after"] == "30"
    # Everybody else signs in to the same accounts.
    assert sign_in(browser(OFFICE), "a1").status_code == 200
    assert any(f"the address {ELSEWHERE}" in line for line in details(admin, "auth.failed"))


def test_somebody_elses_guesses_do_not_keep_the_person_out_of_their_account(admin: TestClient, clock: Clock):
    make_user(admin)
    office = browser(OFFICE)
    assert sign_in(office).status_code == 200
    # Guesses from five addresses, so that no address waits: the account does.
    for last in range(1, 6):
        assert sign_in(browser(f"198.51.100.{last}"), password="nope").status_code == 401
    assert sign_in(browser("198.51.100.99")).status_code == 429
    # From where the account last signed in, it is not made to wait by them.
    assert sign_in(browser(OFFICE)).status_code == 200
    # That address still answers for its own failures.
    for _ in range(5):
        assert sign_in(office, password="nope").status_code == 401
    assert sign_in(office).status_code == 429


def test_wrong_codes_have_their_own_count_and_wait(admin: TestClient, clock: Clock):
    make_user(admin)
    secret, codes = enrol(signed_in(), clock)
    client = browser()
    assert sign_in(client).json().get("secondFactor")
    for _ in range(5):
        assert client.post("/api/auth/login/code", json={"code": "000000"}).status_code == 401
    clock.advance(seconds=1)
    waits = client.post("/api/auth/login/code", json={"code": code_now(secret, clock)})
    assert waits.status_code == 429 and waits.headers["retry-after"] == "29"
    # A recovery code waits on the same count, and the password step is not concerned.
    assert client.post("/api/auth/login/code", json={"recoveryCode": codes[0]}).status_code == 429
    assert sign_in(browser()).status_code == 200
    clock.advance(seconds=30)
    assert client.post("/api/auth/login/code", json={"recoveryCode": "zzzz-zzzz-zzzz-zzzz"}).status_code == 401
    assert client.post("/api/auth/login/code", json={"code": code_now(secret, clock)}).headers["retry-after"] == "60"
    clock.advance(seconds=61)
    assert client.post("/api/auth/login/code", json={"code": code_now(secret, clock)}).status_code == 200
    said = details(admin, "auth.code.failed")
    # Grouped: the first failure and those from the threshold on, not each one.
    assert len(said) == 3 and "5 failed second-factor codes in a row" in str(said)


def test_the_admins_are_told_once_when_a_run_of_failures_grows_long(admin: TestClient, clock: Clock):
    make_user(admin)
    make_user(admin, "vera", ("viewer",))
    set_policy(admin, notifyAfter=6)
    client = browser(ELSEWHERE)
    for _ in range(9):
        res = sign_in(client, password="nope")
        if res.status_code == 429:
            clock.advance(seconds=int(res.headers["retry-after"]) + 1)
            assert sign_in(client, password="nope").status_code == 401
    told = [n for n in admin.get("/api/notifications").json()["notifications"] if n["kind"] == "signin.failures"]
    assert len(told) == 2  # one for the account, one for the address; not one per failure
    assert any('the account "anna"' in n["text"] for n in told) and any(ELSEWHERE in n["text"] for n in told)
    vera = signed_in("vera")
    assert not [n for n in vera.get("/api/notifications").json()["notifications"] if n["kind"] == "signin.failures"]
    # The audit log has the run, grouped.
    said = details(admin, "auth.failed")
    assert sum("A failed sign-in for" in line for line in said) == 1
    assert any("failed sign-ins in a row" in line for line in said)


def test_an_admins_password_reset_ends_the_wait(admin: TestClient, clock: Clock):
    anna = make_user(admin)
    client = browser()
    for _ in range(5):
        sign_in(client, password="nope")
    assert sign_in(client).status_code == 429
    assert admin.patch(f"/api/users/{anna['id']}", json={"password": "fresh-secret"}).status_code == 200
    assert sign_in(client, password="fresh-secret").status_code == 200


# --------------------------------------------------------------------------- #
# The address of the client                                                   #
# --------------------------------------------------------------------------- #
def test_the_forwarded_address_is_believed_only_from_the_proxy(admin: TestClient, monkeypatch):
    make_user(admin)
    monkeypatch.setattr(settings, "TRUSTED_PROXIES", [PROXY])
    forged = {"X-Forwarded-For": OFFICE}

    def seen_by(client: TestClient) -> str:
        assert sign_in(client).status_code == 200
        return client.get("/api/auth/sessions").json()["sessions"][0]["address"]

    # Through the proxy: the address it names.
    assert seen_by(browser(PROXY, **forged)) == OFFICE
    # From anywhere else the header is the client's own claim, and changes nothing.
    assert seen_by(browser(ELSEWHERE, **forged)) == ELSEWHERE
    assert seen_by(browser(ELSEWHERE)) == ELSEWHERE
    # The proxy names the last hop it saw: what the client wrote before it is ignored.
    assert seen_by(browser(PROXY, **{"X-Forwarded-For": f"{OFFICE}, {ELSEWHERE}"})) == ELSEWHERE
    assert seen_by(browser(PROXY, **{"X-Forwarded-For": f"{ELSEWHERE}, {PROXY}"})) == ELSEWHERE
    # A header nobody can read is not believed: the proxy's own address stands.
    assert seen_by(browser(PROXY, **{"X-Forwarded-For": "not an address"})) == PROXY
    assert seen_by(browser(PROXY)) == PROXY
    # IPv6, and an IPv4 address carried inside one.
    assert seen_by(browser(PROXY, **{"X-Forwarded-For": "2001:db8::17"})) == "2001:db8::17"
    assert seen_by(browser(f"::ffff:{PROXY}", **forged)) == OFFICE
    # Nobody is trusted when no proxy is named.
    monkeypatch.setattr(settings, "TRUSTED_PROXIES", [])
    assert seen_by(browser(PROXY, **forged)) == PROXY


def test_a_forged_header_does_not_buy_a_fresh_count(admin: TestClient, clock: Clock, monkeypatch):
    make_user(admin)
    monkeypatch.setattr(settings, "TRUSTED_PROXIES", [PROXY])
    for attempt in range(5):
        res = browser(ELSEWHERE, **{"X-Forwarded-For": f"192.0.2.{attempt}"}).post(
            "/api/auth/login", json={"username": f"name{attempt}", "password": "x"}
        )
        assert res.status_code == 401
    waits = browser(ELSEWHERE, **{"X-Forwarded-For": "192.0.2.200"}).post(
        "/api/auth/login", json={"username": "another", "password": "x"}
    )
    assert waits.status_code == 429


@pytest.fixture()
def named_proxy(monkeypatch):
    """``TRUSTED_PROXIES=web``, with the test as the resolver: ``named_proxy(address)`` says what
    ``web`` has now (None: no address) and looks it up as the thread of the backend would."""
    state = {"address": None, "clock": 1000.0, "asked": 0}

    def lookup(name, _port):
        state["asked"] += 1
        if name != "web" or state["address"] is None:
            raise OSError("no such host")
        return [(None, None, None, "", (state["address"], 0))]

    monkeypatch.setattr(settings, "TRUSTED_PROXIES", ["web", "10.9.0.0/16", "fd00::/8"])
    monkeypatch.setattr(client_address.socket, "getaddrinfo", lookup)
    monkeypatch.setattr(client_address, "_start", lambda: None)  # no thread: the test asks itself
    client_address.forget()

    def now_has(address: str | None, after: float = 0.0) -> bool:
        state["address"] = address
        state["clock"] += after
        return client_address.refresh(state["clock"])

    now_has.state = state
    yield now_has
    client_address.forget()


def test_a_proxy_named_by_its_host_name_is_looked_up_apart_from_the_requests(named_proxy):
    # Nothing is known before the name was asked, and a request never asks: it would wait for the resolver.
    assert not client_address.inside(PROXY, client_address.trusted_proxies())
    assert client_address.inside("10.9.4.4", client_address.trusted_proxies())
    assert client_address.inside("fd12::5", client_address.trusted_proxies())
    assert named_proxy.state["asked"] == 0
    assert named_proxy(PROXY) is True
    networks = client_address.trusted_proxies()
    assert client_address.inside(PROXY, networks) and not client_address.inside(OFFICE, networks)
    assert named_proxy.state["asked"] == 1
    # A name that stops answering keeps its address for a while (the resolver may be what is down), not for ever.
    assert named_proxy(None, after=client_address.KEEP_SECONDS - 1) is False
    assert client_address.inside(PROXY, client_address.trusted_proxies())
    assert named_proxy(None, after=2) is False
    assert not client_address.inside(PROXY, client_address.trusted_proxies())


def test_a_proxy_that_got_a_new_address_is_believed_again(admin: TestClient, named_proxy):
    make_user(admin)

    def seen_from(proxy: str) -> str:
        client = browser(proxy, **{"X-Forwarded-For": OFFICE})
        assert sign_in(client).status_code == 200
        return client.get("/api/auth/sessions").json()["sessions"][0]["address"]

    # The backend starts first: the name has no address yet, and nobody is believed.
    named_proxy(None)
    assert seen_from(PROXY) == PROXY
    # The web container is there a moment later.
    named_proxy(PROXY, after=client_address.RETRY_SECONDS)
    assert seen_from(PROXY) == OFFICE
    # Recreated with another address (an update): the new one is believed, the old one no longer.
    named_proxy("10.20.0.9", after=client_address.RETRY_SECONDS)
    assert seen_from("10.20.0.9") == OFFICE
    assert seen_from(PROXY) == PROXY
    # A connection from somebody who is not the proxy asks for the name to be looked up again soon.
    assert client_address._wake.is_set()


def test_the_resolver_thread_starts_only_when_a_name_is_to_be_looked_up(monkeypatch):
    started = []
    monkeypatch.setattr(client_address.threading, "Thread", lambda **kwargs: started.append(kwargs) or FakeThread())
    monkeypatch.setattr(client_address, "_thread", None)
    monkeypatch.setattr(settings, "TRUSTED_PROXIES", ["10.9.0.0/16"])
    client_address.trusted_proxies()
    assert started == []
    monkeypatch.setattr(settings, "TRUSTED_PROXIES", ["web"])
    client_address.trusted_proxies()
    client_address.trusted_proxies()
    assert len(started) == 1 and started[0]["daemon"] is True


class FakeThread:
    def start(self) -> None:
        pass


def test_the_server_says_when_it_cannot_know_where_its_clients_are(admin: TestClient, monkeypatch):
    import ipaddress

    monkeypatch.setattr(settings, "TRUSTED_PROXIES", [PROXY])
    monkeypatch.setattr(client_address, "own_networks", lambda: [ipaddress.ip_network("10.20.0.0/24")])
    # Through the proxy, from an address of the server's own container network: not the person's.
    hidden = browser(PROXY, **{"X-Forwarded-For": "10.20.0.1"})
    assert sign_in(hidden, **ADMIN).status_code == 200
    seen = hidden.get("/api/auth/policy").json()["address"]
    assert seen["knowable"] is False and "10.20.0.1" in seen["reason"] and "rootless podman" in seen["reason"]
    assert seen["address"] == "10.20.0.1" and seen["connection"] == PROXY and seen["throughProxy"] is True
    assert seen["trustedProxies"] == [PROXY] and seen["overtrusting"] is False
    # Nothing is counted per address there: everybody would share the count.
    for attempt in range(6):
        assert sign_in(browser(PROXY, **{"X-Forwarded-For": "10.20.0.1"}), f"n{attempt}", "x").status_code == 401
    with SessionLocal() as db:
        assert not [key for key in db.scalars(sa.select(SigninAttempt.key)) if ":address:" in key]
    # So is a connection straight from that network that is no trusted proxy: a proxy nobody named.
    unnamed = browser("10.20.0.77", **{"X-Forwarded-For": OFFICE})
    assert sign_in(unnamed, **ADMIN).status_code == 200
    seen = unnamed.get("/api/auth/policy").json()["address"]
    assert seen["knowable"] is False and seen["address"] == "10.20.0.77" and "TRUSTED_PROXIES" in seen["reason"]
    assert unnamed.put("/api/auth/policy", json={"adminNetworks": ["10.20.0.0/24"]}).json()["code"] == "address_unknown"
    # A real address through the same proxy is the person's.
    real = browser(PROXY, **{"X-Forwarded-For": OFFICE})
    assert sign_in(real, **ADMIN).status_code == 200
    assert real.get("/api/auth/policy").json()["address"]["knowable"] is True
    # The old Compose setting that rewrites every address from the header is said.
    monkeypatch.setenv("FORWARDED_ALLOW_IPS", "*")
    assert real.get("/api/auth/policy").json()["address"]["overtrusting"] is True


def test_own_networks_are_read_from_the_routes_of_the_container(monkeypatch):
    import builtins
    import io
    import sys

    table = (
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
        "eth0\t00000000\t010014AC\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
        "eth0\t000014AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n"
        "eth1\t0000590A\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n"
    )
    zeros = "0" * 32
    table6 = (
        f"fd4d6169736f6e000000000000000000 40 {zeros} 00 {zeros} 00000100 00000001 00000000 00000001     eth0\n"
        f"fe800000000000000000000000000000 40 {zeros} 00 {zeros} 00000100 00000001 00000000 00000001     eth0\n"
        f"{zeros} 00 {zeros} 00 fd4d6169736f6e000000000000000001 00000400 00000001 00000000 00000003     eth0\n"
        f"00000000000000000000000000000001 80 {zeros} 00 {zeros} 00000000 00000002 00000000 80200001       lo\n"
        f"ff000000000000000000000000000000 08 {zeros} 00 {zeros} 00000100 00000001 00000000 00000001     eth0\n"
    )
    real_open = builtins.open

    def fake_open(path, *args, **kwargs):
        if path == "/proc/net/route":
            return io.StringIO(table)
        if path == "/proc/net/ipv6_route":
            return io.StringIO(table6)
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", fake_open)
    found = sorted(str(network) for network in client_address.own_networks())
    assert "fd4d:6169:736f:6e00::/64" in found and not [network for network in found if network.startswith("fe80")]
    if sys.byteorder == "little":
        assert found == ["10.89.0.0/24", "172.20.0.0/16", "fd4d:6169:736f:6e00::/64"]


# --------------------------------------------------------------------------- #
# Administrators only from listed networks                                    #
# --------------------------------------------------------------------------- #
def test_admins_are_accepted_from_the_listed_networks_only(admin: TestClient, clock: Clock):
    make_user(admin, "anna")
    office_admin = browser(OFFICE)
    assert sign_in(office_admin, **ADMIN).status_code == 200
    key = make_key(office_admin, label="adm", roles=["admin"])
    reader = make_key(office_admin, label="reader", roles=["viewer"])
    set_policy(office_admin, adminNetworks=["203.0.113.0/24", "2001:db8:aa::/48"])

    # Inside: as before.
    assert office_admin.get("/api/users").status_code == 200
    assert sign_in(browser("203.0.113.200"), **ADMIN).status_code == 200
    inside6 = browser("2001:db8:aa:1::9")
    assert sign_in(inside6, **ADMIN).status_code == 200 and inside6.get("/api/users").status_code == 200
    # Outside: said plainly, after the right password; a wrong one learns nothing about the account.
    outside = browser(ELSEWHERE)
    refused = sign_in(outside, **ADMIN)
    assert refused.status_code == 403 and refused.json()["code"] == "admin_network"
    assert ELSEWHERE in refused.json()["detail"] and "nik_session" not in refused.cookies
    assert sign_in(browser(ELSEWHERE), "admin", "wrong").json() == {"detail": "Invalid username or password"}
    assert sign_in(browser(ELSEWHERE), "anna", "wrong").json() == {"detail": "Invalid username or password"}
    assert sign_in(browser("2001:db8:bb::1"), **ADMIN).json()["code"] == "admin_network"
    # Whoever is not an administrator signs in from anywhere.
    assert sign_in(browser(ELSEWHERE), "anna").status_code == 200
    # A session that moves outside is refused where it is, and answers again when it is back.
    token = office_admin.cookies.get("nik_session")
    moved = browser(ELSEWHERE)
    for path in ("/api/users", "/api/auth/me", "/api/incidents"):
        assert moved.get(path, headers=holding("nik_session", token)).json()["code"] == "admin_network", path
    assert office_admin.get("/api/users").status_code == 200
    # An administrator's key is held to the same networks; another key is not.
    assert browser(ELSEWHERE).get("/api/users", headers=key).json()["code"] == "admin_network"
    assert browser(OFFICE).get("/api/users", headers=key).status_code == 200
    assert browser(ELSEWHERE).get("/api/incidents", headers=reader).status_code == 200
    assert "auth.refused" in actions(office_admin)


def test_the_networks_are_checked_after_the_second_factor_too(admin: TestClient, clock: Clock):
    office_admin = browser(OFFICE)
    assert sign_in(office_admin, **ADMIN).status_code == 200
    secret, _codes = enrol(office_admin, clock)
    set_policy(office_admin, adminNetworks=[f"{OFFICE}/32"])
    clock.advance(seconds=30)
    outside = browser(ELSEWHERE)
    # The password alone says nothing of it, wrong codes neither.
    assert sign_in(outside, **ADMIN).json().get("secondFactor")
    assert outside.post("/api/auth/login/code", json={"code": "000000"}).json() == {
        "detail": "That code is not right, or was used already"
    }
    refused = outside.post("/api/auth/login/code", json={"code": code_now(secret, clock)})
    assert refused.status_code == 403 and refused.json()["code"] == "admin_network"
    assert outside.get("/api/auth/me").status_code == 401


def test_a_list_that_would_refuse_the_admin_who_saves_it_is_refused_unless_they_insist(admin: TestClient):
    office_admin = browser(OFFICE)
    assert sign_in(office_admin, **ADMIN).status_code == 200
    refused = office_admin.put("/api/auth/policy", json={"adminNetworks": ["192.0.2.0/24"]})
    assert (
        refused.status_code == 409 and refused.json()["code"] == "locks_you_out" and OFFICE in refused.json()["detail"]
    )
    assert office_admin.get("/api/auth/policy").json()["policy"]["adminNetworks"] == []
    # Saying so explicitly saves it: and the next request is refused, as announced.
    assert (
        office_admin.put("/api/auth/policy", json={"adminNetworks": ["192.0.2.0/24"], "confirm": True}).status_code
        == 200
    )
    assert office_admin.get("/api/users").json()["code"] == "admin_network"
    assert account.main(["clear-admin-networks"]) == 0
    assert office_admin.get("/api/users").status_code == 200

    # Where the server cannot know the address (the test client has none), the list is refused with the reason.
    blind = admin.put("/api/auth/policy", json={"adminNetworks": ["192.0.2.0/24"]})
    assert blind.status_code == 409 and blind.json()["code"] == "address_unknown"
    # A list that holds the address is saved without a question; other values never ask.
    saved = set_policy(office_admin, adminNetworks=[f"{OFFICE}", "10.0.0.0/8", "10.0.0.0/8"])
    assert saved["policy"]["adminNetworks"] == [f"{OFFICE}/32", "10.0.0.0/8"]
    assert set_policy(office_admin, idleMinutes=45)["policy"]["adminNetworks"] == [f"{OFFICE}/32", "10.0.0.0/8"]
    assert set_policy(office_admin, adminNetworks=[])["policy"]["adminNetworks"] == []


# --------------------------------------------------------------------------- #
# The policy                                                                  #
# --------------------------------------------------------------------------- #
def test_the_policy_starts_with_nothing_turned_on_and_refuses_what_makes_no_sense(admin: TestClient):
    shown = admin.get("/api/auth/policy").json()
    assert (
        shown["policy"]
        == shown["defaults"]
        == {
            "requiredRoles": [],
            "idleMinutes": 480,
            "idleMinutesAdmin": 480,
            "lifetimeHours": 12,
            "attemptsBeforeWait": 5,
            "firstWaitSeconds": 30,
            "maxWaitMinutes": 15,
            "notifyAfter": 10,
            "adminNetworks": [],
        }
    )
    assert shown["recommended"] == {"requiredRoles": ["admin"], "idleMinutesAdmin": 30}
    assert shown["limits"]["lifetimeHours"] == {"min": 1, "max": 720}
    for body in (
        {"requiredRoles": ["root"]},
        {"requiredRoles": "admin"},
        {"idleMinutes": -1},
        {"idleMinutes": 1.5},
        {"idleMinutes": True},
        {"lifetimeHours": 0},
        {"attemptsBeforeWait": 1},
        {"firstWaitSeconds": 1000, "maxWaitMinutes": 1},
        {"adminNetworks": ["10.0.0.0/33"]},
        {"adminNetworks": ["everywhere"]},
        {"adminNetworks": "10.0.0.0/8"},
    ):
        res = admin.put("/api/auth/policy", json=body)
        assert res.status_code == 400, body
    assert admin.get("/api/auth/policy").json()["policy"] == shown["defaults"]
    # Only what is sent changes; an unknown name is ignored.
    after = set_policy(admin, idleMinutesAdmin=30, somethingElse=1)["policy"]
    assert after == {**shown["defaults"], "idleMinutesAdmin": 30}
    # A value stored by hand that no longer fits falls back to its default, the others stand.
    with SessionLocal() as db:
        signin_policy.store(db, {"idleMinutes": "soon", "lifetimeHours": 3})
        db.commit()
        loaded = signin_policy.load(db)
    assert loaded["idleMinutes"] == 480 and loaded["lifetimeHours"] == 3


def test_the_lifetime_follows_the_environment_until_the_screen_sets_another(admin: TestClient, monkeypatch):
    monkeypatch.setattr(settings, "SESSION_TTL_HOURS", 4)
    assert admin.get("/api/auth/policy").json()["policy"]["lifetimeHours"] == 4
    set_policy(admin, lifetimeHours=9)
    assert admin.get("/api/auth/policy").json()["policy"]["lifetimeHours"] == 9


def test_only_an_admin_reads_and_writes_the_policy(admin: TestClient):
    make_user(admin)
    anna = signed_in()
    assert anna.get("/api/auth/policy").status_code == 403
    assert anna.put("/api/auth/policy", json={"requiredRoles": []}).status_code == 403
    assert browser().get("/api/auth/policy").status_code == 401

"""Backups and the second factor together: what a backup carries of the accounts, what a restored
server keeps and what it ends, what an API key may do to the backups, and one change of
``SECRET_KEY`` for every kind of stored secret."""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy import select

from app.backups import config, container, database, runner
from app.core import vault
from app.core.config import settings
from app.core.db import SessionLocal
from app.core.models import RecoveryCode, Setting, UserFactor
from app.core.models import Session as SessionModel
from tests.conftest import ADMIN, make_key

from .test_backups import PHRASE, T0, audit_lines, backups, quick_keys, set_phrase  # noqa: F401 - fixtures
from .test_signin import (  # noqa: F401 - fixtures
    browser,
    clock,
    code_now,
    enrol,
    make_user,
    no_rate_limit,
    set_policy,
    sign_in,
)


def restored_into(scratch, name: str) -> sa.Engine:
    loader = database.Loader(scratch.url)
    with open(runner.file_of(name), "rb") as source:
        reader = container.Reader(source, container.Secrets(passphrases=(PHRASE,)))
        for part in reader.parts():
            loader.take(part)
    loader.finish(reader.manifest)
    return sa.create_engine(scratch.url)


def count(conn, table: str) -> int:
    return conn.execute(sa.text(f"SELECT count(*) FROM {table}")).scalar()  # noqa: S608 - names written here


def test_a_backup_carries_the_second_factors_and_the_policy_and_a_restore_ends_the_sessions(backups, clock):  # noqa: F811
    set_phrase(backups)
    secret, codes = enrol(backups, clock)
    set_policy(backups, adminSecondFactor=True)
    make_user(backups, "anna")
    # Somebody half-way through a sign-in, and somebody who typed a wrong password: both of that moment.
    assert sign_in(browser(), **ADMIN).json().get("secondFactor")
    assert sign_in(browser(), "anna", "not her password").status_code == 401
    with SessionLocal() as db:
        factor = db.scalars(select(UserFactor)).one()
        kept_secret, policy = factor.secret, dict(db.get(Setting, 5).doc)
        assert db.query(SessionModel).count() >= 1
    assert policy["adminSecondFactor"] is True

    name = runner.take(now=T0)
    with SessionLocal() as db:
        assert db.get(runner.Backup, name).verify_state == "passed"
    with open(runner.file_of(name), "rb") as source:
        rows = container.walk(source, container.Secrets(passphrases=(PHRASE,)))["database"]["rows"]
    assert rows["user_factors"] == 1 and rows["recovery_codes"] == len(codes) and rows["signin_tickets"] >= 1
    assert rows["signin_attempts"] >= 1 and rows["sessions"] >= 1

    with database.Scratch("scratch", separate_role=False) as scratch:
        other = restored_into(scratch, name)
        try:
            with other.connect() as conn:
                # Everything came back, as it was.
                assert conn.execute(sa.text("SELECT secret FROM user_factors")).scalar() == kept_secret
                assert count(conn, "recovery_codes") == len(codes)
                assert count(conn, "sessions") >= 1 and count(conn, "signin_tickets") >= 1
            other.dispose()
            # Then what belongs to the day of the backup is ended; what the server is, is kept.
            gone = database.after_restore(scratch.url)
            assert gone["sessions"] >= 1 and gone["signin_tickets"] >= 1 and gone["signin_attempts"] >= 1
            assert gone["backups"] == 1, "the row of the backup itself, which said it was being written"
            with other.connect() as conn:
                for table in ("sessions", "signin_tickets", "signin_attempts", "leases"):
                    assert count(conn, table) == 0, table
                assert conn.execute(sa.text("SELECT secret FROM user_factors")).scalar() == kept_secret
                assert count(conn, "recovery_codes") == len(codes)
                assert count(conn, "users") == 2
                doc = conn.execute(sa.text("SELECT doc FROM settings WHERE id = 5")).scalar()
                assert "adminSecondFactor" in str(doc)
        finally:
            other.dispose()
    # The factor that was restored is the one the authenticator app still answers to.
    assert vault.decrypt(kept_secret) == secret


def test_every_table_the_restore_clears_is_one_the_models_know(backups):  # noqa: F811
    """A table renamed in a later release must not be skipped in silence."""
    from app.core.db import Base

    known = set(Base.metadata.tables)
    assert {table for table, _condition in database.AFTER_RESTORE} <= known


def test_a_key_reads_and_asks_but_only_a_signed_in_administrator_changes_or_takes(backups):  # noqa: F811
    set_phrase(backups)
    name = runner.take(now=T0)
    key = make_key(backups, label="monitoring", roles=["admin"])
    alone = browser()  # no session: the key and nothing else
    assert alone.get("/api/backups", headers=key).status_code == 200
    assert alone.post(f"/api/backups/{name}/verify", headers=key).status_code == 202
    asked = alone.post("/api/backups/run", headers=key)
    assert asked.status_code == 202 and asked.json()["requestedBy"].startswith("api:")
    for method, path, body in (
        ("PUT", "/api/backups/passphrase", {"passphrase": "a passphrase of the key holder"}),
        ("PUT", "/api/backups/settings", {"includeKey": True}),
        ("DELETE", f"/api/backups/{name}?confirm={name}&lastGood=true", None),
        ("GET", f"/api/backups/{name}/download", None),
    ):
        refused = alone.request(method, path, json=body, headers=key)
        assert refused.status_code == 401, (method, path, refused.status_code)
    assert runner.file_of(name).exists()
    with SessionLocal() as db:
        assert config.passphrase(db) == PHRASE and config.read(db)["includeKey"] is False
    # The signed-in administrator does all four.
    assert backups.put("/api/backups/settings", json={"includeKey": True}).status_code == 200
    assert backups.get(f"/api/backups/{name}/download").status_code == 200


def test_an_administrator_who_must_enrol_reaches_no_backup_route(backups, clock):  # noqa: F811
    set_phrase(backups)
    enrol(backups, clock)
    make_user(backups, "otto", ("admin",))
    otto = browser()
    assert sign_in(otto, "otto", "password1").status_code == 200
    assert otto.get("/api/backups").status_code == 200
    set_policy(backups, adminSecondFactor=True)
    for method, path in (("GET", "/api/backups"), ("POST", "/api/backups/run"), ("PUT", "/api/backups/passphrase")):
        refused = otto.request(method, path, json={} if method != "GET" else None)
        assert refused.status_code == 403 and refused.json()["code"] == "second_factor_required", (method, path)
    assert backups.get("/api/backups").status_code == 200, "the one who has a factor goes on"


def test_one_change_of_secret_key_moves_every_kind_of_stored_secret(backups, clock, monkeypatch):  # noqa: F811
    set_phrase(backups)
    secret, _codes = enrol(backups, clock)
    made = backups.post("/api/automation/credentials", json={"name": "kept_key", "kind": "secret", "value": "v-1"})
    assert made.status_code == 201, made.text
    set_phrase(backups, "the second passphrase")  # the first one is kept among the earlier ones
    saved = backups.put(
        "/api/backups/settings",
        json={
            "destination": {
                "kind": "sftp",
                "host": "second.nik.example",
                "user": "nikbackup",
                "auth": "password",
                "secret": "the password of the account",
                "path": "/incoming",
            }
        },
    )
    assert saved.status_code == 200, saved.text
    old_key = settings.SECRET_KEY
    monkeypatch.setattr(settings, "SECRET_KEY", "a-new-secret-key-of-the-server-0123456789")
    with SessionLocal() as db:
        assert config.passphrase(db) is None and vault.decrypt(db.scalars(select(UserFactor)).one().secret) is None
    monkeypatch.setattr(settings, "SECRET_KEY_PREVIOUS", [old_key])
    # The factor, the credential, the passphrase, the earlier passphrase, the password of the destination.
    assert vault.reencrypt(SessionLocal) == 5
    assert vault.reencrypt(SessionLocal) == 0, "all of them are under the new key now"
    monkeypatch.setattr(settings, "SECRET_KEY_PREVIOUS", [])
    with SessionLocal() as db:
        assert config.passphrase(db) == "the second passphrase"
        assert config.secrets(db).passphrases == ("the second passphrase", PHRASE)
        assert config.destination_secret(db, config.read(db)["destination"]) == "the password of the account"
        assert vault.decrypt(db.scalars(select(UserFactor)).one().secret) == secret
        assert db.query(RecoveryCode).count() > 0
    clock.advance(seconds=30)
    client = browser()
    assert sign_in(client, **ADMIN).json().get("secondFactor")
    assert client.post("/api/auth/login/code", json={"code": code_now(secret, clock)}).status_code == 200

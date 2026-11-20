"""The audit log sent to syslog: the message (RFC 5424), the three transports against local
doubles, order, at least once across a receiver that restarts, a receiver that is stuck, the
backlog, checkpoints, the last word to the old receiver, and where the sender may connect."""

from __future__ import annotations

import json
import re
import threading
import time

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.auditlog import chain, forward, syslog, transport, verifier
from app.automation import egress
from app.core import audit
from app.core.db import SessionLocal
from app.core.models import AuditEntry, Credential, Setting
from app.main import app as fastapi_app
from tests.conftest import make_key
from tests.syslog_double import Authority, Receiver

# <PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP SD SP MSG
HEADER = re.compile(
    r"^<(\d{1,3})>1 (\S+) (\S+) (\S+) (\S+) (\S+) (\[nik@32473(?: [a-z]+=\"(?:[^\"\\\]]|\\[\"\\\]])*\")*\]) (.*)$",
    re.DOTALL,
)


@pytest.fixture(autouse=True)
def fresh_sender():
    """What the sender holds between passes belongs to one test."""
    forward.reset()
    yield
    forward.reset()


class Clock:
    """The time the passes are told: real time, moved forward by hand."""

    def __init__(self) -> None:
        self.ahead = 0.0

    def now(self) -> float:
        return time.time() + self.ahead

    def passes(self, count: int = 1, step: float = 1.0) -> list[str]:
        did: list[str] = []
        for _ in range(count):
            self.ahead += step
            did += forward.ship(now=self.now())
        return did


@pytest.fixture()
def clock() -> Clock:
    return Clock()


def _set(admin: TestClient, **changes) -> dict:
    saved = admin.put("/api/audit/forwarding", json=changes)
    assert saved.status_code == 200, saved.text
    return saved.json()


def _to(receiver: Receiver, **more) -> dict:
    return {"enabled": True, "host": "127.0.0.1", "port": receiver.port, "protocol": receiver.protocol, **more}


def _write(count: int, start: int = 0) -> None:
    with SessionLocal() as db:
        for number in range(start, start + count):
            audit.record(db, "anna", "test.entry", f"entry {number}")
            db.commit()


def _head() -> int:
    with SessionLocal() as db:
        return chain.head(db)[0]


def _state() -> dict:
    with SessionLocal() as db:
        return forward.out(db)["state"]


def _entry(**changes) -> dict:
    entry = {
        "id": "0b0e6a1c-5c1e-4a53-9d53-2d0f6f1f6c11",
        "at": "2026-11-20T09:15:02.481220+00:00",
        "actor": "anna",
        "action": "user.update",
        "target": "bruno",
        "details": "Changed the roles of bruno: analyst, audit",
        "incident_id": None,
        "incident_name": None,
        "seq": 4182,
        "prev": "a" * 64,
    } | changes
    entry["hash"] = verifier.entry_hash(entry["seq"], entry["prev"], entry)
    return entry


# --------------------------------------------------------------------------- #
# The message                                                                 #
# --------------------------------------------------------------------------- #
def test_an_entry_is_one_rfc_5424_message_that_carries_the_entry_and_its_place_in_the_chain():
    entry = _entry()
    line = syslog.render(entry, {"facility": 13, "severity": 5, "hostname": "nik.example", "appName": "nik"}).decode()
    found = HEADER.match(line)
    assert found, line
    priority, when, host, app, process, kind, data, message = found.groups()
    assert (priority, host, app, process, kind) == (str(13 * 8 + 5), "nik.example", "nik", "-", "audit")
    assert when == "2026-11-20T09:15:02.481220Z"
    assert data == (
        f'[nik@32473 seq="4182" hash="{entry["hash"]}" prev="{"a" * 64}" '
        'id="0b0e6a1c-5c1e-4a53-9d53-2d0f6f1f6c11" action="user.update"]'
    )
    body = json.loads(message)
    assert body == {
        "nik": "audit",
        "v": 1,
        "seq": 4182,
        "prev": "a" * 64,
        "hash": entry["hash"],
        "id": entry["id"],
        "at": entry["at"],
        "actor": "anna",
        "action": "user.update",
        "target": "bruno",
        "details": "Changed the roles of bruno: analyst, audit",
        "incidentId": None,
        "incidentName": None,
    }
    # What the receiver holds is enough to make the hash again.
    assert verifier.entry_hash(body["seq"], body["prev"], verifier.normal(body)) == body["hash"]
    # Settable facility and severity, by number; a header field never holds a space or a non-ASCII character.
    other = syslog.render(entry, {"facility": 16, "severity": 6, "hostname": "nik séc", "appName": ""}).decode()
    assert other.startswith("<134>1 2026-11-20T09:15:02.481220Z niksc nik - audit ")


def test_whatever_an_entry_holds_the_message_stays_one_line_of_ascii_with_its_data_escaped():
    hostile = _entry(
        action='x"] evil="1',
        details='line one\nline two\r\n"quoted" \\ ] é 日本 \x00\x1f 😀',
        actor="-- [nik@32473] --",
        at="not a time",
    )
    raw = syslog.render(hostile, {})
    line = raw.decode("ascii")  # nothing but ASCII leaves
    assert "\n" not in line and "\r" not in line and "\x00" not in line
    found = HEADER.match(line)
    assert found, line
    assert found.group(2) == "-"  # a time that cannot be read is the nil value, not a guess
    # In the structured data: the quote, the backslash and the closing bracket are escaped.
    assert 'action="x\\"\\] evil=\\"1"' in found.group(7)
    body = json.loads(found.group(8))
    assert body["details"] == hostile["details"] and body["action"] == hostile["action"]
    assert verifier.entry_hash(body["seq"], body["prev"], verifier.normal(body)) == hostile["hash"]
    # And the verifier finds the object after whatever prefix a receiver writes, brackets and braces included.
    assert verifier.message("Nov 20 host app[1]: {x} " + line)["seq"] == 4182
    # Framing over TCP and TLS: the length in bytes, a space, the message.
    assert syslog.frame(raw) == str(len(raw)).encode() + b" " + raw


def test_a_message_too_large_for_a_datagram_is_shortened_and_says_so():
    long = _entry(details="é" * 5000, target="t" * 3000)
    whole = syslog.render(long, {})
    assert len(whole) > 30000
    short = syslog.render(long, {}, limit=1024)
    assert len(short) <= 1024
    body = json.loads(HEADER.match(short.decode()).group(8))
    assert body["truncated"] is True and len(body["details"]) < 5000
    # Its place in the chain is whole; its content can no longer be hashed again, and the verifier knows.
    assert (body["seq"], body["hash"], body["prev"]) == (long["seq"], long["hash"], long["prev"])
    found = verifier.read_capture([short.decode()])
    assert found.problems == [] and found.chain == {long["seq"]: long["hash"]}
    # A message that fits is not touched.
    assert "truncated" not in syslog.render(_entry(), {}, limit=1024).decode()


def test_a_checkpoint_carries_the_head_and_the_count():
    line = syslog.checkpoint(4182, "b" * 64, 4000, 1795166102.5, {"hostname": "nik"}).decode()
    found = HEADER.match(line)
    assert found and found.group(6) == "checkpoint"
    assert found.group(7) == f'[nik@32473 seq="4182" hash="{"b" * 64}" count="4000"]'
    body = json.loads(found.group(8))
    assert body == {"nik": "checkpoint", "v": 1, "seq": 4182, "hash": "b" * 64, "count": 4000, "at": body["at"]}
    assert found.group(2).endswith("Z") and body["at"].startswith(found.group(2)[:19])


# --------------------------------------------------------------------------- #
# The settings                                                                #
# --------------------------------------------------------------------------- #
def test_the_settings_are_checked_kept_without_showing_a_key_and_recorded(admin: TestClient):
    first = admin.get("/api/audit/forwarding").json()
    assert first["settings"]["enabled"] is False and first["settings"]["protocol"] == "tls"
    assert first["state"]["destination"] == "" and first["state"]["backlog"]["entries"] == 0
    for body, words in (
        ({"enabled": True}, "Name the receiver"),
        ({"host": "siem example"}, "host name or an address"),
        ({"host": "siem.example", "port": 0}, "port"),
        ({"protocol": "http"}, "tls, tcp or udp"),
        ({"facility": 24}, "facility"),
        ({"severity": "loud"}, "severity"),
        ({"appName": "two words"}, "application name"),
        ({"checkpointMinutes": 0}, "checkpoints"),
        ({"ca": "not a certificate"}, "PEM"),
        ({"startFrom": "yesterday"}, "beginning"),
        ({"colour": "red"}, "Not a setting"),
    ):
        refused = admin.put("/api/audit/forwarding", json=body)
        assert refused.status_code == 422 and words in refused.json()["detail"], (body, refused.text)
    authority = Authority()
    certificate, key = authority.issue("nik-client", server=False)
    saved = _set(
        admin,
        enabled=True,
        host="SIEM.example",
        port=6514,
        ca=authority.pem,
        clientCert=certificate,
        clientKey=key,
        facility="local3",
        severity="info",
    )
    kept = saved["settings"]
    assert (kept["host"], kept["facility"], kept["severity"]) == ("siem.example", 19, 6)
    assert kept["clientKeySet"] is True and "clientKey" not in kept and "PRIVATE KEY" not in json.dumps(saved)
    with SessionLocal() as db:
        stored = db.get(Setting, forward.SETTINGS_ID).doc
        assert stored["settings"]["clientKey"].startswith("vault:") and "PRIVATE" not in json.dumps(stored)
        assert forward.client_key(db, stored["settings"]) == key.strip() + "\n"
        said = db.scalars(select(AuditEntry).where(AuditEntry.action == "audit.forward.settings")).one()
    assert said.details.startswith("Turned on the forwarding of the audit log to tls://siem.example:6514: ")
    assert "PRIVATE" not in said.details and stored["changeEntry"] == said.id
    # Saving the same again changes nothing and records nothing.
    _set(admin, host="siem.example")
    with SessionLocal() as db:
        assert (
            db.scalar(select(func.count()).select_from(AuditEntry).where(AuditEntry.action == "audit.forward.settings"))
            == 1
        )
    # The key may be a stored credential, named as in an instance; a pair is not a key.
    with SessionLocal() as db:
        from app.core import vault

        db.add(
            Credential(
                id="c1",
                name="syslog_key",
                kind="secret",
                secret=vault.encrypt(key),
                created_at="x",
                created_by="t",
                updated_at="x",
                updated_by="t",
            )
        )
        db.commit()
    named = _set(admin, clientKey="{{ credentials.syslog_key }}")["settings"]
    assert named["clientKeyCredential"] == "{{ credentials.syslog_key }}"
    with SessionLocal() as db:
        assert forward.client_key(db, forward.read(db)) == key
    assert admin.put("/api/audit/forwarding", json={"clientKey": "{{ credentials.nope }}"}).status_code == 422


def test_a_changed_secret_key_keeps_the_key_of_the_client_certificate(admin: TestClient, monkeypatch):
    from app.core import vault
    from app.core.config import settings

    authority = Authority()
    certificate, key = authority.issue("nik-client", server=False)
    monkeypatch.setattr(settings, "SECRET_KEY", "the-old-key")
    _set(admin, host="siem.example", ca=authority.pem, clientCert=certificate, clientKey=key)
    with SessionLocal() as db:
        doc = db.get(Setting, forward.SETTINGS_ID).doc
        old = doc["settings"]["clientKey"]
        db.add(Setting(id=forward.STATE_ID, doc={"version": doc["version"], "active": doc["settings"]}))
        db.commit()
    monkeypatch.setattr(settings, "SECRET_KEY", "a-new-key")
    assert forward.rekey(forward.SETTINGS_ID) is False  # nothing says what the old key was
    with SessionLocal() as db, pytest.raises(transport.TransportError, match="cannot be read any more"):
        forward.client_key(db, forward.read(db))
    monkeypatch.setattr(settings, "SECRET_KEY_PREVIOUS", ["the-old-key"])
    assert forward.rekey(forward.SETTINGS_ID) is True and forward.rekey(forward.STATE_ID) is True
    monkeypatch.setattr(settings, "SECRET_KEY_PREVIOUS", [])
    with SessionLocal() as db:
        kept = forward.read(db)["clientKey"]
        assert kept != old and vault.decrypt(kept[len("vault:") :]) == key.strip() + "\n"
        assert forward.client_key(db, forward._active(db.get(Setting, forward.STATE_ID).doc)) == key.strip() + "\n"
        # The settings did not change for the sender: nothing is taken up again.
        assert db.get(Setting, forward.SETTINGS_ID).doc["version"] == doc["version"]


def test_changing_and_testing_the_forwarding_need_a_signed_in_administrator(admin: TestClient):
    key = make_key(admin, label="adm", roles=["admin"])
    caller = TestClient(fastapi_app)
    assert caller.get("/api/audit/forwarding", headers=key).status_code == 200
    assert caller.put("/api/audit/forwarding", headers=key, json={"enabled": False}).status_code == 401
    assert caller.post("/api/audit/forwarding/test", headers=key).status_code == 401
    assert caller.get("/api/audit/forwarding", headers=make_key(admin, label="aud", roles=["audit"])).status_code == 403
    assert admin.post("/api/audit/forwarding/test").status_code == 409  # nothing saved to test


# --------------------------------------------------------------------------- #
# TCP                                                                         #
# --------------------------------------------------------------------------- #
def test_entries_leave_in_order_over_tcp_and_the_cursor_follows(admin: TestClient, clock: Clock):
    with Receiver("tcp") as receiver:
        _set(admin, **_to(receiver))
        _write(20)
        total = _head()
        assert _state()["backlog"]["entries"] == total and _state()["destination"] == ""
        did = clock.passes(1)
        assert f"sent:{total}" in did
        receiver.wait(total)
        assert receiver.errors == []
        assert receiver.numbers() == list(range(1, total + 1))  # the whole log, from its first entry
        # Written is not arrived: the cursor moves at the next pass, when the receiver is still there.
        assert _state()["cursor"] == 0
        assert f"confirmed:{total}" in clock.passes(1)
        state = _state()
        assert (state["cursor"], state["sent"], state["backlog"]["entries"], state["error"]) == (total, total, 0, "")
        assert state["destination"] == f"tcp://127.0.0.1:{receiver.port}" and state["pendingChange"] is False
        # What is written afterwards follows, over the same connection.
        _write(5, start=100)
        clock.passes(2)
        receiver.wait(total + 5)
        assert receiver.numbers() == list(range(1, total + 6)) and receiver.connections == 1
        # Every message is whole, and the copy of the receiver verifies on its own.
        assert all(HEADER.match(line) for line in receiver.lines)
        found = verifier.read_capture(receiver.lines)
        assert found.problems == [] and found.gaps == [] and found.head[0] == total + 5


def test_checkpoints_are_sent_when_due_even_when_nothing_happened(admin: TestClient, clock: Clock):
    with Receiver("tcp") as receiver:
        _set(admin, **_to(receiver, checkpointMinutes=2))
        clock.passes(2)
        first = receiver.bodies("checkpoint")
        assert len(first) == 1  # the first pass that sends anything
        assert clock.passes(3) == []  # nothing new, not due: nothing is sent
        clock.passes(1, step=120)
        receiver.wait(len(receiver.raw) + 1, timeout=3)
        marks = receiver.bodies("checkpoint")
        assert len(marks) == 2
        with SessionLocal() as db:
            seq, held = chain.head(db)
            count = db.scalar(select(func.count()).select_from(AuditEntry))
        assert (marks[-1]["seq"], marks[-1]["hash"], marks[-1]["count"]) == (seq, held, count)
        assert verifier.read_capture(receiver.lines).checkpoint == (seq, held)
        assert _state()["checkpointAt"] is not None


def test_a_receiver_that_restarts_gets_everything_at_least_once_and_in_order(admin: TestClient, clock: Clock):
    receiver = Receiver("tcp").start()
    try:
        _set(admin, **_to(receiver))
        _write(10)
        clock.passes(2)
        receiver.wait(_head())
        confirmed = _state()["cursor"]
        assert confirmed == _head()
        # More is written and sent, and the receiver dies before the sender knows it arrived.
        _write(10, start=10)
        clock.passes(1)
        receiver.wait(_head())
        receiver.stop()
        got_before = receiver.numbers()
        _write(10, start=20)
        did = clock.passes(1)
        assert "failed" in did or not any(word.startswith("confirmed") for word in did)
        clock.passes(3)
        state = _state()
        assert state["cursor"] == confirmed  # nothing is counted as arrived
        assert state["error"] and "cannot be reached" in state["error"] or "stopped listening" in state["error"]
        assert state["backlog"]["entries"] == _head() - confirmed and state["errorSince"]
        # audit.record goes on, at once, whatever the receiver does.
        began = time.perf_counter()
        _write(5, start=30)
        assert time.perf_counter() - began < 2
        # The receiver is back on the same port: the backlog drains in order, from the cursor.
        receiver.start()
        clock.passes(3, step=70)
        receiver.wait(len(got_before) + (_head() - confirmed))
        clock.passes(2)
    finally:
        receiver.stop()
    numbers = receiver.numbers()
    assert set(numbers) == set(range(1, _head() + 1)), "an entry never arrived"
    # In order: each connection's messages rise by one, and the second starts at the entry after the cursor.
    after = numbers[len(got_before) :]
    assert after[0] == confirmed + 1 and after == list(range(confirmed + 1, _head() + 1))
    assert len(numbers) > _head()  # the ten sent before the restart came twice: at least once, said by the number
    found = verifier.read_capture(receiver.lines)
    assert found.problems == [] and found.repeated == 10 and found.gaps == []
    state = _state()
    assert state["error"] == "" and state["backlog"]["entries"] == 0 and state["cursor"] == _head()


def test_a_receiver_that_does_not_read_holds_the_sender_and_nothing_else(admin: TestClient, clock: Clock, monkeypatch):
    monkeypatch.setattr(transport, "SEND_TIMEOUT", 1)
    with Receiver("tcp") as receiver:
        _set(admin, **_to(receiver))
        clock.passes(2)
        receiver.wait(_head())
        receiver.reading.clear()  # connected, and taking nothing
        with SessionLocal() as db:
            for number in range(4000):
                audit.record(db, "anna", "test.flood", f"{number} " + "x" * 400)
            db.commit()
        began = time.perf_counter()
        did = clock.passes(1)
        # The socket filled: the pass waited for the receiver, no longer than its timeout, and gave up.
        assert "failed" in did and time.perf_counter() - began < 10
        assert "is not reading" in _state()["error"]
        confirmed = _state()["cursor"]
        assert confirmed < _head()
        # Writing to the log never waited for any of it.
        began = time.perf_counter()
        _write(3, start=9000)
        assert time.perf_counter() - began < 2
        receiver.reading.set()
        for _ in range(12):
            clock.passes(1, step=70)
            if _state()["backlog"]["entries"] == 0:
                break
            time.sleep(0.2)
        clock.passes(1)
        assert _state()["backlog"]["entries"] == 0 and _state()["error"] == ""
        receiver.wait(10**9, timeout=1)
        assert set(receiver.numbers()) == set(range(1, _head() + 1)) and receiver.errors == []
        assert verifier.read_capture(receiver.lines).problems == []


def test_a_log_changed_after_it_was_sent_is_said_and_sent_again_so_the_receiver_holds_both(
    admin: TestClient, clock: Clock, tmp_path, monkeypatch
):
    from sqlalchemy import delete, update

    from app.core.config import settings
    from app.core.db import engine
    from app.core.models import AuditChain

    (tmp_path / "backups").mkdir()
    monkeypatch.setattr(settings, "BACKUP_DIR", str(tmp_path / "backups"))
    with Receiver("tcp") as receiver:
        _set(admin, **_to(receiver))
        _write(6)
        clock.passes(2)
        _write(4, start=6)
        clock.passes(2)
        total = _head()
        receiver.wait(total)
        assert _state()["cursor"] == total
        with SessionLocal() as db:
            sent_head = forward.cursor(db)
            assert sent_head[0] == total
            kept = db.scalar(select(AuditEntry.hash).where(AuditEntry.seq == total - 3))
        # Somebody removes the three newest entries and puts the head back: consistent on the server.
        with engine.begin() as conn:
            conn.execute(delete(AuditEntry).where(AuditEntry.seq > total - 3))
            conn.execute(update(AuditChain).values(seq=total - 3, hash=kept))
        # The trimming that says so is not that: an entry that follows the cursor still names its hash.
        _write(2, start=50)
        did = clock.passes(3)
        assert any(word.startswith("sent:") for word in did)
        receiver.wait(total + 3)
        clock.passes(1)
        said = [body for body in receiver.bodies() if body["action"] == "audit.forward.diverged"]
        assert len(said) == 1
        assert said[0]["details"].startswith(
            f"Entry {total} is no longer in the log as it was sent to tcp://127.0.0.1:"
        )
        assert "The log is sent again from entry" in said[0]["details"]
        # The receiver holds what the log said and what it says now: the same numbers, another content.
        found = verifier.read_capture(receiver.lines)
        assert [(problem.kind, problem.seq) for problem in found.problems][0] == ("rewritten", total - 2)
        # The head the receiver ever took is not moved back, and the walk of the chain is held against it.
        with SessionLocal() as db:
            assert forward.cursor(db) == sent_head
            problem = chain.verify(db, full=True)["problem"]
            db.commit()
        assert problem["kind"] in ("rewritten", "cut") and "The forwarding to syslog" in problem["text"]
        # Said once: the passes that follow send what is written and nothing else.
        _write(1, start=60)
        clock.passes(3)
        assert len([body for body in receiver.bodies() if body["action"] == "audit.forward.diverged"]) == 1


def test_one_process_sends_at_a_time(admin: TestClient, clock: Clock):
    with Receiver("tcp") as receiver:
        _set(admin, **_to(receiver))
        assert any(word.startswith("sent:") for word in forward.ship(now=clock.now(), holder="one"))
        # Another process finds the lease taken: it sends nothing, and holds no connection.
        assert forward.ship(now=clock.now() + 1, holder="two") == []
        receiver.wait(_head())
        assert receiver.numbers() == list(range(1, _head() + 1)) and receiver.connections == 1


# --------------------------------------------------------------------------- #
# TLS                                                                         #
# --------------------------------------------------------------------------- #
def test_tls_verifies_the_receiver_against_what_was_pasted_and_presents_a_client_certificate(
    admin: TestClient, clock: Clock, tmp_path
):
    authority = Authority()
    certificate, key = authority.issue("nik-client", server=False)
    with Receiver("tls", tmp_path, authority, want_client=True) as receiver:
        base = {"enabled": True, "host": "localhost", "port": receiver.port, "protocol": "tls"}
        # No authority given: the certificate of the double is nobody's, and nothing is sent.
        _set(admin, **base)
        _write(3)
        assert "failed" in clock.passes(1)
        assert "certificate of localhost was refused" in _state()["error"]
        assert receiver.raw == []
        # Its authority pasted, and no client certificate: the receiver refuses the client.
        _set(admin, ca=authority.pem)
        clock.passes(4, step=70)
        assert receiver.raw == [] and _state()["error"]
        # With the client certificate: everything leaves.
        _set(admin, clientCert=certificate, clientKey=key)
        clock.passes(4, step=70)
        receiver.wait(_head())
        assert receiver.numbers()[: _head()] == list(range(1, _head() + 1))
        clock.passes(1)
        assert _state()["error"] == "" and _state()["cursor"] >= 4
        assert receiver.errors == [] or all("handshake" in error for error in receiver.errors)
    # A certificate of the receiver pasted alone pins it; a name it does not carry is checked unless told not to.
    forward.reset()
    with Receiver("tls", tmp_path, authority) as receiver:
        _set(admin, host="127.0.0.1", port=receiver.port, ca=receiver.certificate, clientCert="", verifyName=True)
        clock.passes(4, step=70)
        receiver.wait(1)
        assert receiver.numbers()[:1] == [1]
    forward.reset()
    with Receiver("tls", tmp_path, authority, name="collector.internal") as receiver:
        _set(admin, host="localhost", port=receiver.port, ca=authority.pem)
        clock.passes(3, step=70)
        assert receiver.raw == [] and "refused" in _state()["error"]
        _set(admin, verifyName=False)
        clock.passes(4, step=70)
        receiver.wait(1)
        assert receiver.numbers()[:1] == [1]
    # Another authority's receiver on the same name is refused: the pin is what is trusted, not the name.
    forward.reset()
    with Receiver("tls", tmp_path, Authority("Somebody else")) as receiver:
        _set(admin, host="localhost", port=receiver.port, verifyName=True)
        clock.passes(3, step=70)
        assert receiver.raw == [] and "refused" in _state()["error"]


# --------------------------------------------------------------------------- #
# UDP                                                                         #
# --------------------------------------------------------------------------- #
def test_udp_sends_one_datagram_an_entry_and_shortens_what_does_not_fit(admin: TestClient, clock: Clock):
    with Receiver("udp") as receiver:
        _set(admin, **_to(receiver, maxDatagram=900))
        with SessionLocal() as db:
            audit.record(db, "anna", "test.big", "d" * 400, target="t" * 4000)
            db.commit()
        total = _head()
        clock.passes(1)
        receiver.wait(total + 1)
        assert receiver.numbers() == list(range(1, total + 1))
        assert all(len(datagram) <= 900 for datagram in receiver.raw)
        big = receiver.bodies()[-1]
        assert big["truncated"] is True and big["action"] == "test.big"
        # A datagram counts as sent when it left: the cursor moves in the same pass.
        assert _state()["cursor"] == total and _state()["sent"] == total
        assert verifier.read_capture(receiver.lines).problems == []
        assert len(receiver.bodies("checkpoint")) == 1


# --------------------------------------------------------------------------- #
# The last word                                                               #
# --------------------------------------------------------------------------- #
def test_the_old_receiver_hears_of_the_change_before_it_takes_effect(admin: TestClient, clock: Clock):
    with Receiver("tcp") as old, Receiver("tcp") as new:
        _set(admin, **_to(old))
        _write(3)
        clock.passes(2)
        old.wait(_head())
        # Pointed elsewhere: the entry that says so goes to the old receiver, and is the last it gets.
        _set(admin, port=new.port, startFrom="now")
        change = _head()
        _write(2, start=10)  # written after the change: not for the old receiver
        assert _state()["pendingChange"] is True
        clock.passes(1)
        old.wait(change)
        assert new.raw == []
        last = old.bodies()[-1]
        assert last["seq"] == change and last["action"] == "audit.forward.settings"
        assert last["details"].startswith(f"Pointed the forwarding of the audit log from tcp://127.0.0.1:{old.port} to")
        clock.passes(3)
        new.wait(3)
        assert old.bodies()[-1]["seq"] == change  # nothing after it
        # The new receiver starts at that same entry ("from now"), and gets what followed.
        assert new.numbers() == list(range(change, _head() + 1))
        assert _state()["destination"] == f"tcp://127.0.0.1:{new.port}" and _state()["pendingChange"] is False
        # Turned off: the last thing the receiver hears is that.
        _set(admin, enabled=False)
        off = _head()
        clock.passes(3)
        new.wait(len(new.raw) + 1, timeout=2)
        assert new.bodies()[-1]["seq"] == off
        assert new.bodies()[-1]["details"].startswith("Turned off the forwarding of the audit log to tcp://127.0.0.1")
        _write(2, start=20)
        clock.passes(3)
        assert new.bodies()[-1]["seq"] == off and _state()["destination"] == ""


def test_a_dead_receiver_does_not_keep_the_forwarding_from_being_changed(admin: TestClient, clock: Clock):
    dead = Receiver("tcp").start()
    port = dead.port
    dead.stop()
    with Receiver("tcp") as new:
        _set(admin, enabled=True, host="127.0.0.1", port=port, protocol="tcp")
        clock.passes(2)
        assert _state()["error"]
        _set(admin, port=new.port)
        clock.passes(3, step=2)
        assert _state()["pendingChange"] is True and new.raw == []  # still trying to tell the old one
        clock.passes(2, step=forward.LAST_WORD_SECONDS)
        new.wait(_head())
        assert _state()["pendingChange"] is False
        # A new receiver gets the log from its beginning, and an entry says what the old one never heard.
        numbers = new.numbers()
        assert numbers[0] == 1
        clock.passes(2)
        new.wait(_head())
        unheard = [body for body in new.bodies() if body["action"] == "audit.forward.unheard"]
        assert (
            len(unheard) == 1 and f"The receiver tcp://127.0.0.1:{port} did not take the last" in unheard[0]["details"]
        )


# --------------------------------------------------------------------------- #
# Where the sender may connect                                                #
# --------------------------------------------------------------------------- #
def test_the_receiver_is_an_exception_of_its_own_for_that_host_and_port_only(admin: TestClient, monkeypatch):
    asked = []

    def resolve(host, port, datagram):
        asked.append((host, port))
        return {
            "siem.corp": [(2, "10.20.30.40")],
            "meta.corp": [(2, "169.254.169.254")],
            "multi.corp": [(2, "224.0.0.5")],
            "mixed.corp": [(2, "10.0.0.1"), (2, "169.254.10.10")],
        }.get(host, [])

    monkeypatch.setattr(transport, "resolve", resolve)
    # A private address is the normal place of a SIEM: allowed, because it is the receiver that was set.
    assert transport.address_of("siem.corp", 6514) == (2, "10.20.30.40")
    for host, why in (("meta.corp", "link-local"), ("multi.corp", "multicast"), ("mixed.corp", "link-local")):
        with pytest.raises(transport.TransportError, match=why):
            transport.address_of(host, 6514)
    with pytest.raises(transport.TransportError, match="could not be resolved"):
        transport.address_of("nowhere.corp", 6514)
    # The connection goes to the address that was checked, never to the name again.
    connected = []

    def connect(address, timeout):
        connected.append(address)
        raise OSError(111, "Connection refused")

    monkeypatch.setattr(transport.socket, "create_connection", connect)
    link = transport.Connection({"host": "siem.corp", "port": 6514, "protocol": "tcp"})
    with pytest.raises(transport.TransportError, match="siem.corp:6514 cannot be reached"):
        link.connect()
    assert connected == [("10.20.30.40", 6514)] and asked[-1] == ("siem.corp", 6514)
    # It opens nothing for a playbook: the same host, set as the receiver, is still refused to a
    # playbook that does not list it, and still an address inside the network to one that may reach any host.
    _set(admin, enabled=True, host="siem.corp", port=6514, protocol="tcp")
    monkeypatch.setattr(egress, "resolve", lambda host, port: ["10.20.30.40"])
    with pytest.raises(egress.EgressError, match="not among the hosts"):
        egress.destination(egress.Policy(), "https://siem.corp:6514/")
    with pytest.raises(egress.EgressError, match="inside the network"):
        egress.destination(egress.Policy(mode="any"), "https://siem.corp:6514/")
    with SessionLocal() as db:
        from app.automation import state

        assert "siem.corp" not in json.dumps(state.read(db)["hosts"])


# --------------------------------------------------------------------------- #
# Test                                                                        #
# --------------------------------------------------------------------------- #
def test_the_test_button_sends_a_marked_message_and_says_what_the_socket_said(admin: TestClient, tmp_path):
    stop = threading.Event()

    def sender() -> None:
        while not stop.is_set():
            forward.ship()
            time.sleep(0.2)

    thread = threading.Thread(target=sender, daemon=True)
    authority = Authority()
    with Receiver("tls", tmp_path, authority) as receiver:
        # Saved and not turned on: the test works before anything is forwarded.
        _set(admin, enabled=False, host="localhost", port=receiver.port, ca=authority.pem)
        thread.start()
        try:
            answer = admin.post("/api/audit/forwarding/test").json()
            assert answer["ok"] is True, answer
            assert f"Connected to 127.0.0.1:{receiver.port} with TLSv1.3" in answer["message"]
            assert "the receiver presented commonName=localhost" in answer["message"]
            assert "kept the connection open" in answer["message"]
            receiver.wait(1)
            tests = receiver.bodies("test")
            assert len(tests) == 1 and tests[0]["test"] == answer["mark"] and receiver.bodies() == []
            assert HEADER.match(receiver.lines[0]).group(6) == "test"
            port = receiver.port
        finally:
            pass
    try:
        # Nothing listens any more: the answer says what the socket said.
        answer = admin.post("/api/audit/forwarding/test").json()
        assert answer["ok"] is False and f"localhost:{port} cannot be reached" in answer["message"]
    finally:
        stop.set()
        thread.join(timeout=5)
    with SessionLocal() as db:
        said = [row.details for row in db.scalars(select(AuditEntry).where(AuditEntry.action == "audit.forward.test"))]
    assert said == [f"Tested the syslog receiver tls://localhost:{port}"] * 2

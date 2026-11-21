"""The audit log as a chain: its canonical form, the order under concurrent writers, every
kind of tampering found and named, what only a head kept outside shows, trimming, restores,
and the standalone verifier."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, func, select, text, update

from app.auditlog import chain, forward, restored, syslog, verifier
from app.auditlog import key as signing
from app.core import audit
from app.core.config import settings
from app.core.db import SessionLocal, engine
from app.core.models import AuditChain, AuditEntry, Setting
from app.main import app as fastapi_app
from tests.conftest import make_key

POSTGRES = engine.dialect.name == "postgresql"
ZERO = "0" * 64


@pytest.fixture()
def heads(tmp_path, monkeypatch):
    """A backup directory of the test's own: where the heads are noted outside the database."""
    folder = tmp_path / "backups"
    folder.mkdir()
    monkeypatch.setattr(settings, "BACKUP_DIR", str(folder))
    return folder / chain.HEADS_FILE


def _write(count: int, actor: str = "anna", start: int = 0) -> None:
    with SessionLocal() as db:
        for number in range(start, start + count):
            audit.record(db, actor, "test.entry", f"entry {number}", target=f"t{number}")
            db.commit()


def _rows() -> list[AuditEntry]:
    with SessionLocal() as db:
        return list(db.scalars(select(AuditEntry).order_by(AuditEntry.seq)))


def _verify(**options) -> dict:
    with SessionLocal() as db:
        state = chain.verify(db, **options)
        db.commit()
        return state


def _as_dict(row: AuditEntry) -> dict:
    return {name: getattr(row, name) for name in (*verifier.FIELDS, "origin", "mac", "key_id")} | {
        "seq": row.seq,
        "prev": row.prev_hash,
        "hash": row.hash,
    }


# --------------------------------------------------------------------------- #
# The canonical form                                                          #
# --------------------------------------------------------------------------- #
def test_the_canonical_form_is_the_one_written_down_byte_for_byte():
    entry = {
        "id": "7f1c",
        "at": "2026-11-20T09:15:02.481220+00:00",
        "actor": "anna",
        "action": "user.update",
        "target": None,
        "details": 'Changed "Bär"\nline two',
        "incident_id": "",
        "incident_name": None,
    }
    expected = (
        b"nik-audit-1\n"
        b"seq 12\n"
        b"prev " + b"ab" * 32 + b"\n"
        b"id 4:7f1c\n"
        b"at 32:2026-11-20T09:15:02.481220+00:00\n"
        b"actor 4:anna\n"
        b"action 11:user.update\n"
        b"target -\n"
        b'details 23:Changed "B\xc3\xa4r"\nline two\n'
        b"incident_id 0:\n"
        b"incident_name -\n"
    )
    assert verifier.canonical(12, "ab" * 32, entry) == expected
    assert verifier.entry_hash(12, "ab" * 32, entry) == hashlib.sha256(expected).hexdigest()
    # Nothing and the empty text are not the same entry, nor is a text that looks like the next field.
    assert verifier.entry_hash(12, ZERO, entry) != verifier.entry_hash(12, ZERO, {**entry, "target": ""})
    assert verifier.entry_hash(12, ZERO, {**entry, "actor": "a\naction 1:x"}) != verifier.entry_hash(12, ZERO, entry)
    # An entry that came in a file from another server has one more line, hashed with the rest:
    # the entries the server wrote itself are hashed exactly as before.
    assert verifier.canonical(12, "ab" * 32, {**entry, "origin": "import"}) == expected + b"origin 6:import\n"
    assert verifier.canonical(12, "ab" * 32, {**entry, "origin": None}) == expected
    assert verifier.normal({"origin": "import"})["origin"] == "import" and "origin" not in verifier.normal({})
    # The API's names for the two fields that differ are read as the columns.
    assert verifier.normal({"incidentId": "i", "incidentName": "n", "prev": "p"}) | {} == verifier.normal(
        {"incident_id": "i", "incident_name": "n", "prev_hash": "p"}
    )


def test_the_verifier_file_needs_nothing_of_nik(tmp_path):
    """Copied out and run alone, as the guide says: only the standard library is imported."""
    source = Path(verifier.__file__).read_text(encoding="utf-8")
    assert "from ." not in source and "import app" not in source and "sqlalchemy" not in source
    copy = tmp_path / "verifier.py"
    copy.write_text(source, encoding="utf-8")
    entries, prev = [], ZERO
    for seq in range(1, 4):
        entry = {"id": f"e{seq}", "at": "2026-01-01T00:00:00+00:00", "actor": "a", "action": "x", "details": str(seq)}
        entry |= {"target": None, "incident_id": None, "incident_name": None}
        hashed = verifier.entry_hash(seq, prev, entry)
        entries.append(entry | {"seq": seq, "prev": prev, "hash": hashed})
        prev = hashed
    export = tmp_path / "export.jsonl"
    export.write_text("\n".join(json.dumps(entry) for entry in entries), encoding="utf-8")
    ran = subprocess.run([sys.executable, "-I", str(copy), str(export)], capture_output=True, text=True, cwd=tmp_path)
    assert ran.returncode == 0, ran.stdout + ran.stderr
    assert "3 entries hold together" in ran.stdout and f"head 3:{prev}" in ran.stdout
    assert "Nothing outside the log was given" in ran.stdout
    entries[1]["details"] = "changed"
    export.write_text(json.dumps({"entries": entries}), encoding="utf-8")
    ran = subprocess.run([sys.executable, "-I", str(copy), str(export)], capture_output=True, text=True, cwd=tmp_path)
    assert ran.returncode == 1 and "PROBLEM (edited, entry 2)" in ran.stdout


# --------------------------------------------------------------------------- #
# Linking                                                                     #
# --------------------------------------------------------------------------- #
def test_entries_are_numbered_and_linked_when_their_transaction_commits(client: TestClient):
    with SessionLocal() as db:
        first = audit.record(db, "anna", "test.one", "one")
        assert first.seq is None
        db.flush()
        assert db.scalar(select(AuditEntry.seq).where(AuditEntry.id == first.id)) is None
        # A row added without audit.record, as many handlers do, is linked the same way.
        import uuid

        db.add(
            AuditEntry(id=str(uuid.uuid4()), at="2026-11-20T10:00:00+00:00", actor="b", action="test.two", details="")
        )
        db.commit()
        # The objects of the session carry what was written.
        assert first.seq is not None and first.hash and first.prev_hash
    rows = _rows()
    assert [row.seq for row in rows] == [1, 2]
    # Within one transaction: in the order of their time.
    assert [row.action for row in rows] == ["test.two", "test.one"]
    assert rows[0].prev_hash == ZERO and rows[1].prev_hash == rows[0].hash
    for row in rows:
        assert row.hash == verifier.entry_hash(row.seq, row.prev_hash, _as_dict(row))
    with SessionLocal() as db:
        assert chain.head(db) == (2, rows[1].hash)
        # What is rolled back never takes a number.
        audit.record(db, "anna", "test.gone", "never")
        db.flush()
        db.rollback()
        audit.record(db, "anna", "test.three", "three")
        db.commit()
    assert [(row.seq, row.action) for row in _rows()][-1] == (3, "test.three")
    assert verifier.check(map(_as_dict, _rows())).problem is None


def test_a_savepoint_does_not_link_and_what_it_rolls_back_is_gone(client: TestClient):
    with SessionLocal() as db:
        audit.record(db, "anna", "test.kept", "kept")
        with db.begin_nested():
            audit.record(db, "anna", "test.inner", "inner")
        assert db.scalar(select(func.count()).select_from(AuditEntry).where(AuditEntry.seq.isnot(None))) == 0
        nested = db.begin_nested()
        audit.record(db, "anna", "test.undone", "undone")
        db.flush()
        nested.rollback()
        db.commit()
    assert sorted(row.action for row in _rows()) == ["test.inner", "test.kept"]
    assert [row.seq for row in _rows()] == [1, 2]


def test_the_api_shows_the_place_of_each_entry_and_the_state_of_the_chain(admin: TestClient, heads):
    entries = admin.get("/api/audit").json()["entries"]
    assert entries and all(entry["seq"] and len(entry["hash"]) == 64 and len(entry["prev"]) == 64 for entry in entries)
    assert verifier.check(entries).problem is None
    found = admin.get("/api/audit/chain").json()
    assert found["head"]["seq"] == max(entry["seq"] for entry in entries)
    assert found["verified"] is None and found["problem"] is None and found["guard"] is False
    done = admin.post("/api/audit/chain/verify", json={}).json()
    assert done["problem"] is None and done["verified"]["seq"] == found["head"]["seq"]
    assert done["headFile"]["seq"] == found["head"]["seq"] and heads.exists()
    # Verifying is recorded, and the entry that says so is linked after what it verified.
    last = admin.get("/api/audit").json()["entries"][0]
    assert last["action"] == "audit.verify" and last["seq"] == found["head"]["seq"] + 1
    assert admin.post("/api/audit/chain/verify", json={"head": {"seq": 1, "hash": "nope"}}).status_code == 422
    # Whoever reads the log may walk it; whoever does not may not.
    auditor = TestClient(fastapi_app)
    assert auditor.post("/api/audit/chain/verify", json={}, headers=make_key(admin, roles=["audit"])).status_code == 200
    assert auditor.get("/api/audit/chain", headers=make_key(admin, roles=["analyst"])).status_code == 403


@pytest.mark.skipif(not POSTGRES, reason="several connections writing at once: PostgreSQL only")
def test_concurrent_writers_never_fork_the_chain_on_postgresql(client: TestClient):
    writers, each = 8, 40
    failures: list[BaseException] = []
    ready = threading.Barrier(writers)

    def write(name: int) -> None:
        try:
            ready.wait(timeout=30)
            with SessionLocal() as db:
                for number in range(each):
                    # Some transactions hold several entries, some do other work before they commit.
                    audit.record(db, f"writer{name}", "test.burst", f"{name}/{number}")
                    if number % 5 == 0:
                        audit.record(db, f"writer{name}", "test.burst", f"{name}/{number} again")
                        db.flush()
                        db.execute(text("SELECT pg_sleep(0.002)"))
                    db.commit()
        except BaseException as error:  # noqa: BLE001 - reported by the test below
            failures.append(error)

    threads = [threading.Thread(target=write, args=(name,)) for name in range(writers)]
    clock = time.monotonic()
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=120)
    took = time.monotonic() - clock
    assert not failures, failures
    rows = _rows()
    total = writers * (each + each // 5)
    assert [row.seq for row in rows] == list(range(1, total + 1)), "a number is missing or was given twice"
    walk = verifier.check(map(_as_dict, rows))
    assert walk.problem is None and walk.count == total
    with SessionLocal() as db:
        assert chain.head(db) == (total, rows[-1].hash)
    # The entries of one writer are in the order it wrote them.
    for name in range(writers):
        mine = [row.details for row in rows if row.actor == f"writer{name}"]
        assert mine == sorted(mine, key=lambda words: (int(words.split("/")[1].split()[0]), "again" in words))
    print(f"\n{total} entries from {writers} writers in {took:.2f} s ({total / took:.0f} a second)")


def test_an_entry_written_outside_a_session_is_linked_by_the_next_one(client: TestClient):
    _write(2)
    with engine.begin() as conn:
        conn.execute(
            text("INSERT INTO audit_log (id, at, actor, action, details) VALUES ('raw', '2020-01-01', 'x', 'raw', '')")
        )
    assert chain.link_strays() == 1
    rows = _rows()
    assert [(row.id == "raw", row.seq) for row in rows][-1] == (True, 3)
    # Linked and signed, and marked as what the server did not write itself.
    assert [row.origin for row in rows] == [None, None, "outside"] and rows[-1].mac
    assert verifier.check(map(_as_dict, rows)).problem is None
    assert chain.link_strays() == 0


def test_the_scheduled_walk_runs_in_one_process_at_a_time_and_reads_everything_once_a_day(client: TestClient, heads):
    now = 1_795_000_000.0
    _write(4)
    with engine.begin() as conn:
        conn.execute(
            text("INSERT INTO audit_log (id, at, actor, action, details) VALUES ('raw', '2020-01-01', 'x', 'raw', '')")
        )
    first = chain.check(now=now, holder="one")
    # The entry that came from outside a session was linked, then everything was read: the first walk is a full one.
    assert first["problem"] is None and first["verified"]["seq"] == 5 and first["full"]["entries"] == 5
    assert chain.check(now=now + 10, holder="two") is None  # another process holds the lease
    _write(2, start=10)
    later = chain.check(now=now + 300, holder="one")
    assert later["verified"]["seq"] == 7 and later["full"]["at"] == now  # only what is new
    # An edit the walk of what is new cannot see is found by the walk of the next day.
    _tamper(update(AuditEntry).where(AuditEntry.seq == 2).values(target="changed"))
    assert chain.check(now=now + 600, holder="one")["problem"] is None
    found = chain.check(now=now + 86400 + 1, holder="one")
    assert (found["problem"]["kind"], found["problem"]["seq"]) == ("edited", 2)
    # Once the lease ran out, another process takes over.
    assert chain.check(now=now + 86400 + 1000, holder="two")["problem"]["kind"] == "edited"


# --------------------------------------------------------------------------- #
# Tampering                                                                   #
# --------------------------------------------------------------------------- #
def _tamper(statement) -> None:
    with engine.begin() as conn:
        conn.execute(statement)


def test_an_edited_entry_is_found_and_named(client: TestClient, heads):
    _write(6)
    assert _verify()["problem"] is None
    _tamper(update(AuditEntry).where(AuditEntry.seq == 3).values(details="it was not me"))
    # The pass that only reads what is new does not look at entry 3 again: a full walk does.
    assert _verify()["problem"] is None
    problem = _verify(full=True)["problem"]
    assert (problem["kind"], problem["seq"]) == ("edited", 3)
    assert problem["text"] == "The content of entry 3 was changed after it was written"
    # Found again, it is the same problem, since the same moment.
    assert _verify(full=True)["problem"]["since"] == problem["since"]
    # An edit with its hash made again is found at the entry after it.
    rows = _rows()
    forged = verifier.entry_hash(3, rows[2].prev_hash, _as_dict(rows[2]))
    _tamper(update(AuditEntry).where(AuditEntry.seq == 3).values(hash=forged))
    # Without the key the forged hash has no signature to go with it: found at the entry itself.
    problem = _verify(full=True)["problem"]
    assert (problem["kind"], problem["seq"]) == ("forged", 3)
    assert problem["text"] == (
        "The signature of entry 3 was not made with the key it names: it was rewritten without the key"
    )
    # With the signature taken away instead: an entry the server never signed.
    _tamper(update(AuditEntry).where(AuditEntry.seq == 3).values(mac=None))
    assert (_verify(full=True)["problem"]["kind"], _verify(full=True)["problem"]["seq"]) == ("unsigned", 3)
    # Signed again by somebody who has the key, it is found at the entry after it, by the hashes.
    _tamper(update(AuditEntry).where(AuditEntry.seq == 3).values(mac=verifier.sign(signing.current()[1], forged)))
    problem = _verify(full=True)["problem"]
    assert (problem["kind"], problem["seq"]) == ("relinked", 4)
    with SessionLocal() as db:
        assert chain.out(db)["problem"]["kind"] == "relinked"


def test_an_entry_deleted_in_the_middle_is_found_and_named(client: TestClient, heads):
    _write(6)
    _tamper(delete(AuditEntry).where(AuditEntry.seq.in_((3, 4))))
    problem = _verify()["problem"]
    assert (problem["kind"], problem["seq"]) == ("missing", 3)
    assert "2 entries are missing: 3 to 4" in problem["text"]


def test_entries_whose_order_was_changed_are_found_and_named(client: TestClient, heads):
    _write(6)
    with engine.begin() as conn:
        conn.execute(update(AuditEntry).where(AuditEntry.seq == 2).values(seq=-1))
        conn.execute(update(AuditEntry).where(AuditEntry.seq == 5).values(seq=2))
        conn.execute(update(AuditEntry).where(AuditEntry.seq == -1).values(seq=5))
    problem = _verify()["problem"]
    assert (problem["kind"], problem["seq"]) == ("reordered", 2)
    assert problem["text"] == "Entry 2 was written as entry 5: the order of the log was changed"


def test_a_cut_tail_is_found_by_whatever_still_knows_the_head(client: TestClient, heads):
    _write(6)
    assert _verify()["problem"] is None  # notes the head 6 in the file
    # 1. The newest entries removed, nothing else touched: the head row knows.
    _tamper(delete(AuditEntry).where(AuditEntry.seq > 4))
    problem = _verify()["problem"]
    assert (problem["kind"], problem["seq"]) == ("cut", 5)
    assert "The head of the chain is entry 6 and the log ends at entry 4" in problem["text"]
    # 2. The head row put back to match: the file of heads, outside the database, knows.
    fourth = _rows()[-1].hash
    _tamper(update(AuditChain).values(seq=4, hash=fourth))
    problem = _verify()["problem"]
    assert (problem["kind"], problem["seq"]) == ("cut", 5)
    assert problem["text"].startswith("The file of heads in the backup directory knows the log up to entry 6")
    # 3. The file gone too, and what the walk remembered: nothing on the server can tell any more.
    heads.unlink()
    _tamper(delete(Setting).where(Setting.id == chain.SETTINGS_ID))
    assert _verify(full=True)["problem"] is None
    # 4. A head that left the server (the last checkpoint a receiver got) still tells.
    problem = _verify(outside=(6, "f" * 64))["problem"]
    assert (problem["kind"], problem["seq"]) == ("cut", 5)
    assert problem["text"].startswith("The head given knows the log up to entry 6 and it ends at entry 4")


def _compute_again(before: list[AuditEntry], key: bytes | None) -> None:
    """Entry 3 changed, and everything from it on computed again, head included: what somebody
    who can write to the database does. With ``key`` they sign what they wrote, too."""
    prev = before[1].hash
    with engine.begin() as conn:
        for row in before[2:]:
            entry = _as_dict(row) | ({"details": "rewritten"} if row.seq == 3 else {})
            hashed = verifier.entry_hash(row.seq, prev, entry)
            conn.execute(
                update(AuditEntry)
                .where(AuditEntry.seq == row.seq)
                .values(
                    details=entry["details"],
                    prev_hash=prev,
                    hash=hashed,
                    **({"mac": verifier.sign(key, hashed)} if key else {}),
                )
            )
            prev = hashed
        conn.execute(update(AuditChain).values(hash=prev))


def test_a_log_computed_again_without_the_key_is_found_by_its_signatures(client: TestClient, heads):
    _write(5)
    second = _rows()[1].hash
    _compute_again(_rows(), None)
    # The hashes hold together again; the signatures are the ones of what was there before.
    assert verifier.check(map(_as_dict, _rows())).problem is None
    problem = _verify(full=True)["problem"]
    assert (problem["kind"], problem["seq"]) == ("forged", 3)
    # Taking the numbers away to have the server link and sign the stretch again does not launder it:
    # what the server did not write itself is marked, and the mark is hashed.
    with engine.begin() as conn:
        conn.execute(
            update(AuditEntry).where(AuditEntry.seq >= 3).values(seq=None, prev_hash=None, hash=None, mac=None)
        )
        conn.execute(update(AuditChain).values(seq=2, hash=second))
    assert chain.link_strays() == 3
    rows = _rows()
    assert [row.origin for row in rows] == [None, None, "outside", "outside", "outside"]
    assert _verify(full=True)["problem"] is None  # linked and signed, and plainly not the server's own
    for row in rows[2:]:
        assert row.hash == verifier.entry_hash(row.seq, row.prev_hash, _as_dict(row))
        assert row.hash != verifier.entry_hash(row.seq, row.prev_hash, _as_dict(row) | {"origin": None})


def test_a_log_computed_again_with_the_key_shows_only_against_a_head_from_outside(client: TestClient, heads):
    _write(5)
    before = _rows()
    _compute_again(before, signing.current()[1])
    # Consistent in itself, signatures included: nothing on the server can tell.
    assert _verify(full=True)["problem"] is None
    problem = _verify(full=True, outside=(5, before[4].hash))["problem"]
    assert (problem["kind"], problem["seq"]) == ("rewritten", 5)
    # Held against an earlier head too: the hash of any entry the outside knows.
    assert _verify(full=True, outside=(2, before[1].hash))["problem"] is None
    assert _verify(full=True, outside=(3, before[2].hash))["problem"]["kind"] == "rewritten"


def test_a_log_that_starts_late_without_saying_why_is_found(client: TestClient, heads):
    _write(5)
    _tamper(delete(AuditEntry).where(AuditEntry.seq < 3))
    problem = _verify(full=True)["problem"]
    assert problem["kind"] == "start"
    assert "starts at entry 3 and no entry says that the 2 before it were removed" in problem["text"]


# --------------------------------------------------------------------------- #
# The key                                                                     #
# --------------------------------------------------------------------------- #
@pytest.fixture()
def no_audit_key(monkeypatch):
    for name in ("AUDIT_KEY", "AUDIT_KEY_FILE", "AUDIT_KEY_PREVIOUS", "AUDIT_KEY_PREVIOUS_FILE", "NIK_AUDIT_KEYS"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(settings, "SECRET_KEY", "the-secret-key-of-the-tests")
    monkeypatch.setattr(settings, "SECRET_KEY_PREVIOUS", [])


def test_the_signature_is_an_hmac_of_the_hash_and_the_id_names_the_key_without_giving_it():
    import hmac

    key = b"a key of the tests"
    hashed = "ab" * 32
    expected = hmac.new(key, b"nik-audit-mac-1\n" + hashed.encode() + b"\n", hashlib.sha256).hexdigest()
    assert verifier.sign(key, hashed) == expected
    assert verifier.fingerprint(key) == hashlib.sha256(b"nik audit key id\n" + key).hexdigest()[:12]
    assert verifier.key_bytes("  a key of the tests\n") == key and verifier.key_bytes("hex:00ff10") == b"\x00\xff\x10"
    entry = {"hash": hashed, "mac": expected, "key_id": f"set-{verifier.fingerprint(key)}"}
    ring = verifier.keyring(["a key of the tests"])
    assert verifier.signature(entry, ring) == "ok"
    assert verifier.signature(entry | {"mac": "0" * 64}, ring) == "forged"
    assert verifier.signature(entry | {"hash": "cd" * 32}, ring) == "forged"
    assert verifier.signature(entry | {"mac": None}, ring) == "unsigned"
    assert verifier.signature(entry, verifier.keyring(["another key"])) == "unknown"
    assert verifier.normal({"keyId": "set-1", "mac": "m"})["key_id"] == "set-1"


def test_every_entry_is_signed_with_a_key_derived_from_secret_key_unless_one_is_set(
    client: TestClient, heads, no_audit_key, monkeypatch, tmp_path
):
    derived_id, derived = signing.current()
    assert derived_id == f"derived-{verifier.fingerprint(derived)}" and len(derived) == 32
    assert derived == signing.derived("the-secret-key-of-the-tests") != signing.derived("another")
    _write(2)
    rows = _rows()
    assert all(row.key_id == derived_id and row.mac == verifier.sign(derived, row.hash) for row in rows)
    # The key is nowhere in the database: only its id.
    with engine.connect() as conn:
        everything = json.dumps(
            [[str(value) for value in row] for row in conn.execute(text("SELECT * FROM audit_log"))]
        )
        everything += json.dumps([str(row) for row in conn.execute(text("SELECT * FROM settings"))])
    assert derived.hex() not in everything and "the-secret-key-of-the-tests" not in everything
    # A key of its own, from the environment or from a file: it signs from the next entry on.
    monkeypatch.setenv("AUDIT_KEY", "a key of its own")
    own_id, own = signing.current()
    assert own_id == f"set-{verifier.fingerprint(b'a key of its own')}" and own == b"a key of its own"
    _write(1, start=5)
    monkeypatch.delenv("AUDIT_KEY")
    (tmp_path / "audit.key").write_text("hex:" + "5a" * 32 + "\n", encoding="utf-8")
    monkeypatch.setenv("AUDIT_KEY_FILE", str(tmp_path / "audit.key"))
    assert signing.current() == (f"set-{verifier.fingerprint(b'Z' * 32)}", b"Z" * 32)
    _write(1, start=6)
    assert [row.key_id.split("-")[0] for row in _rows()] == ["derived", "derived", "set", "set"]
    assert len({row.key_id for row in _rows()}) == 3
    # Entries of the derived key still verify (it is made from SECRET_KEY); those of the key that was
    # replaced and not kept cannot be checked, which is said and is not a break.
    state = _verify(full=True)
    assert state["problem"] is None and state["unchecked"] == {own_id: 1}
    with SessionLocal() as db:
        found = chain.out(db)
    assert found["keyId"].startswith("set-") and found["unchecked"] == {own_id: 1} and found["outside"] == 0
    # Kept as an earlier key, they are checked again.
    monkeypatch.setenv("AUDIT_KEY_PREVIOUS", "something else, a key of its own")
    assert _verify(full=True)["unchecked"] == {}
    # A key that cannot be checked is not a way round: an entry rewritten under it is still found
    # by the hashes, and one whose signature is taken away is unsigned whatever the key.
    monkeypatch.delenv("AUDIT_KEY_PREVIOUS")
    _tamper(update(AuditEntry).where(AuditEntry.seq == 3).values(mac=None))
    assert _verify(full=True)["problem"]["kind"] == "unsigned"


def test_changing_secret_key_starts_a_new_derived_key_and_the_old_entries_follow_the_previous_one(
    client: TestClient, heads, no_audit_key, monkeypatch, capsys
):
    from app.auditlog import __main__ as command

    old_id, old = signing.current()
    _write(3)
    assert command.main(["key", "--derived"]) == 0
    printed = capsys.readouterr().out.strip()
    assert printed == "hex:" + old.hex()
    # SECRET_KEY is changed, with the old value kept for the start: nothing is lost.
    monkeypatch.setattr(settings, "SECRET_KEY", "a-new-secret-key")
    monkeypatch.setattr(settings, "SECRET_KEY_PREVIOUS", ["the-secret-key-of-the-tests"])
    new_id, _new = signing.current()
    assert new_id != old_id and new_id.startswith("derived-")
    _write(2, start=10)
    assert [row.key_id for row in _rows()] == [old_id] * 3 + [new_id] * 2
    state = _verify(full=True)
    assert state["problem"] is None and state["unchecked"] == {}
    assert command.main(["key"]) == 0
    said = capsys.readouterr().out
    assert f"Entries are signed with the key {new_id}." in said and old_id.split("-")[1] in said
    # The old value is taken away: the entries it signed cannot be checked any more, and that is
    # what is said. Their place in the chain of hashes is verified all the same.
    monkeypatch.setattr(settings, "SECRET_KEY_PREVIOUS", [])
    state = _verify(full=True)
    assert state["problem"] is None and state["unchecked"] == {old_id: 3} and state["verified"]["seq"] == 5
    assert command.main(["verify-audit", "--full"]) == 0
    assert f"3 entries cannot be checked: this server can no longer make the key {old_id}." in capsys.readouterr().out
    # Unless the old derived key was kept, as the command printed it.
    monkeypatch.setenv("AUDIT_KEY_PREVIOUS", printed)
    assert _verify(full=True)["unchecked"] == {}
    # A walk of what is new adds to what the full one counted, and does not count twice.
    monkeypatch.delenv("AUDIT_KEY_PREVIOUS")
    assert _verify(full=True)["unchecked"] == {old_id: 3}
    _write(1, start=20)
    assert _verify()["unchecked"] == {old_id: 3}


def test_the_standalone_verifier_checks_signatures_only_when_it_is_given_the_key(
    client: TestClient, heads, no_audit_key, monkeypatch, tmp_path, capsys
):
    from app.auditlog import __main__ as command

    _write(4)
    export = tmp_path / "audit.jsonl"
    assert command.main(["export", str(export)]) == 0
    capsys.readouterr()
    rows = [_as_dict(row) for row in _rows()]
    capture = tmp_path / "capture.log"
    capture.write_text("\n".join(_capture(rows)) + "\n", encoding="utf-8")
    # No key: the hashes are checked, and it says plainly that the signatures were not.
    assert verifier.main([str(export), "--syslog", str(capture)]) == 0
    said = capsys.readouterr().out
    assert "export: signatures not checked: no key" in said and "syslog: signatures not checked: no key" in said
    # The key in a file, or in the environment: never on the command line.
    keys = tmp_path / "keys"
    keys.write_text("hex:" + signing.derived(settings.SECRET_KEY).hex() + "\n", encoding="utf-8")
    assert verifier.main([str(export), "--syslog", str(capture), "--keys", str(keys)]) == 0
    said = capsys.readouterr().out
    assert "export: 4 signatures hold" in said and "syslog: 4 signatures hold" in said
    monkeypatch.setenv("NIK_AUDIT_KEYS", "not the key")
    assert verifier.main([str(export)]) == 0
    said = capsys.readouterr().out
    assert "export: 0 signatures hold" in said
    assert f"export: 4 cannot be checked: the key {rows[0]['key_id']} was not given" in said
    monkeypatch.delenv("NIK_AUDIT_KEYS")
    # A log computed again by somebody without the key: fine to who has no key, forged to who has it.
    entries = [json.loads(line) for line in export.read_text(encoding="utf-8").splitlines()]
    prev = entries[0]["hash"]
    for entry in entries[1:]:
        entry["details"] = entry["details"] + " (rewritten)"
        entry["prev"] = prev
        entry["hash"] = prev = verifier.entry_hash(entry["seq"], prev, verifier.normal(entry))
    export.write_text("\n".join(json.dumps(entry) for entry in entries), encoding="utf-8")
    assert verifier.main([str(export)]) == 0
    assert verifier.main([str(export), "--keys", str(keys)]) == 1
    assert "PROBLEM (forged, entry 2)" in capsys.readouterr().out
    # The receiver's copy is checked the same way, message by message.
    forged = [line.replace(rows[2]["mac"], "0" * 64) for line in _capture(rows)]
    found = verifier.read_capture(forged, verifier.keyring(keys.read_text().splitlines()))
    assert [(problem.kind, problem.seq) for problem in found.problems] == [("forged", 3)]
    assert verifier.read_capture(forged).problems == []


# --------------------------------------------------------------------------- #
# Trimming                                                                    #
# --------------------------------------------------------------------------- #
def test_trimming_keeps_a_link_that_says_what_went_and_the_chain_still_verifies(client: TestClient, heads):
    _write(5)
    assert _verify()["problem"] is None
    upto = _rows()[4].hash
    with SessionLocal() as db:
        assert chain.trim(db, "admin") == 5
        db.commit()
    rows = _rows()
    assert [(row.seq, row.action) for row in rows] == [(6, "audit.trim")]
    assert rows[0].details == f"Removed 5 entries, sequence 1 to 5, up to hash {upto}, by clearing the log"
    assert rows[0].prev_hash == upto
    assert _verify(full=True)["problem"] is None
    _write(3, start=10)
    assert _verify()["problem"] is None and _verify(full=True)["problem"] is None
    # A second trim removes the first one's entry with the rest, and the log still explains its start.
    with SessionLocal() as db:
        assert chain.trim(db, "admin") == 4
        db.commit()
    assert [row.seq for row in _rows()] == [10]
    assert _verify(full=True)["problem"] is None
    # Without the entry of the trim, a log that starts late is a log with its start missing.
    _write(2, start=20)
    _tamper(update(AuditEntry).where(AuditEntry.seq == 10).values(seq=None, prev_hash=None, hash=None))
    _tamper(delete(AuditEntry).where(AuditEntry.seq.is_(None)))
    assert _verify(full=True)["problem"]["kind"] == "start"


def test_trimming_by_age_removes_only_the_old_start_of_the_log(client: TestClient, heads):
    now = time.time()
    with SessionLocal() as db:
        for days in (40, 35, 20, 31, 1):  # the fourth is old but comes after one that is not
            import uuid
            from datetime import datetime, timezone

            at = datetime.fromtimestamp(now - days * 86400, timezone.utc).isoformat()
            db.add(AuditEntry(id=str(uuid.uuid4()), at=at, actor="a", action="test.old", details=str(days)))
            db.commit()
        assert chain.trim(db, "admin", older_than_days=30, now=now) == 2
        db.commit()
    rows = _rows()
    assert [row.details for row in rows[:3]] == ["20", "31", "1"]
    assert "sequence 1 to 2" in rows[-1].details and "older than 30 days" in rows[-1].details
    assert _verify(full=True)["problem"] is None
    with SessionLocal() as db:
        assert chain.trim(db, "admin", older_than_days=30, now=now) == 0


def test_what_was_not_forwarded_yet_is_never_trimmed(admin: TestClient, heads):
    saved = admin.put("/api/audit/forwarding", json={"enabled": True, "host": "siem.example", "protocol": "tcp"})
    assert saved.status_code == 200, saved.text
    with SessionLocal() as db:
        total = db.scalar(select(func.count()).select_from(AuditEntry))
    # Turned on and nothing sent: everything waits, nothing goes.
    assert admin.delete("/api/audit").json() == {"removed": 0, "entries": total}
    # The sender took the first three: those may go.
    with SessionLocal() as db:
        third = db.scalar(select(AuditEntry.hash).where(AuditEntry.seq == 3))
        settings_row = db.get(Setting, forward.SETTINGS_ID).doc
        db.add(
            Setting(
                id=forward.STATE_ID,
                doc={
                    "version": settings_row["version"],
                    "active": settings_row["settings"],
                    "cursor": 3,
                    "cursorHash": third,
                    "sent": 3,
                    "sentHead": [3, third],
                },
            )
        )
        db.commit()
    assert admin.delete("/api/audit").json()["removed"] == 3
    assert [row.seq for row in _rows()][0] == 4
    assert _verify(full=True)["problem"] is None


def test_removing_entries_needs_a_signed_in_administrator(admin: TestClient):
    key = make_key(admin, label="adm", roles=["admin"])
    assert TestClient(fastapi_app).delete("/api/audit", headers=key).status_code == 401


# --------------------------------------------------------------------------- #
# After a restore                                                             #
# --------------------------------------------------------------------------- #
def test_a_restore_leaves_an_entry_and_the_chain_goes_on_from_the_restored_head(client: TestClient, heads):
    _write(4)
    assert _verify()["problem"] is None
    backup_head = _rows()[-1].hash
    _write(3, start=4)
    assert _verify()["problem"] is None  # the file of heads now knows entry 7
    # The database goes back to what it was after entry 4 (what a restore does), head included.
    _tamper(delete(AuditEntry).where(AuditEntry.seq > 4))
    _tamper(update(AuditChain).values(seq=4, hash=backup_head))
    _tamper(delete(Setting).where(Setting.id == chain.SETTINGS_ID))
    assert restored.note(engine.url, "nik-20261120-023000", "2026-11-20T02:30:00+00:00") is True
    assert chain.link_strays() == 1
    last = _rows()[-1]
    assert (last.seq, last.action, last.actor, last.prev_hash) == (5, "audit.restore", "server console", backup_head)
    assert last.origin == "outside"  # written by the restore command, not by a transaction of the server
    assert "restored from the backup nik-20261120-023000, taken 2026-11-20T02:30:00+00:00" in last.details
    assert "between the backup and this restore is not in this log" in last.details
    # The heads noted before the restore are not held against the restored log.
    assert _verify(full=True)["problem"] is None
    _write(2, start=50)
    assert _verify()["problem"] is None


# --------------------------------------------------------------------------- #
# The standalone verifier                                                     #
# --------------------------------------------------------------------------- #
def _capture(rows: list[dict], settings_: dict | None = None) -> list[str]:
    """Lines as a receiver writes them: its own prefix, then the message Nik sent."""
    return ["Nov 20 09:15:02 collector nik: " + syslog.render(row, settings_ or {}).decode("utf-8") for row in rows]


def test_the_export_command_and_the_verifier_agree_with_the_server(client: TestClient, heads, tmp_path, capsys):
    from app.auditlog import __main__ as command

    _write(5)
    export = tmp_path / "audit.jsonl"
    assert command.main(["export", str(export)]) == 0
    assert len(export.read_text(encoding="utf-8").splitlines()) == 5
    # An imported entry keeps its mark in the export and in the message, and verifies in both.
    with SessionLocal() as db:
        import uuid

        db.add(
            AuditEntry(
                id=str(uuid.uuid4()),
                at="2019-03-01T08:00:00+00:00",
                actor="somebody elsewhere",
                action="incident.delete",
                details="from a file",
                origin="import",
            )
        )
        db.commit()
    assert command.main(["export", str(export)]) == 0
    last = json.loads(export.read_text(encoding="utf-8").splitlines()[-1])
    assert last["origin"] == "import" and "origin" not in json.loads(export.read_text(encoding="utf-8").splitlines()[0])
    sent = syslog.render(_as_dict(_rows()[-1]) | {"origin": "import"}, {}).decode()
    assert ' action="incident.delete" origin="import" keyid="' in sent and '"origin":"import","mac":"' in sent
    assert verifier.read_capture([sent]).problems == []
    assert verifier.read_capture([sent.replace('"origin":"import"', '"origin":null')]).problems[0].kind == "edited"
    _tamper(delete(AuditEntry).where(AuditEntry.seq == 6))
    _tamper(update(AuditChain).values(seq=5, hash=_rows()[-1].hash))
    assert verifier.main([str(export)]) == 0
    assert command.main(["verify-audit", "--full"]) == 0
    assert "The chain holds: 5 entries, head 5:" in capsys.readouterr().out
    rows = [_as_dict(row) for row in _rows()]
    capture = tmp_path / "capture.log"
    capture.write_text("\n".join(_capture(rows)) + "\n", encoding="utf-8")
    assert verifier.main([str(export), "--syslog", str(capture)]) == 0
    assert "syslog: 5 entries" in capsys.readouterr().out
    # The newest entry removed on the server, head row and all: the receiver's copy shows it.
    _tamper(delete(AuditEntry).where(AuditEntry.seq == 5))
    _tamper(update(AuditChain).values(seq=4, hash=rows[3]["hash"]))
    assert command.main(["export", str(export)]) == 0
    assert verifier.main([str(export)]) == 0
    assert verifier.main([str(export), "--syslog", str(capture)]) == 1
    said = capsys.readouterr().out
    assert "PROBLEM (cut, entry 5): The receiver knows the log up to entry 5 and it ends at entry 4" in said
    assert verifier.main([str(export), "--head", f"5:{rows[4]['hash']}"]) == 1
    assert command.main(["verify-audit", "--head", f"5:{rows[4]['hash']}"]) == 1
    assert "PROBLEM (cut, entry 5)" in capsys.readouterr().out


def test_what_a_receiver_got_is_checked_on_its_own():
    rows, prev = [], ZERO
    for seq in range(1, 8):
        entry = {"id": f"e{seq}", "at": "2026-11-20T09:00:00+00:00", "actor": "anna", "action": "x", "target": None}
        entry |= {"details": f'entry {seq} "quoted" ] \\ é', "incident_id": None, "incident_name": None}
        hashed = verifier.entry_hash(seq, prev, entry)
        rows.append(entry | {"seq": seq, "prev": prev, "hash": hashed})
        prev = hashed
    lines = _capture(rows)
    found = verifier.read_capture(lines)
    assert found.problems == [] and found.head == (7, rows[6]["hash"]) and found.gaps == []
    # Sent again after a reconnection: the same entry twice is not a problem.
    found = verifier.read_capture(lines[:4] + lines[2:])
    assert found.problems == [] and found.repeated == 2 and len(found.chain) == 7
    # A datagram that was lost: a hole, said, not a break.
    found = verifier.read_capture(lines[:3] + lines[5:])
    assert found.problems == [] and found.gaps == [(4, 5)]
    # A line changed on the receiver.
    found = verifier.read_capture([lines[0], lines[1].replace("entry 2", "entry two"), lines[2]])
    assert [(problem.kind, problem.seq) for problem in found.problems] == [("edited", 2)]
    # The same number with another content: a rewriting on the server after it was sent.
    other = rows[4] | {"details": "another"}
    other["hash"] = verifier.entry_hash(5, other["prev"], other)
    found = verifier.read_capture(lines + _capture([other]))
    assert [(problem.kind, problem.seq) for problem in found.problems] == [("rewritten", 5)]
    # … unless it is the entry a restore leaves: then what came after it exists only on the receiver.
    back = rows[4] | {"action": "audit.restore", "details": "The database was restored from the backup b"}
    back["hash"] = verifier.entry_hash(5, back["prev"], back)
    found = verifier.read_capture(lines + _capture([back]))
    assert found.problems == [] and found.head == (5, back["hash"])
    assert found.notes == [
        "The server was restored from a backup at entry 5: the 3 entries it had sent from that number on "
        "exist only here"
    ]
    # A checkpoint is the head the server announced: one that disagrees with the entries is a problem.
    good = syslog.checkpoint(7, rows[6]["hash"], 7, 1795000000.0, {}).decode()
    bad = syslog.checkpoint(7, "e" * 64, 7, 1795000000.0, {}).decode()
    assert verifier.read_capture([*lines, good]).checkpoint == (7, rows[6]["hash"])
    assert [problem.kind for problem in verifier.read_capture([*lines, bad]).problems] == ["rewritten"]
    # A log that ends before the last checkpoint the receiver holds was cut.
    walk = verifier.check(rows[:5])
    held = {row["seq"]: row["hash"] for row in rows[:5]}
    assert [problem.kind for problem in verifier.compare(walk, held, verifier.read_capture([*lines[:5], good]))] == [
        "cut"
    ]


# --------------------------------------------------------------------------- #
# The backups of 6.7 with the chain in the schema                             #
# --------------------------------------------------------------------------- #
from tests.test_backups import backups, quick_keys, set_phrase  # noqa: E402, F401
from tests.test_backups_upgrade import elsewhere  # noqa: E402, F401


def test_a_backup_carries_the_chain_passes_its_restore_test_and_restores_with_it(elsewhere, capsys):  # noqa: F811
    """What 0051 adds (two tables' worth of columns, a unique index, the head row) is nothing a
    backup refuses: it is dumped, the restore test passes, and what is put back verifies."""
    import sqlalchemy as sa

    from app.backups import restore
    from app.core.models import Backup

    path, _source, _target, scratch = elsewhere
    with SessionLocal() as db:
        (taken,) = db.scalars(select(Backup))
        assert (taken.state, taken.verify_state) == ("done", "passed"), taken.verify
        before = {row.seq: row.hash for row in db.scalars(select(AuditEntry)) if row.seq}
    assert restore.main(["restore", str(path)]) == 0
    other = sa.create_engine(scratch.url)
    try:
        with other.connect() as conn:
            rows = [dict(row) for row in conn.execute(sa.text("SELECT * FROM audit_log")).mappings()]
            head = tuple(conn.execute(sa.text("SELECT seq, hash FROM audit_chain WHERE id = 1")).one())
            if other.dialect.name == "postgresql":
                indexes = [
                    row[0]
                    for row in conn.execute(sa.text("SELECT indexdef FROM pg_indexes WHERE tablename = 'audit_log'"))
                ]
                assert any("UNIQUE INDEX ux_audit_log_seq" in index for index in indexes), indexes
    finally:
        other.dispose()
    chained = [row for row in rows if row["seq"] is not None]
    # The log of the backup, as it was when the backup read it, and its head.
    assert chained and {row["seq"]: row["hash"] for row in chained}.items() <= before.items()
    assert head == max((row["seq"], row["hash"]) for row in chained)
    assert verifier.check(row | {"prev": row["prev_hash"]} for row in chained).problem is None
    # And the one entry the restore adds, not linked yet: the server links it when it starts.
    (waiting,) = [row for row in rows if row["seq"] is None]
    assert waiting["action"] == "audit.restore" and waiting["actor"] == "server console"
    assert path.name[: -len(".nikbak")] in waiting["details"]

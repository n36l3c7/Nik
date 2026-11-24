"""The copy of the backups off the server, against an SFTP server of the tests' own
(``sftp_double.py``: real SSH, on the loopback; nothing leaves the machine)."""

from __future__ import annotations

import socket
from pathlib import Path

import pytest
from sqlalchemy import select

from app.backups import config, offsite, runner, watch
from app.core.config import settings
from app.core.db import SessionLocal
from app.core.models import Backup, Setting

from .sftp_double import SftpDouble
from .test_backups import PHRASE, T0, audit_lines, backups, quick_keys, roomy, set_phrase  # noqa: F401 - fixtures


@pytest.fixture()
def second_host(backups, tmp_path, monkeypatch):  # noqa: F811
    """The second host: an SFTP account, and the settings of the first that send copies to it."""
    with SftpDouble(tmp_path / "second-host") as server:
        # The name in the settings is the one an operator would write; the connection goes to the double.
        monkeypatch.setattr(
            offsite.Sftp, "connect", lambda self: socket.create_connection(("127.0.0.1", server.port), 10)
        )
        monkeypatch.setattr(offsite.time, "sleep", lambda _seconds: None)
        set_phrase(backups)
        saved = backups.put(
            "/api/backups/settings",
            json={
                "destination": {
                    "kind": "sftp",
                    "host": "second.nik.example",
                    "port": 22,
                    "user": server.user,
                    "auth": "key",
                    "secret": server.client_pem,
                    "hostKey": server.host_line,
                    "path": "/nik-backups",
                }
            },
        )
        assert saved.status_code == 200, saved.text
        yield backups, server


def remote(server: SftpDouble) -> list[str]:
    folder = server.root / "nik-backups"
    return sorted(path.name for path in folder.iterdir()) if folder.is_dir() else []


def row_of(name: str) -> Backup:
    with SessionLocal() as db:
        return db.get(Backup, name)


def test_a_backup_that_passed_its_test_is_copied_and_checked(second_host):
    client, server = second_host
    name = runner.take(now=T0)
    assert row_of(name).offsite_state == "pending"
    assert offsite.ship(now=T0 + 10) == [f"copied:{name}"]
    assert remote(server) == [f"{name}.json", f"{name}.nikbak"]
    local = runner.file_of(name).read_bytes()
    assert (server.root / "nik-backups" / f"{name}.nikbak").read_bytes() == local
    row = row_of(name)
    assert row.offsite_state == "copied" and row.offsite["bytes"] == len(local) and len(row.offsite["sha256"]) == 64
    assert row.offsite["where"] == f"sftp://{server.user}@second.nik.example:22/nik-backups"
    assert audit_lines("backup.offsite") == [
        f"Copied {name} to {row.offsite['where']} ({len(local)} bytes, checked after the upload)"
    ]
    assert offsite.ship(now=T0 + 20) == [], "copied once"
    shown = client.get("/api/backups").json()
    assert shown["backups"][0]["offsiteState"] == "copied" and shown["state"]["copies"] == row.offsite["where"]
    # Neither the private key nor the passphrase comes back from the server.
    text = client.get("/api/backups").text
    assert "PRIVATE KEY" not in text and PHRASE not in text
    assert shown["settings"]["destination"]["secretSet"] is True and "secret" not in shown["settings"]["destination"]
    with SessionLocal() as db:
        assert "PRIVATE KEY" not in str(db.get(Setting, config.SETTINGS_ID).doc)


def test_a_backup_that_failed_its_test_is_not_copied(second_host):
    _client, server = second_host
    name = runner.take(now=T0)
    with SessionLocal() as db:
        db.get(Backup, name).verify_state = "failed"
        db.commit()
    assert offsite.ship(now=T0 + 10) == [] and remote(server) == []


def test_a_host_key_that_is_not_the_pinned_one_receives_nothing(second_host):
    client, server = second_host
    other = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ0000000000000000000000000000000000000000000"
    assert client.put("/api/backups/settings", json={"destination": {"hostKey": other}}).status_code == 200
    name = runner.take(now=T0)
    assert offsite.ship(now=T0 + 10) == [f"failed:{name}"]
    row = row_of(name)
    assert row.offsite_state == "failed" and "not the one pinned" in row.offsite["error"]
    assert server.host_line in row.offsite["error"], "the key it did present is shown, to compare"
    assert remote(server) == []
    assert server.connections == 1, "a wrong host key is not tried three times"
    # The administrators are told, once; and told when it works again.
    assert watch.check(T0 + 20, usage=roomy) == ["problem:offsite"]
    assert watch.check(T0 + 90, usage=roomy) == []
    assert offsite.ship(now=T0 + 100) == [], "not tried again within the hour"
    client.put("/api/backups/settings", json={"destination": {"hostKey": server.host_line}})
    assert offsite.ship(now=T0 + 3700) == [f"copied:{name}"]
    assert watch.check(T0 + 3800, usage=roomy) == ["solved:offsite"]
    assert len(audit_lines("backup.offsite")) == 2


def test_no_pinned_key_means_nothing_is_sent(second_host):
    client, server = second_host
    client.put("/api/backups/settings", json={"destination": {"hostKey": ""}})
    name = runner.take(now=T0)
    assert row_of(name).offsite_state == "", "a destination with no pinned key is not ready: no copy is asked for"
    assert offsite.ship(now=T0 + 10) == [] and remote(server) == []
    assert client.get("/api/backups").json()["settings"]["destination"]["ready"] is False


def test_a_fingerprint_can_be_pinned_instead_of_the_key(second_host):
    client, server = second_host
    print_of = offsite.fingerprint(server.host_key)
    assert print_of.startswith("SHA256:") and len(print_of) == 50
    assert client.put("/api/backups/settings", json={"destination": {"hostKey": print_of}}).status_code == 200
    name = runner.take(now=T0)
    assert offsite.ship(now=T0 + 10) == [f"copied:{name}"]


def test_a_key_the_account_does_not_know_is_refused(second_host):
    client, server = second_host
    stranger = SftpDouble(server.root.parent / "unused").client_pem
    client.put("/api/backups/settings", json={"destination": {"secret": stranger}})
    name = runner.take(now=T0)
    assert offsite.ship(now=T0 + 10) == [f"failed:{name}"]
    assert "refused the key of the account" in row_of(name).offsite["error"] and remote(server) == []


def test_a_password_works_where_no_key_is_used(second_host):
    client, server = second_host
    server.password = "a password for the double"
    saved = client.put(
        "/api/backups/settings", json={"destination": {"auth": "password", "secret": "a password for the double"}}
    )
    assert saved.status_code == 200 and "a password for the double" not in saved.text
    name = runner.take(now=T0)
    assert offsite.ship(now=T0 + 10) == [f"copied:{name}"]


def test_the_key_can_be_a_stored_credential(second_host):
    client, server = second_host
    made = client.post(
        "/api/automation/credentials",
        json={"name": "backup_host", "kind": "secret", "value": server.client_pem, "title": "x"},
    )
    assert made.status_code in (200, 201), made.text
    saved = client.put("/api/backups/settings", json={"destination": {"secret": "{{ credentials.backup_host }}"}})
    assert saved.status_code == 200, saved.text
    assert saved.json()["settings"]["destination"]["secretCredential"] == "{{ credentials.backup_host }}"
    missing = client.put("/api/backups/settings", json={"destination": {"secret": "{{ credentials.nobody }}"}})
    assert missing.status_code == 422 and "no stored credential named nobody" in missing.json()["detail"]
    name = runner.take(now=T0)
    assert offsite.ship(now=T0 + 10) == [f"copied:{name}"]


def test_an_upload_that_is_cut_is_resumed(second_host, monkeypatch):
    _client, server = second_host
    extra = Path(settings.SAMPLE_STORE) / ("c" * 64 + ".bin")
    extra.write_bytes(bytes(range(256)) * 12_000)  # three megabytes that do not all shrink away
    import os

    extra.write_bytes(os.urandom(3_000_000))
    name = runner.take(now=T0)
    size = runner.file_of(name).stat().st_size
    assert size > 3_000_000
    server.drop_after = 1_000_000
    assert offsite.ship(now=T0 + 10) == [f"copied:{name}"]
    assert server.connections >= 2, "the first connection was cut"
    assert (server.root / "nik-backups" / f"{name}.nikbak").read_bytes() == runner.file_of(name).read_bytes()
    assert remote(server) == [f"{name}.json", f"{name}.nikbak"], "no partial file is left"


def test_what_arrived_is_compared_with_what_was_sent(second_host, monkeypatch):
    _client, server = second_host
    name = runner.take(now=T0)
    real = offsite.Sftp._send

    def corrupting(sftp, source, partial, size):
        real(sftp, source, partial, size)
        target = server.root / partial.lstrip("/")
        data = bytearray(target.read_bytes())
        data[100] ^= 0xFF
        target.write_bytes(bytes(data))

    monkeypatch.setattr(offsite.Sftp, "_send", staticmethod(corrupting))
    assert offsite.ship(now=T0 + 10) == [f"failed:{name}"]
    assert "is not what was sent" in row_of(name).offsite["error"]
    assert remote(server) == [], "what did not match was removed"


def test_the_retention_removes_the_copy_too(second_host):
    client, server = second_host
    client.put("/api/backups/settings", json={"retention": {"last": 1, "weeks": 0}})
    first = runner.take(now=T0)
    assert offsite.ship(now=T0 + 10) == [f"copied:{first}"]
    second = runner.take(now=T0 + 3600)
    assert row_of(first).offsite_state == "delete" and not runner.file_of(first).exists()
    assert [row["id"] for row in client.get("/api/backups").json()["backups"]] == [second]
    assert offsite.ship(now=T0 + 3700) == [f"removed:{first}", f"copied:{second}"]
    assert remote(server) == [f"{second}.json", f"{second}.nikbak"]
    assert row_of(first) is None
    assert f"Removed the copy of {first} off the server" in audit_lines("backup.offsite")
    # Deleted by hand: the same.
    assert client.delete(f"/api/backups/{second}?confirm={second}&lastGood=true").status_code == 200
    assert offsite.ship(now=T0 + 3800) == [f"removed:{second}"] and remote(server) == []


def test_a_copy_that_is_gone_from_the_destination_is_sent_again_or_forgotten(second_host, monkeypatch):
    _client, server = second_host
    monkeypatch.setattr(offsite, "_reconciled", 0.0)
    name = runner.take(now=T0)
    assert offsite.ship(now=T0 + 10) == [f"copied:{name}"]
    (server.root / "nik-backups" / f"{name}.nikbak").unlink()
    assert offsite.ship(now=T0 + 20) == [f"again:{name}"]
    assert offsite.ship(now=T0 + 30) == [f"copied:{name}"], "sent again at the next pass"
    assert remote(server) == [f"{name}.json", f"{name}.nikbak"]
    assert offsite.ship(now=T0 + 40) == [], "looked at once an hour"
    # A row that says a copy exists, with no file here and none there: a database put back from earlier.
    with SessionLocal() as db:
        db.add(
            Backup(id="nik-20260101-000000", state="done", local=False, offsite_state="copied", created_at="2026-01-01")
        )
        db.commit()
    assert offsite.ship(now=T0 + 3700) == ["forgotten:nik-20260101-000000"]
    assert row_of("nik-20260101-000000") is None and row_of(name).offsite_state == "copied"
    assert "The destination no longer holds: nik-20260101-000000" in audit_lines("backup.offsite")


def test_a_snapshot_taken_before_an_upgrade_is_copied_and_its_copy_follows_its_retention(second_host):
    from app.backups import container

    client, server = second_host

    def snapshot(at: float, verified: bool) -> str:
        """A snapshot as the upgrade leaves it: a file and its note in the directory, no row yet."""
        name = runner.new_name("upgrade", at)
        with SessionLocal() as db:
            key = runner.snapshot_key(db)
        note = runner.write_file(name, key, kind="upgrade", label="Before the upgrade from 6.6.1 to 6.7.0", now=at)
        if verified:  # the rehearsal restored it
            runner.write_note({**note, "verify": {"passed": True, "checks": ["rehearsed"], "at": runner.iso(at)}})
        return name

    first = snapshot(T0, verified=True)
    with SessionLocal() as db:
        runner.sync(db)
        db.commit()
    row = row_of(first)
    assert (row.kind, row.verify_state, row.offsite_state) == ("upgrade", "passed", "pending")
    assert offsite.ship(now=T0 + 10) == [f"copied:{first}"]
    assert remote(server) == [f"{first}.json", f"{first}.nikbak"]
    assert (server.root / "nik-backups" / f"{first}.nikbak").read_bytes().startswith(container.MAGIC)
    # One that was not rehearsed is tested before it is sent, like every backup.
    second = snapshot(T0 + 60, verified=False)
    with SessionLocal() as db:
        runner.sync(db)
        db.commit()
    assert (row_of(second).verify_state, row_of(second).offsite_state) == ("queued", "pending")
    assert offsite.ship(now=T0 + 70) == [], "not before its test"
    assert runner.verify(second) is True
    assert offsite.ship(now=T0 + 80) == [f"copied:{second}"]
    # A copy that fails is told like the others, and nothing waited for it.
    third = snapshot(T0 + 120, verified=True)
    with SessionLocal() as db:
        runner.sync(db)
        db.commit()
    client.put("/api/backups/settings", json={"destination": {"hostKey": "SHA256:" + "A" * 43}})
    assert offsite.ship(now=T0 + 130) == [f"failed:{third}"]
    with SessionLocal() as db:
        assert f"The copy of the backup {third} off the server failed" in watch.problems(db, T0 + 140, roomy)["offsite"]
    client.put("/api/backups/settings", json={"destination": {"hostKey": server.host_line}})
    assert offsite.ship(now=T0 + 4000) == [f"copied:{third}"]
    # The upgrade keeps the latest few by itself, by the files: the copy of one it removed goes too.
    for path in (runner.file_of(first), runner.note_of(first)):
        path.unlink()
    with SessionLocal() as db:
        runner.sync(db)
        db.commit()
    assert row_of(first).offsite_state == "delete"
    assert offsite.ship(now=T0 + 4100) == [f"removed:{first}"]
    assert remote(server) == sorted(f"{name}{suffix}" for name in (second, third) for suffix in (".json", ".nikbak"))
    # And the retention of the screen (keep 3, here 1) removes it on both sides.
    client.put("/api/backups/settings", json={"retention": {"upgrades": 1}})
    with SessionLocal() as db:
        assert runner.apply_retention(db, T0 + 4200) == [second]
        db.commit()
    assert offsite.ship(now=T0 + 4300) == [f"removed:{second}"]
    assert remote(server) == [f"{third}.json", f"{third}.nikbak"]


def test_the_test_button_reports_the_key_the_server_presents(second_host, monkeypatch):
    client, server = second_host
    with SessionLocal() as db:
        request = offsite.ask_test(db, now=T0)
        db.commit()
    # Answered even by a process that does not hold the lease: a person is waiting.
    with SessionLocal() as db:
        assert runner.acquire(db, "the container this one replaced", T0, offsite.LEASE)
    assert offsite.ship(now=T0 + 1) == ["test"]
    with SessionLocal() as db:
        runner.release(db, "the container this one replaced", offsite.LEASE)
    with SessionLocal() as db:
        answer = offsite.test_answer(db, request)
    assert answer["ok"] is True and "read back and removed" in answer["message"]
    assert answer["hostKey"] == server.host_line and answer["fingerprint"] == offsite.fingerprint(server.host_key)
    assert remote(server) == [], "the probe file is gone"
    # With no key pinned yet the test fails, and shows the key to compare and pin.
    client.put("/api/backups/settings", json={"destination": {"hostKey": ""}})
    with SessionLocal() as db:
        request = offsite.ask_test(db, now=T0 + 10)
        db.commit()
    assert offsite.ship(now=T0 + 11) == ["test"]
    with SessionLocal() as db:
        answer = offsite.test_answer(db, request)
    assert answer["ok"] is False and "No host key is pinned" in answer["message"]
    assert answer["hostKey"] == server.host_line
    # The route asks and waits for the process that sends; here nobody answers.
    monkeypatch.setattr(offsite, "TEST_ANSWER_WITHIN", 1)
    waited = client.post("/api/backups/destination/test")
    assert waited.status_code == 200 and waited.json()["ok"] is False
    assert "did not answer" in waited.json()["message"]
    assert "Tested the destination of the copy off the server" in audit_lines("backup.request")


def test_a_destination_that_cannot_be_reached_fails_the_copy_and_is_told(second_host, monkeypatch):
    _client, server = second_host

    def unreachable(self):
        raise offsite.OffsiteError("second.nik.example:22 cannot be reached: timed out")

    monkeypatch.setattr(offsite.Sftp, "connect", unreachable)
    name = runner.take(now=T0)
    assert offsite.ship(now=T0 + 10) == [f"failed:{name}"]
    row = row_of(name)
    assert "failed 3 times" in row.offsite["error"] and row.offsite["tries"] == 1
    assert runner.file_of(name).exists(), "the local backup is untouched"
    with SessionLocal() as db:
        assert "off the server failed" in watch.problems(db, T0 + 20, roomy)["offsite"]


def test_without_a_destination_nothing_is_sent_and_nothing_is_wrong(backups):  # noqa: F811
    set_phrase(backups)
    name = runner.take(now=T0)
    assert row_of(name).offsite_state == "" and offsite.ship(now=T0 + 10) == []
    assert backups.post("/api/backups/destination/test").status_code == 409
    with SessionLocal() as db:
        assert "offsite" not in watch.problems(db, T0 + 86400 * 3, roomy)
        assert db.scalars(select(Backup.offsite_state)).all() == [""]


def test_the_files_of_the_pool_go_before_the_backup_that_names_them_and_leave_after_it(second_host):
    import hashlib

    from app.backups import pool
    from app.core.models import BackupBlob

    client, server = second_host
    client.put("/api/backups/settings", json={"retention": {"last": 1, "weeks": 0}})
    data = b"an original of host evidence, named by its hash\n" * 4000
    sha256 = hashlib.sha256(data).hexdigest()
    place = Path(settings.SAMPLE_STORE) / "_evidence"
    place.mkdir()
    (place / f"{sha256}.bin").write_bytes(data)

    first = runner.take(now=T0)
    gen = row_of(first).summary["pool"]
    there = server.root / "nik-backups" / f"pool-{gen}" / sha256[:2] / f"{sha256}{pool.SUFFIX}"
    assert offsite.ship(now=T0 + 10) == [f"copied:{first}"]
    assert there.read_bytes() == pool.blob_path(runner.directory(), gen, sha256).read_bytes()
    assert "after 1 file(s) of the pool it names" in audit_lines("backup.offsite")[-1]

    # The next backup names the same file: it is not sent again.
    sent_at = there.stat().st_mtime_ns
    second = runner.take(now=T0 + 3600)
    assert offsite.ship(now=T0 + 3700) == [f"removed:{first}", f"copied:{second}"]
    assert there.stat().st_mtime_ns == sent_at and "of the pool" not in audit_lines("backup.offsite")[-1]

    # The original is deleted: once no backup names its file of the pool, the copy there goes too.
    (place / f"{sha256}.bin").unlink()
    third = runner.take(now=T0 + 7200)
    assert offsite.ship(now=T0 + 7300) == [f"removed:{second}", f"copied:{third}"]
    with SessionLocal() as db:
        runner.apply_retention(db, T0 + 7400)
        db.commit()
        assert db.get(BackupBlob, (gen, sha256)).offsite_state == "delete"
    assert offsite.ship(now=T0 + 7500) == [f"removed:pool:{sha256[:12]}"]
    assert not there.exists()
    with SessionLocal() as db:
        assert db.get(BackupBlob, (gen, sha256)) is None

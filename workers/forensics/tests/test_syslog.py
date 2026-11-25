"""The ``syslog`` parser: auth.log, journalctl, audit.log and the macOS unified log, made here, never evidence."""

# ruff: noqa: E501 - a log line is one line

from __future__ import annotations

import gzip
import io
import json
import os
import sys
from datetime import UTC, datetime

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nik_forensics import parsers  # noqa: E402
from nik_forensics.context import Context  # noqa: E402
from nik_forensics.parsers import BadLocator, ViewError, syslog  # noqa: E402
from nik_forensics.parsers.syslog_parts import audit, messages  # noqa: E402
from nik_forensics.sigma.engine import Engine  # noqa: E402
from sigma_support import rule  # noqa: E402


def ms(text: str) -> int:
    return int(datetime.fromisoformat(text).replace(tzinfo=UTC).timestamp() * 1000)


def said(path: str, source: str, params: dict | None = None) -> list[dict]:
    out = io.BytesIO()
    syslog.parse(path, Context(out, {"host": "IR-1", **(params or {})}), source)
    return [json.loads(line) for line in out.getvalue().splitlines() if line]


def write(tmp_path, name: str, data: bytes | str, modified: str | None = None) -> str:
    path = tmp_path / name
    path.write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))
    if modified:
        stamp = ms(modified) / 1000
        os.utime(path, (stamp, stamp))
    return str(path)


def records(found: list[dict]) -> list[dict]:
    return [event for event in found if event["t"] == "r"]


def notes(found: list[dict]) -> dict[str, dict]:
    return {event["reason"]: event for event in found if event["t"] == "note"}


def skips(found: list[dict]) -> list[dict]:
    return [event for event in found if event["t"] == "skip"]


def end(found: list[dict]) -> dict:
    return found[-1]


# --------------------------------------------------------------------------- #
# linux.auth                                                                  #
# --------------------------------------------------------------------------- #
AUTH = """\
Nov 25 10:00:01 web01 sshd[1201]: Accepted publickey for alice from 203.0.113.7 port 51822 ssh2: ED25519 SHA256:abc
Nov 25 10:00:02 web01 sshd[1201]: Accepted password for bob from 2001:db8::5 port 22 ssh2
Nov 25 10:00:05 web01 sshd[1202]: Failed password for invalid user admin from 198.51.100.9 port 4242 ssh2
Nov 25 10:00:06 web01 sshd[1203]: Failed password for root from 198.51.100.9 port 4243 ssh2
Nov 25 10:00:07 web01 sshd[1204]: Invalid user test from 198.51.100.9 port 4244
Nov 25 10:00:08 web01 sshd[1205]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=198.51.100.10  user=root
Nov 25 10:01:00 web01 sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow
Nov 25 10:01:01 web01 sudo: pam_unix(sudo:session): session opened for user root(uid=0) by alice(uid=1000)
Nov 25 10:01:30 web01 sudo: pam_unix(sudo:session): session closed for user root
Nov 25 10:01:40 web01 sudo:      bob : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/su
Nov 25 10:01:50 web01 sudo:      eve : user NOT in sudoers ; TTY=pts/2 ; PWD=/tmp ; USER=root ; COMMAND=/bin/ls
Nov 25 10:02:00 web01 useradd[2001]: new user: name=bob2, UID=1001, GID=1001, home=/home/bob2, shell=/bin/bash
Nov 25 10:02:10 web01 passwd[2002]: pam_unix(passwd:chauthtok): password changed for bob2
Nov 25 10:02:20 web01 usermod[2003]: add 'bob2' to group 'sudo'
Nov 25 10:03:00 web01 su[3001]: Successful su for root by alice
Nov 25 10:03:10 web01 su[3002]: FAILED su for root by bob
Nov 25 10:04:00 web01 login[4001]: FAILED LOGIN 1 FROM tty1 FOR carol, Authentication failure
Nov 25 10:04:10 web01 gdm-password]: pam_unix(gdm-password:session): session opened for user dave(uid=1000) by (uid=0)
Nov 25 10:04:30 web01 CRON[5001]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)
Nov 25 10:05:00 web01 kernel: something happened
Nov 25 10:05:01 web01 last message repeated 3 times
"""


def by_type(found: list[dict]) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = {}
    for one in records(found):
        grouped.setdefault(one["type"], []).append(one)
    return grouped


def test_the_module_says_what_it_reads():
    assert syslog.KIND == "syslog" and syslog.NAME == "syslog" and syslog.VERSION == "2"
    assert set(syslog.SOURCES) == {"linux.auth", "linux.journal", "linux.audit", "macos.unifiedlog"}
    assert parsers.by_source("syslog", "linux.audit") is syslog
    assert callable(syslog.view)


def test_every_kind_of_message_that_matters_is_decoded(tmp_path):
    path = write(tmp_path, "auth.log", AUTH, "2026-11-26 00:00:00")
    found = said(path, "linux.auth")
    got = records(found)
    assert len(got) == 21 and end(found)["in_file"] == 21 and end(found)["read"] == 21
    assert all(one["channel"] == "auth" and one["host"] == "web01" for one in got)
    kinds = [one["type"] for one in got]
    assert kinds == [
        "logon", "logon", "logon_failed", "logon_failed", "logon_failed", "logon_failed", "sudo", "session", "session",
        "logon_failed", "sudo", "account", "account", "account", "logon", "logon_failed", "logon_failed", "logon",
        "session", "log", "log",
    ]  # fmt: skip
    first, second, invalid, root, test_user, pam = got[:6]
    assert first["username"] == "alice" and first["ts"] == ms("2026-11-25T10:00:01")
    assert first["data"]["source_ip"] == "203.0.113.7" and first["data"]["source_port"] == 51822
    assert first["data"]["method"] == "publickey" and first["data"]["logon_type"] == "ssh"
    assert first["data"]["key"] == "ED25519 SHA256:abc" and first["data"]["program"] == "sshd"
    assert first["data"]["pid"] == 1201 and first["ioc"] == [["ip", "203.0.113.7"]]
    assert second["data"]["source_ip"] == "2001:db8::5" and second["ioc"] == [["ip", "2001:db8::5"]]
    assert invalid["username"] == "admin" and invalid["data"]["invalid_user"] is True
    assert invalid["data"]["method"] == "password" and invalid["ioc"] == [["ip", "198.51.100.9"]]
    assert root["username"] == "root" and root["data"]["invalid_user"] is False
    assert test_user["username"] == "test" and test_user["data"]["source_port"] == 4244
    assert (
        pam["username"] == "root" and pam["data"]["source_ip"] == "198.51.100.10" and pam["data"]["service"] == "sshd"
    )
    sudo, opened, closed, wrong, refused = got[6:11]
    assert sudo["username"] == "alice" and sudo["ioc"] == []
    assert {k: sudo["data"][k] for k in ("tty", "pwd", "runas", "command")} == {
        "tty": "pts/0",
        "pwd": "/home/alice",
        "runas": "root",
        "command": "/usr/bin/cat /etc/shadow",
    }
    # A session opened by sudo is a session (rights taken), not a logon; the user it runs as stays in the data.
    assert opened["type"] == "session" and opened["data"]["action"] == "opened" and opened["data"]["runas"] == "root"
    assert opened["data"]["logon_type"] == "sudo" and opened["data"]["by"] == "alice" and opened["username"] == "root"
    assert closed["data"]["action"] == "closed" and closed["data"]["service"] == "sudo"
    assert (
        wrong["username"] == "bob" and wrong["data"]["command"] == "/bin/su" and "incorrect" in wrong["data"]["error"]
    )
    assert refused["username"] == "eve" and refused["data"]["error"] == "user NOT in sudoers"
    added, password, group = got[11:14]
    assert (added["data"]["action"], added["username"], added["data"]["uid"]) == ("user_added", "bob2", 1001)
    assert added["data"]["home"] == "/home/bob2" and added["data"]["shell"] == "/bin/bash"
    assert (password["data"]["action"], password["username"]) == ("password_changed", "bob2")
    assert (group["data"]["action"], group["data"]["group"], group["username"]) == ("added_to_group", "sudo", "bob2")
    su_ok, su_bad, login_bad, gdm, cron = got[14:19]
    assert su_ok["username"] == "root" and su_ok["data"]["by"] == "alice" and su_ok["data"]["logon_type"] == "su"
    assert su_bad["type"] == "logon_failed" and su_bad["data"]["by"] == "bob"
    assert login_bad["username"] == "carol" and login_bad["data"]["tty"] == "tty1"
    assert (
        gdm["username"] == "dave" and gdm["data"]["logon_type"] == "gdm" and gdm["data"]["program"] == "gdm-password]"
    )
    assert got[19]["type"] == "log" and got[19]["summary"] == "kernel: something happened"
    assert got[20]["data"]["program"] == "" and got[20]["data"]["message"] == "last message repeated 3 times"


def test_a_session_of_cron_is_a_session_and_not_a_logon(tmp_path):
    path = write(tmp_path, "auth.log", AUTH, "2026-11-26 00:00:00")
    cron = records(said(path, "linux.auth"))[18]
    assert cron["type"] == "session" and cron["data"]["action"] == "opened" and cron["username"] == "root"


def test_the_key_is_stable_and_the_view_is_the_line(tmp_path):
    path = write(tmp_path, "auth.log", AUTH, "2026-11-26 00:00:00")
    one = records(said(path, "linux.auth"))
    again = records(said(path, "linux.auth"))
    assert [r["key"] for r in one] == [r["key"] for r in again]
    assert one[0]["key"].startswith("auth:web01:Nov-25-10:00:01:") and len(set(r["key"] for r in one)) == 21
    shown = syslog.view(path, "linux.auth", one[2]["loc"])
    assert shown["kind"] == "text" and shown["highlight"] == [3, 3]
    assert "Failed password for invalid user admin" in shown["text"].split("\n")[2]
    # The keys do not depend on the year that was assumed.
    other = records(said(path, "linux.auth", {"year": 2020}))
    assert [r["key"] for r in one] == [r["key"] for r in other]
    with pytest.raises(ViewError):
        syslog.view(path, "linux.auth", {"line": 1, "offset": 10**6, "length": 5})
    with pytest.raises(BadLocator):
        syslog.view(path, "linux.auth", {"line": 1})


def test_the_year_is_taken_from_the_files_date_so_that_no_line_is_in_its_future(tmp_path):
    text = "Nov 20 09:00:00 h a[1]: y\nDec  3 10:00:00 h a[1]: x\n"
    found = said(write(tmp_path, "a", text, "2026-11-25 12:00:00"), "linux.auth")
    got = records(found)
    assert [r["ts"] for r in got] == [
        ms("2025-11-20T09:00:00"),
        ms("2025-12-03T10:00:00"),
    ]  # the last one is not in 2026
    year = notes(found)["year assumed"]
    assert year["count"] == 2 and "2025" in year["detail"] and "params.year" in year["detail"]
    given = said(write(tmp_path, "b", text, "2026-11-25 12:00:00"), "linux.auth", {"year": 2019})
    assert [r["ts"] for r in records(given)] == [ms("2019-11-20T09:00:00"), ms("2019-12-03T10:00:00")]
    assert "params.year" in notes(given)["year assumed"]["detail"] and "2019" in notes(given)["year assumed"]["detail"]


def test_the_year_is_taken_from_the_files_own_date_when_the_upload_says_it(tmp_path):
    # The mtime here is the time of the transfer (2026); the file's own date, sent by the browser, is 2023.
    text = "Nov 20 09:00:00 h a[1]: y\nDec  3 10:00:00 h a[1]: x\n"
    path = write(tmp_path, "a", text, "2026-11-25 12:00:00")
    found = said(path, "linux.auth", {"file_time": ms("2023-12-10T08:00:00")})
    assert [r["ts"] for r in records(found)] == [ms("2023-11-20T09:00:00"), ms("2023-12-03T10:00:00")]
    year = notes(found)["year assumed"]["detail"]
    assert "2023-12-10" in year and "own date" in year
    # Not a usable value: the date on the worker, as before.
    for bad in (None, "", 0, -5, "x", True):
        found = said(path, "linux.auth", {"file_time": bad})
        assert records(found)[0]["ts"] == ms("2025-11-20T09:00:00")
        assert "on the worker" in notes(found)["year assumed"]["detail"]


def test_a_december_to_january_turn_adds_a_year(tmp_path):
    text = "Dec 30 23:59:00 h a[1]: one\nDec 31 23:59:59 h a[1]: two\nJan  1 00:00:01 h a[1]: three\nJan  2 08:00:00 h a[1]: four\n"
    found = said(write(tmp_path, "a", text, "2026-01-05 12:00:00"), "linux.auth")
    assert [r["ts"] for r in records(found)] == [
        ms("2025-12-30T23:59:00"),
        ms("2025-12-31T23:59:59"),
        ms("2026-01-01T00:00:01"),
        ms("2026-01-02T08:00:00"),
    ]
    assert "1 time(s)" in notes(found)["year assumed"]["detail"] and "2025" in notes(found)["year assumed"]["detail"]
    given = said(write(tmp_path, "b", text, "2026-01-05 12:00:00"), "linux.auth", {"year": 2023})
    assert records(given)[3]["ts"] == ms("2024-01-02T08:00:00")


def test_a_leap_day_and_a_day_that_does_not_exist(tmp_path):
    text = "Feb 29 10:00:00 h a[1]: leap\nFeb 30 10:00:00 h a[1]: never\n"
    found = said(write(tmp_path, "a", text, "2024-03-05 00:00:00"), "linux.auth")
    got = records(found)
    assert got[0]["ts"] == ms("2024-02-29T10:00:00") and got[1]["ts"] is None
    assert notes(found)["record without a time"]["count"] == 1
    assert notes(found)["line with a date that does not exist in the assumed year"]["count"] == 1


def test_the_times_are_utc_unless_a_zone_is_given_and_a_note_says_so(tmp_path):
    text = "Nov 25 10:00:00 h a[1]: x\n"
    path = write(tmp_path, "a", text, "2026-11-26 00:00:00")
    plain = said(path, "linux.auth")
    assert records(plain)[0]["ts"] == ms("2026-11-25T10:00:00") and "times taken as UTC" in notes(plain)
    rome = said(path, "linux.auth", {"tz": "Europe/Rome"})
    assert records(rome)[0]["ts"] == ms("2026-11-25T09:00:00") and "times taken in Europe/Rome" in notes(rome)
    wrong = said(path, "linux.auth", {"tz": "Nowhere/Land"})
    assert records(wrong)[0]["ts"] == ms("2026-11-25T10:00:00") and "time zone not understood" in notes(wrong)


def test_iso_and_rfc5424_lines_have_their_own_year_and_zone(tmp_path):
    text = (
        "2026-11-25T10:00:01.123456+01:00 web01 sshd[9]: Failed password for root from 198.51.100.1 port 1 ssh2\n"
        "2026-11-25T10:00:02Z web01 sudo: pam_unix(sudo:session): session opened for user root(uid=0) by bob(uid=1000)\n"
        '<38>1 2026-11-25T10:00:03.5+00:00 web02 sshd 77 ID47 [meta k="v"] Accepted password for eve from 192.0.2.4 port 22 ssh2\n'
        "<86>1 2026-11-25T10:00:04Z web02 - - - - nothing here\n"
        "2026-11-25 10:00:05 web03 cron[4]: tick\n"
    )
    found = said(write(tmp_path, "a", text), "linux.auth")
    got = records(found)
    assert [r["ts"] for r in got[:4]] == [
        ms("2026-11-25T09:00:01") + 123,
        ms("2026-11-25T10:00:02"),
        ms("2026-11-25T10:00:03") + 500,
        ms("2026-11-25T10:00:04"),
    ]
    assert got[0]["type"] == "logon_failed" and got[0]["host"] == "web01"
    assert got[2]["type"] == "logon" and got[2]["data"]["structured"] == '[meta k="v"]' and got[2]["host"] == "web02"
    assert got[2]["data"]["pid"] == 77 and got[3]["data"]["message"] == "nothing here"
    assert got[4]["ts"] == ms("2026-11-25T10:00:05")
    assert "year assumed" not in notes(found)
    assert notes(found)["times taken as UTC"]["count"] == 1  # only the line without a zone


def test_lines_that_are_not_syslog_are_skips_with_their_offset(tmp_path):
    text = "Nov 25 10:00:00 h a[1]: good\n" + "this is not a log line\n" + "\n" + "Nov 25 10:00:01 h a[1]: good too\n"
    path = write(tmp_path, "a", text, "2026-11-26 00:00:00")
    found = said(path, "linux.auth")
    assert len(records(found)) == 2 and end(found)["in_file"] == 3
    (skip,) = skips(found)
    first = len("Nov 25 10:00:00 h a[1]: good\n")
    assert skip["reason"] == "line is not in a syslog format" and skip["offset"] == first and skip["lost"] == 1
    assert "line 2" in skip["detail"] and "this is not a log line" in skip["detail"]
    assert notes(found)["blank line"]["count"] == 1


def test_many_bad_lines_are_listed_a_few_at_a_time_and_counted(tmp_path, monkeypatch):
    monkeypatch.setattr(syslog, "MAX_LISTED", 3)
    text = "Nov 25 10:00:00 h a[1]: good\n" + "garbage\n" * 10
    found = said(write(tmp_path, "a", text, "2026-11-26 00:00:00"), "linux.auth")
    listed = skips(found)
    assert len(listed) == 4 and sum(s["lost"] for s in listed) == 10
    assert listed[-1]["lost"] == 7 and "7 more" in listed[-1]["detail"]
    assert end(found)["in_file"] == 11 and end(found)["read"] == 1


def test_a_line_twice_is_a_duplicate_by_design_and_a_note(tmp_path):
    text = "Nov 25 10:00:00 h a[1]: same\nNov 25 10:00:00 h a[1]: same\nNov 25 10:00:00 h a[1]: other\n"
    found = said(write(tmp_path, "a", text, "2026-11-26 00:00:00"), "linux.auth")
    got = records(found)
    assert len(got) == 3 and got[0]["key"] == got[1]["key"] != got[2]["key"]
    assert notes(found)["line that comes twice in the file"]["count"] == 1 and not skips(found)


def test_a_compressed_file_is_refused_with_the_sentence(tmp_path):
    path = write(tmp_path, "auth.log.2.gz", gzip.compress(AUTH.encode()))
    found = said(path, "linux.auth")
    assert not records(found)
    (skip,) = skips(found)
    assert skip["reason"] == "compressed file: unpack it first" and skip["lost"] == 0
    assert "unpack it first" in skip["detail"] and end(found)["t"] == "end"
    assert syslog.sniff(path, "auth.log.2.gz", open(path, "rb").read(4096)) == "linux.auth"
    assert syslog.sniff(path, "backup.gz", open(path, "rb").read(4096)) is None


def test_bytes_that_are_not_utf8_and_a_line_over_the_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(syslog, "MAX_LINE", 100)
    data = (
        b"Nov 25 10:00:00 h a[1]: caf\xe9\n"
        + b"Nov 25 10:00:01 h a[1]: "
        + b"x" * 300
        + b"\nNov 25 10:00:02 h a[1]: ok\n"
    )
    found = said(write(tmp_path, "a", data, "2026-11-26 00:00:00"), "linux.auth")
    assert len(records(found)) == 2 and "caf�" in records(found)[0]["data"]["message"]
    assert notes(found)["line with bytes that are not UTF-8"]["count"] == 1
    (skip,) = skips(found)
    first = len(b"Nov 25 10:00:00 h a[1]: caf\xe9\n")
    assert skip["reason"] == "line longer than the limit" and skip["offset"] == first
    assert skip["length"] == len(b"Nov 25 10:00:01 h a[1]: ") + 300 + 1
    assert end(found)["in_file"] == 3


def test_a_file_over_the_limits_of_a_job_stops_with_a_skip_that_says_where(tmp_path, monkeypatch):
    monkeypatch.setattr(syslog, "MAX_LINES", 3)
    text = "".join(f"Nov 25 10:00:0{n} h a[1]: m{n}\n" for n in range(6))
    found = said(write(tmp_path, "a", text, "2026-11-26 00:00:00"), "linux.auth")
    assert len(records(found)) == 3
    (skip,) = skips(found)
    assert (
        skip["reason"] == "file over the limits of a job"
        and skip["lost"] == 0
        and skip["offset"] == 3 * len(text.splitlines()[0] + "\n")
    )
    assert "after 3 lines" in skip["detail"]


# --------------------------------------------------------------------------- #
# linux.journal                                                               #
# --------------------------------------------------------------------------- #
def jline(message, **fields) -> str:
    base = {
        "__CURSOR": f"s=abc;i=1;b=2;m=3;t=4;x=5{abs(hash(str(message))) % 1000}",
        "__REALTIME_TIMESTAMP": "1764065101123456",
        "_HOSTNAME": "web01",
        "SYSLOG_IDENTIFIER": "sshd",
        "_COMM": "sshd",
        "_PID": "812",
        "_UID": "0",
        "_TRANSPORT": "syslog",
        "PRIORITY": "6",
        "SYSLOG_FACILITY": "4",
        "MESSAGE": message,
    }
    base.update(fields)
    return json.dumps(base)


def test_journal_entries_are_decoded_like_the_text_logs(tmp_path):
    lines = [
        jline("Accepted publickey for alice from 203.0.113.7 port 51822 ssh2"),
        jline("Failed password for root from 198.51.100.9 port 22 ssh2", __REALTIME_TIMESTAMP="1764065102000000"),
        jline(
            "  alice : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/bash",
            SYSLOG_IDENTIFIER="sudo",
            _COMM="sudo",
            _EXE="/usr/bin/sudo",
            _CMDLINE="sudo -i",
        ),
        jline([104, 105, 0xC3, 0xA9], SYSLOG_IDENTIFIER="app"),  # a byte array: "hié"
        jline(["one", "two"], SYSLOG_IDENTIFIER="app", _SYSTEMD_UNIT="app.service"),
        jline("kernel noise", _TRANSPORT="kernel", SYSLOG_IDENTIFIER="kernel", SYSLOG_FACILITY="0"),
    ]
    path = write(tmp_path, "journal.json", "\n".join(lines) + "\n")
    assert syslog.sniff(path, "journal.json", open(path, "rb").read(4096)) == "linux.journal"
    found = said(path, "linux.journal")
    got = records(found)
    assert len(got) == 6 and end(found)["in_file"] == 6
    assert [r["type"] for r in got] == ["logon", "logon_failed", "sudo", "log", "log", "log"]
    assert all(r["channel"] == "journal" and r["host"] == "web01" for r in got)
    first = got[0]
    assert first["ts"] == 1764065101123 and first["username"] == "alice" and first["ioc"] == [["ip", "203.0.113.7"]]
    assert first["data"]["MESSAGE"].startswith("Accepted") and first["data"]["_PID"] == "812"
    assert first["data"]["_SYSTEMD_UNIT"] if "_SYSTEMD_UNIT" in first["data"] else True
    assert first["data"]["facility"] == "auth" and first["data"]["program"] == "sshd"
    assert first["key"].startswith("journal:web01:s=abc;i=1")
    assert got[2]["data"]["_EXE"] == "/usr/bin/sudo" and got[2]["data"]["_CMDLINE"] == "sudo -i"
    assert got[2]["data"]["command"] == "/bin/bash"
    assert got[3]["data"]["MESSAGE"] == "hié" and got[4]["data"]["MESSAGE"] == "one\ntwo"
    assert got[4]["data"]["_SYSTEMD_UNIT"] == "app.service" and got[5]["data"]["facility"] == "kern"
    shown = syslog.view(path, "linux.journal", got[1]["loc"])
    assert "Failed password for root" in shown["text"] and shown["highlight"] == [2, 2]


def test_a_journal_without_a_cursor_is_keyed_by_time_and_a_hash(tmp_path):
    line = jline("hello", SYSLOG_IDENTIFIER="app")
    document = json.loads(line)
    del document["__CURSOR"]
    path = write(tmp_path, "j", json.dumps(document) + "\n" + json.dumps(document) + "\n")
    got = records(said(path, "linux.journal"))
    assert got[0]["key"].startswith("journal:web01:1764065101123456:") and got[0]["key"] == got[1]["key"]


def test_a_journal_export_with_a_header_a_footer_and_a_cut_object(tmp_path):
    good = jline("fine")
    text = (
        "-- Logs begin at Mon 2026-11-02, end at Tue 2026-11-25. --\n"
        + good
        + "\n"
        + jline("two")
        + "\n"
        + "not json at all\n"
        + '{"__REALTIME_TIMESTAMP": "17640651011234'
        + "\n"
        + "[1, 2]\n"
        + "{}\n"
        + "-- No more entries --\n"
    )
    found = said(write(tmp_path, "j", text), "linux.journal")
    assert len(records(found)) == 3  # the two, and the empty object
    reasons = sorted(s["reason"] for s in skips(found))
    assert reasons == [
        "line is not valid JSON (a cut object?)",
        "line that is not a JSON object",
        "line that is not a JSON object",
    ]
    assert notes(found)["text before the first record"]["count"] == 1
    assert notes(found)["text after the last record"]["count"] == 1
    assert end(found)["in_file"] == 6  # 3 objects, the cut one, and the two lines between records that are no object
    cut = next(s for s in skips(found) if "cut" in s["reason"])
    assert cut["offset"] > 0 and cut["lost"] == 1
    assert records(found)[2]["ts"] is None and notes(found)["record without a time"]["count"] == 1


# --------------------------------------------------------------------------- #
# linux.audit                                                                 #
# --------------------------------------------------------------------------- #
def hexed(text: str) -> str:
    return text.encode().hex().upper()


AUDIT = f"""\
type=SYSCALL msg=audit(1764065101.100:500): arch=c000003e syscall=59 success=yes exit=0 a0=55d0 a1=55d1 a2=55d2 a3=7ffc items=2 ppid=812 pid=900 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="curl" exe="/usr/bin/curl" key="susp_activity"
type=USER_LOGIN msg=audit(1764065101.200:501): pid=812 uid=0 auid=4294967295 ses=4294967295 msg='op=login acct="root" exe="/usr/sbin/sshd" hostname=? addr=198.51.100.9 terminal=ssh res=failed'
type=EXECVE msg=audit(1764065101.100:500): argc=4 a0="curl" a1="-o" a2="/tmp/x y" a3={hexed("http://198.51.100.9/a b")}
type=CWD msg=audit(1764065101.100:500):  cwd="/home/alice"
type=USER_AUTH msg=audit(1764065101.300:502): pid=812 uid=0 auid=1000 ses=3 msg='op=PAM:authentication acct="alice" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/0 res=success'
type=PATH msg=audit(1764065101.100:500): item=0 name="/usr/bin/curl" inode=1 dev=08:01 mode=0100755 ouid=0 ogid=0 nametype=NORMAL
type=PATH msg=audit(1764065101.100:500): item=1 name="/lib64/ld-linux-x86-64.so.2" inode=2 dev=08:01 mode=0100755 ouid=0 ogid=0 nametype=NORMAL
type=PROCTITLE msg=audit(1764065101.100:500): proctitle={hexed("curl")}00{hexed("-o")}
type=EOE msg=audit(1764065101.100:500):
type=USER_LOGIN msg=audit(1764065102.000:503): pid=812 uid=0 auid=1000 ses=5 msg='op=login id=1000 exe="/usr/sbin/sshd" hostname=laptop addr=203.0.113.7 terminal=/dev/pts/1 res=success'
type=EOE msg=audit(1764065102.000:503):
type=SERVICE_STOP msg=audit(1764065103.000:504): pid=1 uid=0 auid=4294967295 ses=4294967295 msg='unit=ufw comm="systemd" exe="/usr/lib/systemd/systemd" hostname=? addr=? terminal=? res=success'
"""


def test_the_lines_of_an_audit_event_are_one_record_with_the_command_line(tmp_path):
    path = write(tmp_path, "audit.log", AUDIT)
    assert syslog.sniff(path, "audit.log", open(path, "rb").read(4096)) == "linux.audit"
    found = said(path, "linux.audit")
    got = records(found)
    assert [r["type"] for r in got] == ["process", "logon_failed", "audit", "logon", "audit"]
    assert end(found)["in_file"] == 5 and end(found)["read"] == 5
    process = got[0]
    assert process["key"] == "audit:IR-1:1764065101.100:500" and process["channel"] == "audit"
    assert process["ts"] == 1764065101100 and process["username"] == "root"
    data = process["data"]
    assert data["CommandLine"] == "curl -o /tmp/x y http://198.51.100.9/a b" and data["argc"] == 4
    assert data["argv"] == ["curl", "-o", "/tmp/x y", "http://198.51.100.9/a b"]
    assert (data["exe"], data["comm"], data["pid"], data["ppid"], data["uid"], data["auid"]) == (
        "/usr/bin/curl", "curl", "900", "812", "0", "1000"
    )  # fmt: skip
    assert (data["euid"], data["tty"], data["key"], data["cwd"], data["syscall"]) == (
        "0", "pts0", "susp_activity", "/home/alice", "execve"
    )  # fmt: skip
    assert data["types"] == ["SYSCALL", "EXECVE", "CWD", "PATH", "PROCTITLE"]
    assert data["name"] == ["/usr/bin/curl", "/lib64/ld-linux-x86-64.so.2"] and len(data["paths"]) == 2
    assert data["proctitle"] == "curl -o" and data["syscall_args"] == ["55d0", "55d1", "55d2", "7ffc"]
    # the interleaved lines are not his; the place of each line is "number:offset:length" in one short text
    assert process["loc"]["lines"].startswith("1:0:") and len(process["loc"]["lines"].split()) == 6
    assert process["loc"]["more"] == 0
    failed, authentication, logon, stop = got[1:]
    assert failed["username"] == "root" and failed["data"]["source_ip"] == "198.51.100.9"
    assert failed["data"]["res"] == "failed" and failed["data"]["logon_type"] == "ssh"
    assert failed["ioc"] == [["ip", "198.51.100.9"]]
    assert authentication["type"] == "audit" and authentication["username"] == "alice"
    assert (
        logon["username"] == "1000" and logon["data"]["source_ip"] == "203.0.113.7"
    )  # the account is in id=, not acct=
    assert logon["ioc"] == [["ip", "203.0.113.7"]]
    assert stop["data"]["unit"] == "ufw" and stop["data"]["types"] == ["SERVICE_STOP"]


def test_the_view_of_an_event_is_its_lines_even_when_they_are_apart(tmp_path):
    path = write(tmp_path, "audit.log", AUDIT)
    process = records(said(path, "linux.audit"))[0]
    # The locator is sent back to the worker as it is (the API keeps it): its view check takes scalars only.
    import server

    server.check_view({"parser": "syslog", "source": "linux.audit", "loc": process["loc"]})
    shown = syslog.view(path, "linux.audit", process["loc"])
    lines = shown["text"].split("\n")
    assert len(lines) == 6 and lines[0].startswith("type=SYSCALL") and lines[-1].startswith("type=PROCTITLE")
    assert all("audit(1764065101.100:500)" in line for line in lines) and shown["highlight"] == [1, 6]
    with pytest.raises(BadLocator):
        syslog.view(path, "linux.audit", {"lines": "1:2"})
    with pytest.raises(ViewError):
        syslog.view(path, "linux.audit", {"lines": "1:1000000:5"})


def test_audit_arguments_that_are_split_or_encoded_are_joined(tmp_path):
    long = "A" * 20
    text = (
        "node=srv1 type=SYSCALL msg=audit(1764065200.000:7): arch=c00000b7 syscall=221 success=yes exit=0 a0=1 a1=2 a2=3 a3=4"
        ' items=1 ppid=1 pid=2 auid=0 uid=0 gid=0 euid=0 tty=(none) ses=1 comm="sh" exe="/bin/sh"\n'
        'node=srv1 type=EXECVE msg=audit(1764065200.000:7): argc=3 a0="sh" a1="-c" a2_len=40 a2[0]="'
        + long
        + '" a2[1]="'
        + long
        + '"\n'
        "node=srv1 type=EOE msg=audit(1764065200.000:7): \n"
    )
    found = said(write(tmp_path, "a", text), "linux.audit")
    (one,) = records(found)
    assert one["host"] == "srv1" and one["key"] == "audit:srv1:1764065200.000:7"
    assert one["data"]["CommandLine"] == f"sh -c {long}{long}" and one["data"]["syscall"] == "execve"
    assert one["data"]["tty"] == "(none)"  # kept as the log says it
    assert one["data"]["argc"] == 3


def test_enriched_audit_names_do_not_replace_the_numbers(tmp_path):
    text = (
        "type=SYSCALL msg=audit(1764065300.000:9): arch=c000003e syscall=59 success=yes exit=0 a0=1 items=0 ppid=1 pid=2 "
        'auid=1000 uid=0 gid=0 euid=0 tty=pts1 ses=2 comm="ls" exe="/usr/bin/ls"\x1dARCH=x86_64 SYSCALL=execve AUID="alice" UID="root"\n'
        'type=EXECVE msg=audit(1764065300.000:9): argc=1 a0="ls"\n'
    )
    (one,) = records(said(write(tmp_path, "a", text), "linux.audit"))
    assert one["data"]["uid"] == "0" and one["data"]["uid_name"] == "root" and one["data"]["auid_name"] == "alice"
    assert one["username"] == "root" and one["data"]["syscall"] == "execve"


def test_events_that_interleave_are_joined_by_serial_and_given_in_order(tmp_path):
    lines = []
    for serial in (1, 2, 3):
        lines.append(
            f'type=SYSCALL msg=audit(1764065400.{serial:03d}:{serial}): arch=c000003e syscall=59 pid={serial} exe="/bin/e{serial}"'
        )
    for serial in (3, 2, 1):
        lines.append(f'type=EXECVE msg=audit(1764065400.{serial:03d}:{serial}): argc=1 a0="e{serial}"')
    for serial in (2, 1, 3):
        lines.append(f"type=EOE msg=audit(1764065400.{serial:03d}:{serial}): ")
    found = said(write(tmp_path, "a", "\n".join(lines) + "\n"), "linux.audit")
    got = records(found)
    assert [r["data"]["serial"] for r in got] == [1, 2, 3]  # the order they began, though 2 ended first
    assert [r["data"]["CommandLine"] for r in got] == ["e1", "e2", "e3"] and end(found)["in_file"] == 3


def test_an_event_without_its_end_is_given_when_the_file_ends_and_a_full_window_gives_the_oldest(tmp_path, monkeypatch):
    monkeypatch.setattr(audit, "MAX_OPEN", 2)
    text = "".join(
        f'type=SYSCALL msg=audit(1764065500.000:{n}): arch=c000003e syscall=2 pid={n} exe="/bin/x"\n' for n in range(5)
    )
    found = said(write(tmp_path, "a", text), "linux.audit")
    assert [r["data"]["serial"] for r in records(found)] == [0, 1, 2, 3, 4]
    assert notes(found)["audit events written before their end line"]["count"] == 3
    assert end(found)["in_file"] == 5


def test_audit_lines_that_do_not_parse_are_skips_and_an_event_seen_twice_is_a_duplicate(tmp_path):
    one = 'type=SYSCALL msg=audit(1764065600.000:1): arch=c000003e syscall=59 pid=1 exe="/bin/x"\n'
    text = (
        one
        + "this is not audit\n"
        + "type=EOE msg=audit(1764065600.000:1):\n"
        + one
        + "type=EOE msg=audit(1764065600.000:1):\n"
    )
    found = said(write(tmp_path, "a", text), "linux.audit")
    assert len(records(found)) == 2 and records(found)[0]["key"] == records(found)[1]["key"]
    (skip,) = skips(found)
    assert skip["reason"] == "line is not an audit record" and skip["offset"] == len(one) and skip["lost"] == 1
    assert notes(found)["line that comes twice in the file"]["count"] == 1
    assert end(found)["in_file"] == 3


def test_the_syscall_names_come_from_the_architecture(tmp_path):
    assert audit.syscall_name("c000003e", "59") == "execve" and audit.syscall_name("c00000b7", "221") == "execve"
    assert audit.syscall_name("c000003e", "319") == "memfd_create" and audit.syscall_name("zz", "59") == ""
    assert audit.decode_hex("2F62696E00736800") == "/bin sh "


# --------------------------------------------------------------------------- #
# macos.unifiedlog                                                            #
# --------------------------------------------------------------------------- #
def uline(message, process="sshd", **fields) -> str:
    base = {
        "traceID": 1234,
        "eventMessage": message,
        "eventType": "logEvent",
        "subsystem": "com.apple.sshd",
        "category": "auth",
        "messageType": "Default",
        "processImagePath": f"/usr/sbin/{process}",
        "senderImagePath": f"/usr/sbin/{process}",
        "processID": 410,
        "userID": 0,
        "timestamp": "2026-11-25 10:00:01.123456+0100",
        "machTimestamp": 99,
    }
    base.update(fields)
    return json.dumps(base)


def test_unified_log_records_keep_their_zone_and_decode_the_auth_messages(tmp_path):
    lines = [
        uline("Accepted publickey for alice from 203.0.113.7 port 51822 ssh2"),
        uline(
            "Failed password for bob from 198.51.100.9 port 22 ssh2", **{"timestamp": "2026-11-25 10:00:02.000000+0000"}
        ),
        uline("  alice : TTY=ttys000 ; PWD=/Users/alice ; USER=root ; COMMAND=/usr/bin/id", process="sudo"),
        uline(
            "Failed to authorize right 'system.privilege.admin' by client '/Applications/X.app' for authorization created by '/Y' (-60007)",
            process="authd",
        ),
        uline(
            "Succeeded authorizing right 'system.login.console' by client '/System/Library/CoreServices/loginwindow.app' for authorization created by '/Z'",
            process="authd",
        ),
        uline("Login authentication succeeded", process="loginwindow"),
        uline("something else", process="mDNSResponder", timestamp="2026-11-25T10:00:03Z"),
    ]
    path = write(tmp_path, "unified.ndjson", "\n".join(lines) + "\n")
    assert syslog.sniff(path, "unified.ndjson", open(path, "rb").read(4096)) == "macos.unifiedlog"
    found = said(path, "macos.unifiedlog")
    got = records(found)
    assert [r["type"] for r in got] == ["logon", "logon_failed", "sudo", "logon_failed", "logon", "logon", "log"]
    assert end(found)["in_file"] == 7 and all(r["channel"] == "unifiedlog" and r["host"] == "IR-1" for r in got)
    assert got[0]["ts"] == ms("2026-11-25T09:00:01") + 123 and got[1]["ts"] == ms("2026-11-25T10:00:02")
    assert got[0]["username"] == "alice" and got[0]["ioc"] == [["ip", "203.0.113.7"]]
    assert got[0]["data"]["processImagePath"] == "/usr/sbin/sshd" and got[0]["data"]["process"] == "sshd"
    assert got[0]["data"]["subsystem"] == "com.apple.sshd" and got[0]["data"]["messageType"] == "Default"
    assert got[0]["data"]["eventMessage"].startswith("Accepted") and got[0]["data"]["userID"] == 0
    assert got[2]["data"]["command"] == "/usr/bin/id" and got[2]["data"]["runas"] == "root"
    assert got[3]["data"]["right"] == "system.privilege.admin" and got[3]["data"]["error"] == "-60007"
    assert got[4]["data"]["right"] == "system.login.console" and got[6]["ts"] == ms("2026-11-25T10:00:03")
    assert got[0]["key"].startswith(f"unifiedlog:IR-1:{got[0]['ts']}:")
    assert "line" in syslog.view(path, "macos.unifiedlog", got[1]["loc"])["title"].lower()


def test_unified_log_with_a_header_a_footer_and_a_truncated_last_line(tmp_path):
    text = (
        'Filtering the log data using "process == sshd"\n'
        + uline("Accepted password for a from 192.0.2.1 port 1 ssh2")
        + "\n"
        + uline("hello", timestamp="not a time")
        + "\n"
        + uline("cut")[:60]
        + "\n"
    )
    found = said(write(tmp_path, "u", text), "macos.unifiedlog")
    assert len(records(found)) == 2 and records(found)[1]["ts"] is None
    assert notes(found)["text before the first record"]["count"] == 1
    (skip,) = skips(found)
    assert skip["reason"] == "line is not valid JSON (a cut object?)" and skip["lost"] == 1
    assert end(found)["in_file"] == 3


# --------------------------------------------------------------------------- #
# What a file is                                                              #
# --------------------------------------------------------------------------- #
def test_sniff_reads_the_content_and_never_guesses():
    sniff = syslog.sniff
    auth = AUTH.encode()[:4096]
    assert sniff("p", "auth.log", auth) == "linux.auth" and sniff("p", "whatever.bin", auth) == "linux.auth"
    assert sniff("p", "audit.log", AUDIT.encode()[:4096]) == "linux.audit"
    assert sniff("p", "x", (jline("a") + "\n").encode()) == "linux.journal"
    assert sniff("p", "x", (uline("a") + "\n").encode()) == "macos.unifiedlog"
    assert sniff("p", "x", ('Filtering the log data using "x"\n' + uline("a") + "\n").encode()) == "macos.unifiedlog"
    assert sniff("p", "auth.log", b"a,b,c\n1,2,3\n") is None  # a name alone says nothing
    assert sniff("p", "auth.log", b"") is None and sniff("p", "x", b"\x00\x01\x02") is None
    assert sniff("p", "x", b'{"a": 1}\n') is None
    assert sniff("p", "x", b"whoami\nls -la\ncat /etc/passwd\n") is None
    iso = b"2026-11-25T10:00:01+01:00 web01 sshd[9]: hello\n"
    assert sniff("p", "x", iso) == "linux.auth"
    assert sniff("p", "x", b"<38>1 2026-11-25T10:00:03Z h app 1 - - msg\n") == "linux.auth"


def test_recognise_picks_the_parser_for_each_file(tmp_path):
    for name, data, source in (
        ("auth.log", AUTH, "linux.auth"),
        ("audit.log", AUDIT, "linux.audit"),
        ("journal.json", jline("x") + "\n", "linux.journal"),
        ("unified.json", uline("x") + "\n", "macos.unifiedlog"),
    ):
        path = write(tmp_path, name, data)
        module, found = parsers.recognise(path, name)
        assert module is syslog and found == source


def test_messages_that_look_like_these_but_are_not_stay_plain_logs():
    for program, text in (
        ("sshd", "Server listening on 0.0.0.0 port 22."),
        ("sshd", "Connection closed by authenticating user root 1.2.3.4 port 5 [preauth]"),
        ("sudo", "pam_unix(sudo:auth): conversation failed"),
        ("useradd", "failed adding user 'x', data deleted"),
        ("cron", "(root) CMD (run-parts)"),
        ("anything", "Accepted publickey for alice from 1.2.3.4 port 1 ssh2"),
    ):
        assert messages.decode(program, text) is None, text
    assert messages.address("::ffff:192.0.2.1") == "192.0.2.1" and messages.address("host.example") == ""
    assert messages.indicators({"source_ip": "127.0.0.1"}) == [] and messages.indicators({}) == []


# --------------------------------------------------------------------------- #
# Sigma over these records                                                    #
# --------------------------------------------------------------------------- #
def detections(path: str, source: str, rules: list[dict], params: dict | None = None) -> tuple[dict, list[dict]]:
    """The rules that matched, as ``{title: [record keys]}``, and everything the parse said."""
    out = io.BytesIO()
    ctx = Context(out, {"host": "IR-1", **(params or {})})
    ctx.detector = Engine(rules)
    syslog.parse(path, ctx, source)
    found = [json.loads(line) for line in out.getvalue().splitlines() if line]
    by_id = {r["id"]: r["title"] for r in rules}
    hit: dict[str, list[str]] = {}
    for event in found:
        if event["t"] == "det":
            hit.setdefault(by_id[event["rule"]], []).append(event["key"])
    return hit, found


def test_audit_rules_read_the_types_and_the_numbered_arguments_of_the_event(tmp_path):
    path = write(tmp_path, "audit.log", AUDIT)
    rules = [
        rule(
            "execve-curl",
            {"s": {"type": "EXECVE", "a0": "curl", "a1|startswith": "-"}, "condition": "s"},
            "linux",
            None,
            "auditd",
        ),
        rule(
            "syscall",
            {
                "s": {"type": "SYSCALL", "SYSCALL": "execve", "exe|endswith": "/curl", "key": "susp_activity"},
                "condition": "s",
            },
            "linux",
            None,
            "auditd",
        ),
        rule("path", {"s": {"type": "PATH", "name|startswith": "/lib64/"}, "condition": "s"}, "linux", None, "auditd"),
        rule("keyword", {"words": ["198.51.100.9/a"], "condition": "words"}, "linux", None, "auditd"),
        rule(
            "login",
            {"s": {"type": "USER_LOGIN", "res": "failed", "addr": "198.51.100.9"}, "condition": "s"},
            "linux",
            None,
            "auditd",
        ),
        rule("not-this", {"s": {"type": "EXECVE", "a0": "wget"}, "condition": "s"}, "linux", None, "auditd"),
        rule("service-stop", {"s": {"type": "SERVICE_STOP", "unit": "ufw"}, "condition": "s"}, "linux", None, "auditd"),
    ]
    hit, _found = detections(path, "linux.audit", rules)
    key = "audit:IR-1:1764065101.100:500"
    assert hit == {
        "execve-curl": [key],
        "syscall": [key],
        "path": [key],
        "keyword": [key],
        "login": ["audit:IR-1:1764065101.200:501"],
        "service-stop": ["audit:IR-1:1764065103.000:504"],
    }


def test_process_creation_of_linux_reads_the_audit_execve_and_not_the_journal(tmp_path):
    rules = [
        rule(
            "proc",
            {
                "s": {
                    "Image|endswith": "/curl",
                    "CommandLine|contains": "-o /tmp/x",
                    "ParentProcessId": "812",
                    "LogonId": "1000",
                    "CurrentDirectory": "/home/alice",
                    "User": "root",
                },
                "condition": "s",
            },
            "linux",
            "process_creation",
            None,
        ),
        rule(
            "sudo-line",
            {"s": {"Image|endswith": "/sudo", "CommandLine": "sudo -i"}, "condition": "s"},
            "linux",
            "process_creation",
            None,
        ),
    ]
    hit, _ = detections(write(tmp_path, "audit.log", AUDIT), "linux.audit", rules)
    assert hit == {"proc": ["audit:IR-1:1764065101.100:500"]}
    lines = [
        jline(
            "  alice : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/bash",
            SYSLOG_IDENTIFIER="sudo",
            _EXE="/usr/bin/sudo",
            _CMDLINE="sudo -i",
        ),
        jline("no process fields here"),
    ]
    hit, _ = detections(write(tmp_path, "j.json", "\n".join(lines) + "\n"), "linux.journal", rules)
    # A journal entry says a process logged a line, not that it started: no process creation comes from it.
    assert hit == {}


def test_text_log_services_pick_the_program_and_keywords_search_the_message(tmp_path):
    path = write(tmp_path, "auth.log", AUTH, "2026-11-26 00:00:00")
    rules = [
        rule("sshd-words", {"k": ["Failed password for invalid user"], "condition": "k"}, "linux", None, "sshd"),
        rule("sudo-words", {"k": ["Failed password"], "condition": "k"}, "linux", None, "sudo"),
        rule("auth-words", {"k": ["new user: name=bob2"], "condition": "k"}, "linux", None, "auth"),
        rule("syslog-words", {"k": ["something happened"], "condition": "k"}, "linux", None, "syslog"),
        rule("any-linux", {"k": ["last message repeated"], "condition": "k"}, "linux", None, None),
        rule(
            "sudo-fields",
            {"s": {"command|contains": "shadow", "runas": "root", "tty": "pts/0"}, "condition": "s"},
            "linux",
            None,
            "sudo",
        ),
        rule(
            "typed",
            {"s": {"recordtype": "logon_failed", "source_ip": "198.51.100.9"}, "condition": "s"},
            "linux",
            None,
            None,
        ),
        rule("macos-only", {"k": ["something happened"], "condition": "k"}, "macos", None, None),
    ]
    hit, found = detections(path, "linux.auth", rules)
    assert set(hit) == {"sshd-words", "auth-words", "syslog-words", "any-linux", "sudo-fields", "typed"}
    assert {name: len(keys) for name, keys in hit.items()} == {
        "sshd-words": 1, "auth-words": 1, "syslog-words": 1, "any-linux": 1, "sudo-fields": 1, "typed": 3
    }  # fmt: skip
    # The three failed logons of 198.51.100.9 (the fourth failure came from another address).
    note = notes(found)
    assert "rule not evaluated" not in note


def test_journal_entries_are_auth_only_when_their_facility_is_and_macos_rules_read_the_unified_log(tmp_path):
    lines = [
        jline("Accepted password for a from 192.0.2.1 port 1 ssh2"),
        jline("noise", SYSLOG_FACILITY="3", SYSLOG_IDENTIFIER="app"),
    ]
    rules = [
        rule("auth", {"k": ["noise"], "condition": "k"}, "linux", None, "auth"),
        rule("auth2", {"k": ["Accepted password"], "condition": "k"}, "linux", None, "auth"),
        rule("syslog", {"k": ["noise"], "condition": "k"}, "linux", None, "syslog"),
    ]
    hit, _ = detections(write(tmp_path, "j.json", "\n".join(lines) + "\n"), "linux.journal", rules)
    assert set(hit) == {"auth2", "syslog"}
    unified = write(tmp_path, "u.json", uline("Accepted publickey for alice from 203.0.113.7 port 22 ssh2") + "\n")
    rules = [
        rule("mac", {"k": ["Accepted publickey"], "condition": "k"}, "macos", None, None),
        rule("linux", {"k": ["Accepted publickey"], "condition": "k"}, "linux", None, None),
    ]
    hit, _ = detections(unified, "macos.unifiedlog", rules)
    assert set(hit) == {"mac"}
    # A macOS process rule is not run: the records say who wrote a log line, not that a process started.
    engine = Engine([rule("mp", {"s": {"Image|endswith": "/sh"}, "condition": "s"}, "macos", "process_creation", None)])
    assert engine.not_evaluated()[0][1] == "Nik reads no records of this log source: macos/process_creation"

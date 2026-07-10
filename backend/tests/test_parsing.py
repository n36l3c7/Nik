"""Server-side parser tests (browser SQLite, shell, endpoint) + merge."""

from __future__ import annotations

import os
import sqlite3
import tempfile

import pytest

from app.parsing.registry import apply_upload
from app.parsing.timeutil import any_to_ms, webkit_to_ms


def test_time_conversions():
    ms = 1700000000000
    assert webkit_to_ms((ms + 11644473600000) * 1000) == ms
    assert any_to_ms("2023-11-14T02:41:00+00:00") == 1699929660000


def _chromium_history_bytes():
    fd, path = tempfile.mkstemp(suffix=".sqlite")
    os.close(fd)
    conn = sqlite3.connect(path)
    conn.executescript(
        "CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INT);"
        "CREATE TABLE visits(id INTEGER PRIMARY KEY, url INT, visit_time INT, from_visit INT, transition INT);"
    )
    us = (1700000000000 + 11644473600000) * 1000
    conn.execute("INSERT INTO urls VALUES(1,'http://evil.test/x','Evil',3)")
    conn.execute("INSERT INTO visits VALUES(10,1,?,0,0)", (us,))
    conn.commit()
    conn.close()
    with open(path, "rb") as fh:
        data = fh.read()
    os.remove(path)
    return data


def test_browser_history_upload_merge():
    doc = {"id": "i", "data": {}}
    summary = apply_upload(doc, "browser", {"browser": "chrome", "source": "history"}, _chromium_history_bytes(), "History")
    hist = doc["data"]["browser"]["browsers"]["chrome"]["history"]
    assert summary["format"] == "sqlite"
    assert len(hist) == 1 and hist[0]["visitTime"] == 1700000000000


def test_shell_upload_merge():
    doc = {"id": "i", "data": {}}
    apply_upload(doc, "commands", {"shell": "bash"}, b"#1700000000\nsudo cat /etc/shadow\nls\n", ".bash_history")
    cmds = doc["data"]["commands"]["shells"]["bash"]["commands"]
    assert len(cmds) == 2 and cmds[0]["time"] == 1700000000000


def test_endpoint_configlines_and_csv():
    doc = {"id": "i", "data": {}}
    apply_upload(doc, "endpoint", {"category": "persistence", "source": "sshkeys"},
                 b"# comment\nssh-ed25519 AAAA attacker\n", "authorized_keys")
    recs = doc["data"]["endpoint"]["categories"]["persistence"]["sources"]["sshkeys"]["records"]
    assert len(recs) == 1 and recs[0]["fields"]["kind"] == "authorized_keys"

    apply_upload(doc, "endpoint", {"category": "persistence", "source": "runkeys"},
                 b"name,kind,command,location\nUpd,Run key,C:\\a.exe,HKCU\\Run\n", "runkeys.csv")
    rk = doc["data"]["endpoint"]["categories"]["persistence"]["sources"]["runkeys"]["records"]
    assert rk[0]["fields"]["command"] == "C:\\a.exe"


def test_bad_upload_target():
    with pytest.raises(ValueError):
        apply_upload({"id": "x"}, "browser", {"browser": "nope", "source": "history"}, b"x", "f")

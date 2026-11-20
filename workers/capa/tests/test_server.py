"""The capa worker's HTTP front: it reads only the sample it was given, for one analysis."""

from __future__ import annotations

import hashlib
import json
import os
import sys
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import given  # noqa: E402
import server  # noqa: E402

DATA = b"MZ a harmless fixture, never a sample"
SHA = hashlib.sha256(DATA).hexdigest()
RULE = {"name": "a" * 32 + ".yml", "source": "rule:\n  meta:\n    name: team rule\n"}


def test_digests_must_match_exactly():
    assert server.SHA256.fullmatch("a" * 64)
    assert not server.SHA256.fullmatch("a" * 64 + "\n")


@pytest.fixture()
def worker(tmp_path, monkeypatch):
    seen = []
    work = str(tmp_path / "given")
    monkeypatch.setattr(server, "TOKEN", "test-token")
    monkeypatch.setattr(server, "WORK_DIR", work)
    monkeypatch.setattr(server, "GIVEN", given.Given(work, server.GIVEN.allowed, max_bytes=10**6))

    def analyze(path, timeout, extra_rules=()):
        rules = [(os.path.basename(rule), open(rule, encoding="utf-8").read()) for rule in extra_rules]
        seen.append((path, hashlib.sha256(open(path, "rb").read()).hexdigest(), rules))
        return {"capabilities": []}

    monkeypatch.setattr(server, "analyze", analyze)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}", seen, work
    httpd.shutdown()


def call(url, method="POST", body=None, token="test-token"):
    data = body if isinstance(body, bytes) else json.dumps(body or {}).encode()
    request = urllib.request.Request(url, data=data, method=method, headers={"X-Analyzer-Token": token})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read() or b"{}")


def test_the_sample_is_given_read_once_and_nothing_of_it_stays(worker):
    url, seen, work = worker
    body = {"sha256": SHA, "rules": [RULE]}
    status, answer = call(f"{url}/analyze", body=body)
    assert status == 409 and answer["missing"] == [f"{SHA}.bin"] and seen == []
    assert call(f"{url}/files/{SHA}.bin", "PUT", DATA) == (200, {})
    status, answer = call(f"{url}/analyze", body=body)
    assert status == 200 and answer == {"capabilities": []}
    path, read, rules = seen[0]
    # capa read the sample itself, and the rules that came with the request.
    assert read == SHA and path.startswith(work) and rules == [(RULE["name"], RULE["source"])]
    # One analysis, then neither the sample nor the rules are in the worker any more.
    left = [os.path.join(base, name) for base, _dirs, names in os.walk(work) for name in names]
    assert left == []
    assert call(f"{url}/analyze", body=body)[0] == 409


def test_rules_and_files_that_are_not_what_the_worker_takes_are_refused(worker):
    url, seen, _work = worker
    assert call(f"{url}/files/{SHA}.bin", "PUT", DATA, token="wrong")[0] == 401
    assert call(f"{url}/files/_capa_rules/{'a' * 32}.yml", "PUT", b"rule")[0] == 400
    assert call(f"{url}/files/{'b' * 64}.bin", "PUT", DATA)[0] == 422
    call(f"{url}/files/{SHA}.bin", "PUT", DATA)
    for rules in (["_capa_rules/x.yml"], [{"name": "../x.yml", "source": "r"}], [{"name": "a" * 32 + ".yml"}], "none"):
        assert call(f"{url}/analyze", body={"sha256": SHA, "rules": rules})[0] == 400, rules
    assert call(f"{url}/analyze", body={"sha256": SHA}, token="wrong")[0] == 401
    assert seen == []

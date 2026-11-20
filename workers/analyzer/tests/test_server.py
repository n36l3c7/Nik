"""The analyzer worker's HTTP front: it reads only what it was given, and says what it lacks."""

from __future__ import annotations

import hashlib
import json
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
SIG = "_flirt/" + "a" * 32 + ".sig"


def test_digests_must_match_exactly():
    assert server.SHA256.fullmatch("a" * 64)
    assert not server.SHA256.fullmatch("a" * 64 + "\n")


@pytest.fixture()
def worker(tmp_path, monkeypatch):
    seen = []
    monkeypatch.setattr(server, "TOKEN", "test-token")
    monkeypatch.setattr(server, "GIVEN", given.Given(str(tmp_path / "given"), server.GIVEN.allowed, max_bytes=10**6))

    def analyze(path, **kwargs):
        seen.append(("analyze", path, list(kwargs["signatures"])))
        return {"read": hashlib.sha256(open(path, "rb").read()).hexdigest()}

    def decompile_one(path, addr, **kwargs):
        seen.append(("decompile", path, addr))
        return {"addr": addr}

    monkeypatch.setattr(server, "analyze", analyze)
    monkeypatch.setattr(server, "decompile_one", decompile_one)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}", seen
    httpd.shutdown()


def call(url, method="POST", body=None, token="test-token"):
    data = body if isinstance(body, bytes) else json.dumps(body or {}).encode()
    request = urllib.request.Request(url, data=data, method=method, headers={"X-Analyzer-Token": token})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read() or b"{}")


def test_the_worker_names_what_it_lacks_takes_it_and_then_reads_it(worker):
    url, seen = worker
    body = {"sha256": SHA, "signatures": [SIG]}
    status, answer = call(f"{url}/analyze", body=body)
    assert status == 409 and answer["missing"] == [f"{SHA}.bin", SIG] and seen == []
    assert call(f"{url}/files/{SHA}.bin", "PUT", DATA) == (200, {})
    assert call(f"{url}/analyze", body=body)[1]["missing"] == [SIG]
    assert call(f"{url}/files/{SIG}", "PUT", b"IDASGN")[0] == 200
    status, answer = call(f"{url}/analyze", body=body)
    assert status == 200 and answer == {"read": SHA}
    kind, path, signatures = seen[0]
    # What it read is inside its own folder, and nowhere else.
    assert kind == "analyze" and path.startswith(server.GIVEN.folder) and len(signatures) == 1
    assert call(f"{url}/decompile", body={"sha256": SHA, "addr": 4096})[1] == {"addr": 4096}
    # A sample it was never given is asked for, whatever else it holds.
    other = "b" * 64
    assert call(f"{url}/decompile", body={"sha256": other, "addr": 1})[1]["missing"] == [f"{other}.bin"]


def test_giving_a_file_needs_the_token_and_a_name_the_worker_knows(worker):
    url, _seen = worker
    assert call(f"{url}/files/{SHA}.bin", "PUT", DATA, token="wrong")[0] == 401
    assert call(f"{url}/files/{SHA}.bin", "PUT", DATA, token="")[0] == 401
    for name in (
        "x.bin",
        f"{SHA}.exe",
        f"_flirt/{'a' * 32}.exe",
        f"_captures/{'c' * 32}/capture.pcap",
        f"..%2F{SHA}.bin",
    ):
        assert call(f"{url}/files/{name}", "PUT", DATA)[0] == 400, name
    # Not the file its name says: refused, and not kept.
    status, answer = call(f"{url}/files/{'b' * 64}.bin", "PUT", DATA)
    assert status == 422 and "SHA-256" in answer["detail"]
    assert call(f"{url}/analyze", body={"sha256": "b" * 64})[0] == 409
    assert call(f"{url}/elsewhere", "PUT", DATA)[0] == 404
    assert call(f"{url}/analyze", body={"sha256": SHA}, token="wrong")[0] == 401
    assert call(f"{url}/analyze", body={"sha256": SHA, "signatures": ["../x.sig"]})[0] == 400
    assert call(f"{url}/analyze", body={"sha256": "nope"})[0] == 400
    assert call(f"{url}/decompile", body={"sha256": SHA, "addr": -1})[0] == 400

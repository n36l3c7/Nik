"""The script sandbox: what a script gets back, and the limits it runs under (Linux, in its image)."""

# ruff: noqa: E501 (scripts under test read better on one line)

from __future__ import annotations

import json
import os
import sys
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SANDBOX_TOKEN", "test-token")

import runner  # noqa: E402

import server  # noqa: E402


def run(code: str, args: dict | None = None, timeout: int | None = None) -> dict:
    return runner.run(code, args, timeout)


def test_a_script_gets_its_arguments_and_gives_back_what_main_returns():
    code = "def main(args):\n    print('working on', len(args['items']))\n    return {'total': sum(args['items']), 'who': args.get('who')}\n"
    answer = run(code, {"items": [1, 2, 3], "who": "anna"})
    assert answer["ok"] is True and answer["result"] == {"total": 6, "who": "anna"}
    assert answer["stdout"] == "working on 3\n" and answer["duration_ms"] >= 0
    # The standard library a script computes with is there.
    code = (
        "import json, re, math, datetime, collections, itertools, hashlib, base64, ipaddress, statistics, csv, io\n"
        "from urllib.parse import urlsplit\n"
        "def main(args):\n"
        "    return {'host': urlsplit(args['url']).hostname, 'sha': hashlib.sha256(b'x').hexdigest()[:8],\n"
        "            'private': ipaddress.ip_address('10.0.0.1').is_private, 'mean': statistics.mean([1, 2, 3])}\n"
    )
    assert run(code, {"url": "https://evil.example/a"})["result"] == {
        "host": "evil.example",
        "sha": "2d711642",
        "private": True,
        "mean": 2,
    }


def test_what_goes_wrong_in_a_script_is_said_with_its_line():
    assert run("def main(args):\n    return 1 / 0\n")["error"] == "Line 2: ZeroDivisionError: division by zero"
    assert run("def main(args)\n    return 1\n")["error"].startswith("Line 1: ")
    assert run("x = 1\n")["error"] == "The script defines no main(args)"
    assert run("def main(args):\n    return {1, 2}\n")["error"].startswith(
        "main(args) returned something that is not JSON"
    )
    assert run("def main(args):\n    raise SystemExit(3)\n")["ok"] is False
    assert run("")["error"] == "There is no code to run"
    assert run("x" * (runner.MAX_CODE + 1))["error"] == "The script is too long"
    answer = run(
        "import sys\ndef main(args):\n    print('to the log'); print('and errors', file=sys.stderr)\n    return None\n"
    )
    assert (
        answer["ok"] is True
        and answer["result"] is None
        and "to the log" in answer["stdout"]
        and "and errors" in answer["stdout"]
    )


@pytest.mark.parametrize(
    "module",
    ["socket", "subprocess", "ctypes", "multiprocessing", "http.client", "urllib.request", "asyncio", "ssl", "shutil"],
)
def test_a_script_does_not_get_the_modules_that_reach_out(module):
    answer = run(f"import {module}\ndef main(args):\n    return 1\n")
    assert answer["ok"] is False and "is not available to scripts" in answer["error"], answer
    lazy = run(f"def main(args):\n    __import__('{module}')\n    return 1\n")
    assert lazy["ok"] is False and "is not available to scripts" in lazy["error"]


def test_a_script_cannot_open_files_or_read_its_environment():
    assert run("def main(args):\n    return open('/etc/passwd').read()\n")["error"].startswith("Line 2: NameError")
    # Nothing of the server's environment (its token) reaches a script; Python may set its own locale.
    assert set(run("import os\ndef main(args):\n    return dict(os.environ)\n")["result"]) <= {"LC_CTYPE"}
    # Its working directory is a fresh one, gone afterwards.
    answer = run("import os\ndef main(args):\n    return os.getcwd()\n")
    assert "nik-script-" in answer["result"] and not os.path.exists(answer["result"])


def test_a_script_is_stopped_when_it_takes_too_long():
    spin = run("def main(args):\n    while True:\n        pass\n", timeout=1)
    assert spin["ok"] is False and spin["error"] == "The script ran longer than 1 seconds and was stopped"
    assert spin["duration_ms"] < 5000
    sleep = run("import time\ndef main(args):\n    time.sleep(30)\n    return 1\n", timeout=1)
    assert sleep["error"] == "The script ran longer than 1 seconds and was stopped" and sleep["duration_ms"] < 5000
    # The timeout a caller asks for is capped.
    assert run("def main(args):\n    return 1\n", timeout=10_000)["ok"] is True


def test_a_script_cannot_take_all_the_memory_or_write_without_end():
    greedy = run("def main(args):\n    x = bytearray(1024 * 1024 * 1024)\n    return len(x)\n")
    assert greedy["ok"] is False and ("MemoryError" in greedy["error"] or "memory" in greedy["error"])
    loud = run("def main(args):\n    print('x' * 5_000_000)\n    return 1\n")
    assert loud["ok"] is True and len(loud["stdout"]) == runner.MAX_LOG  # the log is cut
    big = run("def main(args):\n    return 'x' * 2_000_000\n")
    assert big["ok"] is False and big["error"] == "The result is larger than 1 MB"


@pytest.mark.skipif(os.geteuid() == 0, reason="the process limit is not enforced for root")
def test_a_script_cannot_start_processes_or_threads():
    fork = run("import os\ndef main(args):\n    return os.fork()\n")
    assert fork["ok"] is False and ("BlockingIOError" in fork["error"] or "OSError" in fork["error"])
    thread = run(
        "import threading\ndef main(args):\n    t = threading.Thread(target=lambda: None); t.start(); return 1\n"
    )
    assert thread["ok"] is False


def test_the_server_runs_a_script_for_whoever_holds_the_token():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"

    def post(path, payload, token="test-token"):
        request = urllib.request.Request(
            base + path, data=json.dumps(payload).encode(), headers={"X-Sandbox-Token": token}, method="POST"
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as answer:  # noqa: S310 - the test's own server
                return answer.status, json.loads(answer.read())
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read() or b"{}")

    try:
        with urllib.request.urlopen(base + "/health", timeout=5) as answer:  # noqa: S310
            assert json.loads(answer.read()) == {"status": "ok"}
        status, body = post("/run", {"code": "def main(args):\n    return args['n'] * 2\n", "args": {"n": 21}})
        assert status == 200 and body["ok"] is True and body["result"] == 42
        assert post("/run", {"code": "def main(a):\n    return 1\n"}, token="wrong")[0] == 401
        assert post("/run", {"code": "def main(a):\n    return 1\n"}, token="")[0] == 401
        assert post("/run", {"args": {}})[0] == 400
        assert post("/run", {"code": 7})[0] == 400
        assert post("/nope", {})[0] == 404
    finally:
        httpd.shutdown()

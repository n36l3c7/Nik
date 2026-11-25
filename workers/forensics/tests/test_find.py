"""The search of the viewer: where a text or some bytes sit in an original, from an offset, a block at a time.

Run in the worker's image: ``python -m pytest tests`` from /opt/nik-forensics. Every file is made here.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time

import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
os.environ.setdefault("FORENSICS_TOKEN", "a token for the tests, long enough")

from test_forensics import call, worker  # noqa: E402, F401 - the fixture is used by name

from nik_forensics import finding  # noqa: E402


def write(tmp_path, data: bytes) -> str:
    path = tmp_path / "original.bin"
    path.write_bytes(data)
    return str(path)


def offsets(answer: dict) -> list[tuple[int, str]]:
    return [(m["offset"], m["encoding"]) for m in answer["matches"]]


def test_a_text_is_found_as_utf8_in_any_case(tmp_path):
    data = b"\x00\x01 Mimikatz and MIMIKATZ and mimikatz\n"
    answer = finding.find(write(tmp_path, data), "MimiKatz", "text")
    assert offsets(answer) == [(3, "utf-8"), (16, "utf-8"), (29, "utf-8")]
    assert all(m["length"] == 8 for m in answer["matches"])
    assert answer["next"] is None and answer["cut"] is False and answer["scanned"] == len(data)


def test_a_text_is_found_as_utf16le_too(tmp_path):
    data = b"\xff\xfe" + "Security".encode("utf-16-le") + b"\x00\x00" + b"security"
    answer = finding.find(write(tmp_path, data), "SECURITY", "text")
    assert answer["matches"] == [
        {"offset": 2, "length": 16, "encoding": "utf-16le"},
        {"offset": 20, "length": 8, "encoding": "utf-8"},
    ]


def test_a_letter_beyond_ascii_matches_in_both_cases_and_both_encodings(tmp_path):
    data = "xx Ünï yy ünï".encode() + b"|" + "ÜNÏ".encode("utf-16-le")
    answer = finding.find(write(tmp_path, data), "ünï", "text")
    assert [(m["encoding"], m["length"]) for m in answer["matches"]] == [("utf-8", 5), ("utf-8", 5), ("utf-16le", 6)]


def test_overlapping_matches_are_all_told(tmp_path):
    answer = finding.find(write(tmp_path, b"aaaa"), "aa", "text")
    assert [m["offset"] for m in answer["matches"]] == [0, 1, 2]


def test_hex_is_exact_and_may_have_spaces(tmp_path):
    data = b"\x00\xde\xad\xbe\xef\x00\xde\xad\xbe\xef\xde\xad"
    path = write(tmp_path, data)
    answer = finding.find(path, "DE ad be Ef", "hex")
    assert answer["matches"] == [
        {"offset": 1, "length": 4, "encoding": "hex"},
        {"offset": 6, "length": 4, "encoding": "hex"},
    ]
    assert offsets(finding.find(path, "dead", "hex")) == [(1, "hex"), (6, "hex"), (10, "hex")]
    assert [m["offset"] for m in finding.find(path, "00", "hex")["matches"]] == [0, 5]
    # Text is folded to a case, bytes are not: 0x41 is "A" and is not found by the hex of "a".
    assert finding.find(write(tmp_path, b"A"), "61", "hex")["matches"] == []


def test_a_match_across_the_edge_of_two_blocks_is_found_once(tmp_path):
    needle = "abc"  # six bytes as UTF-16LE: no block is shorter than the tail kept between two
    for block in (6, 7, 8, 16, 33):
        for at in range(0, 40):
            data = b"." * at + needle.encode() + b"." * 30
            answer = finding.find(write(tmp_path, data), needle, "text", block=block)
            assert offsets(answer) == [(at, "utf-8")], (block, at)
    wide = b"." * 13 + needle.encode("utf-16-le") + b"." * 5
    answer = finding.find(write(tmp_path, wide), needle, "text", block=8)
    assert answer["matches"] == [{"offset": 13, "length": 6, "encoding": "utf-16le"}]


def test_a_file_scanned_in_tiny_blocks_gives_what_one_block_gives(tmp_path):
    data = (b"ab" * 7 + b"AB\x00" + "ab".encode("utf-16-le")) * 20
    path = write(tmp_path, data)
    whole = finding.find(path, "ab", "text", limit=200)
    assert 100 < len(whole["matches"]) < 200 and whole["cut"] is False
    for block in (1, 2, 3, 5, 11):  # a block is never shorter than the tail kept between two
        assert finding.find(path, "ab", "text", limit=200, block=block)["matches"] == whole["matches"], block


def test_the_search_goes_on_from_next_until_the_end(tmp_path):
    data = b"x" * 5 + b"abc" + b"y" * 7 + b"abc" + b"abc" + b"z" * 50 + b"abc"
    path = write(tmp_path, data)
    seen, start, calls = [], 0, 0
    while start is not None:
        answer = finding.find(path, "abc", "text", start=start, limit=2, block=16)
        seen += [m["offset"] for m in answer["matches"]]
        assert answer["cut"] is (answer["next"] is not None)
        start, calls = answer["next"], calls + 1
    assert seen == [5, 15, 18, 71] and calls == 2
    # From the middle of the file, and from past its end.
    assert [m["offset"] for m in finding.find(path, "abc", "text", start=16)["matches"]] == [18, 71]
    answer = finding.find(path, "abc", "text", start=10_000)
    assert answer == {"matches": [], "next": None, "scanned": 0, "cut": False}


def test_the_limit_stops_the_search_and_says_where_to_go_on(tmp_path):
    path = write(tmp_path, b"abcd" * 10)
    answer = finding.find(path, "abcd", "text", limit=3)
    assert [m["offset"] for m in answer["matches"]] == [0, 4, 8]
    assert answer["next"] == 12 and answer["cut"] is True
    exact = finding.find(path, "abcd", "text", limit=10)  # as many as there are: nothing left, nothing cut
    assert len(exact["matches"]) == 10 and exact["next"] is None and exact["cut"] is False


def test_the_clock_stops_the_search_between_blocks_and_next_loses_no_match(tmp_path):
    data = b"." * 7 + b"needle" + b"." * 40 + b"needle" + b"." * 9
    path = write(tmp_path, data)
    answer = finding.find(path, "needle", "text", block=12, deadline=time.monotonic() - 1)
    assert answer["cut"] is True and answer["next"] is not None and answer["scanned"] == 12
    seen, start = [], 0
    while start is not None:  # every call reads one block only, and the calls together find what one call does
        answer = finding.find(path, "needle", "text", start=start, block=12, deadline=time.monotonic() - 1)
        seen += [m["offset"] for m in answer["matches"]]
        assert answer["next"] is None or answer["next"] > start
        start = answer["next"]
    assert seen == [7, 53]


def test_a_bad_needle_is_said(tmp_path):
    path = write(tmp_path, b"abc")
    bad = (("a", "text"), ("a" * 257, "text"), ("", "hex"), ("abc", "hex"), ("zz", "hex"), ("00" * 129, "hex"))
    for needle, how in (*bad, ("ab", "base64")):
        with pytest.raises(finding.BadNeedle):
            finding.find(path, needle, how)
    with pytest.raises(finding.BadNeedle, match="UTF-8"):
        finding.find(path, "ab\ud800", "text")
    assert finding.find(path, "00" * 128, "hex")["matches"] == []
    assert finding.find(path, "a" * 256, "text")["matches"] == []


# --------------------------------------------------------------------------- #
# Over HTTP                                                                   #
# --------------------------------------------------------------------------- #
def test_the_search_over_http(worker):  # noqa: F811
    _server, base = worker
    data = b"..Needle.." + "needle".encode("utf-16-le") + b"..\xca\xfe"
    sha256 = hashlib.sha256(data).hexdigest()
    asked = {"sha256": sha256, "needle": "NEEDLE", "as": "text"}
    status, body = call(base, "POST", "/find", asked)
    assert status == 409 and json.loads(body)["missing"] == [f"{sha256}.bin"]
    assert call(base, "PUT", f"/files/{sha256}.bin", raw=data)[0] == 200
    status, body = call(base, "POST", "/find", asked)
    assert status == 200 and json.loads(body) == {
        "matches": [
            {"offset": 2, "length": 6, "encoding": "utf-8"},
            {"offset": 10, "length": 12, "encoding": "utf-16le"},
        ],
        "next": None,
        "scanned": len(data),
        "cut": False,
    }
    hexed = {"sha256": sha256, "needle": "ca fe", "as": "hex", "from": 5, "limit": 1}
    status, body = call(base, "POST", "/find", hexed)
    assert status == 200 and json.loads(body)["matches"] == [{"offset": len(data) - 2, "length": 2, "encoding": "hex"}]
    status, body = call(base, "POST", "/find", {"sha256": sha256, "needle": "nee", "limit": 1})  # "as" defaults to text
    shown = json.loads(body)
    assert shown["cut"] is True and shown["next"] == 10 and len(shown["matches"]) == 1
    assert call(base, "POST", "/find", asked, token="wrong")[0] == 401


def test_a_bad_request_is_a_400_before_the_file_is_looked_for(worker):  # noqa: F811
    _server, base = worker
    sha256 = "0" * 64  # the worker does not hold it: a 409 would say the request passed the checks
    for change in (
        {"needle": "a"},
        {"needle": 7},
        {"needle": "zz", "as": "hex"},
        {"as": "base64"},
        {"from": -1},
        {"from": "1"},
        {"from": True},
        {"limit": 0},
        {"limit": 201},
        {"limit": 1.5},
        {"sha256": "x"},
        {"sha256": 7},
    ):
        status, body = call(base, "POST", "/find", {"sha256": sha256, "needle": "ab", **change})
        assert status == 400 and json.loads(body)["detail"], change
    assert call(base, "POST", "/find", {"needle": "ab"})[0] == 400
    assert call(base, "POST", "/find", {"sha256": sha256, "needle": "ab"})[0] == 409
    status, body = call(base, "POST", "/find", {"sha256": sha256, "needle": "a"})
    assert "2 to 256" in json.loads(body)["detail"]


def _finder(tmp_path, code: str) -> str:
    path = tmp_path / f"finder{abs(hash(code))}.py"
    path.write_text(code)
    return str(path)


def test_a_search_cut_by_its_clock_answers_with_next_and_is_not_an_error(worker, monkeypatch):  # noqa: F811
    server, base = worker
    data = b"x" * (finding.BLOCK + 1000) + b"needle"  # more than one block
    sha256 = hashlib.sha256(data).hexdigest()
    call(base, "PUT", f"/files/{sha256}.bin", raw=data)
    asked = {"sha256": sha256, "needle": "needle"}
    with monkeypatch.context() as patch:  # the child's own clock is out at once: it reads one block and says so
        patch.setattr(server, "FIND_STOP_SECONDS", 0)
        status, body = call(base, "POST", "/find", asked)
    shown = json.loads(body)
    assert status == 200 and shown["cut"] is True and shown["matches"] == []
    assert shown["scanned"] == finding.BLOCK and shown["next"] == finding.BLOCK - 11  # the tail of 11 bytes is kept
    status, body = call(base, "POST", "/find", {**asked, "from": shown["next"]})
    shown = json.loads(body)
    assert (
        status == 200
        and shown["cut"] is False
        and shown["matches"] == [{"offset": finding.BLOCK + 1000, "length": 6, "encoding": "utf-8"}]
    )


def test_a_runaway_search_is_a_504_a_huge_answer_a_502_and_the_slots_are_few(worker, tmp_path, monkeypatch):  # noqa: F811
    server, base = worker
    data = b"x" * 1000 + b"needle"
    sha256 = hashlib.sha256(data).hexdigest()
    call(base, "PUT", f"/files/{sha256}.bin", raw=data)
    asked = {"sha256": sha256, "needle": "needle"}
    sleeper = _finder(tmp_path, "import time\ntime.sleep(30)\n")
    flood = _finder(tmp_path, "print('{\"x\": \"' + 'a' * (300 * 1024) + '\"}')\n")
    failing = _finder(tmp_path, "import sys\nsys.exit(7)\n")
    with monkeypatch.context() as patch:
        patch.setattr(server, "FINDER", sleeper)
        patch.setattr(server, "FIND_SECONDS", 1)
        assert call(base, "POST", "/find", asked)[0] == 504
    with monkeypatch.context() as patch:
        patch.setattr(server, "FINDER", flood)
        assert call(base, "POST", "/find", asked)[0] == 502
    with monkeypatch.context() as patch:
        patch.setattr(server, "FINDER", failing)
        assert call(base, "POST", "/find", asked)[0] == 500
    taken = [server._find_slots.acquire(blocking=False) for _ in range(server.FIND_SLOTS)]
    try:
        assert all(taken) and call(base, "POST", "/find", asked)[0] == 503
    finally:
        for _ in taken:
            server._find_slots.release()
    status, body = call(base, "POST", "/find", asked)
    assert status == 200 and json.loads(body)["matches"] == [{"offset": 1000, "length": 6, "encoding": "utf-8"}]


def test_the_child_exits_as_the_server_expects(tmp_path):
    path = write(tmp_path, b"..abc..")
    job = [sys.executable, "-I", os.path.join(HERE, "find_job.py"), path]
    asked = json.dumps({"needle": "ABC", "as": "text", "seconds": 5})
    done = subprocess.run([*job, asked], capture_output=True, check=False)
    assert done.returncode == 0 and json.loads(done.stdout)["matches"][0]["offset"] == 2
    bad = subprocess.run([*job, json.dumps({"needle": "a", "as": "text"})], capture_output=True, check=False)
    assert bad.returncode == 5 and "2 to 256" in json.loads(bad.stdout)["detail"]

"""The prefetch parser: run times, volumes, the loaded files, and what libscca refuses. Run in the worker's image.

The files are written by ``artifact_gen.prefetch_bytes`` in the uncompressed layouts of formats 23 and 30; the MAM
(compressed) path of libscca is only proven by the checks against real files said in the report, not by a test here.
"""

from __future__ import annotations

import io
import json
import os
import struct
import sys

import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "tests"))

import artifact_gen as gen  # noqa: E402
from nik_forensics import parsers  # noqa: E402
from nik_forensics.context import Context  # noqa: E402
from nik_forensics.parsers import ViewError, prefetch  # noqa: E402

TIMES = [1_600_000_000_000, 1_600_000_100_000, 1_600_000_200_000]


def said(tmp_path, data: bytes) -> list[dict]:
    path = tmp_path / "in.pf"
    path.write_bytes(data)
    out = io.BytesIO()
    prefetch.parse(str(path), Context(out, {"host": "WKS-1", "file_name": "NOTEPAD.EXE-D8414F97.pf"}), prefetch.SOURCE)
    return [json.loads(line) for line in out.getvalue().splitlines() if line]


def of(found: list[dict], kind: str) -> list[dict]:
    return [event for event in found if event["t"] == kind]


def test_the_module_declares_what_the_worker_needs():
    assert (prefetch.NAME, prefetch.VERSION, prefetch.KIND) == ("prefetch", "1", "endpoint")
    assert prefetch.SOURCES == ("windows.execution.prefetch",)
    assert parsers.by_source("endpoint", "windows.execution.prefetch") is prefetch


def test_a_windows_10_file_gives_one_record_per_stored_run_time(tmp_path):
    data = gen.prefetch_bytes(30, run_times=TIMES, run_count=3)
    found = said(tmp_path, data)
    records = of(found, "r")
    assert len(records) == 3
    # Newest first, as libscca gives them; the key holds the run time.
    assert [r["ts"] for r in records] == TIMES and records[0]["key"] == "pf:WKS-1:NOTEPAD.EXE:D8414F97:1600000000000"
    first = records[0]["data"]
    assert first["executable"] == "NOTEPAD.EXE" and first["prefetch_hash"] == "D8414F97" and first["run_count"] == 3
    assert first["format_version"] == 30 and first["windows"] == "Windows 10"
    assert first["volumes"] == [
        {"serial": "70ECFA33", "created": 1_500_000_000_000, "device_path": r"\VOLUME{01d0e1a2b3c4d5e6-70ecfa33}"}
    ]
    assert [r["data"]["run_index"] for r in records] == [0, 1, 2]
    assert records[0]["loc"] == {"offset": 0, "length": len(data), "run": 0}
    end = of(found, "end")[0]
    assert end["in_file"] == 3 and end["read"] == 3 and not of(found, "skip") and not of(found, "note")


def test_the_loaded_files_are_in_the_record_of_the_most_recent_run_only(tmp_path):
    # The times are given oldest first: the record that holds the files is the one with the largest time, not the first.
    data = gen.prefetch_bytes(30, run_times=[TIMES[0], TIMES[2], TIMES[1]], run_count=3)
    records = of(said(tmp_path, data), "r")
    holding = [r for r in records if "files" in r["data"]]
    assert len(holding) == 1 and holding[0]["ts"] == TIMES[2]
    assert holding[0]["data"]["files"][-1].endswith(r"\NOTEPAD.EXE")
    assert holding[0]["data"]["executable_path"].endswith(r"\SYSTEM32\NOTEPAD.EXE")
    assert holding[0]["data"]["files_total"] == 2


def test_a_windows_7_file_stores_one_time_and_a_larger_run_count_is_a_note(tmp_path):
    found = said(tmp_path, gen.prefetch_bytes(23, run_times=[TIMES[0]], run_count=5))
    (record,) = of(found, "r")
    assert record["ts"] == TIMES[0] and record["data"]["format_version"] == 23
    assert "files" in record["data"]
    (note,) = of(found, "note")
    assert note["reason"] == "run count above the stored run times" and note["count"] == 4
    assert of(found, "end")[0]["in_file"] == 1


def test_a_file_with_no_run_time_is_still_one_record_without_a_time(tmp_path):
    found = said(tmp_path, gen.prefetch_bytes(30, run_times=[], run_count=2))
    (record,) = of(found, "r")
    assert record["ts"] is None and record["data"]["executable"] == "NOTEPAD.EXE" and "files" in record["data"]
    assert [n["reason"] for n in of(found, "note")] == ["no run time stored"]
    assert of(found, "end")[0]["in_file"] == 1


def test_a_long_list_of_loaded_files_is_cut_and_the_cut_is_said(tmp_path, monkeypatch):
    names = [rf"\VOLUME{{01d0}}\WINDOWS\LIB{i}.DLL" for i in range(12)] + [r"\VOLUME{01d0}\X\NOTEPAD.EXE"]
    data = gen.prefetch_bytes(30, run_times=[TIMES[0]], files=names)
    monkeypatch.setattr(prefetch, "MAX_FILES", 5)
    found = said(tmp_path, data)
    (record,) = of(found, "r")
    assert len(record["data"]["files"]) == 5 and record["data"]["files_total"] == 13
    (skip,) = of(found, "skip")
    assert skip["reason"] == "list of loaded files cut" and skip["lost"] == 0 and "8 of 13" in skip["detail"]
    # The viewer is not cut.
    path = tmp_path / "v.pf"
    path.write_bytes(data)
    assert len(prefetch.view(str(path), prefetch.SOURCE, {})["text"].splitlines()) == 13


def test_a_file_libscca_refuses_is_a_failed_read_with_its_sentence(tmp_path):
    good = gen.prefetch_bytes(30, run_times=TIMES)
    for broken in (good[:200], good[:90] + b"\xff" * (len(good) - 90), b"\x1e\x00\x00\x00SCCA" + b"\x00" * 40):
        found = said(tmp_path, broken)
        assert not of(found, "r")
        (skip,) = of(found, "skip")
        assert skip["reason"] == "prefetch file cannot be read" and skip["lost"] == 0 and skip["detail"]
        assert "\n" not in skip["detail"]
        assert of(found, "end")[0]["in_file"] is None


def test_a_compressed_file_that_claims_a_huge_size_is_refused_before_the_library(tmp_path):
    hostile = b"MAM\x04" + struct.pack("<I", 0x7FFFFFFF) + b"\x00" * 64
    found = said(tmp_path, hostile)
    (skip,) = of(found, "skip")
    assert skip["reason"] == "prefetch file cannot be read" and "expands to 2147483647" in skip["detail"]
    small = tmp_path / "x.pf"
    small.write_bytes(b"\x00" * 100)
    old, prefetch.MAX_SIZE = prefetch.MAX_SIZE, 50
    try:
        out = io.BytesIO()
        prefetch.parse(str(small), Context(out, {}), prefetch.SOURCE)
    finally:
        prefetch.MAX_SIZE = old
    assert "the limit is 50" in out.getvalue().decode()


def test_sniff_by_the_signature_and_for_a_compressed_file_by_its_name(tmp_path):
    data = gen.prefetch_bytes(30)
    assert prefetch.sniff("", "whatever", data[:4096]) == "windows.execution.prefetch"
    assert prefetch.sniff("", "x.pf", b"MAM\x04" + b"\x00" * 20) == "windows.execution.prefetch"
    assert prefetch.sniff("", "x.bin", b"MAM\x04" + b"\x00" * 20) is None
    assert prefetch.sniff("", "x.pf", b"\x1e\x00\x00\x00XXXX") is None
    path = tmp_path / "f"
    path.write_bytes(data)
    module, source = parsers.recognise(str(path), "f")
    assert module is prefetch and source == prefetch.SOURCE


def test_view_shows_the_header_fields_and_the_strings(tmp_path):
    path = tmp_path / "v.pf"
    data = gen.prefetch_bytes(30, run_times=TIMES[:2], run_count=9)
    path.write_bytes(data)
    shown = prefetch.view(str(path), prefetch.SOURCE, {"offset": 0, "length": len(data)})
    rows = dict(shown["rows"])
    assert rows["executable"] == "NOTEPAD.EXE" and rows["prefetch hash"] == "D8414F97" and rows["run count"] == "9"
    assert rows["format version"].startswith("30 (Windows 10)")
    assert rows["run time 0"].startswith("2020-09-13T12:26:40") and "run time 1" in rows and "volume 0" in rows
    assert shown["text"].splitlines()[-1].endswith("NOTEPAD.EXE") and shown["where"]["length"] == len(data)
    path.write_bytes(b"not a prefetch file")
    with pytest.raises(ViewError):
        prefetch.view(str(path), prefetch.SOURCE, {})


def test_damaged_prefetch_files_never_stop_the_parse_and_always_end(tmp_path):
    import random

    rng = random.Random(7)
    for version in (23, 30):
        data = gen.prefetch_bytes(version, run_times=TIMES, run_count=3)
        for round_ in range(120):
            damaged = bytearray(data)
            if round_ % 2:
                damaged = damaged[: rng.randrange(1, len(damaged))]
            else:
                for _ in range(rng.randint(1, 8)):
                    damaged[rng.randrange(len(damaged))] = rng.randrange(256)
            assert said(tmp_path, bytes(damaged))[-1]["t"] == "end"

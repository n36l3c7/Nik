"""The shortcut parser: the fields, the time chosen, the MAC, the damage. Run in the worker's image.

Every shortcut is written here by ``artifact_gen.lnk_bytes`` (the structure of the format, harmless values).
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import sys

import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "tests"))

import artifact_gen as gen  # noqa: E402

from nik_forensics import parsers  # noqa: E402
from nik_forensics.context import Context  # noqa: E402
from nik_forensics.parsers import ViewError, lnk  # noqa: E402


def said(tmp_path, data: bytes, name: str = "plan.docx.lnk") -> list[dict]:
    path = tmp_path / "in.lnk"
    path.write_bytes(data)
    out = io.BytesIO()
    lnk.parse(str(path), Context(out, {"host": "WKS-1", "username": "alice", "file_name": name}), lnk.SOURCE)
    return [json.loads(line) for line in out.getvalue().splitlines() if line]


def of(found: list[dict], kind: str) -> list[dict]:
    return [event for event in found if event["t"] == kind]


def test_the_module_declares_what_the_worker_needs():
    assert (lnk.NAME, lnk.VERSION, lnk.KIND, lnk.SOURCES) == ("lnk", "1", "endpoint", ("windows.fileaccess.lnk",))
    assert parsers.by_source("endpoint", "windows.fileaccess.lnk") is lnk


def test_a_shortcut_is_one_record_with_its_target_its_times_and_its_machine(tmp_path):
    data = gen.lnk_bytes(arguments="-open", working_dir=r"C:\Users\alice", icon=r"C:\icons\doc.ico")
    found = said(tmp_path, data)
    (record,) = of(found, "r")
    assert record["key"] == f"lnk:WKS-1:{hashlib.sha1(data).hexdigest()}"  # noqa: S324
    assert record["type"] == "lnk"
    fields = record["data"]
    assert fields["target"] == r"C:\Users\alice\Documents\plan.docx" and fields["target_from"] == "local base path"
    assert (fields["arguments"], fields["working_dir"], fields["icon"]) == (
        "-open",
        r"C:\Users\alice",
        r"C:\icons\doc.ico",
    )
    assert (fields["target_created"], fields["target_accessed"], fields["target_modified"]) == (
        1_600_000_000_000,
        1_600_000_600_000,
        1_600_000_300_000,
    )
    assert fields["target_size"] == 12345
    assert (fields["drive_type"], fields["drive_serial"], fields["drive_label"]) == ("DRIVE_FIXED", "0x70ecfa33", "OS")
    assert fields["machine_id"] == "wks-042" and fields["mac"] == "00:1d:09:fa:5a:1c"
    assert fields["droid_time"] == 1_247_531_342_000
    assert fields["name"] == "plan.docx.lnk"
    assert record["loc"] == {"offset": 0, "length": len(data)}
    assert "plan.docx" in record["summary"] and "-open" in record["summary"]
    assert record["ioc"] == []
    # The time of the record is the target's last access.
    assert record["ts"] == 1_600_000_600_000 and fields["ts_from"] == "accessed"
    assert of(found, "end")[0]["in_file"] == 1 and not of(found, "skip") and not of(found, "note")


def test_the_time_falls_back_to_the_last_write_then_the_creation(tmp_path):
    (one,) = of(said(tmp_path, gen.lnk_bytes(accessed=None)), "r")
    assert (one["ts"], one["data"]["ts_from"]) == (1_600_000_300_000, "modified")
    (two,) = of(said(tmp_path, gen.lnk_bytes(accessed=None, modified=None)), "r")
    assert (two["ts"], two["data"]["ts_from"]) == (1_600_000_000_000, "created")
    found = said(tmp_path, gen.lnk_bytes(accessed=None, modified=None, created=None))
    (three,) = of(found, "r")
    assert three["ts"] is None and three["data"]["ts_from"] == ""
    assert [note["reason"] for note in of(found, "note")] == ["shortcut without a time"]


def test_the_mac_is_only_read_from_a_version_1_droid(tmp_path):
    (record,) = of(said(tmp_path, gen.lnk_bytes(droid="9d5c8c4e-1b2a-4f6e-8a3c-5d7e9f0a1b2c")), "r")
    assert record["data"]["mac"] == "" and record["data"]["droid_time"] is None
    assert record["data"]["droid_file"] == "9D5C8C4E-1B2A-4F6E-8A3C-5D7E9F0A1B2C"


def test_a_network_target_gives_its_share_and_a_link_without_info_gives_the_item_list(tmp_path):
    (net,) = of(said(tmp_path, gen.lnk_bytes(None, share=r"\\srv\share\docs", id_list=True, machine=None)), "r")
    assert net["data"]["target"] == r"\\srv\share\docs" and net["data"]["target_from"] == "network share"
    assert net["data"]["network_share"] == r"\\srv\share\docs" and net["data"]["network_device"] == "Z:"
    assert net["data"]["machine_id"] == "" and net["data"]["mac"] == ""
    assert net["data"]["item_list"]
    (bare,) = of(said(tmp_path, gen.lnk_bytes(None, machine=None)), "r")
    assert bare["data"]["target"] == "" and bare["data"]["target_from"] == ""


def test_extent_says_where_the_shortcut_ends_and_why_it_does_not():
    data = gen.lnk_bytes(arguments="x", working_dir="y")
    assert lnk.extent(data) == (len(data), "")
    assert lnk.extent(data + b"trailing") == (len(data), "")
    assert lnk.extent(b"\x00" * 100)[1] == "not a shell link header"
    for cut in (10, 76, 90, 120, len(data) - 6):
        length, why = lnk.extent(data[:cut])
        assert why and length <= cut
    # A start inside a larger buffer: what a custom destinations file needs.
    assert lnk.extent(b"abcd" + data, 4) == (len(data), "")


def test_a_shortcut_with_bytes_after_its_end_is_parsed_in_part(tmp_path):
    found = said(tmp_path, gen.lnk_bytes() + b"\xde\xad\xbe\xef" * 5)
    assert len(of(found, "r")) == 1
    (note,) = of(found, "note")
    assert note["reason"] == "shortcut parsed in part" and "20 bytes after the end" in note["detail"]
    assert not of(found, "skip")


@pytest.mark.parametrize("cut", [20, 76, 100, 200, 290])
def test_a_shortcut_cut_short_is_never_read_in_silence(tmp_path, cut):
    data = gen.lnk_bytes(arguments="x" * 20)
    assert cut < len(data)
    found = said(tmp_path, data[:cut])
    assert of(found, "end")[0]["in_file"] == 1
    said_so = [s["reason"] for s in of(found, "skip")] + [n["reason"] for n in of(found, "note")]
    assert said_so, "a damaged shortcut must be said"
    if of(found, "r"):
        assert "shortcut parsed in part" in said_so
    else:
        assert of(found, "skip")[0]["lost"] == 1 and "shortcut cannot be read" in said_so


def test_what_is_not_a_shortcut_and_what_is_too_large_are_skips(tmp_path):
    found = said(tmp_path, b"MZ" + b"\x00" * 200)
    assert not of(found, "r")
    (skip,) = of(found, "skip")
    assert skip["reason"] == "shortcut cannot be read" and skip["lost"] == 1 and skip["offset"] == 0
    assert of(found, "end")[0]["in_file"] == 1
    small = tmp_path / "big.lnk"
    small.write_bytes(b"\x00" * 100)
    old, lnk.MAX_SIZE = lnk.MAX_SIZE, 50
    try:
        out = io.BytesIO()
        lnk.parse(str(small), Context(out, {}), lnk.SOURCE)
    finally:
        lnk.MAX_SIZE = old
    found = [json.loads(line) for line in out.getvalue().splitlines()]
    assert of(found, "skip")[0]["reason"] == "file too large to read as a shortcut"
    assert of(found, "end")[0]["in_file"] is None


def test_a_library_warning_becomes_a_note(tmp_path, monkeypatch):
    import warnings

    import LnkParse3

    real = LnkParse3.lnk_file

    def noisy(handle, *args, **kwargs):
        warnings.warn("the extra block is shorter than its size says", stacklevel=2)
        return real(handle, *args, **kwargs)

    monkeypatch.setattr(LnkParse3, "lnk_file", noisy)
    found = said(tmp_path, gen.lnk_bytes())
    assert len(of(found, "r")) == 1
    (note,) = of(found, "note")
    assert note["reason"] == "shortcut parsed in part" and "shorter than its size" in note["detail"]


def test_sniff_by_the_header_only():
    data = gen.lnk_bytes()
    assert lnk.sniff("", "whatever.bin", data[:4096]) == "windows.fileaccess.lnk"
    assert lnk.sniff("", "a.lnk", b"MZ" + data[2:4096]) is None
    assert lnk.sniff("", "a.lnk", b"") is None


def test_recognise_finds_the_shortcut_among_all_parsers(tmp_path):
    path = tmp_path / "x"
    path.write_bytes(gen.lnk_bytes())
    module, source = parsers.recognise(str(path), "x")
    assert module is lnk and source == "windows.fileaccess.lnk"


def test_view_shows_the_library_reading_and_the_bytes(tmp_path):
    path = tmp_path / "v.lnk"
    data = gen.lnk_bytes(arguments="-open")
    path.write_bytes(data)
    shown = lnk.view(str(path), lnk.SOURCE, {"offset": 0, "length": len(data)})
    assert shown["kind"] == "fields" and shown["where"] == {"offset": 0, "length": len(data)}
    names = [row[0] for row in shown["rows"]]
    assert "header" in names and "link_info" in names and "data" in names
    assert "00000000" in shown["text"]
    path.write_bytes(b"not a shortcut at all")
    with pytest.raises(ViewError):
        lnk.view(str(path), lnk.SOURCE, {})


def test_damaged_shortcuts_never_stop_the_parse_and_always_end(tmp_path):
    import random

    rng = random.Random(7)
    data = gen.lnk_bytes(arguments="abc", working_dir=r"C:\x", icon="i.ico", share=None)
    for round_ in range(150):
        damaged = bytearray(data)
        if round_ % 2:
            damaged = damaged[: rng.randrange(1, len(damaged))]
        else:
            for _ in range(rng.randint(1, 8)):
                damaged[rng.randrange(len(damaged))] = rng.randrange(256)
        assert said(tmp_path, bytes(damaged))[-1]["t"] == "end"

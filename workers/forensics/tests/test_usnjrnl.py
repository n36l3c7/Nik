"""The $J parser: the records of a journal against what it was said to hold, damage, zeros, V4, keys, the view.

The journal is made here (``ntfs_fixtures.make_usn``): harmless bytes. Run in the worker's image.
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
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ntfs_fixtures as fx  # noqa: E402
from nik_forensics import parsers  # noqa: E402
from nik_forensics.context import Context  # noqa: E402
from nik_forensics.parsers import BadLocator, ViewError  # noqa: E402
from nik_forensics.parsers import usnjrnl as parser  # noqa: E402


def said(path: str, host: str = "WKS-1") -> list[dict]:
    out = io.BytesIO()
    parser.parse(path, Context(out, {"host": host}), "ntfs.usnjrnl")
    return [json.loads(line) for line in out.getvalue().splitlines() if line]


def write(tmp_path, name: str, data: bytes) -> str:
    path = tmp_path / name
    path.write_bytes(data)
    return str(path)


def of(found: list[dict], t: str) -> list[dict]:
    return [event for event in found if event["t"] == t]


def notes(found: list[dict]) -> dict[str, dict]:
    return {event["reason"]: event for event in of(found, "note")}


@pytest.fixture(scope="module")
def journal(tmp_path_factory):
    made = fx.make_usn()
    path = tmp_path_factory.mktemp("usn") / "$UsnJrnl_$J"
    path.write_bytes(made.data)
    return made, str(path), said(str(path))


def test_the_parser_is_declared():
    assert (parser.NAME, parser.VERSION, parser.KIND, parser.SOURCES) == ("usnjrnl", "1", "disk", ("ntfs.usnjrnl",))
    assert parsers.by_source("disk", "ntfs.usnjrnl") is parser


def test_every_record_is_read_in_order_and_the_count_is_the_scans(journal):
    made, _path, found = journal
    records = of(found, "r")
    assert [event["data"]["usn"] for event in records] == made.usns
    end = of(found, "end")[0]
    assert end["in_file"] == made.expect["found"] and end["read"] == len(records)
    # found = read + the V4 record + the two stretches passed over + the record the file stops in
    assert end["in_file"] == len(records) + 1 + 2 + 1


def test_damage_is_a_skip_with_offset_and_length_and_the_reader_goes_on(journal):
    made, _path, found = journal
    skips = of(found, "skip")
    assert len(skips) == made.expect["skips"] == 3
    by_name = {event["data"]["name"]: event for event in of(found, "r")}
    garbage, bad_name, tail = skips
    renamed = by_name["renamed é.txt"]["loc"]
    after = by_name["after_garbage.txt"]["loc"]
    assert garbage["offset"] == renamed["offset"] + renamed["length"] and garbage["length"] == 64
    assert garbage["offset"] + garbage["length"] == after["offset"]
    assert "version of the record is wrong" in garbage["detail"]
    assert f"starts at byte {after['offset']}" in garbage["detail"]
    next_good = by_name["after_bad_name.txt"]["loc"]["offset"]
    assert (
        bad_name["offset"] == after["offset"] + after["length"] and bad_name["offset"] + bad_name["length"] == next_good
    )
    assert "name does not fit" in bad_name["detail"]
    assert tail["lost"] == 1 and tail["length"] == 40 and "middle of a record" in tail["detail"]


def test_zero_runs_v4_and_times_are_notes(journal):
    _made, _path, found = journal
    n = notes(found)
    zeros = n["zeros of the sparse start or freed areas"]
    assert zeros["count"] == 2 and "70536 bytes" in zeros["detail"] and "the first at byte 0" in zeros["detail"]
    assert n["zeros that pad pages between records"]["count"] == 1
    assert n["USN_RECORD_V4 records (ranges of a file that changed)"]["count"] == 1
    assert n["records without a valid time"]["count"] == 1
    assert n["records whose USN was already seen in the file"]["count"] == 1


def test_the_fields_of_a_record_and_the_reasons_by_name(journal):
    _made, _path, found = journal
    records = of(found, "r")
    first = records[0]
    assert first["type"] == "usn" and first["ts"] == 1_700_000_000_123 and first["host"] == "WKS-1"
    data = first["data"]
    assert data["name"] == "setup.exe" and data["reasons"] == ["FILE_CREATE"]
    assert (data["fileEntry"], data["fileSequence"], data["parentEntry"], data["parentSequence"]) == (33, 1, 32, 1)
    assert data["time"] == "2023-11-14T22:13:20.1234567Z" and data["attributes"] == ["ARCHIVE"] and data["version"] == 2
    assert records[1]["data"]["reasons"] == ["DATA_OVERWRITE", "DATA_EXTEND"]
    assert records[2]["data"]["reasons"] == ["FILE_CREATE", "CLOSE"]
    assert records[3]["data"]["version"] == 3 and records[3]["data"]["reasons"] == ["FILE_DELETE"]
    assert records[3]["data"]["fileSequence"] == 2
    renamed = records[4]["data"]
    assert renamed["name"] == "renamed é.txt" and renamed["reasons"] == ["RENAME_OLD_NAME", "RENAME_NEW_NAME"]
    assert renamed["attributes"] == ["HIDDEN"]
    assert [e["ts"] for e in records if e["data"]["name"] == "no_time.txt"] == [None]


def test_keys_are_stable_and_a_repeated_usn_is_kept_with_another_key(journal):
    made, path, found = journal
    records = of(found, "r")
    keys = [event["key"] for event in records]
    assert len(set(keys)) == len(keys) and keys[0] == f"usn:WKS-1:{made.usns[0]}"
    assert keys[-1] == f"usn:WKS-1:{made.usns[-1]}:o{records[-1]['loc']['offset']}"
    assert [event["key"] for event in of(said(path), "r")] == keys
    assert of(said(path, host=""), "r")[0]["key"] == f"usn:?:{made.usns[0]}"


def test_the_view_shows_the_bytes_and_the_fields(journal):
    _made, path, found = journal
    rec = of(found, "r")[0]
    shown = parser.view(path, "ntfs.usnjrnl", rec["loc"])
    assert shown["kind"] == "text" and shown["where"]["offset"] == rec["loc"]["offset"]
    assert "name: 'setup.exe'" in shown["text"] and "FILE_CREATE" in shown["text"]
    assert "file: entry 33, sequence 1" in shown["text"] and f"{rec['loc']['offset']:010x}" in shown["text"]
    nothing = parser.view(path, "ntfs.usnjrnl", {"offset": 8, "length": 64})
    assert "not a readable record" in nothing["title"]
    with pytest.raises(ViewError):
        parser.view(path, "ntfs.usnjrnl", {"offset": 10**9, "length": 64})
    with pytest.raises(BadLocator):
        parser.view(path, "ntfs.usnjrnl", {"offset": 0})


def test_v3_with_a_128_bit_id_keeps_the_whole_id(tmp_path):
    raw = fx.usn_v3(7, 9, 1, 5, 1, "refs.txt", 0x100, fx.ft(1_700_000_000), hi=3)
    found = said(write(tmp_path, "refs", raw))
    data = of(found, "r")[0]["data"]
    assert data["fileId128"].startswith("0000000000000003") and data["fileEntry"] == 9


def test_all_zeros_empty_and_a_file_of_garbage(tmp_path):
    assert of(said(write(tmp_path, "e", b"")), "end")[0]["in_file"] == 0
    found = said(write(tmp_path, "z", bytes(10_000)))
    assert of(found, "end")[0]["in_file"] == 0
    assert notes(found)["zeros of the sparse start or freed areas"]["count"] == 1
    found = said(write(tmp_path, "g", b"\xff" * 5000))
    assert (
        of(found, "end")[0]["in_file"] == 1 and len(of(found, "skip")) == 1 and of(found, "skip")[0]["length"] == 5000
    )
    found = said(write(tmp_path, "t", b"hello, this is text and not a journal at all.\n" * 50))
    assert not of(found, "r") and of(found, "skip")


def test_a_hostile_length_never_swallows_the_neighbours(tmp_path):
    good = fx.usn_v2(100, 1, 1, 5, 1, "a", 0x100, fx.ft(1_700_000_000))
    again = fx.usn_v2(200, 2, 1, 5, 1, "b", 0x100, fx.ft(1_700_000_000))
    huge = bytearray(again)
    struct.pack_into("<I", huge, 0, 0x7FFFFFF8)
    found = said(write(tmp_path, "h", good + bytes(huge) + again))
    assert [event["data"]["name"] for event in of(found, "r")] == ["a", "b"]
    assert len(of(found, "skip")) == 1 and of(found, "skip")[0]["offset"] == len(good)


def test_many_unreadable_stretches_are_listed_up_to_a_limit_and_counted(tmp_path, monkeypatch):
    monkeypatch.setattr(parser, "MAX_LISTED", 3)
    good = fx.usn_v2(100, 1, 1, 5, 1, "a", 0x100, fx.ft(1_700_000_000))
    found = said(write(tmp_path, "m", (b"\xff" * 16 + good) * 8))
    skips = of(found, "skip")
    assert len(skips) == 4 and "5 more stretches" in skips[-1]["detail"]
    assert len(of(found, "r")) == 8 and of(found, "end")[0]["in_file"] == 16


SNIFF_TABLE = [
    ("a journal by content after a sparse start", "x.bin", "usn", "ntfs.usnjrnl"),
    ("a journal without its sparse start", "x.bin", "short", "ntfs.usnjrnl"),
    ("by name: $J", "$J", b"\0" * 5000, "ntfs.usnjrnl"),
    ("by name: $UsnJrnl_$J", "$UsnJrnl_$J", b"junk" * 40, "ntfs.usnjrnl"),
    ("by name: $Extend_$UsnJrnl_$J", "C_$Extend_$UsnJrnl_$J", b"junk" * 40, "ntfs.usnjrnl"),
    ("by name: $UsnJrnl%3A$J", "$UsnJrnl%3A$J", b"junk" * 40, "ntfs.usnjrnl"),
    ("by name: $UsnJrnl$J.bin", "$UsnJrnl$J.bin", b"junk" * 40, "ntfs.usnjrnl"),
    ("the Max stream is not the journal", "$UsnJrnl_$Max", b"junk" * 40, None),
    ("a file called j", "j", b"junk" * 40, None),
    ("a table", "x.dat", "mft", None),
    ("text", "a.txt", b"some text that is not a journal " * 20, None),
    ("zeros with no name", "x", b"\0" * 9000, None),
    ("a record that is not followed by another", "x", "alone", None),
]


@pytest.mark.parametrize(("why", "name", "content", "expected"), SNIFF_TABLE, ids=[row[0] for row in SNIFF_TABLE])
def test_sniff_table(tmp_path, why, name, content, expected):
    t = fx.ft(1_700_000_000)
    if content == "usn":
        content = fx.make_usn().data
    elif content == "short":
        content = fx.usn_v2(1000, 1, 1, 5, 1, "a", 0x100, t) + fx.usn_v2(1080, 2, 1, 5, 1, "b", 0x100, t)
    elif content == "mft":
        content = fx.make_mft().data
    elif content == "alone":
        content = bytes(8192) + fx.usn_v2(9000, 1, 1, 5, 1, "a", 0x100, t) + b"\xff" * 80
    path = write(tmp_path, "f", content)
    assert parser.sniff(path, name, content[:4096]) == expected, why


def test_the_sniff_looks_past_a_long_sparse_start_but_not_for_ever(tmp_path, monkeypatch):
    t = fx.ft(1_700_000_000)
    record = fx.usn_v2(1, 1, 1, 5, 1, "a", 0x100, t) * 2
    far = write(tmp_path, "far", bytes(3 << 20) + record)
    assert parser.sniff(far, "x", bytes(4096)) == "ntfs.usnjrnl"
    monkeypatch.setattr(parser, "SNIFF_LOOK", 1 << 20)
    assert parser.sniff(far, "x", bytes(4096)) is None

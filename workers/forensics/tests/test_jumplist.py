"""The jump list parser: both file kinds, the DestList, the custom structure, the damage. Run in the worker's image.

The compound files are written here by ``artifact_gen.ole_bytes`` (FAT, mini stream, directory) and read back with
olefile, so the generator is checked by a library that is not ours.
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
from nik_forensics.parsers import BadLocator, ViewError, jumplist  # noqa: E402

AUTO = "1b4dd67f29cb1962.automaticDestinations-ms"
CUSTOM = "5afe4de1b92fc382.customDestinations-ms"


def said(tmp_path, data: bytes, name: str = AUTO) -> list[dict]:
    path = tmp_path / "in.bin"
    path.write_bytes(data)
    out = io.BytesIO()
    jumplist.parse(str(path), Context(out, {"host": "WKS-1", "file_name": name}), jumplist.SOURCE)
    return [json.loads(line) for line in out.getvalue().splitlines() if line]


def of(found: list[dict], kind: str) -> list[dict]:
    return [event for event in found if event["t"] == kind]


def reasons(found: list[dict], kind: str) -> list[str]:
    return [event["reason"] for event in of(found, kind)]


LINKS = [gen.lnk_bytes(rf"C:\Users\alice\f{i}.txt", arguments=f"-n{i}") for i in range(3)]


def test_the_module_declares_what_the_worker_needs():
    assert (jumplist.NAME, jumplist.VERSION, jumplist.KIND) == ("jumplist", "1", "endpoint")
    assert jumplist.SOURCES == ("windows.fileaccess.jumplist",)
    assert parsers.by_source("endpoint", "windows.fileaccess.jumplist") is jumplist


def test_the_generated_compound_file_is_one_olefile_reads():
    import olefile

    big = b"B" * 6000
    data = gen.ole_bytes({"DestList": b"D" * 100, "1": LINKS[0], "2": big})
    ole = olefile.OleFileIO(io.BytesIO(data))
    assert sorted(item[0] for item in ole.listdir()) == ["1", "2", "DestList"]
    assert ole.openstream("2").read() == big and ole.openstream("1").read() == LINKS[0]


@pytest.mark.parametrize("version", [1, 3])
def test_an_automatic_list_gives_one_record_per_destlist_entry(tmp_path, version):
    items = [(1, r"C:\a\one.txt", LINKS[0]), (0xA, r"C:\a\two.txt", LINKS[1]), (0x1F, r"C:\a\three.txt", LINKS[2])]
    found = said(tmp_path, gen.automatic_destinations(items, version=version, pinned_ids=(0xA,)))
    records = of(found, "r")
    assert [r["key"] for r in records] == [f"jl:WKS-1:1b4dd67f29cb1962:{n}" for n in ("1", "a", "1f")]
    first, second, third = (r["data"] for r in records)
    assert first["app_id"] == "1b4dd67f29cb1962" and first["app_name"] == "Windows Explorer"
    assert first["jumplist"] == "automatic" and first["listed"] is True and first["has_shortcut"] is True
    assert (first["position"], second["position"], third["position"]) == (0, 1, 2)
    assert (first["pinned"], second["pinned"], third["pinned"]) == (False, True, False)
    assert second["pin_order"] == 0 and first["pin_order"] is None
    assert (first["access_count"], second["access_count"]) == (2, 11)  # entry id + 1 by the generator
    assert first["host_name"] == "WKS-042"
    assert first["target"] == r"C:\Users\alice\f0.txt" and first["destlist_path"] == r"C:\a\one.txt"
    assert first["arguments"] == "-n0"
    assert [r["ts"] for r in records] == [1_600_001_001_000, 1_600_001_010_000, 1_600_001_031_000]
    assert records[0]["loc"]["stream"] == "1" and records[1]["loc"]["offset"] > records[0]["loc"]["offset"]
    end = of(found, "end")[0]
    assert end["in_file"] == 3 and end["read"] == 3 and not of(found, "skip")


def test_a_shortcut_in_a_large_stream_is_read_from_the_regular_sectors(tmp_path):
    long_link = gen.lnk_bytes(r"C:\x\big.txt", arguments="a" * 5000)
    assert len(long_link) > 4096
    found = said(tmp_path, gen.automatic_destinations([(1, r"C:\x\big.txt", long_link)]))
    (record,) = of(found, "r")
    assert record["data"]["target"] == r"C:\x\big.txt" and record["data"]["arguments"] == "a" * 5000
    assert not of(found, "skip") and not of(found, "note")


def test_an_entry_without_a_stream_and_a_stream_without_an_entry_are_both_said(tmp_path):
    items = [(1, r"C:\a\one.txt", LINKS[0]), (2, r"C:\a\two.txt", None)]
    found = said(tmp_path, gen.automatic_destinations(items, extra_streams={"2b": LINKS[2]}))
    records = of(found, "r")
    assert [r["key"].rsplit(":", 1)[1] for r in records] == ["1", "2", "2b"]
    assert records[1]["data"]["has_shortcut"] is False and records[1]["data"]["target"] == r"C:\a\two.txt"
    assert records[2]["data"]["listed"] is False and records[2]["data"]["position"] is None
    assert records[2]["ts"] == 1_600_000_600_000  # no DestList entry: the shortcut's own time
    assert reasons(found, "note") == ["entry without a shortcut stream", "shortcut stream not in the DestList"]
    assert of(found, "end")[0]["in_file"] == 3 and of(found, "end")[0]["read"] == 3


def test_a_destlist_that_says_more_than_it_holds_loses_entries_with_an_offset(tmp_path):
    items = [(1, r"C:\a\one.txt", LINKS[0]), (2, r"C:\a\two.txt", LINKS[1])]
    found = said(tmp_path, gen.automatic_destinations(items, declared=5))
    assert len(of(found, "r")) == 2
    (skip,) = of(found, "skip")
    assert skip["reason"] == "DestList entry is cut short" and skip["lost"] == 3 and skip["offset"] > 32
    assert of(found, "end")[0]["in_file"] == 5


def test_a_destlist_of_a_version_not_known_loses_its_entries_but_not_the_streams(tmp_path):
    items = [(1, r"C:\a\one.txt", LINKS[0])]
    data = gen.automatic_destinations(items, version=3)
    stream = gen.destlist([gen.destlist_entry(1, r"C:\a\one.txt")], version=9)
    found = said(tmp_path, gen.ole_bytes({"DestList": stream, "1": LINKS[0]}))
    (skip,) = of(found, "skip")
    assert skip["reason"] == "DestList version 9 is not known" and skip["lost"] == 1
    (record,) = of(found, "r")
    assert record["data"]["listed"] is False and record["data"]["target"] == r"C:\Users\alice\f0.txt"
    assert data  # the same entry in a known version is read: see the tests above


def test_a_stream_that_is_not_a_shortcut_keeps_the_entry_and_says_so(tmp_path):
    items = [(1, r"C:\a\one.txt", b"this is not a shell link, it is just text" * 4)]
    found = said(tmp_path, gen.automatic_destinations(items))
    (record,) = of(found, "r")
    assert record["data"]["has_shortcut"] is False and record["data"]["target"] == r"C:\a\one.txt"
    (skip,) = of(found, "skip")
    assert skip["reason"] == "shortcut of an entry cannot be read" and skip["lost"] == 0 and "entry 1" in skip["detail"]


def test_an_empty_destlist_is_an_empty_list_and_a_short_one_is_a_skip(tmp_path):
    found = said(tmp_path, gen.ole_bytes({"DestList": b""}))
    assert not of(found, "r") and of(found, "end")[0]["in_file"] == 0 and not of(found, "skip")
    found = said(tmp_path, gen.ole_bytes({"DestList": b"\x03\x00\x00\x00" * 4}))
    assert reasons(found, "skip") == ["DestList is shorter than its header"]


def test_a_compound_file_that_is_not_a_jump_list_or_not_a_compound_file_is_a_skip(tmp_path):
    found = said(tmp_path, gen.ole_bytes({"Other": b"x" * 10}))
    assert reasons(found, "skip") == ["no DestList stream"] and of(found, "end")[0]["in_file"] is None
    found = said(tmp_path, gen.ole_bytes({"DestList": b""})[:300])
    assert reasons(found, "skip") == ["compound file cannot be opened"]


def test_the_app_id_comes_from_the_file_name_and_a_name_without_one_is_said(tmp_path):
    data = gen.automatic_destinations([(1, r"C:\a\one.txt", LINKS[0])])
    found = said(tmp_path, data, name="copy of jumplist")
    (record,) = of(found, "r")
    assert record["data"]["app_id"] == "" and record["key"].startswith("jl:WKS-1:file-")
    assert reasons(found, "note") == ["file name is not an application id"]
    found = said(tmp_path, data, name="C:\\Users\\a\\9B9CDC69C1C24E2B.AutomaticDestinations-ms")
    assert of(found, "r")[0]["data"]["app_name"] == "Notepad (64-bit)"


def test_an_entry_without_a_time_is_kept_and_counted(tmp_path):
    entry = gen.destlist_entry(1, r"C:\a\one.txt", accessed=None)
    data = gen.ole_bytes({"DestList": gen.destlist([entry]), "1": LINKS[0]})
    found = said(tmp_path, data)
    assert of(found, "r")[0]["ts"] is None
    assert [n for n in of(found, "note") if n["reason"] == "entry without a time"][0]["count"] == 1


# -- custom destinations ----------------------------------------------------------- #
def test_a_custom_list_is_read_by_its_categories(tmp_path):
    data = gen.custom_destinations(
        [(0, "My Category", [LINKS[0]]), (1, 1, []), (2, 0, [LINKS[1], LINKS[2]]), (1, 2, [])]
    )
    found = said(tmp_path, data, CUSTOM)
    records = of(found, "r")
    assert [r["data"]["target"] for r in records] == [rf"C:\Users\alice\f{i}.txt" for i in range(3)]
    assert [r["data"]["category"] for r in records] == ["My Category", "Tasks", "Tasks"]
    assert [r["data"]["position"] for r in records] == [0, 0, 1]
    assert all(r["data"]["jumplist"] == "custom" and r["data"]["app_id"] == "5afe4de1b92fc382" for r in records)
    assert records[0]["key"].startswith("jl:WKS-1:5afe4de1b92fc382:c0-")
    assert records[1]["key"].startswith("jl:WKS-1:5afe4de1b92fc382:c2-") and len({r["key"] for r in records}) == 3
    assert records[0]["ts"] == 1_600_000_600_000  # the shortcut's own target time
    assert records[0]["loc"]["offset"] == 12 + 4 + 2 + 2 * len("My Category") + 4 + 16
    assert of(found, "end")[0]["in_file"] == 3 and not of(found, "skip")


def test_an_entry_that_is_not_a_shortcut_stops_the_list_and_counts_what_was_not_reached(tmp_path):
    good = gen.custom_destinations([(2, 0, [LINKS[0], LINKS[1], LINKS[2]])])
    at = good.index(LINKS[1]) - 16
    bad = good[:at] + b"\x11" * 16 + good[at + 16 :]
    found = said(tmp_path, bad, CUSTOM)
    assert len(of(found, "r")) == 1
    (skip,) = of(found, "skip")
    assert skip["reason"] == "entry is not a shortcut" and skip["offset"] == at and skip["lost"] == 2
    assert of(found, "end")[0]["in_file"] == 3


def test_a_custom_list_cut_short_says_where(tmp_path):
    good = gen.custom_destinations([(2, 0, [LINKS[0], LINKS[1]])])
    cut = good.index(LINKS[1]) + 40
    found = said(tmp_path, good[:cut], CUSTOM)
    assert len(of(found, "r")) == 1
    (skip,) = of(found, "skip")
    assert skip["reason"] == "shortcut of an entry is cut short or damaged" and skip["lost"] == 1
    assert skip["offset"] == good.index(LINKS[1])


def test_a_missing_footer_a_stray_tail_and_an_unknown_category_are_skips_with_offsets(tmp_path):
    good = gen.custom_destinations([(2, 0, [LINKS[0]])])
    found = said(tmp_path, good[:-4] + b"\x00\x00\x00\x00", CUSTOM)
    assert reasons(found, "skip") == ["category footer is not where the structure says"]
    assert of(found, "skip")[0]["offset"] == len(good) - 4 and len(of(found, "r")) == 1
    found = said(tmp_path, good + b"tail", CUSTOM)
    (skip,) = of(found, "skip")
    assert skip["reason"] == "bytes after the last category" and skip["offset"] == len(good) and skip["length"] == 4
    odd = struct.pack("<III", 2, 1, 0) + struct.pack("<I", 7)
    assert reasons(said(tmp_path, odd, CUSTOM), "skip") == ["category type not known"]
    assert reasons(said(tmp_path, struct.pack("<III", 2, 5000, 0), CUSTOM), "skip") == ["too many categories"]


def test_a_shortcut_of_an_entry_that_does_not_decode_is_a_skip_and_the_walk_goes_on(tmp_path, monkeypatch):
    real = jumplist.lnk.decode
    calls = []

    def flaky(raw):
        calls.append(1)
        if len(calls) == 1:
            raise ValueError("ValueError: damaged")
        return real(raw)

    monkeypatch.setattr(jumplist.lnk, "decode", flaky)
    found = said(tmp_path, gen.custom_destinations([(2, 0, [LINKS[0], LINKS[1]])]), CUSTOM)
    assert len(of(found, "r")) == 1
    (skip,) = of(found, "skip")
    assert skip["reason"] == "shortcut of an entry cannot be read" and skip["lost"] == 1 and "damaged" in skip["detail"]


# -- recognising and showing ---------------------------------------------------------- #
def test_sniff_by_content_and_then_by_name(tmp_path):
    auto = tmp_path / "a"
    auto.write_bytes(gen.automatic_destinations([(1, r"C:\a\one.txt", LINKS[0])]))
    head = auto.read_bytes()[:4096]
    assert jumplist.sniff(str(auto), AUTO, head) == jumplist.SOURCE
    assert jumplist.sniff(str(auto), "no-name", head) == jumplist.SOURCE  # it holds a DestList
    other = tmp_path / "o"
    other.write_bytes(gen.ole_bytes({"Other": b"x"}))
    assert jumplist.sniff(str(other), "x.doc", other.read_bytes()[:4096]) is None
    custom = tmp_path / "c"
    custom.write_bytes(gen.custom_destinations([(2, 0, [LINKS[0]])]))
    head = custom.read_bytes()[:4096]
    assert jumplist.sniff(str(custom), CUSTOM, head) == jumplist.SOURCE
    assert jumplist.sniff(str(custom), "no-name", head) == jumplist.SOURCE  # the shell link class id is in its head
    assert jumplist.sniff(str(custom), "x", struct.pack("<III", 2, 1, 0)) is None
    assert jumplist.sniff(str(custom), "x", b"") is None
    module, source = parsers.recognise(str(custom), "no-name")
    assert module is jumplist and source == jumplist.SOURCE


def test_view_shows_the_destlist_entry_and_its_shortcut(tmp_path):
    path = tmp_path / "v"
    path.write_bytes(gen.automatic_destinations([(1, r"C:\a\one.txt", LINKS[0]), (0xA, r"C:\a\two.txt", LINKS[1])]))
    shown = jumplist.view(str(path), jumplist.SOURCE, {"stream": "a", "offset": 0})
    assert shown["kind"] == "fields" and shown["where"] == {"stream": "a"}
    rows = dict(shown["rows"])
    assert rows["destlist path"] == r"C:\a\two.txt" and rows["destlist entry_id"] == "10"
    assert "link_info" in rows and shown["text"]
    with pytest.raises(ViewError):
        jumplist.view(str(path), jumplist.SOURCE, {"stream": "ff"})
    with pytest.raises(BadLocator):
        jumplist.view(str(path), jumplist.SOURCE, {"stream": "zz!"})
    custom = tmp_path / "c"
    data = gen.custom_destinations([(2, 0, [LINKS[0]])])
    custom.write_bytes(data)
    offset = data.index(LINKS[0])
    shown = jumplist.view(str(custom), jumplist.SOURCE, {"offset": offset, "length": len(LINKS[0])})
    assert shown["where"] == {"offset": offset, "length": len(LINKS[0])} and dict(shown["rows"])["link_info"]
    with pytest.raises(ViewError):
        jumplist.view(str(custom), jumplist.SOURCE, {"offset": len(data), "length": 50})
    with pytest.raises(BadLocator):
        jumplist.view(str(custom), jumplist.SOURCE, {"offset": 1})


def test_damaged_jump_lists_never_stop_the_parse_and_always_end(tmp_path):
    import random

    seeds = [
        (gen.automatic_destinations([(1, r"C:\a\1", LINKS[0]), (2, r"C:\a\2", LINKS[1]), (3, r"C:\a\3", None)]), AUTO),
        (gen.custom_destinations([(0, "Cat", [LINKS[0]]), (1, 1, []), (2, 0, [LINKS[1], LINKS[2]])]), CUSTOM),
    ]
    rng = random.Random(7)
    for data, name in seeds:
        for round_ in range(120):
            damaged = bytearray(data)
            if round_ % 2:
                damaged = damaged[: rng.randrange(1, len(damaged))]
            else:
                for _ in range(rng.randint(1, 8)):
                    damaged[rng.randrange(len(damaged))] = rng.randrange(256)
            found = said(tmp_path, bytes(damaged), name)
            assert found[-1]["t"] == "end"

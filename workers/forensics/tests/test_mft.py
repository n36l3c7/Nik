"""The $MFT parser: what a table holds against what the parser said, damage, paths, the keys, the view.

Every table is made here (``ntfs_fixtures.make_mft``): harmless bytes, never a volume. Run in the worker's image.
"""

from __future__ import annotations

import io
import json
import os
import sys

import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ntfs_fixtures as fx  # noqa: E402
from nik_forensics import parsers  # noqa: E402
from nik_forensics.context import Context  # noqa: E402
from nik_forensics.parsers import BadLocator, ViewError  # noqa: E402
from nik_forensics.parsers import mft as parser  # noqa: E402

ZONE = b"[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://example.test/setup.exe\r\n"


def said(path: str, host: str = "WKS-1") -> list[dict]:
    out = io.BytesIO()
    parser.parse(path, Context(out, {"host": host}), "ntfs.mft")
    return [json.loads(line) for line in out.getvalue().splitlines() if line]


def write(tmp_path, name: str, data: bytes) -> str:
    path = tmp_path / name
    path.write_bytes(data)
    return str(path)


def of(found: list[dict], t: str) -> list[dict]:
    return [event for event in found if event["t"] == t]


def notes(found: list[dict]) -> dict[str, dict]:
    return {event["reason"]: event for event in of(found, "note")}


def by_slot(found: list[dict]) -> dict[int, dict]:
    return {event["loc"]["entry"]: event for event in of(found, "r")}


@pytest.fixture(scope="module")
def table(tmp_path_factory):
    made = fx.make_mft()
    path = tmp_path_factory.mktemp("mft") / "$MFT"
    path.write_bytes(made.data)
    return made, str(path), said(str(path))


def test_the_parser_is_declared():
    assert (parser.NAME, parser.VERSION, parser.KIND, parser.SOURCES) == ("mft", "1", "disk", ("ntfs.mft",))
    assert parsers.by_source("disk", "ntfs.mft") is parser


def test_the_count_of_the_file_is_the_count_of_its_slots_and_everything_adds_up(table):
    made, _path, found = table
    end = of(found, "end")[0]
    assert end["in_file"] == made.expect["in_file"] == 34
    records = of(found, "r")
    lost = sum(event["lost"] for event in of(found, "skip"))
    n = notes(found)
    assert len(records) == 20 and end["read"] == 20
    assert lost == 5  # four damaged entries and the one the file stops inside
    assert n["entries that continue another entry"]["count"] == 3
    assert n["entries without a name or a time"]["count"] == 6
    assert len(records) + lost + 3 + 6 == end["in_file"]
    assert n["unused entries (all zeros)"]["count"] == made.expect["empty"] == 23


def test_every_damaged_entry_is_a_skip_with_its_offset(table):
    _made, _path, found = table
    listed = {event["offset"]: event for event in of(found, "skip")}
    assert "does not start with FILE" in listed[50 * 1024]["detail"]
    assert "BAAD" in listed[51 * 1024]["detail"]
    assert "fix-up of sector 0" in listed[52 * 1024]["detail"]
    assert "fix-up of sector 1" in listed[53 * 1024]["detail"]
    assert listed[56 * 1024]["length"] == 300 and "middle of an entry" in listed[56 * 1024]["detail"]
    assert {o for o in listed if listed[o]["lost"] == 1} == {50 * 1024, 51 * 1024, 52 * 1024, 53 * 1024, 56 * 1024}
    # the entry whose attributes break is read as far as it goes: a skip that lost nothing, and its record
    chain = listed[48 * 1024]
    assert chain["lost"] == 0 and "chain of attributes breaks" in chain["detail"]
    assert by_slot(found)[48]["data"]["name"] == "cut.txt"


def test_paths_come_from_the_parents_even_when_a_parent_is_later_in_the_table(table):
    _made, _path, found = table
    rec = by_slot(found)
    assert rec[33]["data"]["path"] == "\\Users\\bob\\setup.exe"
    assert rec[30]["data"]["path"] == "\\Users\\bob\\Documents\\report.docx"  # entry 40 comes after it
    assert rec[5]["data"]["path"] == "\\."
    assert rec[0]["data"]["path"] == "\\$MFT"
    assert rec[37]["data"]["path"] == "\\Users\\bob\\old\\inside.txt"  # through a deleted directory
    assert rec[47]["data"]["path"] == "\\Users\\bob\\wide é中.txt"


def test_a_parent_that_is_gone_gives_an_orphan(table):
    _made, _path, found = table
    rec = by_slot(found)
    assert rec[38]["data"]["path"] == "<orphan>\\lost.bin" and rec[38]["data"]["orphan"] is True
    assert rec[39]["data"]["path"] == "<orphan>\\stale.txt"  # the entry of its parent has been reused
    assert rec[33]["data"]["orphan"] is False
    assert notes(found)["names whose parent directory is gone"]["count"] == 2


def test_in_use_deleted_directory_size_and_streams(table):
    _made, _path, found = table
    rec = by_slot(found)
    assert rec[33]["data"]["inUse"] and not rec[33]["data"]["isDirectory"]
    assert rec[35]["data"]["inUse"] is False and rec[35]["summary"].endswith("[deleted]")
    assert rec[35]["data"]["sequence"] == 3 and rec[35]["key"] == "mft:WKS-1:35:3"
    assert rec[32]["data"]["isDirectory"] is True and "size" not in rec[32]["data"]
    assert rec[33]["data"]["size"] == 5_000_000 and rec[33]["data"]["allocatedSize"] == 5_001_216
    assert rec[34]["data"]["size"] == 12  # resident
    streams = {s["name"]: s["size"] for s in rec[33]["data"]["streams"]}
    assert streams == {"Zone.Identifier": len(ZONE), "hidden": 777, "extra": 2}  # "extra" is in entry 45
    assert "ZoneId=3" in rec[33]["data"]["zoneIdentifier"] and rec[33]["data"]["zoneId"] == 3
    assert "streams" not in rec[34]["data"]
    assert rec[33]["data"]["ads"] is True and rec[34]["data"]["ads"] is False and rec[32]["data"]["ads"] is False


def test_continuation_entries_are_merged_into_their_base(table):
    _made, _path, found = table
    rec = by_slot(found)
    assert 45 not in rec and 49 not in rec and 54 not in rec  # they have no record of their own
    assert rec[33]["data"]["continuationEntries"] == 1  # a stream that the base does not hold
    assert rec[34]["data"]["continuationEntries"] == 1  # a file name the base does not hold
    assert rec[34]["data"]["names"] == [
        {
            "name": "second_name.txt",
            "namespace": "win32",
            "parentEntry": 40,
            "parentSequence": 1,
            "path": "\\Users\\bob\\Documents\\second_name.txt",
        }
    ]
    assert "stale" not in {s["name"] for s in rec[34]["data"].get("streams", [])}  # its base was reused
    n = notes(found)
    assert n["continuation entries that were not merged"]["count"] == 1


def test_the_best_name_is_the_record_and_the_others_are_in_data(table):
    _made, _path, found = table
    rec = by_slot(found)
    assert rec[33]["data"]["name"] == "setup.exe" and rec[33]["data"]["namespace"] == "win32"
    assert rec[33]["data"]["names"] == [{"name": "SETUP~1.EXE", "namespace": "dos"}]
    assert rec[41]["data"]["names"] == [
        {
            "name": "link.txt",
            "namespace": "win32",
            "parentEntry": 40,
            "parentSequence": 1,
            "path": "\\Users\\bob\\Documents\\link.txt",
        }
    ]


def test_ts_is_the_creation_time_and_the_eight_times_are_there(table):
    _made, _path, found = table
    rec = by_slot(found)
    one = rec[33]
    assert one["ts"] == 1_700_000_000_123  # 100 ns are cut to the millisecond
    data = one["data"]
    assert data["siCreated"] == "2023-11-14T22:13:20.1234567Z"
    assert data["siModified"] == "2024-03-09T16:00:00.7654321Z"
    assert data["fnCreated"] == "2023-11-14T22:13:20.1234567Z"
    for name in ("siMftModified", "siAccessed", "fnModified", "fnMftModified", "fnAccessed"):
        assert data[name]
    assert one["type"] == "file" and one["host"] == "WKS-1"
    assert rec[46]["ts"] is None and notes(found)["records without a creation time"]["count"] == 1


def test_the_timestomp_hint_is_strict(table):
    _made, _path, found = table
    marked = [event["loc"]["entry"] for event in of(found, "r") if event["data"]["siBeforeFn"]]
    assert marked == [42]  # whole seconds, 2010 before 2023: only this one of the 20


def test_the_keys_are_the_entry_and_its_sequence_and_a_second_read_gives_the_same(table):
    _made, path, found = table
    keys = [event["key"] for event in of(found, "r")]
    assert len(set(keys)) == len(keys) and "mft:WKS-1:33:1" in keys
    again = said(path)
    assert [event["key"] for event in of(again, "r")] == keys
    assert [event["data"] for event in of(again, "r")] == [event["data"] for event in of(found, "r")]
    assert "mft:?:33:1" in {e["key"] for e in of(said(path, host=""), "r")}


def test_the_locator_and_the_view(table):
    _made, path, found = table
    rec = by_slot(found)[33]
    assert rec["loc"] == {"offset": 33 * 1024, "length": 1024, "entry": 33}
    shown = parser.view(path, "ntfs.mft", rec["loc"])
    assert shown["kind"] == "text" and shown["where"] == {"offset": 33 * 1024, "length": 1024, "entry": 33}
    text = shown["text"]
    assert "Entry 33, sequence 1, in use, file" in text
    assert "$STANDARD_INFORMATION created: 2023-11-14T22:13:20.1234567Z" in text
    assert "'setup.exe'" in text and "'SETUP~1.EXE'" in text
    assert "$DATA stream 'hidden': 777 bytes" in text and "Zone.Identifier: [ZoneTransfer]" in text
    assert f"{33 * 1024:010x}  46 49 4c 45" in text  # the bytes as stored: FILE


def test_the_view_of_a_damaged_entry_and_of_bad_locators(table):
    _made, path, _found = table
    damaged = parser.view(path, "ntfs.mft", {"offset": 50 * 1024, "length": 1024, "entry": 50})
    assert "not a readable entry" in damaged["title"]
    unfixed = parser.view(path, "ntfs.mft", {"offset": 52 * 1024, "length": 1024, "entry": 52})
    assert "The fix-up is not applied" in unfixed["text"]
    with pytest.raises(ViewError):
        parser.view(path, "ntfs.mft", {"offset": 10**9, "length": 1024})
    with pytest.raises(BadLocator):
        parser.view(path, "ntfs.mft", {"length": 1024})
    with pytest.raises(BadLocator):
        parser.view(path, "ntfs.mft", {"offset": 0, "length": 3})


def test_a_table_of_4096_byte_entries_and_one_that_does_not_say(tmp_path):
    entry = fx.build_entry(fx.Spec(0, names=[(5, 5, "$MFT", 3)], si=(1, 1, 1, 1)), size=4096)
    found = said(write(tmp_path, "big", entry * 2))
    assert of(found, "end")[0]["in_file"] == 2 and "entry size assumed to be 1024 bytes" not in notes(found)
    mangled = bytearray(fx.build_entry(fx.Spec(0, names=[(5, 5, "$MFT", 3)], si=(1, 1, 1, 1))))
    mangled[28:32] = b"\x07\x00\x00\x00"
    found = said(write(tmp_path, "odd", bytes(mangled)))
    assert "entry size assumed to be 1024 bytes" in notes(found)


def test_an_empty_file_and_zeros_and_nonsense(tmp_path):
    assert of(said(write(tmp_path, "e", b"")), "end")[0]["in_file"] == 0
    found = said(write(tmp_path, "z", bytes(4096)))
    assert of(found, "end")[0]["in_file"] == 0 and notes(found)["unused entries (all zeros)"]["count"] == 4
    found = said(write(tmp_path, "n", b"\xff" * 3000 + b"\x01"))
    assert of(found, "end")[0]["in_file"] == 3 and len(of(found, "skip")) == 3 and not of(found, "r")


def _chain(depth: int) -> bytes:
    """Directories that each have the next slot as their parent (the table is read from the deepest one), and a
    file in the deepest: its path is as long as the chain."""
    out = bytes(5 * 1024) + fx.build_entry(fx.Spec(5, directory=True, names=[(5, 5, ".", 1)], si=(1, 1, 1, 1)))
    last = 5 + depth
    for n in range(6, last + 1):
        parent = n + 1 if n < last else 5
        out += fx.build_entry(fx.Spec(n, directory=True, names=[(parent, 1, f"d{n}", 1)], si=(1, 1, 1, 1)))
    return out + fx.build_entry(fx.Spec(last + 1, names=[(6, 1, "leaf.txt", 1)], si=(1, 1, 1, 1)))


def test_a_chain_of_directories_deeper_than_the_limit_is_cut_and_said(tmp_path):
    depth = parser.MAX_DEPTH + 20
    found = said(write(tmp_path, "$MFT", _chain(depth)))
    leaf = by_slot(found)[6 + depth]
    assert leaf["data"]["path"].startswith("<orphan>\\") and leaf["data"]["path"].endswith("\\leaf.txt")
    assert notes(found)["paths cut where directories loop or are deeper than 256"]["count"] >= 1
    shallow = said(write(tmp_path, "$MFT2", _chain(40)))
    path = by_slot(shallow)[46]["data"]["path"]
    assert path.startswith("\\d45\\d44\\") and path.endswith("\\d7\\d6\\leaf.txt")


def test_a_loop_of_directories_is_not_followed_for_ever(tmp_path):
    out = bytes(5 * 1024) + fx.build_entry(fx.Spec(5, directory=True, names=[(5, 5, ".", 1)], si=(1, 1, 1, 1)))
    out += fx.build_entry(fx.Spec(6, directory=True, names=[(7, 1, "a", 1)], si=(1, 1, 1, 1)))
    out += fx.build_entry(fx.Spec(7, directory=True, names=[(6, 1, "b", 1)], si=(1, 1, 1, 1)))
    out += fx.build_entry(fx.Spec(8, names=[(6, 1, "f", 1)], si=(1, 1, 1, 1)))
    found = said(write(tmp_path, "loop", out))
    assert by_slot(found)[8]["data"]["path"].startswith("<orphan>")


SNIFF_TABLE = [
    ("a table by content, any name", "whatever.bin", "mft", "ntfs.mft"),
    ("a table by content, no name", "", "mft", "ntfs.mft"),
    ("by name: $MFT", "$MFT", b"\0" * 64, "ntfs.mft"),
    ("by name: KAPE C_ prefix", "C_$MFT", b"\0" * 64, "ntfs.mft"),
    ("by name: with a path", "evidence\\C\\$MFT", b"junk" * 16, "ntfs.mft"),
    ("by name: $MFT.bin", "$MFT.bin", b"\0" * 64, "ntfs.mft"),
    ("the mirror by name only is not read", "$MFTMirr", b"junk" * 16, None),
    ("a note that mentions it", "mft_notes.txt", b"hello world " * 8, None),
    ("a csv", "mft.csv", b"a,b,c\n1,2,3\n", None),
    ("FILE and nothing like a table", "x.dat", b"FILE" + b"\x00" * 60, None),
    ("a usn journal", "x.bin", "usn", None),
]


@pytest.mark.parametrize(("why", "name", "content", "expected"), SNIFF_TABLE, ids=[row[0] for row in SNIFF_TABLE])
def test_sniff_table(tmp_path, why, name, content, expected):
    if content == "mft":
        content = fx.make_mft().data
    elif content == "usn":
        content = fx.make_usn().data
    path = write(tmp_path, "f", content)
    assert parser.sniff(path, name, content[:4096]) == expected, why


def test_many_damaged_entries_are_listed_up_to_a_limit_and_the_rest_counted(tmp_path, monkeypatch):
    monkeypatch.setattr(parser, "MAX_LISTED", 5)
    good = fx.build_entry(fx.Spec(0, names=[(5, 5, "$MFT", 3)], si=(1, 1, 1, 1)))
    bad = bytearray(good)
    bad[0:4] = b"XXXX"
    found = said(write(tmp_path, "many", good + bytes(bad) * 9))
    skips = of(found, "skip")
    assert len(skips) == 6 and skips[-1]["lost"] == 0 and "4 more entries" in skips[-1]["detail"]
    assert of(found, "end")[0]["in_file"] == 10
    assert sum(event["lost"] for event in skips) == 5  # the others are counted in the end of the parse, not listed


def test_the_library_agrees_on_the_names_and_the_times(table):
    mft = pytest.importorskip("mft")
    _made, path, found = table
    rec = by_slot(found)
    seen = 0
    for entry in mft.PyMftParser(path, skip_errors=True).entries():
        if entry.entry_id not in rec or not entry.is_allocated or entry.base_entry_id:
            continue
        try:
            attrs = [(a.type_code, a.attribute_content) for a in entry.attributes()]
        except OSError:
            continue  # the entry whose attributes break: the parser says so, and so does the library, lazily
        mine = rec[entry.entry_id]["data"]
        sis = [c for kind, c in attrs if kind == 0x10]
        names = {c.name for kind, c in attrs if kind == 0x30}
        if sis and mine["siCreated"]:
            assert mine["siCreated"][:26] == sis[0].created.strftime("%Y-%m-%dT%H:%M:%S.%f")
            seen += 1
        assert not names or mine["name"] in names
    assert seen >= 10


# --------------------------------------------------------------------------- #
# A table that another implementation wrote                                    #
# --------------------------------------------------------------------------- #
NTFS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "ntfs", "mft-ntfsprogs.bin")


@pytest.fixture(scope="module")
def volume():
    return said(NTFS, host="VOL")


def test_a_table_written_by_ntfs_3g_is_read_as_ntfsinfo_reads_it(volume):
    """Facts checked by hand against ``ntfsinfo -i N`` and ``ntfsls -l -R`` of the volume (see fixtures/README.md)."""
    found = volume
    end = of(found, "end")[0]
    n = notes(found)
    assert end["in_file"] == 120 and end["read"] == 83 and not of(found, "skip")
    assert n["entries without a name or a time"]["count"] == 37
    assert n["records without a creation time"]["count"] == 1  # $MFT: ntfs-3g leaves its $STANDARD_INFORMATION times 0
    rec = by_slot(found)
    assert rec[0]["data"]["path"] == "\\$MFT" and rec[0]["data"]["size"] == 122880 and rec[0]["ts"] is None
    assert rec[5]["data"]["isDirectory"] and rec[11]["data"]["path"] == "\\$Extend"
    assert rec[24]["data"]["path"] == "\\$Extend\\$Quota" and rec[26]["data"]["path"] == "\\$Extend\\$Reparse"
    assert rec[2]["data"]["path"] == "\\$LogFile" and rec[2]["data"]["size"] == 2097152
    assert rec[8]["data"]["streams"] == [{"name": "$Bad", "size": 67104768}] and rec[8]["data"]["size"] == 0
    assert [rec[n]["data"]["inUse"] for n in (12, 15, 16, 23)] == [True, True, False, False]
    assert rec[69]["data"]["path"] == "\\Users\\bob\\Documents\\A Very Long File Name Here.docx"
    assert rec[69]["data"]["names"] == [{"name": "AVERYL~1.DOC", "namespace": "dos"}] and rec[69]["data"]["size"] == 200
    assert rec[70]["data"]["path"] == "\\Users\\bob\\Downloads\\setup.exe" and rec[70]["data"]["size"] == 6
    assert rec[70]["data"]["streams"] == [{"name": "Zone.Identifier", "size": 62}]
    assert rec[70]["data"]["zoneId"] == 3 and "HostUrl=https://example.test/a.exe" in rec[70]["data"]["zoneIdentifier"]
    assert (
        rec[71]["data"]["names"] == [{"name": "hardlink.txt", "namespace": "posix"}]
        and rec[71]["data"]["hardLinks"] == 2
    )
    assert rec[71]["data"]["streams"] == [{"name": "secret", "size": 62}]
    assert rec[72]["data"]["path"] == "\\big.bin" and rec[72]["data"]["size"] == 3_000_000  # non-resident
    assert rec[73]["data"]["size"] == 6  # resident
    assert rec[113]["data"]["path"] == "\\Users\\bob\\Documents\\many_file_with_a_longish_name_40.txt"
    gone = {n: (rec[n]["data"]["path"], rec[n]["data"]["inUse"], rec[n]["data"]["sequence"]) for n in range(114, 118)}
    assert gone == {
        114: ("\\Users\\alice\\gone.bin", False, 2),
        115: ("\\Users\\alice\\gone.txt", False, 2),
        116: ("\\Users\\alice\\olddir", False, 2),
        117: ("\\Users\\alice\\olddir\\inside.txt", False, 2),
    }  # deleted: the directory chain still resolves, through a deleted directory
    assert rec[114]["data"]["size"] == 3_000_000
    assert not any(e["data"]["orphan"] or e["data"]["siBeforeFn"] for e in of(found, "r"))
    assert rec[70]["data"]["siCreated"][:19] == rec[70]["data"]["fnCreated"][:19] == "2026-11-25T06:17:45"

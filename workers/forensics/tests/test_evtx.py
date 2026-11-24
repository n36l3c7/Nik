"""The evtx parser: what a log holds against what the parser read, damage of every kind, the normalised event.

Run in the worker's image: ``python -m pytest tests`` from /opt/nik-forensics.

One real log is committed (``fixtures/Application_no_crc32.evtx``, 17 records, one chunk; see
``fixtures/README.md``). The logs of the tests are made from it here, at run time: its chunk is copied (with new record
numbers and checksums that are right) into a log of several chunks, and the damage is done to that log with the same
techniques as a real one suffers: bytes in a record, a record's signature or size, checksums, a chunk's signature, a
file cut short, a chunk cleared with its records left in it, chunks in the order of a log that wrapped.
"""

from __future__ import annotations

import io
import json
import os
import struct
import sys
import tempfile
import zlib

import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

from nik_forensics import evtxscan, parsers  # noqa: E402
from nik_forensics.context import Context  # noqa: E402
from nik_forensics.parsers import evtx as parser  # noqa: E402

SAMPLE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "Application_no_crc32.evtx")
CHUNK = evtxscan.CHUNK
HEADER = evtxscan.HEADER
PER_CHUNK = 17  # the records of the sample's chunk
STEP = PER_CHUNK  # record numbers between one chunk of a made log and the next: the numbers run on


# --------------------------------------------------------------------------- #
# Logs made from the sample                                                   #
# --------------------------------------------------------------------------- #
def _fix_checksums(buf: bytearray, base: int) -> None:
    free = struct.unpack_from("<I", buf, base + 48)[0]
    struct.pack_into("<I", buf, base + 52, zlib.crc32(bytes(buf[base + 512 : base + free])))
    struct.pack_into(
        "<I", buf, base + 124, zlib.crc32(bytes(buf[base : base + 120]) + bytes(buf[base + 128 : base + 512]))
    )


def _fix_file_header(buf: bytearray, chunks: int, next_id: int) -> None:
    struct.pack_into("<QQQ", buf, 8, 0, chunks - 1, next_id)
    struct.pack_into("<H", buf, 42, chunks)
    struct.pack_into("<I", buf, 120, 0)  # flags: the sample says "no checksums"; the made log has them, and is clean
    struct.pack_into("<I", buf, 124, zlib.crc32(bytes(buf[:120])))


def make_log(order: tuple[int, ...] = (0, 1, 2)) -> bytearray:
    """A log of ``len(order)`` chunks of the sample's chunk. The chunk in file slot ``n`` holds the record
    numbers of ``order[n]`` (426 + 1000 * order[n], …): a log that has wrapped is not in the order of its records."""
    raw = open(SAMPLE, "rb").read()
    base_chunk = bytearray(raw[HEADER : HEADER + CHUNK])
    free = struct.unpack_from("<I", base_chunk, 48)[0]
    base_chunk[free:] = bytes(CHUNK - free)  # the unused space of the sample holds old records: not the made log's
    buf = bytearray(raw[:HEADER])
    first = struct.unpack_from("<Q", base_chunk, 24)[0]
    scan = next(evtxscan.Scanner(SAMPLE).chunks())
    for slot, which in enumerate(order):
        chunk = bytearray(base_chunk)
        shift = which * STEP
        no1, no2, id1, id2 = struct.unpack_from("<QQQQ", chunk, 8)
        struct.pack_into("<QQQQ", chunk, 8, no1 + shift, no2 + shift, id1 + shift, id2 + shift)
        for record_id, (offset, _size, _ok) in scan.records.items():
            struct.pack_into("<Q", chunk, offset - HEADER + 8, record_id + shift)
        buf += chunk
        _fix_checksums(buf, HEADER + slot * CHUNK)
    _fix_file_header(buf, len(order), first + max(order) * STEP + PER_CHUNK)
    return buf


def write(tmp_path, name: str, data: bytes | bytearray) -> str:
    path = tmp_path / name
    path.write_bytes(bytes(data))
    return str(path)


def records_of(buf: bytes | bytearray) -> dict[int, tuple[int, int, int]]:
    """Every record of a log by the scanner: ID -> (offset, size, chunk)."""
    found: dict[int, tuple[int, int, int]] = {}
    with tempfile.TemporaryDirectory() as folder:
        path = os.path.join(folder, "scan.evtx")
        with open(path, "wb") as handle:
            handle.write(bytes(buf))
        for chunk in evtxscan.Scanner(path).chunks():
            for record_id, (offset, size, _ok) in chunk.records.items():
                found[record_id] = (offset, size, chunk.number)
    return found


def run(path: str, params: dict | None = None) -> list[dict]:
    out = io.BytesIO()
    parser.parse(path, Context(out, params or {}), "evtx")
    return [json.loads(line) for line in out.getvalue().splitlines() if line]


def of(events: list[dict], kind: str) -> list[dict]:
    return [event for event in events if event["t"] == kind]


def reasons(events: list[dict], kind: str) -> list[str]:
    return [event["reason"] for event in of(events, kind)]


def end(events: list[dict]) -> dict:
    (last,) = of(events, "end")
    return last


# --------------------------------------------------------------------------- #
# A log that is whole                                                         #
# --------------------------------------------------------------------------- #
def test_the_sample_is_a_log_of_one_chunk_and_the_parser_is_the_one_that_is_loaded():
    assert os.path.getsize(SAMPLE) == 69632
    with open(SAMPLE, "rb") as handle:
        assert parser.sniff(SAMPLE, "Application.evtx", handle.read(4096)) == "evtx"
    assert parser.sniff(SAMPLE, "x.evtx", b"MZ\x90\x00") is None
    assert parser.sniff(SAMPLE, "x.evtx", b"") is None
    assert parsers.load("evtx") is parser
    assert (parser.NAME, parser.VERSION, parser.KIND, parser.SOURCES) == ("evtx", "1", "eventlog", ("evtx",))


def test_a_whole_log_gives_every_record_with_its_place_and_nothing_else(tmp_path):
    buf = make_log()
    path = write(tmp_path, "whole.evtx", buf)
    events = run(path)
    assert reasons(events, "skip") == [] and reasons(events, "note") == []
    found = records_of(buf)
    assert len(found) == 3 * PER_CHUNK
    assert end(events)["in_file"] == end(events)["read"] == 3 * PER_CHUNK
    (source,) = of(events, "source")
    assert (source["parser"], source["kind"], source["source"], source["host"]) == (
        "evtx",
        "eventlog",
        "evtx",
        "DESKTOP-0HIJB49",
    )
    records = of(events, "r")
    assert events[0] is source and events[-1]["t"] == "end"
    keys = [record["key"] for record in records]
    assert len(set(keys)) == len(keys)
    for record in records:
        offset, size, chunk = found[record["loc"]["record"]]
        assert record["loc"] == {"offset": offset, "length": size, "chunk": chunk, "record": record["loc"]["record"]}
        assert buf[offset : offset + 4] == b"\x2a\x2a\x00\x00"
        assert record["key"] == f"evtx:{record['host']}:{record['channel']}:{record['loc']['record']}"
        assert record["type"] == "event" and record["ts"] and record["event_id"] is not None
        assert record["data"]["provider"] and "recovered" not in record["data"]


def test_the_keys_of_a_log_are_the_same_when_it_is_read_again(tmp_path):
    path = write(tmp_path, "whole.evtx", make_log())
    first = [(event["key"], event["loc"]) for event in of(run(path), "r")]
    again = [(event["key"], event["loc"]) for event in of(run(path), "r")]
    assert first == again and len(first) == 3 * PER_CHUNK


def test_a_log_that_wrapped_is_read_whole_though_its_chunks_are_not_in_order(tmp_path):
    buf = make_log(order=(2, 0, 1))
    events = run(write(tmp_path, "wrapped.evtx", buf))
    assert reasons(events, "skip") == [] and reasons(events, "note") == []
    assert end(events)["in_file"] == end(events)["read"] == 3 * PER_CHUNK
    found = records_of(buf)
    for record in of(events, "r"):
        assert record["loc"]["offset"] == found[record["loc"]["record"]][0]
        assert "chunk" in record["loc"]


def test_the_file_header_is_said_when_the_log_was_open_or_its_checksum_is_wrong(tmp_path):
    buf = make_log()
    struct.pack_into("<I", buf, 120, 1)  # dirty
    buf[60] ^= 0x55  # a byte the header checksum covers
    events = run(write(tmp_path, "dirty.evtx", buf))
    assert sorted(reasons(events, "note")) == ["file header checksum does not match", "log not closed"]
    assert reasons(events, "skip") == [] and end(events)["read"] == 3 * PER_CHUNK


def test_a_log_written_without_checksums_is_not_told_off_for_them(tmp_path):
    events = run(SAMPLE)  # the sample: flag "no CRC32", checksums that mean nothing
    assert reasons(events, "skip") == [] and end(events)["read"] == end(events)["in_file"] == PER_CHUNK
    # old records left in the unused space that the parser cannot give back: not part of the live log
    (note,) = of(events, "note")
    assert (note["reason"], note["count"]) == ("record remnant in unused space not rebuilt", 34)


def test_what_is_not_an_event_log_raises_after_saying_so(tmp_path):
    path = write(tmp_path, "not.evtx", b"MZ" + bytes(200))
    out = io.BytesIO()
    with pytest.raises(evtxscan.NotEvtx):
        parser.parse(path, Context(out, {}), "evtx")
    said = [json.loads(line) for line in out.getvalue().splitlines()]
    assert [event["t"] for event in said] == ["source", "skip"] and said[1]["reason"] == "not an event log"


# --------------------------------------------------------------------------- #
# Damage                                                                      #
# --------------------------------------------------------------------------- #
def a_record(buf: bytearray, chunk: int = 1, nth: int = 8) -> tuple[int, int, int]:
    """(ID, offset, size) of a record in the middle of a chunk."""
    found = [(rid, off, size) for rid, (off, size, ch) in records_of(buf).items() if ch == chunk]
    return sorted(found)[nth]


def test_bytes_inside_a_record_lose_that_record_and_say_where(tmp_path):
    buf = make_log()
    record_id, offset, size = a_record(buf)
    buf[offset + 40 : offset + min(size - 8, 120)] = b"\xff" * (min(size - 8, 120) - 40)
    _fix_checksums(buf, HEADER + CHUNK)
    events = run(write(tmp_path, "garbage.evtx", buf))
    (skip,) = of(events, "skip")
    assert (skip["reason"], skip["offset"], skip["length"], skip["lost"]) == ("record cannot be read", offset, size, 1)
    assert buf[skip["offset"] : skip["offset"] + 4] == b"\x2a\x2a\x00\x00"
    assert f"Failed to parse record number {record_id}" in skip["detail"]
    assert (end(events)["in_file"], end(events)["read"]) == (3 * PER_CHUNK, 3 * PER_CHUNK - 1)
    assert record_id not in {record["loc"]["record"] for record in of(events, "r")}
    assert reasons(events, "note") == []


def test_a_destroyed_record_signature_is_a_stretch_nobody_can_count(tmp_path):
    buf = make_log()
    record_id, offset, size = a_record(buf)
    buf[offset : offset + 4] = bytes(4)
    _fix_checksums(buf, HEADER + CHUNK)
    events = run(write(tmp_path, "magic.evtx", buf))
    (skip,) = of(events, "skip")
    assert (skip["reason"], skip["offset"], skip["length"], skip["lost"]) == ("record cannot be read", offset, size, 1)
    assert buf[skip["offset"] : skip["offset"] + 4] == bytes(4)
    assert "header counts 17 records, 16 were found" in skip["detail"]
    assert (end(events)["in_file"], end(events)["read"]) == (3 * PER_CHUNK, 3 * PER_CHUNK - 1)
    assert end(events)["in_file"] - end(events)["read"] == skip["lost"]
    (gap,) = [note for note in of(events, "note") if note["reason"] == "gap in record numbers"]
    assert gap["count"] == 1 and f"{record_id}..{record_id}" in gap["detail"]


def test_an_absurd_record_size_is_a_stretch_nobody_can_count(tmp_path):
    buf = make_log()
    record_id, offset, size = a_record(buf)
    struct.pack_into("<I", buf, offset + 4, 0x7FFF0000)
    _fix_checksums(buf, HEADER + CHUNK)
    events = run(write(tmp_path, "size.evtx", buf))
    (skip,) = of(events, "skip")
    assert (skip["reason"], skip["offset"], skip["length"], skip["lost"]) == (
        "record size is not valid",
        offset,
        size,
        1,
    )
    assert f"record {record_id}" in skip["detail"]
    assert (end(events)["in_file"], end(events)["read"]) == (3 * PER_CHUNK, 3 * PER_CHUNK - 1)


def test_a_checksum_that_does_not_match_is_a_note_and_every_record_is_read(tmp_path):
    buf = make_log()
    struct.pack_into("<I", buf, HEADER + CHUNK + 124, 0xDEADBEEF)  # chunk 1: header checksum
    struct.pack_into("<I", buf, HEADER + 2 * CHUNK + 52, 0xDEADBEEF)  # chunk 2: events checksum
    events = run(write(tmp_path, "crc.evtx", buf))
    assert reasons(events, "skip") == []
    (note,) = of(events, "note")
    assert note["reason"] == "chunk checksum does not match" and note["count"] == 2
    assert "chunks 1, 2" in note["detail"]
    assert end(events)["read"] == end(events)["in_file"] == 3 * PER_CHUNK


def test_a_destroyed_chunk_signature_loses_the_chunk_and_says_what_the_neighbours_imply(tmp_path):
    buf = make_log()
    buf[HEADER + CHUNK : HEADER + CHUNK + 8] = b"XXXXXXXX"
    events = run(write(tmp_path, "chunk.evtx", buf))
    (skip,) = of(events, "skip")
    assert (skip["reason"], skip["offset"], skip["length"], skip["lost"]) == (
        "chunk cannot be read",
        HEADER + CHUNK,
        CHUNK,
        0,
    )
    assert buf[skip["offset"] : skip["offset"] + 8] == b"XXXXXXXX"
    assert f"imply {PER_CHUNK} record numbers are missing" in skip["detail"]
    assert f"{PER_CHUNK} whole record headers" in skip["detail"]
    assert (end(events)["in_file"], end(events)["read"]) == (2 * PER_CHUNK, 2 * PER_CHUNK)


def test_a_chunk_of_something_else_with_no_record_in_it_is_not_a_loss(tmp_path):
    buf = make_log() + bytes(CHUNK)  # a chunk past the last: left from an earlier life of the file
    buf[HEADER + 3 * CHUNK : HEADER + 3 * CHUNK + 600] = bytes(range(1, 256)) * 2 + bytes(90)  # not a chunk, no record
    events = run(write(tmp_path, "junk.evtx", buf))
    assert reasons(events, "skip") == []
    (note,) = of(events, "note")
    assert note["reason"] == "stale chunk" and note["count"] == 1
    assert end(events)["read"] == end(events)["in_file"] == 3 * PER_CHUNK


def test_a_chunk_past_the_count_that_only_copies_records_is_left_out(tmp_path):
    buf = make_log()
    copy = bytes(buf[HEADER : HEADER + CHUNK])  # chunk 0 again, after the last one
    events = run(write(tmp_path, "copy.evtx", bytes(buf) + copy))
    assert reasons(events, "skip") == []
    (note,) = of(events, "note")
    assert note["reason"] == "stale chunk" and note["count"] == 1 and f"{PER_CHUNK} records left out" in note["detail"]
    assert end(events)["read"] == end(events)["in_file"] == 3 * PER_CHUNK
    keys = [record["key"] for record in of(events, "r")]
    assert len(set(keys)) == len(keys)


def test_a_file_cut_short_says_where_it_ends_and_which_records_went_with_it(tmp_path):
    buf = make_log()
    cut = HEADER + 2 * CHUNK + 0x2400
    events = run(write(tmp_path, "cut.evtx", buf[:cut]))
    short = [skip for skip in of(events, "skip") if skip["reason"] == "file is cut short"]
    assert len(short) == 1 and short[0]["offset"] == cut and short[0]["lost"] > 0
    assert short[0]["length"] == CHUNK - 0x2400 and "were found" in short[0]["detail"]
    lost = [skip for skip in of(events, "skip") if skip["reason"] == "record cannot be read"]
    for skip in lost:  # whole records of the last chunk that the parser did not give
        assert skip["lost"] == 1 and skip["offset"] + skip["length"] <= cut
        assert buf[skip["offset"] : skip["offset"] + 4] == b"\x2a\x2a\x00\x00"
    assert (
        end(events)["read"] + sum(skip["lost"] for skip in of(events, "skip"))
        == end(events)["in_file"]
        == 3 * PER_CHUNK
    )


def test_a_cleared_chunk_gives_back_its_records_marked_recovered(tmp_path):
    buf = make_log()
    base = HEADER + CHUNK
    struct.pack_into("<QQQQ", buf, base + 8, 0, 0xFFFFFFFFFFFFFFFF, 0, 0xFFFFFFFFFFFFFFFF)
    struct.pack_into("<II", buf, base + 44, 0, 512)  # no record in use: they are all left in the free space
    _fix_checksums(buf, base)
    found = records_of(buf)
    path = write(tmp_path, "cleared.evtx", buf)
    events = run(path)
    records = of(events, "r")
    recovered = [record for record in records if record["data"].get("recovered")]
    assert len(recovered) == PER_CHUNK and len(records) == 3 * PER_CHUNK
    assert end(events)["in_file"] == 2 * PER_CHUNK  # the used area of the chunks: the cleared one holds none
    (note,) = [note for note in of(events, "note") if note["reason"] == "recovered record"]
    assert note["count"] == PER_CHUNK
    assert "cleared or wrapped" in note["detail"]
    chunk = evtxscan.Scanner(path).read_chunk(1)
    slack = {offset: (size, rid) for offset, size, rid in chunk.slack}
    assert len(slack) == PER_CHUNK
    for record in recovered:
        offset = record["loc"]["offset"]
        assert record["key"].endswith(f":r{offset}") and offset in slack
        assert slack[offset] == (record["loc"]["length"], record["loc"]["record"])
        assert buf[offset : offset + 4] == b"\x2a\x2a\x00\x00"
    assert records_of(buf).keys() == found.keys()
    again = [record["key"] for record in of(run(path), "r")]
    assert again == [record["key"] for record in records]


def test_a_record_size_copy_that_differs_is_a_note_when_the_record_was_read(tmp_path):
    buf = make_log()
    record_id, offset, size = a_record(buf)
    struct.pack_into("<I", buf, offset + size - 4, size + 8)
    _fix_checksums(buf, HEADER + CHUNK)
    events = run(write(tmp_path, "copy-size.evtx", buf))
    notes = {note["reason"]: note for note in of(events, "note")}
    assert notes["record size copy does not match"]["count"] == 1
    assert end(events)["read"] == end(events)["in_file"] == 3 * PER_CHUNK


def test_a_per_record_failure_of_ours_is_a_skip_at_the_records_offset(tmp_path, monkeypatch):
    buf = make_log()
    record_id, offset, size = a_record(buf, chunk=0)
    real = parser.normalise

    def broken(record):
        if record["event_record_id"] == record_id:
            raise KeyError("System")
        return real(record)

    monkeypatch.setattr(parser, "normalise", broken)
    events = run(write(tmp_path, "ours.evtx", buf))
    (skip,) = of(events, "skip")
    assert (skip["reason"], skip["offset"], skip["length"], skip["lost"]) == (
        "record cannot be understood",
        offset,
        size,
        1,
    )
    assert end(events)["read"] == 3 * PER_CHUNK - 1


# --------------------------------------------------------------------------- #
# The event: normalisation                                                    #
# --------------------------------------------------------------------------- #
def event(
    event_id=4624, channel="Security", provider="Microsoft-Windows-Security-Auditing", data=None, extra=None, **system
):
    body = {
        "Event": {
            "#attributes": {"xmlns": "http://schemas.microsoft.com/win/2004/08/events/event"},
            "System": {
                "Provider": {"#attributes": {"Name": provider, "Guid": "{x}"}},
                "EventID": event_id,
                "Level": 0,
                "Task": 12544,
                "Opcode": 0,
                "Keywords": "0x8020000000000000",
                "TimeCreated": {"#attributes": {"SystemTime": "2024-03-05T10:20:30.123456Z"}},
                "EventRecordID": 77,
                "Execution": {"#attributes": {"ProcessID": 604, "ThreadID": 1408}},
                "Channel": channel,
                "Computer": "WKS-042.corp.example",
                "Security": {"#attributes": {"UserID": "S-1-5-18"}},
                **system,
            },
            "EventData": data or {},
            **(extra or {}),
        }
    }
    return {
        "event_record_id": 77,
        "timestamp": "2024-03-05T10:20:30.1234567Z UTC",
        "data": json.dumps(body),
        "recovered": False,
    }


def test_an_event_is_flattened_with_its_system_fields_and_a_stable_key():
    norm = parser.normalise(
        event(
            data={
                "SubjectUserName": "WKS-042$",
                "TargetUserName": "alice",
                "TargetDomainName": "CORP",
                "LogonType": 3,
                "IpAddress": "10.1.2.3",
                "WorkstationName": "LAPTOP-7",
                "Empty": "",
                "Dash": "-",
                "Unset": "%%1793",
            }
        )
    )
    assert (norm["computer"], norm["channel"], norm["record_id"], norm["event_id"]) == (
        "WKS-042.corp.example",
        "Security",
        77,
        4624,
    )
    assert norm["ts"] == 1709634030123  # milliseconds, not rounded by a float
    assert norm["username"] == "alice"
    assert norm["summary"] == "CORP\\alice — network from LAPTOP-7 / 10.1.2.3"
    assert norm["ioc"] == [("ip", "10.1.2.3")]
    data = norm["data"]
    assert data["provider"] == "Microsoft-Windows-Security-Auditing" and data["sid"] == "S-1-5-18"
    assert (data["level"], data["task"], data["opcode"], data["keywords"], data["pid"], data["tid"]) == (
        0,
        12544,
        0,
        "0x8020000000000000",
        604,
        1408,
    )
    assert data["LogonType"] == "3" and "Empty" not in data and "Dash" not in data and "Unset" not in data


def test_event_id_with_qualifiers_and_names_that_collide_with_the_fixed_ones():
    norm = parser.normalise(
        event(
            7045,
            "System",
            "Service Control Manager",
            EventID={"#attributes": {"Qualifiers": 16384}, "#text": 7045},
            data={"ServiceName": "evil", "ImagePath": "C:\\x.exe", "provider": "mine", "pid": "9", "recovered": "no"},
        )
    )
    assert norm["event_id"] == 7045 and norm["data"]["qualifiers"] == 16384
    assert norm["data"]["provider"] == "Service Control Manager" and norm["data"]["Data.provider"] == "mine"
    assert norm["data"]["pid"] == 604 and norm["data"]["Data.pid"] == "9" and norm["data"]["Data.recovered"] == "no"
    assert norm["summary"] == "evil → C:\\x.exe"


def test_unnamed_data_and_userdata_are_flattened_and_any_event_gets_a_summary():
    body = event(
        104,
        "System",
        "Microsoft-Windows-Eventlog",
        data=None,
        extra={
            "UserData": {
                "LogFileCleared": {"#attributes": {"xmlns": "x"}, "SubjectUserName": "bob", "Channel": "Security"}
            }
        },
    )
    norm = parser.normalise(body)
    assert (
        norm["data"]["SubjectUserName"] == "bob"
        and norm["summary"] == "Security cleared by bob"
        and norm["username"] == "bob"
    )
    plain = event(1000, "Application", "Some App", data={"Data": ["first", "second", None, "-"]})
    norm = parser.normalise(plain)
    assert norm["data"]["Data1"] == "first" and norm["data"]["Data2"] == "second" and "Data3" not in norm["data"]
    assert norm["summary"] == "Some App 1000 — Data1=first, Data2=second"
    single = parser.normalise(event(1, "Application", "App", data={"Data": "only"}))
    assert single["data"]["Data"] == "only"


def test_a_time_that_is_none_falls_back_to_the_record_and_then_to_no_time():
    body = json.loads(event()["data"])
    del body["Event"]["System"]["TimeCreated"]
    record = {"event_record_id": 5, "timestamp": "2024-03-05T10:20:30.5Z UTC", "data": json.dumps(body)}
    assert parser.normalise(record)["ts"] == 1709634030500
    record["timestamp"] = "not a time"
    assert parser.normalise(record)["ts"] is None
    assert parser.to_ms("1601-01-01T00:00:00Z") is None and parser.to_ms("2024-13-45T00:00:00Z") is None
    assert parser.to_ms("2024-03-05 10:20:30") == 1709634030000


def test_a_shape_that_is_not_an_event_raises_for_the_caller_to_skip():
    for data in ("[]", "{}", '{"Event": {}}', '{"Event": {"System": 3}}', "not json"):
        with pytest.raises((KeyError, TypeError, ValueError)):
            parser.normalise({"event_record_id": 1, "timestamp": "", "data": data})


def test_the_account_of_an_event():
    logon = parser.normalise(event(data={"SubjectUserName": "WKS$", "TargetUserName": "alice"}))
    assert logon["username"] == "alice"
    process = parser.normalise(
        event(4688, data={"SubjectUserName": "bob", "TargetUserName": "x", "CommandLine": "cmd /c whoami"})
    )
    assert process["username"] == "bob" and process["summary"] == "cmd /c whoami"
    sysmon = parser.normalise(
        event(
            1,
            "Microsoft-Windows-Sysmon/Operational",
            "Microsoft-Windows-Sysmon",
            data={"User": "NT AUTHORITY\\SYSTEM", "Image": "C:\\a.exe", "CommandLine": "a.exe -x"},
        )
    )
    assert sysmon["username"] == "NT AUTHORITY\\SYSTEM" and sysmon["summary"] == "a.exe -x"
    assert parser.normalise(event(5156, data={"Application": "x"}))["username"] == ""


def test_indicators_come_only_from_the_fields_that_declare_them():
    sysmon = "Microsoft-Windows-Sysmon/Operational"
    provider = "Microsoft-Windows-Sysmon"
    for address in ("-", "::1", "127.0.0.1", ""):
        assert parser.normalise(event(4624, data={"IpAddress": address}))["ioc"] == []
    assert parser.normalise(event(4648, data={"IpAddress": "192.0.2.9"}))["ioc"] == [("ip", "192.0.2.9")]
    assert parser.normalise(event(4625, data={"IpAddress": "198.51.100.4"}))["ioc"] == [("ip", "198.51.100.4")]
    # An IpAddress of another event is not an indicator, nor is a Security field of another channel.
    assert parser.normalise(event(4634, data={"IpAddress": "192.0.2.9"}))["ioc"] == []
    assert parser.normalise(event(4624, "Application", "x", data={"IpAddress": "192.0.2.9"}))["ioc"] == []
    net = parser.normalise(
        event(
            3,
            sysmon,
            provider,
            data={
                "DestinationIp": "203.0.113.5",
                "DestinationHostname": "c2.example.net",
                "DestinationPort": "443",
                "Image": "C:\\w\\evil.exe",
            },
        )
    )
    assert net["ioc"] == [("ip", "203.0.113.5"), ("domain", "c2.example.net")]
    assert net["summary"] == "evil.exe → c2.example.net:443"
    assert parser.normalise(event(22, sysmon, provider, data={"QueryName": "bad.example.org", "Image": "C:\\x.exe"}))[
        "ioc"
    ] == [("domain", "bad.example.org")]
    sha256, md5, sha1 = "A" * 64, "b" * 32, "C" * 40
    for event_id in (1, 7):
        hashes = f"SHA1={sha1},MD5={md5},SHA256={sha256},IMPHASH={'d' * 32}"
        found = parser.normalise(event(event_id, sysmon, provider, data={"Hashes": hashes}))["ioc"]
        assert found == [("sha1", sha1.lower()), ("md5", md5), ("sha256", sha256.lower())]
    assert parser.normalise(event(1, sysmon, provider, data={"Hashes": "SHA256=zz,MD5=12"}))["ioc"] == []
    assert (
        parser.normalise(event(13, sysmon, provider, data={"Hashes": f"MD5={md5}", "QueryName": "x.example"}))["ioc"]
        == []
    )


# --------------------------------------------------------------------------- #
# PowerShell script blocks                                                    #
# --------------------------------------------------------------------------- #
PS = "Microsoft-Windows-PowerShell/Operational"


def block(
    number: int, total: int, text: str, script_id: str = "11111111-aaaa", record_id: int = 1, when: str = "10:00:00"
):
    body = event(
        4104,
        PS,
        "Microsoft-Windows-PowerShell",
        data={
            "MessageNumber": number,
            "MessageTotal": total,
            "ScriptBlockText": text,
            "ScriptBlockId": script_id,
            "Path": "C:\\s.ps1",
        },
    )
    parsed = json.loads(body["data"])
    parsed["Event"]["System"]["TimeCreated"]["#attributes"]["SystemTime"] = f"2024-03-05T{when}.000Z"
    body["data"] = json.dumps(parsed)
    body["event_record_id"] = record_id
    return body


def feed(blocks: list[dict]) -> tuple[list[dict], parser._Scripts]:
    out = io.BytesIO()
    scripts = parser._Scripts(Context(out, {}))
    for number, record in enumerate(blocks):
        norm = parser.normalise(record)
        scripts.add(norm, {"offset": 100 + number, "record": norm["record_id"]})
    return [json.loads(line) for line in out.getvalue().splitlines()], scripts


def test_script_blocks_are_put_together_in_order_when_the_last_one_arrives():
    events, scripts = feed(
        [
            block(2, 3, "Write-Host 2\n", record_id=2, when="10:00:02"),
            block(1, 3, "# first line\n", record_id=1, when="10:00:01"),
            block(3, 3, "Write-Host 3", record_id=3, when="10:00:03"),
        ]
    )
    (record,) = events
    assert (record["type"], record["key"]) == ("script", "ps:WKS-042.corp.example:11111111-aaaa")
    assert record["data"] == {
        "script": "# first line\nWrite-Host 2\nWrite-Host 3",
        "blocks": 3,
        "of": 3,
        "path": "C:\\s.ps1",
    }
    assert record["summary"] == "# first line" and record["loc"] == {"offset": 101, "record": 1}
    assert record["ts"] == parser.to_ms("2024-03-05T10:00:01Z") and record["channel"] == PS
    scripts.finish()
    assert [event["t"] for event in events] == ["r"]


def test_a_script_with_blocks_missing_is_said_at_the_end_with_what_was_seen():
    events, scripts = feed([block(1, 3, "a"), block(3, 3, "c"), block(1, 1, "alone", script_id="22222222-bbbb")])
    assert [record["key"] for record in events] == ["ps:WKS-042.corp.example:22222222-bbbb"]
    scripts.finish()
    out = scripts.ctx._out.getvalue().splitlines()
    lines = [json.loads(line) for line in out]
    incomplete = [line for line in lines if line["t"] == "r" and line["data"]["of"] == 3][0]
    assert incomplete["data"] == {"script": "ac", "blocks": 2, "of": 3, "path": "C:\\s.ps1"}
    notes = {line["reason"]: line["count"] for line in lines if line["t"] == "note"}
    assert notes == {"script incomplete": 1, "script put together": 2}


def test_the_text_waiting_for_its_blocks_is_bounded(monkeypatch):
    monkeypatch.setattr(parser, "MAX_PENDING_SCRIPT", 100)
    blocks = [block(1, 2, "x" * 60, script_id=f"{n:08d}", record_id=n) for n in range(4)]
    events, scripts = feed(blocks)
    assert len(events) == 3 and all(event["data"]["blocks"] == 1 and event["data"]["of"] == 2 for event in events)
    assert scripts.size <= 100
    scripts.finish()
    lines = [json.loads(line) for line in scripts.ctx._out.getvalue().splitlines()]
    assert [line["reason"] for line in lines if line["t"] == "note"] == [
        "script incomplete",
        "script said before its end",
        "script put together",
    ]


def test_a_script_id_that_comes_back_gets_a_key_of_its_own_that_is_the_same_next_time():
    events, _ = feed([block(1, 1, "one"), block(1, 1, "two")])
    assert [event["key"] for event in events] == [
        "ps:WKS-042.corp.example:11111111-aaaa",
        "ps:WKS-042.corp.example:11111111-aaaa:1",
    ]


def test_script_blocks_of_a_log_are_events_and_one_script(tmp_path, monkeypatch):
    """Through the whole parse: every block is a record of its own, and the script is one more."""
    buf = make_log()
    found = sorted(records_of(buf))[:2]
    texts = {
        found[0]: block(1, 2, "Get-Process\n", record_id=found[0]),
        found[1]: block(2, 2, "Get-Service", record_id=found[1]),
    }
    real = parser.normalise

    def pretend(record):
        if record["event_record_id"] in texts:
            return real(texts[record["event_record_id"]])
        return real(record)

    monkeypatch.setattr(parser, "normalise", pretend)
    events = run(write(tmp_path, "ps.evtx", buf))
    scripts = [record for record in of(events, "r") if record["type"] == "script"]
    assert len(scripts) == 1 and scripts[0]["data"]["script"] == "Get-Process\nGet-Service"
    assert len([record for record in of(events, "r") if record["type"] == "event"]) == 3 * PER_CHUNK
    assert scripts[0]["loc"]["record"] == found[0] and "offset" in scripts[0]["loc"]


# --------------------------------------------------------------------------- #
# What it does when much is wrong                                             #
# --------------------------------------------------------------------------- #
def test_skips_past_the_limit_are_said_once_with_what_they_lost(tmp_path, monkeypatch):
    monkeypatch.setattr(parser, "MAX_LISTED", 2)
    buf = make_log()
    for nth in (2, 4, 6, 8, 10):
        record_id, offset, size = a_record(buf, nth=nth)
        buf[offset + 40 : offset + min(size - 8, 120)] = b"\xff" * (min(size - 8, 120) - 40)
    _fix_checksums(buf, HEADER + CHUNK)
    events = run(write(tmp_path, "many.evtx", buf))
    skips = of(events, "skip")
    assert [skip["reason"] for skip in skips] == ["record cannot be read"] * 3
    # (a damaged record can take the records that use its templates with it: how many are lost is the scan's to say)
    lost = end(events)["in_file"] - end(events)["read"]
    assert lost >= 5 and [skip["lost"] for skip in skips] == [1, 1, lost - 2] and skips[2]["offset"] is None
    assert f"{lost - 2} more of the same kind after the first 2" in skips[2]["detail"]


def test_a_parser_that_stops_leaves_the_rest_as_skips_the_survey_knows_of(tmp_path, monkeypatch):
    path = write(tmp_path, "whole.evtx", make_log())
    real = parser._records

    def dies(path_, failure):
        for number, record in enumerate(real(path_, failure)):
            if number == 20:
                failure.append("RuntimeError: the library gave up")
                return
            yield record

    monkeypatch.setattr(parser, "_records", dies)
    events = run(path)
    assert end(events)["read"] == 20 and end(events)["in_file"] == 3 * PER_CHUNK
    stopped = [skip for skip in of(events, "skip") if skip["reason"] == "the parser stopped"]
    assert len(stopped) == 1 and "gave up" in stopped[0]["detail"]
    lost = [skip for skip in of(events, "skip") if skip["reason"] == "record cannot be read"]
    assert sum(skip["lost"] for skip in lost) == 3 * PER_CHUNK - 20
    assert len({skip["offset"] for skip in lost}) == len(lost)


# --------------------------------------------------------------------------- #
# What the file says it holds, and the holes in its record numbers            #
# --------------------------------------------------------------------------- #
def test_a_chunk_that_promises_more_than_the_walk_finds_puts_the_difference_on_the_first_stretch(tmp_path):
    buf = make_log()
    found = sorted((off, size, rid) for rid, (off, size, ch) in records_of(buf).items() if ch == 1)
    start, end_ = found[4][0], found[8][0]  # records 4 to 7 of the chunk wiped out
    buf[start:end_] = bytes(end_ - start)
    _fix_checksums(buf, HEADER + CHUNK)
    events = run(write(tmp_path, "hole.evtx", buf))
    (skip,) = [skip for skip in of(events, "skip") if skip["offset"] == start]
    assert (skip["reason"], skip["length"], skip["lost"]) == ("record cannot be read", end_ - start, 4)
    assert "header counts 17 records, 13 were found" in skip["detail"]
    assert end(events)["in_file"] == 3 * PER_CHUNK
    assert end(events)["in_file"] - end(events)["read"] == sum(skip["lost"] for skip in of(events, "skip"))
    (gap,) = [note for note in of(events, "note") if note["reason"] == "gap in record numbers"]
    assert gap["count"] == 1 and "4 record numbers" in gap["detail"]


def test_two_damaged_stretches_of_a_chunk_carry_the_difference_once(tmp_path):
    buf = make_log()
    found = sorted((off, size, rid) for rid, (off, size, ch) in records_of(buf).items() if ch == 1)
    for nth in (3, 9):
        buf[found[nth][0] : found[nth][0] + 4] = bytes(4)
    _fix_checksums(buf, HEADER + CHUNK)
    events = run(write(tmp_path, "two.evtx", buf))
    skips = of(events, "skip")
    assert [skip["lost"] for skip in skips] == [2, 0]
    assert "counted on the first damaged stretch" in skips[1]["detail"]
    assert end(events)["in_file"] - end(events)["read"] == 2


def test_a_zero_filled_middle_chunk_is_a_gap_in_the_numbers_and_nothing_else(tmp_path):
    buf = make_log()
    buf[HEADER + CHUNK : HEADER + 2 * CHUNK] = bytes(CHUNK)
    events = run(write(tmp_path, "zeroed.evtx", buf))
    assert reasons(events, "skip") == []
    (gap,) = of(events, "note")
    first = 426 + PER_CHUNK
    assert gap["reason"] == "gap in record numbers" and gap["count"] == 1
    assert f"{first}..{first + PER_CHUNK - 1}" in gap["detail"] and f"{PER_CHUNK} record numbers" in gap["detail"]
    assert end(events)["in_file"] == end(events)["read"] == 2 * PER_CHUNK


def test_a_log_that_wrapped_has_no_gap_before_its_first_record(tmp_path):
    events = run(write(tmp_path, "wrapped.evtx", make_log(order=(2, 0, 1))))
    assert [note for note in of(events, "note") if note["reason"] == "gap in record numbers"] == []
    start = make_log(order=(1, 2))  # a log that starts at 443 is no log with something missing before it
    assert reasons(run(write(tmp_path, "later.evtx", start)), "note") == []

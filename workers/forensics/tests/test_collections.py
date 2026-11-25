"""Collections: the path table, the refusals, hostile zips, and the unpack behind the HTTP front.

Run in the worker's image: ``python -m pytest tests`` from /opt/nik-forensics. Every zip is made here, out of harmless
text: nothing in them is a real program or real evidence.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import struct
import sys
import threading
import urllib.error
import urllib.request
import zipfile
import zlib
from http.server import ThreadingHTTPServer

import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
os.environ.setdefault("FORENSICS_TOKEN", "a token for the tests, long enough")

import unpack_job  # noqa: E402
from nik_forensics import triage  # noqa: E402

TOKEN = os.environ["FORENSICS_TOKEN"]
EVTX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "Application_no_crc32.evtx")
PS_HISTORY = "C/Users/bob/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt"


# --------------------------------------------------------------------------- #
# Zips made here                                                              #
# --------------------------------------------------------------------------- #
def make_zip(path, members: dict, *, compression=zipfile.ZIP_DEFLATED) -> str:
    with zipfile.ZipFile(path, "w", compression) as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return str(path)


def crypt_zip(path, name: str, data: bytes, password: bytes) -> str:
    """A zip of one member stored with the traditional PKWARE encryption (what an archive of malware is sealed
    with, the password ``infected``): the standard library reads it and does not write it."""
    keys = [0x12345678, 0x23456789, 0x34567890]

    def crc(byte: int, state: int) -> int:
        return zlib.crc32(bytes([byte]), state ^ 0xFFFFFFFF) ^ 0xFFFFFFFF

    def update(byte: int) -> None:
        keys[0] = crc(byte, keys[0])
        keys[1] = ((keys[1] + (keys[0] & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        keys[2] = crc(keys[1] >> 24, keys[2])

    def stream() -> int:
        temp = (keys[2] | 2) & 0xFFFF
        return ((temp * (temp ^ 1)) >> 8) & 0xFF

    def encrypt(byte: int) -> int:
        out = byte ^ stream()
        update(byte)
        return out

    for byte in password:
        update(byte)
    checksum = zlib.crc32(data) & 0xFFFFFFFF
    header = bytes([0x11] * 11) + bytes([checksum >> 24])
    body = bytes(encrypt(byte) for byte in header + data)
    raw = name.encode()
    local = struct.pack("<4sHHHHHIIIHH", b"PK\x03\x04", 20, 1, 0, 0, 0x21, checksum, len(body), len(data), len(raw), 0)
    central = struct.pack(
        "<4sHHHHHHIIIHHHHHII",
        b"PK\x01\x02",
        20,
        20,
        1,
        0,
        0,
        0x21,
        checksum,
        len(body),
        len(data),
        len(raw),
        0,
        0,
        0,
        0,
        0,
        0,
    )
    entry = local + raw + body
    directory = central + raw
    end = struct.pack("<4sHHHHIIH", b"PK\x05\x06", 0, 0, 1, 1, len(directory), len(entry), 0)
    with open(path, "wb") as out:
        out.write(entry + directory + end)
    return str(path)


def run(zip_path, tmp_path, **request) -> tuple[list[dict], dict]:
    """The members and the last line of an unpack, in this process (the real job runs the same function)."""
    lines: list[dict] = []
    asked = {
        "total": 1 << 30,
        "files": str(tmp_path / "files"),
        "scratch": str(tmp_path / "scratch"),
        "fileName": "triage.zip",
        **request,
    }
    code = unpack_job.list_members(str(zip_path), asked, lines.append)
    assert lines and lines[-1]["t"] == "end"
    assert code == (3 if lines[-1]["error"] else 0)
    return [line for line in lines if line["t"] == "member"], lines[-1]


def files_of(tmp_path) -> set[str]:
    folder = tmp_path / "files"
    return set(os.listdir(folder)) if folder.exists() else set()


# --------------------------------------------------------------------------- #
# The table of paths                                                          #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("path", "kind", "source", "user", "host", "profile"),
    [
        ("C/Windows/System32/winevt/Logs/Security.evtx", "eventlog", "evtx", "", "", ""),
        ("WKS-042/C/Windows/System32/winevt/Logs/Security.evtx", "eventlog", "evtx", "", "WKS-042", ""),
        ("uploads/auto/C%3A/Windows/System32/winevt/Logs/System.evtx", "eventlog", "evtx", "", "", ""),
        ("C/Windows/prefetch/CMD.EXE-0BD30981.pf", "endpoint", "windows.execution.prefetch", "", "", ""),
        ("C/Users/alice/NTUSER.DAT", "endpoint", "windows.registry.hive", "alice", "", ""),
        ("C/Windows/appcompat/Programs/Amcache.hve", "endpoint", "windows.registry.hive", "", "", ""),
        ("C/Windows/System32/config/SYSTEM", "endpoint", "windows.registry.hive", "", "", ""),
        ("C/Windows/System32/sru/SRUDB.dat", "endpoint", "windows.network.srum-network", "", "", ""),
        (
            "C/Users/alice/AppData/Roaming/Microsoft/Windows/Recent/doc.lnk",
            "endpoint",
            "windows.fileaccess.lnk",
            "alice",
            "",
            "",
        ),
        (
            "C/Users/alice/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/1b4dd67f29cb1962.automaticDestinations-ms",
            "endpoint",
            "windows.fileaccess.jumplist",
            "alice",
            "",
            "",
        ),
        ("C/$MFT", "disk", "ntfs.mft", "", "", ""),
        ("C/$Extend/$J", "disk", "ntfs.usnjrnl", "", "", ""),
        (
            "C/Users/bob/AppData/Local/Google/Chrome/User Data/Default/History",
            "browser",
            "chrome.history",
            "bob",
            "",
            "Default",
        ),
        (
            "C/Users/bob/AppData/Local/Google/Chrome/User Data/Profile 2/History",
            "browser",
            "chrome.history",
            "bob",
            "",
            "Profile 2",
        ),
        (
            "C/Users/bob/AppData/Local/Microsoft/Edge/User Data/Default/History",
            "browser",
            "edge.history",
            "bob",
            "",
            "Default",
        ),
        (
            "C/Users/bob/AppData/Local/BraveSoftware/Brave-Browser/User Data/Default/Bookmarks",
            "browser",
            "brave.bookmarks",
            "bob",
            "",
            "Default",
        ),
        (
            "C/Users/bob/AppData/Roaming/Mozilla/Firefox/Profiles/x1.default/places.sqlite",
            "browser",
            "firefox.places",
            "bob",
            "",
            "x1.default",
        ),
        ("Users/carl/Library/Safari/History.db", "browser", "safari.history", "carl", "", ""),
        (PS_HISTORY, "commands", "powershell", "bob", "", ""),
        ("root/.bash_history", "commands", "bash", "root", "", ""),
        ("home/dana/.zsh_history", "commands", "zsh", "dana", "", ""),
        ("var/log/auth.log", "syslog", "linux.auth", "", "", ""),
        ("var/log/auth.log.1", "syslog", "linux.auth", "", "", ""),
        ("var/log/secure", "syslog", "linux.auth", "", "", ""),
        ("var/log/audit/audit.log", "syslog", "linux.audit", "", "", ""),
        (
            "C/Windows/ServiceProfiles/LocalService/NTUSER.DAT",
            "endpoint",
            "windows.registry.hive",
            "LocalService",
            "",
            "",
        ),
        ("C/Users/Public/Documents/notes.txt", "", "", "", "", ""),
        ("readme.txt", "", "", "", "", ""),
    ],
)
def test_the_path_of_a_file_in_a_triage_tree_says_what_it_is(path, kind, source, user, host, profile):
    found = triage.describe(path)
    assert (found["kind"], found["source"], found["username"], found["host"], found["profile"]) == (
        kind,
        source,
        user,
        host,
        profile,
    )


def test_the_host_is_read_from_the_name_of_a_velociraptor_collection():
    name = "Collection-DESKTOP-9F2-2024-05-01T10_11_12Z.zip"
    assert (
        triage.describe("uploads/auto/C%3A/Windows/System32/winevt/Logs/Security.evtx", name)["host"] == "DESKTOP-9F2"
    )
    assert triage.describe("C/Windows/prefetch/A.pf", "kape.zip")["host"] == ""


@pytest.mark.parametrize(
    ("head", "name", "word"),
    [
        (b"vhdxfile" + b"\x00" * 8, "disk.vhdx", "VHDX"),
        (b"conectix" + b"\x00" * 8, "disk.vhd", "VHD"),
        (b"EVF\x09\x0d\x0a\xff\x00" + b"\x00" * 8, "evidence.E01", "E01"),
        (b"SQLite format 3\x00" + b"\x00" * 8, "timeline.plaso", "psort"),
        (b"\x00" * 16, "super.plaso", "psort"),
        (b"7z\xbc\xaf\x27\x1c" + b"\x00" * 8, "triage.7z", "zip"),
    ],
)
def test_images_and_native_plaso_files_are_refused_with_a_sentence_that_says_how_to_convert(tmp_path, head, name, word):
    path = tmp_path / "f"
    path.write_bytes(head)
    said = triage.what_is(str(path), name)
    assert word in said["refused"] and "refused" in said and "container" not in said


def test_a_plaso_database_is_refused_by_its_tables_whatever_its_name(tmp_path):
    import sqlite3

    path = tmp_path / "storage"
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE metadata (key TEXT, value TEXT)")
    connection.execute("CREATE TABLE event_data (_identifier INTEGER)")
    connection.commit()
    connection.close()
    assert "psort.py -o json_line" in triage.what_is(str(path), "timeline.dat")["refused"]
    other = tmp_path / "other"
    connection = sqlite3.connect(other)
    connection.execute("CREATE TABLE t (a)")
    connection.commit()
    connection.close()
    assert "refused" not in triage.what_is(str(other), "x.dat")


def test_a_zip_a_known_file_and_a_stranger_are_told_apart(tmp_path):
    archive = make_zip(tmp_path / "a.zip", {"x.txt": b"hello"})
    assert triage.what_is(archive, "a.zip") == {"container": "zip", "kind": "collection", "source": "collection.zip"}
    history = tmp_path / "ConsoleHost_history.txt"
    history.write_bytes(b"whoami\n")
    assert triage.what_is(str(history), "ConsoleHost_history.txt")["source"] == "powershell"
    stranger = tmp_path / "x.dat"
    stranger.write_bytes(b"\x00\x01 nothing Nik reads")
    assert "unknown" in triage.what_is(str(stranger), "x.dat")


def test_programs_are_found_by_what_they_are_not_only_by_their_name():
    pe = b"MZ" + b"\x00" * 58 + struct.pack("<I", 64) + b"PE\x00\x00" + b"\x00" * 100
    assert triage.is_executable(pe[:4096], "readme.txt")
    assert triage.is_executable(b"\x7fELF\x02\x01\x01", "bin/ls")
    assert triage.is_executable(b"\xcf\xfa\xed\xfe....", "usr/bin/x")
    assert triage.is_executable(b"#!/bin/sh\n", "run")
    assert triage.is_executable(b"Write-Host x", "a/Invoke.PS1") and triage.is_executable(b"x", "setup.exe")
    assert not triage.is_executable(b"MZ not a program", "notes.txt")
    assert not triage.is_executable(b"plain text", "Security.evtx")
    assert not triage.is_executable(b"{}", "data.json")


# --------------------------------------------------------------------------- #
# Hostile zips                                                                #
# --------------------------------------------------------------------------- #
def test_a_name_that_climbs_out_of_the_folder_is_listed_and_skipped_and_nothing_is_written_outside(tmp_path):
    inside = tmp_path / "inside"
    inside.mkdir()
    archive = make_zip(
        inside / "slip.zip",
        {
            "../../escape.txt": b"x",
            "a/../../escape2.txt": b"x",
            "/etc/cron.d/evil": b"x",
            "C:\\Windows\\ok.txt": b"fine",
        },
    )
    members, end = run(archive, inside)
    by_path = {member["path"]: member for member in members}
    assert (
        "climbs out" in by_path["../../escape.txt"]["skip"] and "climbs out" in by_path["a/../../escape2.txt"]["skip"]
    )
    # An absolute name and a drive are names, not places: they lose their root and are read as any other.
    assert "etc/cron.d/evil" in by_path and "Windows/ok.txt" in by_path
    assert end["skipped"] == 2
    assert not (tmp_path / "escape.txt").exists() and not (tmp_path.parent / "escape.txt").exists()
    assert not os.path.exists("/etc/cron.d/evil")
    # Only the job's own folders were written to.
    assert {path.name for path in tmp_path.iterdir()} == {"inside"}


def test_a_symbolic_link_is_skipped_and_never_followed(tmp_path):
    archive = tmp_path / "links.zip"
    with zipfile.ZipFile(archive, "w") as out:
        link = zipfile.ZipInfo("C/Users/bob/link")
        link.external_attr = (0o120777 << 16) | 0x20
        out.writestr(link, "/etc/passwd")
        out.writestr("C/Users/bob/real.txt", "real")
    members, end = run(archive, tmp_path)
    assert "symbolic link" in members[0]["skip"] and members[0]["sha256"] is None
    assert "skip" not in members[1] and members[1]["sha256"]
    assert end["skipped"] == 1


def test_a_member_larger_than_a_member_may_be_and_a_total_over_the_cap_stop_with_a_skip(tmp_path):
    archive = make_zip(
        tmp_path / "big.zip", {"one.bin": b"\x00" * 600_000, "two.txt": b"a" * 100, "three.txt": b"b" * 100}
    )
    members, end = run(archive, tmp_path, member=500_000)
    assert "larger than" in members[0]["skip"] and members[1]["sha256"] and members[2]["sha256"]
    assert end["skipped"] == 1
    members, end = run(archive, tmp_path, total=600_050)
    # one.bin takes 600,000 of the 600,050 allowed: the next one that would take more is the first that stops.
    assert (
        members[0]["sha256"] and "unpacked size allowed" in members[1]["skip"] and "unpacked size" in members[2]["skip"]
    )
    assert end["bytes"] == 600_000 and "more than" in end["stopped"]
    members, end = run(archive, tmp_path, total=500)
    assert "unpacked size allowed" in members[0]["skip"] and members[1]["skip"] and members[2]["skip"]
    assert "more than" in end["stopped"] and end["bytes"] == 0


def test_a_member_that_expands_too_many_times_is_a_bomb(tmp_path, monkeypatch):
    monkeypatch.setattr(triage, "RATIO_FROM", 100_000)
    monkeypatch.setattr(triage, "RATIO_MAX", 50)
    archive = make_zip(tmp_path / "bomb.zip", {"zeros.bin": b"\x00" * 5_000_000, "text.txt": b"hello world " * 20})
    members, end = run(archive, tmp_path)
    assert "zip bomb" in members[0]["skip"] and members[0]["sha256"] is None
    assert members[1]["sha256"] and end["skipped"] == 1


def test_a_header_that_lies_about_its_size_cannot_make_a_member_expand(tmp_path):
    data = b"A" * 200_000
    archive = make_zip(tmp_path / "lie.zip", {"a.txt": data})
    raw = bytearray(open(archive, "rb").read())
    # The sizes in both headers say 1,000 bytes: the library reads no further than that, and says the member is bad.
    for signature, offset in ((b"PK\x03\x04", 22), (b"PK\x01\x02", 24)):
        at = raw.index(signature)
        struct.pack_into("<I", raw, at + offset, 1000)
    (tmp_path / "lie.zip").write_bytes(bytes(raw))
    members, end = run(tmp_path / "lie.zip", tmp_path)
    assert "cannot be read" in members[0]["skip"] and members[0]["sha256"] is None and end["skipped"] == 1
    assert files_of(tmp_path) == set() and os.listdir(tmp_path / "scratch") == []


def test_a_zip_whose_members_overlap_is_refused_whole(tmp_path):
    archive = make_zip(
        tmp_path / "ok.zip", {"a.txt": b"a" * 5000, "b.txt": b"b" * 5000}, compression=zipfile.ZIP_STORED
    )
    raw = bytearray(open(archive, "rb").read())
    # Both central entries claim the compressed bytes of the whole file: more compressed data than the file holds.
    for at in [index for index in range(len(raw) - 4) if raw[index : index + 4] == b"PK\x01\x02"]:
        struct.pack_into("<I", raw, at + 20, len(raw))
    (tmp_path / "overlap.zip").write_bytes(bytes(raw))
    members, end = run(tmp_path / "overlap.zip", tmp_path)
    assert members == [] and "overlap" in end["error"]


def test_something_that_is_not_a_zip_is_said_not_raised(tmp_path):
    (tmp_path / "x.zip").write_bytes(b"PK\x03\x04 but no more")
    members, end = run(tmp_path / "x.zip", tmp_path)
    assert members == [] and "not a zip" in end["error"]


def test_an_encrypted_member_is_skipped_with_its_reason_and_the_others_are_read(tmp_path):
    archive = make_zip(tmp_path / "mixed.zip", {"secret.txt": b"hidden", "open.txt": b"plain"})
    raw = bytearray(open(archive, "rb").read())
    first_local, first_central = raw.index(b"PK\x03\x04"), raw.index(b"PK\x01\x02")
    struct.pack_into("<H", raw, first_local + 6, struct.unpack_from("<H", raw, first_local + 6)[0] | 1)
    struct.pack_into("<H", raw, first_central + 8, struct.unpack_from("<H", raw, first_central + 8)[0] | 1)
    (tmp_path / "mixed.zip").write_bytes(bytes(raw))
    members, end = run(tmp_path / "mixed.zip", tmp_path)
    assert "encrypted" in members[0]["skip"] and members[1]["sha256"] and not end["password"]


def test_a_zip_encrypted_with_the_password_of_malware_archives_is_opened(tmp_path):
    archive = crypt_zip(
        tmp_path / "infected.zip", "C/Users/bob/ConsoleHost_history.txt", b"whoami\nnet user\n", b"infected"
    )
    members, end = run(archive, tmp_path)
    assert end["password"] is True and members[0]["sha256"] == hashlib.sha256(b"whoami\nnet user\n").hexdigest()
    assert members[0]["source"] == "powershell" and members[0]["kept"]
    wrong = crypt_zip(tmp_path / "other.zip", "a.txt", b"data", b"another password")
    members, end = run(wrong, tmp_path)
    assert end["password"] is False and "encrypted" in members[0]["skip"]


def test_an_archive_inside_the_collection_is_listed_and_not_opened(tmp_path):
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as out:
        out.writestr("ConsoleHost_history.txt", "whoami\n")
    archive = make_zip(
        tmp_path / "nested.zip", {"inner.zip": inner.getvalue(), "log.gz": b"\x1f\x8b\x08\x00" + b"\x00" * 20}
    )
    members, end = run(archive, tmp_path)
    assert all("not opened" in member["skip"] for member in members) and len(members) == 2
    assert all(member["kind"] is None and not member["kept"] for member in members)
    assert files_of(tmp_path) == set()


def test_names_in_odd_encodings_are_kept_as_text(tmp_path):
    archive = tmp_path / "odd.zip"
    with zipfile.ZipFile(archive, "w") as out:
        # Written by a tool that forgot the UTF-8 flag: the bytes are UTF-8, the flag says CP437.
        info = zipfile.ZipInfo("C/Users/bob/caf\u00e9/x.txt")
        out.writestr(info, "1")
        out.writestr("tab\tnew\nline.txt", "2")
        out.writestr("nul\x00name.txt", "3")
        out.writestr("a" * 1100 + ".txt", "4")
        out.writestr("\u202eevil.txt", "5")
    raw = bytearray(archive.read_bytes())
    # The first member: its name as UTF-8 bytes with the UTF-8 flag cleared (what a tool that forgot it writes).
    for signature, flag_at in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        at = raw.index(signature)
        struct.pack_into("<H", raw, at + flag_at, struct.unpack_from("<H", raw, at + flag_at)[0] & ~0x800)
    archive.write_bytes(bytes(raw))
    members, end = run(archive, tmp_path)
    paths = [member["path"] for member in members]
    assert paths[0] == "C/Users/bob/caf\u00e9/x.txt"
    assert "?" in paths[1] and "\t" not in paths[1] and "\n" not in paths[1] and "\x00" not in paths[2]
    assert "longer than" in members[3]["skip"]
    for member in members:
        member["path"].encode("utf-8")  # keepable as text, whatever the zip said
        json.dumps(member)


def test_ten_thousand_members_are_listed_and_a_cap_says_what_it_left_out(tmp_path):
    archive = make_zip(tmp_path / "many.zip", {f"C/data/f{number:05d}.txt": b"%d" % number for number in range(10_000)})
    members, end = run(archive, tmp_path)
    assert len(members) == 10_000 and end["members"] == 10_000 and end["unlisted"] == 0
    assert members[0]["n"] == 0 and members[-1]["n"] == 9_999 and end["recognised"] == 0
    members, end = run(archive, tmp_path, maxMembers=250)
    assert len(members) == 250 and end["unlisted"] == 9_750 and "first 250" in end["stopped"]


def test_a_member_listed_twice_is_two_members_with_the_same_hash(tmp_path):
    archive = tmp_path / "twice.zip"
    with zipfile.ZipFile(archive, "w") as out:
        out.writestr("a/ConsoleHost_history.txt", "whoami\n")
        out.writestr("b/ConsoleHost_history.txt", "whoami\n")
    members, _end = run(archive, tmp_path)
    assert members[0]["sha256"] == members[1]["sha256"] and files_of(tmp_path) == {members[0]["sha256"] + ".bin"}


# --------------------------------------------------------------------------- #
# What an unpack keeps                                                        #
# --------------------------------------------------------------------------- #
def a_triage_zip(tmp_path) -> tuple[str, dict[str, bytes]]:
    pe = b"MZ" + b"\x00" * 58 + struct.pack("<I", 64) + b"PE\x00\x00" + b"\x00" * 200
    members = {
        "C/Windows/System32/winevt/Logs/Application.evtx": open(EVTX, "rb").read(),
        PS_HISTORY: b"whoami\nnet user\n",
        "C/Windows/System32/cmd.exe": pe,
        "C/Users/bob/Desktop/notes.txt": b"nothing for Nik here",
        "C/Users/bob/Downloads/run.ps1": b"Write-Host hi",
        "C/Windows/Prefetch/WHATEVER.EXE-AAAAAAAA.pf": b"not really a prefetch file",
        "tools/inner.zip": zipfile.ZipFile(io.BytesIO(), "w") and b"PK\x05\x06" + b"\x00" * 18,
    }
    return make_zip(tmp_path / "triage.zip", members), members


def test_recognised_members_are_kept_under_their_hash_and_programs_are_listed_and_not_kept(tmp_path):
    archive, content = a_triage_zip(tmp_path)
    members, end = run(archive, tmp_path)
    by_path = {member["path"]: member for member in members}
    evtx = by_path["C/Windows/System32/winevt/Logs/Application.evtx"]
    history = by_path[PS_HISTORY]
    assert (evtx["kind"], evtx["source"], evtx["parser"], evtx["kept"]) == ("eventlog", "evtx", "evtx", True)
    assert (history["kind"], history["source"], history["username"], history["kept"]) == (
        "commands",
        "powershell",
        "bob",
        True,
    )
    assert evtx["sha256"] == hashlib.sha256(content[evtx["path"]]).hexdigest() and evtx["size"] == len(
        content[evtx["path"]]
    )
    cmd, script = by_path["C/Windows/System32/cmd.exe"], by_path["C/Users/bob/Downloads/run.ps1"]
    assert cmd["executable"] and script["executable"] and not cmd["kept"] and cmd["kind"] is None and cmd["sha256"]
    notes = by_path["C/Users/bob/Desktop/notes.txt"]
    assert notes["kind"] is None and not notes["kept"] and "skip" not in notes and not notes["executable"]
    # A file whose place says it is a prefetch file but whose content is not, with no reader of that kind in the
    # worker yet or one that does not take it: it is listed, not kept, and says why.
    prefetch = by_path["C/Windows/Prefetch/WHATEVER.EXE-AAAAAAAA.pf"]
    assert not prefetch["kept"] or prefetch["parser"]
    assert by_path["tools/inner.zip"]["skip"].startswith("an archive inside")
    assert files_of(tmp_path) == {evtx["sha256"] + ".bin", history["sha256"] + ".bin"} | (
        {prefetch["sha256"] + ".bin"} if prefetch["kept"] else set()
    )
    assert end["members"] == len(members) == len(content) and end["executables"] == 2
    assert end["recognised"] == sum(1 for member in members if member["kept"])
    assert os.listdir(tmp_path / "scratch") == []  # nothing of the job is left


def test_a_member_a_parser_reads_by_its_place_alone_is_named_by_the_path(tmp_path):
    archive = make_zip(tmp_path / "t.zip", {"WKS-1/C/Users/ann/.bash_history": b"ls\ncd /tmp\n"})
    members, _end = run(archive, tmp_path)
    assert (members[0]["kind"], members[0]["source"], members[0]["host"], members[0]["username"]) == (
        "commands",
        "bash",
        "WKS-1",
        "ann",
    )


def test_a_chromium_database_is_named_by_the_browser_its_place_says(tmp_path):
    import sqlite3

    database = tmp_path / "History"
    connection = sqlite3.connect(database)
    connection.executescript(
        "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, typed_count INTEGER,"
        " last_visit_time INTEGER, hidden INTEGER);"
        "CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, from_visit INTEGER,"
        " transition INTEGER, segment_id INTEGER, visit_duration INTEGER);"
        "INSERT INTO urls VALUES (1, 'http://x.test/', 'x', 1, 0, 13300000000000000, 0);"
        "INSERT INTO visits VALUES (1, 1, 13300000000000000, 0, 0, 0, 0);"
    )
    connection.commit()
    connection.close()
    archive = make_zip(
        tmp_path / "t.zip",
        {"C/Users/bob/AppData/Local/Microsoft/Edge/User Data/Profile 1/History": database.read_bytes()},
    )
    members, _end = run(archive, tmp_path)
    assert (members[0]["kind"], members[0]["source"], members[0]["profile"], members[0]["username"]) == (
        "browser",
        "edge.history",
        "Profile 1",
        "bob",
    )


# --------------------------------------------------------------------------- #
# Behind the HTTP front                                                       #
# --------------------------------------------------------------------------- #
@pytest.fixture()
def worker(tmp_path, monkeypatch):
    monkeypatch.setenv("FORENSICS_WORK_DIR", str(tmp_path / "work"))
    sys.modules.pop("server", None)
    import server

    server.GIVEN.clear()
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield server, f"http://127.0.0.1:{httpd.server_port}"
    httpd.shutdown()
    httpd.server_close()


def call(base: str, method: str, path: str, body=None, token: str = TOKEN, raw: bytes | None = None):
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    request = urllib.request.Request(base + path, data=data, method=method, headers={"X-Forensics-Token": token})
    try:
        with urllib.request.urlopen(request, timeout=120) as answer:  # noqa: S310 - the test's own server
            return answer.status, answer.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def give(base: str, data: bytes) -> str:
    name = hashlib.sha256(data).hexdigest() + ".bin"
    assert call(base, "PUT", f"/files/{name}", raw=data)[0] == 200
    return name


def lines_of(body: bytes) -> list[dict]:
    return [json.loads(line) for line in body.splitlines() if line]


def test_a_collection_is_unpacked_over_http_and_its_members_are_served(worker, tmp_path):
    server, base = worker
    archive, content = a_triage_zip(tmp_path)
    data = open(archive, "rb").read()
    name = hashlib.sha256(data).hexdigest() + ".bin"
    status, body = call(base, "POST", "/unpack", {"name": name, "fileName": "triage.zip"})
    assert status == 409 and json.loads(body)["missing"] == [name]
    give(base, data)
    assert call(base, "POST", "/unpack", {"name": name}, token="wrong")[0] == 401
    status, body = call(base, "POST", "/unpack", {"name": name, "fileName": "triage.zip", "total": 1 << 30})
    found = lines_of(body)
    members, end = [line for line in found if line["t"] == "member"], found[-1]
    assert status == 200 and end["t"] == "end" and end["members"] == len(members) == len(content) and not end["error"]
    history = next(member for member in members if member["path"] == PS_HISTORY)
    cmd = next(member for member in members if member["path"].endswith("cmd.exe"))
    assert history["kept"] and cmd["executable"] and not cmd["kept"]
    # The member a parser reads is a file the worker holds now: served from there, and parsed with no transfer.
    status, served = call(base, "POST", "/member", {"sha256": history["sha256"], "path": history["path"]})
    assert status == 200 and served == content[PS_HISTORY]
    status, body = call(base, "POST", "/parse", {"name": history["sha256"] + ".bin", "fileName": history["path"]})
    parsed = lines_of(body)
    assert status == 200 and parsed[0]["source"] == "powershell" and parsed[-1]["read"] == 2
    # A program is not kept: it is taken out of the zip again when it is asked for.
    status, served = call(base, "POST", "/member", {"sha256": cmd["sha256"], "path": cmd["path"], "name": name})
    assert status == 200 and served == content[cmd["path"]] and hashlib.sha256(served).hexdigest() == cmd["sha256"]
    assert call(base, "POST", "/member", {"sha256": cmd["sha256"], "path": "nowhere.exe", "name": name})[0] == 404
    assert call(base, "POST", "/member", {"sha256": "1" * 64, "path": cmd["path"], "name": name})[0] == 404
    assert call(base, "POST", "/member", {"sha256": cmd["sha256"], "path": cmd["path"]})[0] == 400
    assert call(base, "POST", "/member", {"sha256": "x", "path": "a"})[0] == 400
    other = "2" * 64 + ".bin"
    assert call(base, "POST", "/member", {"sha256": cmd["sha256"], "path": cmd["path"], "name": other})[0] == 409
    assert (
        call(base, "POST", "/member", {"sha256": cmd["sha256"], "path": cmd["path"], "name": name}, token="wrong")[0]
        == 401
    )
    assert os.listdir(os.path.join(server.GIVEN.folder, "unpack")) == []


def test_a_member_is_served_after_the_worker_forgot_it_was_kept(worker, tmp_path):
    server, base = worker
    archive, content = a_triage_zip(tmp_path)
    data = open(archive, "rb").read()
    name = give(base, data)
    members = [line for line in lines_of(call(base, "POST", "/unpack", {"name": name})[1]) if line["t"] == "member"]
    history = next(member for member in members if member["path"] == PS_HISTORY)
    server.GIVEN.drop(history["sha256"] + ".bin")
    status, served = call(base, "POST", "/member", {"sha256": history["sha256"], "path": history["path"], "name": name})
    assert status == 200 and served == content[PS_HISTORY]


def test_a_zip_that_is_not_one_is_answered_in_the_last_line(worker, tmp_path):
    _server, base = worker
    name = give(base, b"PK\x03\x04 broken")
    status, body = call(base, "POST", "/unpack", {"name": name})
    found = lines_of(body)
    assert status == 200 and found[-1]["t"] == "end" and "not a zip" in found[-1]["error"]
    assert not any(line.get("reason") == "the parser stopped" for line in found)


def test_recognise_tells_a_zip_a_known_file_an_image_and_a_stranger(worker, tmp_path):
    _server, base = worker
    zipped = give(base, make_zip_bytes({"a.txt": b"x"}))
    status, body = call(base, "POST", "/recognise", {"name": zipped, "fileName": "triage.zip"})
    assert status == 200 and json.loads(body) == {"container": "zip", "kind": "collection", "source": "collection.zip"}
    history = give(base, b"whoami\n")
    status, body = call(base, "POST", "/recognise", {"name": history, "fileName": "ConsoleHost_history.txt"})
    assert status == 200 and json.loads(body)["source"] == "powershell"
    image = give(base, b"vhdxfile" + b"\x00" * 64)
    status, body = call(base, "POST", "/recognise", {"name": image, "fileName": "disk.vhdx"})
    answer = json.loads(body)
    assert status == 422 and answer["refused"] is True and "KAPE" in answer["detail"]
    stranger = give(base, b"\x00\x01 nothing Nik reads")
    status, body = call(base, "POST", "/recognise", {"name": stranger, "fileName": "x.dat"})
    answer = json.loads(body)
    assert status == 422 and "refused" not in answer and "No parser" in answer["detail"]


def make_zip_bytes(members: dict) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as out:
        for name, data in members.items():
            out.writestr(name, data)
    return buffer.getvalue()


def test_every_source_the_path_table_names_is_read_by_a_parser_of_that_section():
    from nik_forensics import parsers

    named = {(kind, source) for _pattern, kind, source in triage._LOG_NAMES}
    assert len(named) >= 12
    for kind, source in sorted(named):
        module = parsers.by_source(kind, source)
        assert module is not None, f"no parser of {kind} reads {source}"
        assert module.KIND == kind and source in module.SOURCES
    # A hive found by its place is read whole by the hive parser, whatever hive it is.
    for place in (
        "C/Users/alice/NTUSER.DAT",
        "C/Windows/System32/config/SYSTEM",
        "C/Windows/System32/config/SOFTWARE",
        "C/Windows/appcompat/Programs/Amcache.hve",
    ):
        found = triage.describe(place)
        assert (found["kind"], found["source"]) == ("endpoint", "windows.registry.hive")
        assert parsers.by_source("endpoint", found["source"]).NAME == "hive"
    assert triage.describe("C/Windows/System32/sru/SRUDB.dat")["source"] == "windows.network.srum-network"

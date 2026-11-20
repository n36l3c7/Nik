"""Taking the files out of an archive: in memory, bounded, and a name is never a path."""

from __future__ import annotations

import pytest

from app import unpack
from tests.stores import zip_of, zipcrypto_of

MB = 1024 * 1024
NOTES = {"notes/readme.txt": b"collected on wks-7\n", "notes/hosts.csv": b"host,seen\nwks-7,today\n"}


def names(found: unpack.Unpacked) -> list[str]:
    return [member.name for member in found.members]


def test_the_files_of_a_zip_are_given_as_bytes_and_directories_are_passed_over():
    found = unpack.members(zip_of({"notes/": b"", **NOTES}), limit=MB)
    assert names(found) == ["notes/readme.txt", "notes/hosts.csv"] and found.skipped == []
    assert [member.data for member in found.members] == list(NOTES.values())
    # As a file of its own a member has the last part of its name.
    assert [unpack.file_name(name) for name in names(found)] == ["readme.txt", "hosts.csv"]


def test_an_archive_protected_either_way_opens_with_its_password_and_no_other():
    secret = "S3ntinel-fetch!"
    for archive in (zip_of(NOTES, secret), zipcrypto_of("readme.txt", NOTES["notes/readme.txt"], secret)):
        found = unpack.members(archive, secret, limit=MB)
        assert found.members[0].data == NOTES["notes/readme.txt"]
        for wrong, said in (
            ("", "The archive is protected by a password and none was given: nothing was unpacked"),
            ("not-the-password", "The password does not open the archive: nothing was unpacked"),
        ):
            with pytest.raises(unpack.UnpackError) as refused:
                unpack.members(archive, wrong, limit=MB)
            # The sentence says what happened and repeats no password.
            assert refused.value.message == said and "not-the-password" not in refused.value.message


def test_what_is_not_a_zip_is_said_and_only_a_zip_is_unpacked():
    for bad in (b"MZ\x90\x00 not an archive", b"", b"PK\x03\x04 cut short"):
        with pytest.raises(unpack.UnpackError) as refused:
            unpack.members(bad, limit=MB)
        assert refused.value.message == "The file is not a zip archive Nik can read: nothing was unpacked"
    with pytest.raises(unpack.UnpackError) as refused:
        unpack.members(zip_of(NOTES), limit=MB, fmt="7z")
    assert refused.value.message == "Only a zip archive is unpacked"


def test_a_name_is_data_and_nothing_is_followed():
    inner = zip_of({"deeper.txt": b"inside the inner archive"})
    hostile = {
        "../../etc/passwd": b"root:x:0:0\n",
        "/abs/olute.txt": b"absolute\n",
        "C:\\Windows\\System32\\evil.dll": b"MZ not really\n",
        "CON": b"a device name on Windows\n",
        "line\nbreak\ttab.txt": b"control characters\n",
        "inner.zip": inner,
        "link-to-shadow": b"/etc/shadow",
        "empty.txt": b"",
    }
    found = unpack.members(zip_of(hostile, links=("link-to-shadow",)), limit=MB)
    by_name = {member.name: member.data for member in found.members}
    # Every name came back as the text it is, with its bytes: no path was built from any of them.
    assert by_name["../../etc/passwd"] == b"root:x:0:0\n" and by_name["/abs/olute.txt"] == b"absolute\n"
    assert by_name["C:\\Windows\\System32\\evil.dll"].startswith(b"MZ") and "CON" in by_name
    assert "line break tab.txt" in by_name
    # An archive inside the archive is a file like the others: it is not unpacked.
    assert by_name["inner.zip"] == inner and "deeper.txt" not in by_name
    assert found.skipped == [
        {"name": "link-to-shadow", "reason": "It is a link: links are not followed"},
        {"name": "empty.txt", "reason": "It is empty"},
    ]
    assert unpack.file_name("../../etc/passwd") == "passwd"
    assert unpack.file_name("C:\\Windows\\System32\\evil.dll") == "evil.dll"


def test_an_archive_is_bounded_in_members_in_size_and_in_how_much_it_inflates(monkeypatch):
    # Shaped like a bomb: a few kilobytes that become megabytes.
    bomb = zip_of({"zeroes.bin": b"\0" * (3 * MB), "small.txt": b"fine\n"})
    assert len(bomb) < 10_000
    found = unpack.members(bomb, limit=10 * MB)
    assert names(found) == ["small.txt"]
    assert found.skipped == [
        {"name": "zeroes.bin", "reason": "It is packed more than 200 times over: it is not unpacked"}
    ]
    # A member larger than an upload is left; the others are taken.
    found = unpack.members(zip_of({"big.txt": b"0123456789" * 200, "small.txt": b"fine\n"}), limit=1000)
    assert (
        names(found) == ["small.txt"] and found.skipped[0]["reason"] == "It is larger than the 1 MB limit of an upload"
    )
    # All of them together are no larger than an upload either.
    several = zip_of({f"part-{index}.txt": bytes([65 + index]) * 600 for index in range(4)})
    with pytest.raises(unpack.UnpackError) as refused:
        unpack.members(several, limit=1000)
    assert refused.value.message.startswith("The archive holds more than the 1 MB limit of an upload once unpacked")
    monkeypatch.setattr(unpack, "MEMBERS_MAX", 3)
    with pytest.raises(unpack.UnpackError) as refused:
        unpack.members(several, limit=MB)
    assert refused.value.message == (
        "The archive holds 4 files, more than the 3 that are unpacked: nothing was unpacked"
    )

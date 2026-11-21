"""The files a worker is given (given.py): what it takes, what it refuses, how long it keeps them."""

from __future__ import annotations

import hashlib
import io
import os
import re
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))

import given  # noqa: E402

SAMPLE = re.compile(r"[0-9a-f]{64}\.bin")
SIGNATURE = re.compile(r"_flirt/[0-9a-f]{32}\.(sig|pat)")
CAPTURE = re.compile(r"_captures/[0-9a-f]{32}/capture\.(pcap|pcapng|cap|gz)")


def named(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest() + ".bin"


def take(held: given.Given, name: str, data: bytes) -> None:
    held.take(name, io.BytesIO(data), len(data))


@pytest.fixture()
def held(tmp_path):
    return given.Given(str(tmp_path / "given"), (SAMPLE, SIGNATURE, CAPTURE), max_bytes=10_000)


def test_the_copies_of_this_file_in_the_other_workers_are_the_same():
    """Each image is built from its own folder and holds its own copy: they must not drift apart."""
    mine = (HERE / "given.py").read_bytes()
    others = [HERE.parent / worker / "given.py" for worker in ("capa", "pcap")]
    if not all(path.is_file() for path in others):
        pytest.skip("the other workers are not beside this one here")
    for path in others:
        assert path.read_bytes() == mine, f"{path} differs from workers/analyzer/given.py"


def test_the_workers_that_carry_their_own_reader_of_a_secret_read_it_the_same_way():
    """The workers that are given no file have no given.py: ``secret`` is written in their server.py."""
    reader = re.compile(r"^def secret\(name: str\) -> str:\n.*?^    return held or value\n", re.S | re.M)
    mine = reader.search((HERE / "given.py").read_text(encoding="utf-8"))
    assert mine is not None
    others = [HERE.parent / worker / "server.py" for worker in ("browser", "docview", "sandbox")]
    if not all(path.is_file() for path in others):
        pytest.skip("the other workers are not beside this one here")
    for path in others:
        theirs = reader.search(path.read_text(encoding="utf-8"))
        assert theirs is not None and theirs.group(0) == mine.group(0), f"secret() of {path} differs from given.py"


def test_a_file_that_was_given_is_held_and_one_that_was_not_is_missing(held):
    data = b"a harmless fixture"
    name = named(data)
    assert held.path(name) is None and held.missing([name, "_flirt/" + "a" * 32 + ".sig"]) == [
        name,
        "_flirt/" + "a" * 32 + ".sig",
    ]
    take(held, name, data)
    take(held, "_flirt/" + "a" * 32 + ".sig", b"IDASGN")
    path = held.path(name)
    assert path and open(path, "rb").read() == data and held.missing([name, "_flirt/" + "a" * 32 + ".sig"]) == []
    assert os.path.realpath(path).startswith(os.path.realpath(held.folder) + os.sep)
    # Given again: the same file, once.
    take(held, name, data)
    assert len(list(Path(held.folder, "files").glob("*.bin"))) == 1
    held.drop(name)
    assert held.path(name) is None
    held.drop(name)


@pytest.mark.parametrize(
    "name",
    ["../etc/passwd", "/etc/passwd", "a.bin", "A" * 64 + ".bin", "a" * 64 + ".bin\n", "a" * 64 + ".exe",
     "_flirt/../" + "a" * 64 + ".bin", "_flirt/" + "a" * 32 + ".sig/x", "_captures/" + "c" * 32 + "/../x", "", "."],
)  # fmt: skip
def test_a_name_that_is_not_one_the_worker_is_given_is_refused(held, name):
    with pytest.raises(given.Refused) as refused:
        take(held, name, b"x")
    assert refused.value.status == 400
    assert held.path(name) is None
    assert not os.path.exists(os.path.join(held.folder, "files")) or not os.listdir(os.path.join(held.folder, "files"))


def test_a_sample_must_be_the_one_its_name_says(held):
    data = b"the real content"
    with pytest.raises(given.Refused) as refused:
        take(held, named(b"something else"), data)
    assert refused.value.status == 422 and "SHA-256" in refused.value.detail
    assert held.path(named(b"something else")) is None
    assert not os.listdir(os.path.join(held.folder, "incoming"))


def test_a_file_cut_short_or_too_large_is_refused_and_leaves_nothing(held):
    data = b"x" * 500
    with pytest.raises(given.Refused) as short:
        held.take(named(data), io.BytesIO(data[:100]), len(data))
    assert short.value.status == 400 and held.path(named(data)) is None
    with pytest.raises(given.Refused) as large:
        held.take(named(data), io.BytesIO(data), held.max_bytes + 1)
    assert large.value.status == 413
    with pytest.raises(given.Refused):
        held.take(named(data), io.BytesIO(data), -1)
    assert not os.listdir(os.path.join(held.folder, "incoming"))


def test_the_least_recently_used_go_first_when_room_is_needed(held, monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(given.time, "monotonic", lambda: clock[0])
    files = [bytes([n]) * 3000 for n in range(4)]
    for data in files[:3]:
        clock[0] += 1
        take(held, named(data), data)
    clock[0] += 1
    assert held.path(named(files[0]))  # used again: the first is now the most recent
    clock[0] += 1
    take(held, named(files[3]), files[3])  # 12 000 bytes would not fit in 10 000
    assert held.missing([named(data) for data in files]) == [named(files[1])]


def test_a_file_in_use_is_not_deleted_to_make_room_nor_for_being_idle(held, monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(given.time, "monotonic", lambda: clock[0])
    busy, other, new = b"a" * 4000, b"b" * 4000, b"c" * 4000
    take(held, named(busy), busy)
    clock[0] += 1
    take(held, named(other), other)
    with held.hold([named(busy)]):
        clock[0] += held.idle + 1
        held.expire()
        assert held.path(named(busy)) and held.path(named(other)) is None
        take(held, named(other), other)
        clock[0] += 1
        take(held, named(new), new)  # room is made from what is not in use
        assert held.missing([named(busy), named(other), named(new)]) == [named(other)]
        # When everything held is in use, a file that does not fit is refused, not squeezed in.
        with held.hold([named(new)]), pytest.raises(given.Refused) as full:
            take(held, named(other), other)
        assert full.value.status == 507
    # Once it is no longer in use it expires like the rest.
    clock[0] += held.idle + 1
    held.expire()
    assert held.missing([named(busy), named(new)]) == [named(busy), named(new)]


def test_nothing_is_kept_from_before_the_worker_started(held):
    data = b"left by the worker that stopped"
    take(held, named(data), data)
    Path(held.folder, "incoming", "half").write_bytes(b"half a file")
    again = given.Given(held.folder, held.allowed, max_bytes=10_000)
    again.clear()
    assert again.path(named(data)) is None
    assert not os.path.exists(os.path.join(held.folder, "files")) and not os.path.exists(
        os.path.join(held.folder, "incoming")
    )


def test_a_large_file_goes_to_the_disk_and_a_small_one_stays_in_memory(tmp_path):
    memory, disk = tmp_path / "memory", tmp_path / "work"
    disk.mkdir()
    held = given.Given(str(memory), (CAPTURE,), max_bytes=10**6, large=str(disk), large_from=1000)
    small, large = "_captures/" + "a" * 32 + "/capture.pcap", "_captures/" + "b" * 32 + "/capture.pcapng"
    take(held, small, b"s" * 1000)
    take(held, large, b"l" * 1001)
    assert held.path(small).startswith(str(memory)) and held.path(large).startswith(str(disk))
    # Given again, smaller: it is not left in both places.
    take(held, large, b"l" * 10)
    assert held.path(large).startswith(str(memory)) and not list(disk.rglob("capture.pcapng"))
    held.drop_prefix("_captures/" + "a" * 32 + "/")
    assert held.path(small) is None and held.path(large)
    # Without a work folder that can be written to, everything is in memory.
    plain = given.Given(str(memory), (CAPTURE,), max_bytes=10**6, large=str(tmp_path / "nowhere"), large_from=1000)
    take(plain, small, b"s" * 5000)
    assert plain.path(small).startswith(str(memory))
    held.clear()
    assert not list(disk.iterdir()) or not list(disk.rglob("*.pcap*"))


def test_a_worker_with_no_room_says_so(held, monkeypatch):
    usage = type("Usage", (), {"free": 100})
    monkeypatch.setattr(given.shutil, "disk_usage", lambda _path: usage)
    with pytest.raises(given.Refused) as refused:
        take(held, named(b"x" * 500), b"x" * 500)
    assert refused.value.status == 507 and "100 are free" in refused.value.detail


def test_a_secret_comes_from_its_file_or_from_the_environment_never_both(tmp_path, monkeypatch):
    monkeypatch.delenv("ANALYZER_TOKEN", raising=False)
    monkeypatch.delenv("ANALYZER_TOKEN_FILE", raising=False)
    assert given.secret("ANALYZER_TOKEN") == ""
    monkeypatch.setenv("ANALYZER_TOKEN", "from-the-environment")
    assert given.secret("ANALYZER_TOKEN") == "from-the-environment"
    file = tmp_path / "token"
    file.write_text("")
    monkeypatch.setenv("ANALYZER_TOKEN_FILE", str(file))
    # The empty file the Compose stack mounts while the secrets are in .env counts as none.
    assert given.secret("ANALYZER_TOKEN") == "from-the-environment"
    file.write_text("from-the-file\n")
    with pytest.raises(SystemExit, match="given twice"):
        given.secret("ANALYZER_TOKEN")
    monkeypatch.delenv("ANALYZER_TOKEN")
    assert given.secret("ANALYZER_TOKEN") == "from-the-file"
    monkeypatch.setenv("ANALYZER_TOKEN_FILE", str(tmp_path / "not-there"))
    with pytest.raises(SystemExit, match="cannot be read") as stop:
        given.secret("ANALYZER_TOKEN")
    assert "from-the-file" not in str(stop.value)

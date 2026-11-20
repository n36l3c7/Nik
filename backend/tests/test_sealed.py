"""The sealed file of the store (core/sealed.py): what it gives back, and everything it refuses."""

from __future__ import annotations

import hashlib
import io
import os

import pytest

from app.core import sealed

RING = sealed.Keyring.of("k" * 40)
OTHER = sealed.Keyring.of("another store key, long enough to be one")
C = 1024  # a small chunk, so that files of a few kilobytes have many


def seal(path, data: bytes, name: str = "a.bin", ring: sealed.Keyring = RING, chunk: int = C, step: int = 0) -> None:
    with open(path, "wb") as out:
        writer = sealed.Writer(out, name, ring.current, chunk)
        if step:
            for start in range(0, len(data), step):
                writer.write(data[start : start + step])
        else:
            writer.write(data)
        writer.close()


def unseal(path, name: str = "a.bin", ring: sealed.Keyring = RING) -> bytes:
    with sealed.open_sealed(path, name, ring) as handle:
        return handle.read()


def content(size: int) -> bytes:
    return hashlib.shake_256(str(size).encode()).digest(size)


SIZES = [0, 1, C - 1, C, C + 1, 2 * C - 1, 2 * C, 2 * C + 1, 5 * C, 5 * C + 17]


@pytest.mark.parametrize("size", SIZES)
@pytest.mark.parametrize("step", [0, 1, 7, C, C + 1])
def test_what_is_written_is_what_is_read(tmp_path, size, step):
    if step == 1 and size > 2 * C + 1:
        step = 3
    data, path = content(size), tmp_path / "f"
    seal(path, data, step=step)
    assert unseal(path) == data
    assert os.path.getsize(path) == sealed.sealed_size(size, C)
    assert sealed.plain_size(os.path.getsize(path), C) == size
    # On the disk there is nothing of the content.
    raw = path.read_bytes()
    assert raw.startswith(sealed.MAGIC)
    if size >= 32:
        assert data[:32] not in raw and data[-32:] not in raw


def test_the_writer_knows_the_size_and_takes_nothing_once_closed(tmp_path):
    data = content(3 * C + 5)
    with open(tmp_path / "f", "wb") as out:
        writer = sealed.Writer(out, "a.bin", RING.current, C)
        writer.write(data)
        writer.close()
        assert writer.size == len(data)
        with pytest.raises(sealed.SealError):
            writer.write(b"more")


@pytest.mark.parametrize("size", [1, C, C + 1, 3 * C, 3 * C + 9])
def test_any_range_is_read_without_the_rest(tmp_path, size):
    data, path = content(size), tmp_path / "f"
    seal(path, data)
    edges = sorted({0, 1, C - 1, C, C + 1, 2 * C - 1, 2 * C, 2 * C + 1, size - 1, size} & set(range(size + 1)))
    with sealed.open_sealed(path, "a.bin", RING) as handle:
        assert handle.raw.size == size
        for start in edges:
            for end in edges:
                if end < start:
                    continue
                handle.seek(start)
                assert handle.read(end - start) == data[start:end], (start, end)
        handle.seek(-1, os.SEEK_END)
        assert handle.read() == data[-1:]
        handle.seek(size + 10)
        assert handle.read(5) == b""
        handle.seek(0)
        assert handle.tell() == 0 and handle.seekable() and handle.readable()


def test_only_the_chunks_asked_for_are_decrypted(tmp_path):
    data, path = content(10 * C), tmp_path / "f"
    seal(path, data)
    reader = sealed.Reader(open(path, "rb"), "a.bin", RING)
    loaded = []
    inner = reader._load
    reader._load = lambda number: loaded.append(number) or inner(number)
    reader.seek(4 * C + 3)
    assert reader.read(10) == data[4 * C + 3 : 4 * C + 13]
    assert loaded == [4]
    reader.close()


def test_it_reads_lines_like_a_file(tmp_path):
    text = b"".join(b"line %d\n" % n for n in range(1000))
    seal(tmp_path / "f", text)
    with sealed.open_sealed(tmp_path / "f", "a.bin", RING) as handle:
        assert list(handle) == text.splitlines(keepends=True)


@pytest.mark.parametrize("size", [0, 5, C, 3 * C + 9])
def test_a_flipped_byte_anywhere_is_refused(tmp_path, size):
    data, path = content(size), tmp_path / "f"
    seal(path, data)
    raw = path.read_bytes()
    # Every byte of the head that is used, then bytes of every chunk.
    places = list(range(sealed.PREFIX + sealed.SLOT)) + list(range(sealed.HEADER, len(raw), 97)) + [len(raw) - 1]
    for place in places:
        changed = bytearray(raw)
        changed[place] ^= 0x01
        path.write_bytes(bytes(changed))
        with pytest.raises((sealed.Damaged, sealed.WrongKey)):
            unseal(path)
    path.write_bytes(raw)
    assert unseal(path) == data


@pytest.mark.parametrize("size", [0, 5, C, C + 1, 3 * C, 3 * C + 9])
def test_a_file_cut_short_is_refused_wherever_it_is_cut(tmp_path, size):
    data, path = content(size), tmp_path / "f"
    seal(path, data)
    raw = path.read_bytes()
    cuts = set(range(0, sealed.HEADER + 20)) | {len(raw) - 1, len(raw) - sealed.TAG, len(raw) - sealed.TAG - 1}
    # At every boundary between two chunks, and one byte either side.
    for number in range(1, 5):
        edge = sealed.HEADER + number * (C + sealed.TAG)
        cuts |= {edge - 1, edge, edge + 1}
    for cut in sorted(c for c in cuts if 0 <= c < len(raw)):
        path.write_bytes(raw[:cut])
        with pytest.raises(sealed.Damaged):
            # Refused when it is opened: not after half of it was served.
            sealed.open_sealed(path, "a.bin", RING)


def test_bytes_added_at_the_end_are_refused(tmp_path):
    for size in (0, 7, C, 2 * C + 3):
        path = tmp_path / f"f{size}"
        seal(path, content(size))
        raw = path.read_bytes()
        for extra in (b"\x00", b"x" * sealed.TAG, b"x" * (C + sealed.TAG), raw[sealed.HEADER :]):
            path.write_bytes(raw + extra)
            with pytest.raises(sealed.Damaged):
                unseal(path)


def test_chunks_swapped_repeated_or_left_out_are_refused(tmp_path):
    data, path = content(4 * C), tmp_path / "f"
    seal(path, data)
    raw = path.read_bytes()
    head, body = raw[: sealed.HEADER], raw[sealed.HEADER :]
    step = C + sealed.TAG
    parts = [body[n * step : (n + 1) * step] for n in range(4)]
    for order in ([1, 0, 2, 3], [0, 0, 2, 3], [0, 2, 3], [0, 1, 3, 2], [0, 1, 2, 3, 3], [3, 1, 2, 0]):
        path.write_bytes(head + b"".join(parts[n] for n in order))
        with pytest.raises(sealed.Damaged):
            unseal(path)


def test_a_chunk_of_another_file_is_refused(tmp_path):
    seal(tmp_path / "a", content(3 * C), name="a.bin")
    seal(tmp_path / "b", content(3 * C + 1)[: 3 * C], name="a.bin")
    a, b = (tmp_path / "a").read_bytes(), (tmp_path / "b").read_bytes()
    step = C + sealed.TAG
    (tmp_path / "a").write_bytes(a[: sealed.HEADER + step] + b[sealed.HEADER + step :])
    with pytest.raises(sealed.Damaged):
        unseal(tmp_path / "a")
    # The whole content of one under the head of the other.
    (tmp_path / "a").write_bytes(a[: sealed.HEADER] + b[sealed.HEADER :])
    with pytest.raises(sealed.Damaged):
        unseal(tmp_path / "a")


def test_a_file_under_another_name_is_refused(tmp_path):
    data = content(2 * C)
    seal(tmp_path / "f", data, name="a" * 64 + ".bin")
    assert unseal(tmp_path / "f", name="a" * 64 + ".bin") == data
    with pytest.raises(sealed.Damaged, match="in the place of another"):
        unseal(tmp_path / "f", name="b" * 64 + ".bin")


def test_another_store_key_is_told_from_damage(tmp_path):
    seal(tmp_path / "f", content(100))
    with pytest.raises(sealed.WrongKey, match="not the one of this server"):
        unseal(tmp_path / "f", ring=OTHER)


def test_what_is_not_a_sealed_file_is_refused(tmp_path):
    for raw in (b"", b"MZ\x90\x00" * 100, sealed.MAGIC, sealed.MAGIC + b"\x00" * 200, sealed.MAGIC + b"\xff" * 400):
        (tmp_path / "f").write_bytes(raw)
        with pytest.raises(sealed.Damaged):
            unseal(tmp_path / "f")
    assert sealed.is_sealed(sealed.MAGIC + b"x") and not sealed.is_sealed(b"MZ") and not sealed.is_sealed(b"")


def test_a_head_that_asks_for_a_huge_chunk_is_refused(tmp_path):
    seal(tmp_path / "f", content(10))
    raw = bytearray((tmp_path / "f").read_bytes())
    raw[8:12] = (2**31).to_bytes(4, "big")
    (tmp_path / "f").write_bytes(bytes(raw))
    with pytest.raises(sealed.Damaged):
        unseal(tmp_path / "f")


def test_two_files_with_the_same_content_share_nothing_on_the_disk(tmp_path):
    data = content(2 * C)
    seal(tmp_path / "a", data)
    seal(tmp_path / "b", data)
    a, b = (tmp_path / "a").read_bytes(), (tmp_path / "b").read_bytes()
    assert a[sealed.PREFIX :] != b[sealed.PREFIX :]
    assert a[sealed.HEADER : sealed.HEADER + 64] != b[sealed.HEADER : sealed.HEADER + 64]


def test_the_key_of_a_store_key_and_its_fingerprint():
    one, two = sealed.StoreKey.derive("k" * 40), sealed.StoreKey.derive("k" * 39 + "j")
    assert one == RING.current and one.id != two.id and one.wrapping != two.wrapping
    assert len(one.fingerprint) == 9 and one.fingerprint != two.fingerprint
    # The fingerprint is not a part of the key, of what wraps, or of the id.
    assert one.fingerprint.replace("-", "") not in ("k" * 40 + one.wrapping.hex() + one.id.hex())
    with pytest.raises(sealed.SealError):
        sealed.StoreKey.derive("")


# --------------------------------------------------------------------------- #
# Changing the store key                                                      #
# --------------------------------------------------------------------------- #
NEW = sealed.Keyring.of("the new store key, long enough to be one", ["k" * 40])
NEW_ALONE = sealed.Keyring.of("the new store key, long enough to be one")


def test_rewrapping_changes_the_head_and_not_the_content(tmp_path):
    data, path = content(3 * C + 4), tmp_path / "f"
    seal(path, data)
    before = path.read_bytes()
    assert sealed.needs_rewrap(sealed.read_head(path), NEW)
    assert sealed.rewrap(path, "a.bin", NEW) is True
    after = path.read_bytes()
    assert after[sealed.HEADER :] == before[sealed.HEADER :] and after[: sealed.PREFIX] == before[: sealed.PREFIX]
    assert unseal(path, ring=NEW_ALONE) == data
    with pytest.raises(sealed.WrongKey):
        unseal(path)  # the old key opens it no more
    assert sealed.read_head(path).key_ids() == [NEW.current.id]
    # Again: nothing to do.
    assert sealed.rewrap(path, "a.bin", NEW) is False and path.read_bytes() == after


def test_rewrapping_needs_a_key_that_opens_the_file(tmp_path):
    seal(tmp_path / "f", content(10), ring=OTHER)
    before = (tmp_path / "f").read_bytes()
    with pytest.raises(sealed.WrongKey):
        sealed.rewrap(tmp_path / "f", "a.bin", NEW)
    with pytest.raises(sealed.Damaged):
        sealed.rewrap(
            tmp_path / "f", "b.bin", sealed.Keyring.of("x" * 40, ["another store key, long enough to be one"])
        )
    assert (tmp_path / "f").read_bytes() == before


class _Stops(Exception):
    pass


def _rewrap_stopping(path, stop_at: int, torn: bool, monkeypatch) -> bool:
    """Run a rewrap whose ``stop_at``-th write fails (after half of it reached the disk when ``torn``).
    Says whether it finished."""
    real_open = open
    writes = {"n": 0}

    class Stopping(io.FileIO):
        def write(self, raw):
            writes["n"] += 1
            if writes["n"] == stop_at:
                if torn:
                    super().write(bytes(raw)[: len(raw) // 2])
                raise _Stops()
            return super().write(raw)

    def opening(file, mode="r", *args, **kwargs):
        if mode == "r+b":
            return Stopping(file, "r+")
        return real_open(file, mode, *args, **kwargs)

    monkeypatch.setattr("builtins.open", opening)
    try:
        sealed.rewrap(path, "a.bin", NEW)
        return True
    except _Stops:
        return False
    finally:
        monkeypatch.setattr("builtins.open", real_open)


def test_a_rewrap_stopped_at_any_write_leaves_a_file_one_of_the_keys_opens(tmp_path, monkeypatch):
    """Stopped at each of its writes, and with a write that only half reached the disk."""
    data = content(2 * C + 1)
    for stop_at in range(1, 4):
        for torn in (False, True):
            path = tmp_path / f"f{stop_at}{torn}"
            seal(path, data)
            finished = _rewrap_stopping(path, stop_at, torn, monkeypatch)
            # Whatever happened, the server (which holds both keys until the change is over) reads it,
            assert unseal(path, ring=NEW) == data, (stop_at, torn)
            # and running it again finishes the work.
            sealed.rewrap(path, "a.bin", NEW)
            assert unseal(path, ring=NEW_ALONE) == data
            assert sealed.read_head(path).key_ids() == [NEW.current.id]
            assert finished == (stop_at == 3)

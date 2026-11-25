"""A reader of the ``regf`` registry hive format, written for hostile files: no library, no unbounded recursion.

A hive is a header page of 4096 bytes and then ``hbin`` blocks of cells. A cell is a signed size (negative: in use)
and its data; cells point to each other by offset from the first ``hbin``. The reader gives what ``hive.py`` needs
and says every place it could not read:

    Hive(path)                       opens the file (memory mapped, read-only); ``RegfError`` when it is not a hive
    hive.key(offset)                 the key (``nk`` cell) at an offset
    hive.iter_subkeys(key, report)   its subkeys, in the order of the hive; what cannot be read goes to ``report``
    hive.iter_values(key, report)    its values, the same way
    hive.find(path, report)          a key by its path (names compared without case), or None
    hive.data(value)                 the bytes of a value, up to ``MAX_DATA``, and whether it has more
    hive.scan(report)                walks every ``hbin`` and counts the cells in use (keys, values)

``report(offset, reason, lost)`` (and ``length`` for a run of blocks) is called for each cell, block or list that
cannot be read; ``lost`` is the number of items it is known to have cost (0 when it is not known).
Standard library only.
"""

from __future__ import annotations

import mmap
import struct
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

HEADER = 4096
# A cell or a value is never read beyond these bounds: a hostile size asks for nothing more.
MAX_CELL = 16 * 1024 * 1024
MAX_DATA = 16 * 1024 * 1024
MAX_SUBKEYS = 1_000_000
BIG_DATA_BLOCK = 16344  # the data a block of a "db" value holds (the cell is 16384 bytes with its headers)
NO_OFFSET = 0xFFFFFFFF
EPOCH_DELTA_MS = 11644473600000
# Times outside these years are not times of a computer in use (a zero, a garbage field).
MIN_MS = 315532800000  # 1980
MAX_MS = 4102444800000  # 2100

# report(offset, reason, lost, length=None)
Report = Callable[..., None]


class RegfError(Exception):
    """The file is not a hive, or its header is too damaged to go on."""


class CellError(Exception):
    def __init__(self, offset: int, reason: str) -> None:
        super().__init__(reason)
        self.offset = offset
        self.reason = reason


class LimitHit(Exception):
    """The time given to one hive is over."""


def filetime_ms(value: int) -> int | None:
    """A Windows FILETIME (100 ns since 1601) as epoch milliseconds, None when zero or not plausible."""
    if value <= 0:
        return None
    ms = value // 10000 - EPOCH_DELTA_MS
    return ms if MIN_MS <= ms <= MAX_MS else None


def iso(ms: int | None) -> str:
    return datetime.fromtimestamp(ms / 1000, timezone.utc).strftime("%Y-%m-%d %H:%M:%S") if ms is not None else ""


@dataclass
class Key:
    offset: int
    name: str
    last_write: int  # FILETIME
    flags: int
    subkey_count: int
    subkey_list: int
    value_count: int
    value_list: int

    @property
    def ts(self) -> int | None:
        return filetime_ms(self.last_write)


@dataclass
class Value:
    offset: int  # of the vk cell
    name: str
    type: int
    size: int  # as the value declares it
    inline: bool
    data_offset: int


class Hive:
    def __init__(self, path: str, seconds: float = 600.0) -> None:
        self._file = open(path, "rb")  # noqa: SIM115 - closed by close()
        try:
            self.file_size = self._file.seek(0, 2)
            if self.file_size < HEADER:
                raise RegfError("the file is shorter than the header of a hive")
            self._map = mmap.mmap(self._file.fileno(), 0, access=mmap.ACCESS_READ)
        except (ValueError, OSError) as error:
            self._file.close()
            raise RegfError(f"the file cannot be mapped: {error}") from None
        except RegfError:
            self._file.close()
            raise
        head = self._map[:HEADER]
        if head[:4] != b"regf":
            self.close()
            raise RegfError("the file does not start with regf")
        self.seq1, self.seq2 = struct.unpack_from("<II", head, 4)
        self.written = struct.unpack_from("<Q", head, 12)[0]
        self.major, self.minor = struct.unpack_from("<II", head, 20)
        self.root_offset, self.hbins_size = struct.unpack_from("<II", head, 36)
        self.name = head[48:112].decode("utf-16le", "replace").split("\x00")[0]
        self.checksum = struct.unpack_from("<I", head, 508)[0]
        calc = 0
        for at in range(0, 508, 4):
            calc ^= struct.unpack_from("<I", head, at)[0]
        calc = {0xFFFFFFFF: 0xFFFFFFFE, 0: 1}.get(calc, calc)
        self.checksum_ok = calc == self.checksum
        self.dirty = self.seq1 != self.seq2
        self._deadline = time.monotonic() + seconds

    def close(self) -> None:
        try:
            self._map.close()
        except Exception:  # noqa: BLE001, S110 - already closed
            pass
        self._file.close()

    def __enter__(self) -> Hive:
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.close()

    def tick(self) -> None:
        if time.monotonic() > self._deadline:
            raise LimitHit("the time given to this hive is over")

    # -- cells ---------------------------------------------------------------- #
    def cell(self, offset: int) -> bytes:
        """The data of the cell in use at ``offset`` (without its size)."""
        if offset in (0, NO_OFFSET) or offset % 8:
            raise CellError(offset, "offset does not point to a cell")
        absolute = HEADER + offset
        if offset + 8 > self.hbins_size or absolute + 8 > self.file_size:
            raise CellError(offset, "offset is past the end of the hive")
        size = struct.unpack_from("<i", self._map, absolute)[0]
        if size >= 0:
            raise CellError(offset, "cell is free, not in use")
        length = -size
        if length < 8 or length > MAX_CELL:
            raise CellError(offset, "cell size is not valid")
        if absolute + length > self.file_size:
            raise CellError(offset, "cell goes past the end of the file")
        return bytes(self._map[absolute + 4 : absolute + length])

    # -- keys ----------------------------------------------------------------- #
    def key(self, offset: int) -> Key:
        data = self.cell(offset)
        if len(data) < 76 or data[:2] != b"nk":
            raise CellError(offset, "cell is not a key")
        flags = struct.unpack_from("<H", data, 2)[0]
        last_write = struct.unpack_from("<Q", data, 4)[0]
        subkeys, _volatile, subkey_list = struct.unpack_from("<III", data, 20)
        values, value_list = struct.unpack_from("<II", data, 36)
        name_length = struct.unpack_from("<H", data, 72)[0]
        raw = data[76 : 76 + name_length]
        name = raw.decode("latin-1" if flags & 0x20 else "utf-16le", "replace")
        return Key(offset, name, last_write, flags, subkeys, subkey_list, values, value_list)

    def root(self) -> Key:
        return self.key(self.root_offset)

    def _list(self, offset: int, depth: int, out: list[int], report: Report) -> None:
        try:
            data = self.cell(offset)
        except CellError as error:
            report(error.offset, f"list of subkeys: {error.reason}", 0)
            return
        signature = data[:2]
        count = struct.unpack_from("<H", data, 2)[0] if len(data) >= 4 else 0
        if signature in (b"lf", b"lh"):
            step = 8
        elif signature in (b"li", b"ri"):
            step = 4
        else:
            report(offset, "list of subkeys has a type that is not known", 0)
            return
        if len(data) < 4 + count * step:
            report(offset, "list of subkeys is shorter than its count", 0)
            count = max(0, (len(data) - 4) // step)
        for index in range(count):
            target = struct.unpack_from("<I", data, 4 + index * step)[0]
            if signature == b"ri":
                if depth < 1:
                    self._list(target, depth + 1, out, report)
                else:
                    report(offset, "list of subkeys nested too deep", 0)
                    return
            else:
                out.append(target)
            if len(out) > MAX_SUBKEYS:
                report(offset, "more subkeys than the reader follows", 0)
                return

    def iter_subkeys(self, key: Key, report: Report) -> Iterator[Key]:
        """The subkeys of ``key``. A cell that cannot be read is reported with a lost of one; the subkeys the key
        declares and its list does not give are reported once, with their number."""
        if key.subkey_count == 0:
            return
        offsets: list[int] = []
        self._list(key.subkey_list, 0, offsets, report)
        for offset in offsets:
            self.tick()
            try:
                child = self.key(offset)
            except CellError as error:
                report(error.offset, f"subkey: {error.reason}", 1)
                continue
            yield child
        missing = key.subkey_count - len(offsets)
        if missing > 0:
            report(key.offset, f"key says it has {key.subkey_count} subkeys, its list gives {len(offsets)}", missing)

    def find(self, path: str, report: Report, start: Key | None = None) -> Key | None:
        """The key at ``path`` (names separated by a backslash, compared without case), or None."""
        current = start or self.root()
        for part in (p for p in path.split("\\") if p):
            wanted = part.casefold()
            nxt = None
            for child in self.iter_subkeys(current, report):
                if child.name.casefold() == wanted:
                    nxt = child
                    break
            if nxt is None:
                return None
            current = nxt
        return current

    # -- values --------------------------------------------------------------- #
    def iter_values(self, key: Key, report: Report) -> Iterator[Value]:
        if key.value_count == 0:
            return
        try:
            data = self.cell(key.value_list)
        except CellError as error:
            report(error.offset, f"list of values: {error.reason}", key.value_count)
            return
        count = key.value_count
        if len(data) < count * 4:
            report(key.value_list, "list of values is shorter than the count of the key", count - len(data) // 4)
            count = len(data) // 4
        for index in range(count):
            self.tick()
            offset = struct.unpack_from("<I", data, index * 4)[0]
            try:
                yield self._value(offset)
            except CellError as error:
                report(error.offset, f"value: {error.reason}", 1)

    def _value(self, offset: int) -> Value:
        data = self.cell(offset)
        if len(data) < 20 or data[:2] != b"vk":
            raise CellError(offset, "cell is not a value")
        name_length, size, data_offset, vtype, flags = struct.unpack_from("<HIIIH", data, 2)
        raw = data[20 : 20 + name_length]
        name = raw.decode("latin-1" if flags & 1 else "utf-16le", "replace")
        inline = bool(size & 0x80000000)
        return Value(offset, name, vtype, size & 0x7FFFFFFF, inline, data_offset)

    def data(self, value: Value) -> tuple[bytes, bool]:
        """The data of ``value``, up to ``MAX_DATA`` bytes, and whether the value has more than was returned.
        Raises ``CellError`` when the cells that hold it cannot be read."""
        size = value.size
        if value.inline:
            return struct.pack("<I", value.data_offset)[:size], False
        if size == 0:
            return b"", False
        want = min(size, MAX_DATA)
        head = self.cell(value.data_offset)
        if size > BIG_DATA_BLOCK and head[:2] == b"db":
            blocks, list_offset = struct.unpack_from("<HI", head, 2)
            listing = self.cell(list_offset)
            out = bytearray()
            for index in range(min(blocks, len(listing) // 4)):
                if len(out) >= want:
                    break
                self.tick()
                block = self.cell(struct.unpack_from("<I", listing, index * 4)[0])
                out += block[: min(BIG_DATA_BLOCK, want - len(out))]
            if len(out) < want:
                raise CellError(value.data_offset, "big value has fewer blocks than its size")
            return bytes(out), size > want
        if len(head) < want:
            raise CellError(value.data_offset, "value data is shorter than its size")
        return head[:want], size > want

    # -- the whole hive ------------------------------------------------------- #
    def scan(self, report: Report) -> dict[str, int]:
        """Walk every ``hbin`` and its cells: how many keys and values are in use, whether anything points to
        them or not. A block or cell that does not make sense goes to ``report`` and the walk goes on after it."""
        keys = values = in_use = free = blocks = 0
        end = min(self.file_size, HEADER + self.hbins_size)
        if self.hbins_size > self.file_size - HEADER:
            report(self.file_size - HEADER, "the file ends before the data its header declares", 0)
        position = HEADER
        bad_from = None  # the start of a run of blocks with a bad header: one report for the run
        while position + 32 <= end:
            self.tick()
            size = struct.unpack_from("<I", self._map, position + 8)[0]
            if self._map[position : position + 4] != b"hbin" or size < 4096 or size % 4096:
                bad_from = position if bad_from is None else bad_from
                position += 4096
                continue
            if bad_from is not None:
                report(bad_from - HEADER, "block of cells has a bad header", 0, position - bad_from)
                bad_from = None
            blocks += 1
            block_end = min(position + size, self.file_size)
            if position + size > self.file_size:
                report(position - HEADER, "the last block of cells is cut short", 0)
            at = position + 32
            while at + 8 <= block_end:
                cell = struct.unpack_from("<i", self._map, at)[0]
                length = abs(cell)
                if length < 8 or length % 8 or at + length > block_end:
                    report(at - HEADER, "cell size is not valid, the rest of the block is not read", 0)
                    break
                if cell < 0:
                    in_use += 1
                    kind = bytes(self._map[at + 4 : at + 6])
                    keys += kind == b"nk"
                    values += kind == b"vk"
                else:
                    free += 1
                at += length
            position += size
        if bad_from is not None:
            report(bad_from - HEADER, "block of cells has a bad header", 0, min(position, end) - bad_from)
        return {"blocks": blocks, "cells": in_use, "free": free, "keys": keys, "values": values}


# -- what a value holds --------------------------------------------------------- #
def decode(vtype: int, raw: bytes) -> Any:
    """A value as Python: text for the string types, a number for DWORD and QWORD, a list for a multi-string,
    bytes for anything else (and for a number whose data is too short)."""
    if vtype in (1, 2, 6):
        return raw.decode("utf-16le", "replace").split("\x00")[0]
    if vtype == 7:
        return [part for part in raw.decode("utf-16le", "replace").split("\x00") if part]
    if vtype == 4 and len(raw) >= 4:
        return struct.unpack_from("<I", raw)[0]
    if vtype == 5 and len(raw) >= 4:
        return struct.unpack_from(">I", raw)[0]
    if vtype == 11 and len(raw) >= 8:
        return struct.unpack_from("<Q", raw)[0]
    return raw

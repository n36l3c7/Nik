"""A scanner of the structure of an ``.evtx`` file, independent of the parser library.

The parser (the ``evtx`` crate) says which records it could read; this module
says which records the FILE holds: the file header, the 64 KiB chunks, the
checksums and every record header in each chunk's used area, with its offset.
The difference between the two is what the file lost, and it has to come from
somewhere the parser's own mistakes cannot reach.

The scanner reads one chunk at a time (64 KiB) and hands it out as a
``Chunk``: the memory of a scan is one chunk, whatever the size of the file
(an 8 GB log is 130,000 chunks and a few million records, which are never held
together). The records of a chunk are an index ``id -> (offset, size, flag)``
of at most a few thousand entries.

What it does not do: read BinXML, execute anything, follow offsets outside the
chunk it holds. A hostile file can make it walk garbage, never loop: every
step moves forward by at least four bytes.

Standard library only.
"""

from __future__ import annotations

import struct
import zlib
from collections.abc import Iterator
from dataclasses import dataclass, field

CHUNK = 0x10000
HEADER = 0x1000
CHUNK_HEADER = 512
RECORD_MAGIC = b"\x2a\x2a\x00\x00"
MIN_RECORD = 28  # magic, size, id, time and the trailing copy of the size
FILE_MAGIC = b"ElfFile\x00"
CHUNK_MAGIC = b"ElfChnk\x00"
FLAG_DIRTY = 0x1
FLAG_NO_CRC32 = 0x4  # the log was written without checksums: none of them means anything


@dataclass
class FileHeader:
    size: int
    first_chunk: int
    last_chunk: int
    next_record_id: int
    chunk_count: int
    flags: int
    crc_ok: bool | None  # None: the log keeps no checksums


@dataclass
class Region:
    """A stretch of a chunk's used area that holds no readable record."""

    offset: int  # in the file
    length: int
    kind: str  # "record magic" | "record size"
    record_id: int | None = None


@dataclass
class Chunk:
    number: int  # the slot in the file, from 0
    offset: int
    state: str  # "ok" | "empty" | "bad magic" | "short header"
    available: int = CHUNK  # the bytes of the chunk in the file (less than CHUNK when it is cut off)
    first_no: int = 0
    last_no: int = 0
    first_id: int = 0
    last_id: int = 0
    free_offset: int = 0
    header_crc_ok: bool | None = None
    events_crc_ok: bool | None = None
    free_offset_ok: bool = True
    stale: bool = False  # past the number of chunks the file header counts
    duplicate: bool = False  # stale, and every record in it is one that earlier chunks hold
    records: dict[int, tuple[int, int, bool]] = field(default_factory=dict)  # id -> (offset, size, size copy ok)
    repeated: list[tuple[int, int, int]] = field(default_factory=list)  # (id, offset, size) of ids met twice
    regions: list[Region] = field(default_factory=list)
    slack: list[tuple[int, int, int]] = field(default_factory=list)  # (offset, size, id) left after the used area
    walked: int = 0  # the records of the used area, repeated ones included

    @property
    def cut_short(self) -> bool:
        return self.available < CHUNK


class NotEvtx(ValueError):
    """The file does not start like an event log."""


class Scanner:
    """``Scanner(path)``: ``header`` at once, then ``chunks()`` one by one in file order."""

    def __init__(self, path: str) -> None:
        self.path = path
        self._handle = None
        with open(path, "rb") as handle:
            head = handle.read(128)
            handle.seek(0, 2)
            self.size = handle.tell()
        if len(head) < 128 or head[:8] != FILE_MAGIC:
            raise NotEvtx("The file does not start with the ElfFile signature")
        first, last, next_id, _hsize, _minor, _major, _block, count = struct.unpack_from("<QQQIHHHH", head, 8)
        flags, crc = struct.unpack_from("<II", head, 120)
        self.header = FileHeader(
            size=self.size,
            first_chunk=first,
            last_chunk=last,
            next_record_id=next_id,
            chunk_count=count,
            flags=flags,
            crc_ok=None if flags & FLAG_NO_CRC32 else zlib.crc32(head[:120]) == crc,
        )
        body = max(0, self.size - HEADER)
        self.whole = body // CHUNK
        self.tail = body % CHUNK  # bytes of a last chunk that is cut off (0: none)
        self.slots = self.whole + (1 if self.tail else 0)
        # A file that stops inside its 4 KiB header holds no chunk and is cut short.
        self.cut_header = self.size < HEADER

    def read_chunk(self, number: int) -> Chunk:
        """One chunk again, by its number (the parser does not read them in file order)."""
        if self._handle is None:
            self._handle = open(self.path, "rb")  # noqa: SIM115 - closed by close()
        base = HEADER + number * CHUNK
        self._handle.seek(base)
        return self._chunk(number, base, self._handle.read(CHUNK))

    def close(self) -> None:
        if self._handle is not None:
            self._handle.close()
            self._handle = None

    def chunks(self) -> Iterator[Chunk]:
        with open(self.path, "rb") as handle:
            handle.seek(HEADER)
            for number in range(self.slots):
                base = HEADER + number * CHUNK
                data = handle.read(CHUNK)
                if not data:
                    return
                yield self._chunk(number, base, data)

    # -- one chunk ------------------------------------------------------------ #
    def _chunk(self, number: int, base: int, data: bytes) -> Chunk:
        available = len(data)
        chunk = Chunk(number=number, offset=base, state="ok", available=available)
        chunk.stale = 0 < self.header.chunk_count <= number
        if data[:8] != CHUNK_MAGIC:
            chunk.state = "bad magic" if any(data[:512]) else "empty"
            if chunk.state == "bad magic":
                # Whole records behind a destroyed signature tell a chunk that lost its first bytes from
                # space that never held one.
                self._slack(chunk, data, base, CHUNK_HEADER)
            return chunk
        if available < CHUNK_HEADER:
            chunk.state = "short header"
            return chunk
        no1, no2, id1, id2, _hsize, _last_off, free, events_crc = struct.unpack_from("<QQQQIIII", data, 8)
        flags, header_crc = struct.unpack_from("<II", data, 120)
        chunk.first_no, chunk.last_no, chunk.first_id, chunk.last_id, chunk.free_offset = no1, no2, id1, id2, free
        if not self.header.flags & FLAG_NO_CRC32:
            chunk.header_crc_ok = zlib.crc32(data[:120] + data[128:512]) == header_crc
            if CHUNK_HEADER <= free <= available:
                chunk.events_crc_ok = zlib.crc32(data[CHUNK_HEADER:free]) == events_crc
        chunk.free_offset_ok = CHUNK_HEADER <= free <= CHUNK
        end = min(free, available) if chunk.free_offset_ok else available
        position = self._walk(chunk, data, base, end)
        self._slack(chunk, data, base, max(position, end))
        return chunk

    @staticmethod
    def _walk(chunk: Chunk, data: bytes, base: int, end: int) -> int:
        """The records of the used area, from byte 512 to ``end``. Returns where the walk stopped."""
        position = CHUNK_HEADER
        while position + 24 <= end:
            if data[position : position + 4] != RECORD_MAGIC:
                found = data.find(RECORD_MAGIC, position + 1, end)
                stop = found if found > 0 else end
                chunk.regions.append(Region(base + position, stop - position, "record magic"))
                position = stop
                continue
            size, record_id = struct.unpack_from("<IQ", data, position + 4)
            if size < MIN_RECORD or size > end - position:
                found = data.find(RECORD_MAGIC, position + 4, end)
                stop = found if found >= 0 else end
                chunk.regions.append(Region(base + position, stop - position, "record size", record_id))
                position = stop
                continue
            # The size is repeated in the last four bytes of a record. A record whose copy differs is
            # kept: the walk goes on by the first size, and the parser may read it all the same.
            copy_ok = struct.unpack_from("<I", data, position + size - 4)[0] == size
            chunk.walked += 1
            if record_id in chunk.records:
                chunk.repeated.append((record_id, base + position, size))
            else:
                chunk.records[record_id] = (base + position, size, copy_ok)
            position += size
        return position

    @staticmethod
    def _slack(chunk: Chunk, data: bytes, base: int, start: int) -> None:
        """Records left after the used area (a log that was cleared or has wrapped): only a record
        whose header is whole and whose trailing size copy agrees counts."""
        position = start
        limit = len(data)
        while True:
            found = data.find(RECORD_MAGIC, position, limit)
            if found < 0:
                return
            position = found
            if position + MIN_RECORD <= limit:
                size, record_id = struct.unpack_from("<IQ", data, position + 4)
                if (
                    size >= MIN_RECORD
                    and position + size <= limit
                    and struct.unpack_from("<I", data, position + size - 4)[0] == size
                ):
                    chunk.slack.append((base + position, size, record_id))
                    position += size
                    continue
            position += 4

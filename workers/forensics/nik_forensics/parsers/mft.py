"""The NTFS master file table (``$MFT``): one record for every file and directory of the volume, deleted ones included.

The file is a row of entries of 1024 bytes (the size the first entry says). Nik reads every one itself, with
the standard library only: the structure is small and fixed, and a count that comes from the same code that reads
the entries would say nothing. What the file holds is therefore counted here, slot by slot:

* a slot of zeros is an unused slot: a note, with its number;
* a slot that does not start with ``FILE``, one marked ``BAAD`` by chkdsk, one whose update sequence (fix-up)
  does not match the end of its sectors, and a last slot the file stops in the middle of are skips, with the
  offset and the entry number;
* an entry that belongs to another one (its attributes spill over from a base entry: the base holds the name and
  the times) is a note, with its count; an entry that has neither a name nor a time (reserved and freed entries)
  is a note too;
* an entry whose attributes are damaged after some point is read as far as it goes, and a skip says where it
  stops (``lost`` 0: the entry is in the records).

``ctx.end(in_file=...)`` is the number of slots that are not zeros. The records read, the entries of the notes and
the skips that lost an entry add up to it.

One record per entry, not per file name: a file has a long name and, as a rule, a short 8.3 one, and a hard link has
a second long one. The key is the entry and its sequence number, which is what names a file on the volume, and the
count in the file is a count of entries. The record carries the best long name (Win32, then POSIX, then DOS); the
other names are in ``data.names`` (with their directory when it is not the same).

The path is built from the parents, which are the directories the whole table holds: a first pass reads the
directories (name and parent only) and a second pass reads every entry and gives its record, so that a directory
that comes later in the table than its files is known. A parent that is gone (its entry was reused, so its sequence
number is not the one the name was given under, or is not a directory) gives ``<orphan>\\...``. Paths are made one
level on top of the path of the directory, which is kept for the last directories seen: the work is linear.

``ts`` of a record is the creation time of ``$STANDARD_INFORMATION``. All eight times (four of it and four of
``$FILE_NAME``) are in ``data`` with a tenth of a microsecond, which is what a timestomp shows.
``data.siBeforeFn`` is the stricter timestomp hint: it is a hint to look, never a detection (see ``_hint``).

Hostile files: entries are read one at a time out of a memory map; every offset inside an entry is checked
against the entry; the directory table is bounded (``MAX_DIRS``) and a path is at most ``MAX_DEPTH`` levels.
Nothing is run and nothing is read from outside the file.
"""

from __future__ import annotations

import mmap
import os
import re
import struct
from functools import lru_cache
from typing import Any

from nik_forensics import viewing
from nik_forensics.parsers import BadLocator, ViewError

NAME = "mft"
VERSION = "1"
KIND = "disk"
SOURCES = ("ntfs.mft",)

DEFAULT_SIZE = 1024
SIZES = (512, 1024, 2048, 4096)
SECTOR = 512
ROOT = 5  # the entry of the root directory
MAX_DIRS = 4_000_000  # directories kept for the paths; the ones past it are not parents of anything
MAX_DEPTH = 256  # levels of a path
MAX_ATTRS = 128  # attributes read in one entry
MAX_LISTED = 1000  # skips of one reason said one by one; the rest are said once, with their count
MAX_NAMES = 16  # other names of an entry kept in the record
MAX_STREAMS = 32
MAX_EXTRAS = 1_000_000  # continuation entries kept for the merge
MAX_ZONE = 4096  # characters of a resident Zone.Identifier
MAX_PATHS = 200_000  # directory paths kept
RELEASE = 64 << 20  # bytes of the map read before its pages are given back (the file is never held)
TICKS = 10_000_000  # 100 ns in a second
FILETIME_UNIX = 11_644_473_600  # seconds between 1601 and 1970
MIN_SEC, MAX_SEC = -62_135_596_800, 253_402_300_799  # years 1 and 9999 in Unix seconds

T_SI, T_ATTRLIST, T_FN, T_DATA, T_END = 0x10, 0x20, 0x30, 0x80, 0xFFFFFFFF
FLAG_USE, FLAG_DIR = 1, 2
# Rank of a namespace as the name to show: Win32 and Win32+DOS first, then POSIX, then the DOS short name.
NS_RANK = {1: 0, 3: 0, 0: 1, 2: 3}
NS_NAME = {0: "posix", 1: "win32", 2: "dos", 3: "win32+dos"}
FILE_FLAGS = (
    (0x1, "readonly"),
    (0x2, "hidden"),
    (0x4, "system"),
    (0x20, "archive"),
    (0x40, "device"),
    (0x80, "normal"),
    (0x100, "temporary"),
    (0x200, "sparse"),
    (0x400, "reparse"),
    (0x800, "compressed"),
    (0x1000, "offline"),
    (0x2000, "not indexed"),
    (0x4000, "encrypted"),
)

_NAME_OF_FILE = re.compile(r"^(?:[a-z]_)?\$?mft(?:\.(?:bin|raw|dat|copy|mft))?$|\$mft(?![a-z0-9])", re.IGNORECASE)


# --------------------------------------------------------------------------- #
# Recognising the file                                                        #
# --------------------------------------------------------------------------- #
def _plausible(head: bytes) -> bool:
    """The first entry of a table: ``FILE``, a fix-up array that fits the size the entry says it has."""
    if len(head) < 48 or head[:4] != b"FILE":
        return False
    usa_off, usa_n = struct.unpack_from("<HH", head, 4)
    alloc = struct.unpack_from("<I", head, 28)[0]
    first = struct.unpack_from("<H", head, 20)[0]
    if alloc not in SIZES or usa_n != alloc // SECTOR + 1:
        return False
    return 6 <= usa_off and usa_off + 2 * usa_n <= SECTOR - 2 and usa_off <= first < alloc


def sniff(path: str, name: str, head: bytes) -> str | None:
    if _plausible(head):
        return "ntfs.mft"
    base = (name or "").replace("\\", "/").rsplit("/", 1)[-1]
    return "ntfs.mft" if _NAME_OF_FILE.search(base) else None


# --------------------------------------------------------------------------- #
# One entry                                                                   #
# --------------------------------------------------------------------------- #
def _fixup(raw: bytes) -> bytearray | str:
    """The entry with the end of each sector put back, or why it cannot be: a short sentence."""
    size = len(raw)
    if size < 48:
        return "the entry is shorter than its header"
    usa_off, usa_n = struct.unpack_from("<HH", raw, 4)
    sectors = usa_n - 1
    if sectors < 1 or sectors > size // SECTOR or usa_off < 6 or usa_off + 2 * usa_n > SECTOR - 2:
        return "the update sequence array does not fit the entry"
    check = raw[usa_off : usa_off + 2]
    out = bytearray(raw)
    for index in range(sectors):
        end = (index + 1) * SECTOR
        if raw[end - 2 : end] != check:
            return f"the fix-up of sector {index} does not match"
        out[end - 2 : end] = raw[usa_off + 2 + 2 * index : usa_off + 4 + 2 * index]
    return out


class Entry:
    """What one entry says. ``problem`` is set when its attributes could not be followed to their end."""

    __slots__ = (
        "number", "sequence", "flags", "links", "base", "used", "attrs", "si", "names", "size", "allocated",
        "streams", "zone", "attr_list", "problem", "base_seq", "merged",
    )  # fmt: skip

    def __init__(self) -> None:
        self.attrs: list[tuple[int, str, bool, int, int, int]] = []  # type, name, non-resident, size, flags, offset
        self.si: tuple[int, int, int, int, int, int, int] | None = None  # four times, flags, security id, usn
        self.names: list[tuple[int, int, int, int, int, int, int, str]] = []  # parent, seq, 4 times, ns, name
        self.size: int | None = None
        self.allocated: int | None = None
        self.streams: list[tuple[str, int]] = []
        self.zone: str | None = None
        self.attr_list = False
        self.problem = ""
        self.base = 0
        self.base_seq = 0
        self.merged = 0

    def best(self) -> tuple | None:
        found = None
        for item in self.names:
            if found is None or NS_RANK.get(item[6], 2) < NS_RANK.get(found[6], 2):
                found = item
        return found


def _merge(e: Entry, x: Entry) -> None:
    """What a continuation entry (an extent of the attribute list of ``e``) adds to the base: names, streams, the
    size of the unnamed stream, the Zone.Identifier."""
    e.merged += 1
    for item in x.names:
        if item not in e.names:
            e.names.append(item)
    if e.si is None:
        e.si = x.si
    if e.size is None and x.size is not None:
        e.size, e.allocated = x.size, x.allocated
    known = {s[0] for s in e.streams}
    for stream in x.streams:
        if stream[0] not in known and len(e.streams) < MAX_STREAMS:
            e.streams.append(stream)
    if e.zone is None:
        e.zone = x.zone


def _text_of(data: bytes) -> str:
    if data[:2] == b"\xff\xfe":
        return data[2:].decode("utf-16-le", "replace")
    if data[:3] == b"\xef\xbb\xbf":
        data = data[3:]
    return data.decode("utf-8", "replace")


def _decode(buf: bytes | bytearray, number: int, *, view: bool = False) -> Entry:
    """The entry (fix-up applied). It never raises: a break in the chain of attributes is ``problem``."""
    e = Entry()
    e.number = number
    e.sequence, e.links, first, e.flags, e.used = struct.unpack_from("<HHHHI", buf, 16)
    base = struct.unpack_from("<Q", buf, 32)[0]
    e.base = base & 0xFFFFFFFFFFFF
    e.base_seq = base >> 48
    size = len(buf)
    pos = first
    count = 0
    while True:
        if pos + 8 > size:
            e.problem = f"the attributes run past the entry at byte {pos}"
            break
        kind, length = struct.unpack_from("<II", buf, pos)
        if kind == T_END:
            break
        count += 1
        if count > MAX_ATTRS or length < 24 or length % 8 or pos + length > size:
            e.problem = f"the chain of attributes breaks at byte {pos}"
            break
        nonres, name_len, name_off, aflags = struct.unpack_from("<BBHH", buf, pos + 8)
        aname = ""
        if name_len:
            if name_off + 2 * name_len > length:
                e.problem = f"an attribute name runs past its attribute at byte {pos}"
                break
            aname = bytes(buf[pos + name_off : pos + name_off + 2 * name_len]).decode("utf-16-le", "replace")
        if nonres:
            if length < 64:
                e.problem = f"a non-resident attribute is cut short at byte {pos}"
                break
            start_vcn, _end = struct.unpack_from("<QQ", buf, pos + 16)
            alloc, real = struct.unpack_from("<QQ", buf, pos + 40)
            asize, content = real, None
        else:
            if length < 24:
                e.problem = f"a resident attribute is cut short at byte {pos}"
                break
            asize, coff = struct.unpack_from("<IH", buf, pos + 16)
            if coff + asize > length:
                e.problem = f"the content of an attribute runs past it at byte {pos}"
                break
            start_vcn, alloc = 0, asize
            content = pos + coff
        if view:
            e.attrs.append((kind, aname, bool(nonres), asize, aflags, pos))
        if kind == T_SI and content is not None and asize >= 48:
            c, m, mm, a, fl = struct.unpack_from("<QQQQI", buf, content)
            sec = struct.unpack_from("<I", buf, content + 52)[0] if asize >= 56 else 0
            usn = struct.unpack_from("<Q", buf, content + 64)[0] if asize >= 72 else 0
            if e.si is None:
                e.si = (c, m, mm, a, fl, sec, usn)
        elif kind == T_FN and content is not None and asize >= 66:
            parent = struct.unpack_from("<Q", buf, content)[0]
            c, m, mm, a = struct.unpack_from("<QQQQ", buf, content + 8)
            nlen, ns = struct.unpack_from("<BB", buf, content + 64)
            if 66 + 2 * nlen <= asize:
                text = bytes(buf[content + 66 : content + 66 + 2 * nlen]).decode("utf-16-le", "replace")
                e.names.append((parent & 0xFFFFFFFFFFFF, parent >> 48, c, m, mm, a, ns, text))
        elif kind == T_ATTRLIST:
            e.attr_list = True
        elif kind == T_DATA and start_vcn == 0:
            if not aname:
                if e.size is None:
                    e.size, e.allocated = asize, alloc
            elif len(e.streams) < MAX_STREAMS:
                e.streams.append((aname, asize))
                if content is not None and aname.lower() == "zone.identifier" and e.zone is None:
                    e.zone = _text_of(bytes(buf[content : content + min(asize, 2 * MAX_ZONE)]))[:MAX_ZONE]
        pos += length
    return e


# --------------------------------------------------------------------------- #
# Times                                                                       #
# --------------------------------------------------------------------------- #
def _ms(ticks: int) -> int | None:
    if not ticks:
        return None
    seconds = ticks // TICKS - FILETIME_UNIX
    return ticks // 10_000 - FILETIME_UNIX * 1000 if MIN_SEC <= seconds <= MAX_SEC else None


@lru_cache(maxsize=65_536)
def _second(seconds: int) -> str:
    import time

    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(seconds))


def _iso(ticks: int) -> str | None:
    """ISO 8601 UTC with the 7 digits of a FILETIME (100 ns): the fraction is what shows a timestomp."""
    if not ticks:
        return None
    seconds, fraction = divmod(ticks, TICKS)
    if not MIN_SEC <= seconds - FILETIME_UNIX <= MAX_SEC:
        return None
    return f"{_second(seconds - FILETIME_UNIX)}.{fraction:07d}Z"


def _hint(si: tuple, fn: tuple) -> bool:
    """A reason to look, never a verdict. All four times of ``$STANDARD_INFORMATION`` have no fraction of a second
    (a tool that sets times by the second leaves it so; Windows does not) and its creation is more than a second
    before the creation in ``$FILE_NAME``, which only the system writes. The plain rule (SI before FN) is true of
    a third of the files of a real volume: a file that is copied or moved keeps its creation time."""
    times = si[:4]
    if not all(times) or any(t % TICKS for t in times):
        return False
    return bool(fn[2]) and si[0] < fn[2] - TICKS


# --------------------------------------------------------------------------- #
# Paths                                                                       #
# --------------------------------------------------------------------------- #
class _Dirs:
    """The directories of the table, and the paths they make."""

    def __init__(self) -> None:
        self.table: dict[int, tuple[int, bool, int, int, str]] = {}  # entry: sequence, in use, parent, its seq, name
        self.paths: dict[tuple[int, int], str] = {}
        self.orphans = 0
        self.loops = 0
        self.over = False  # a directory was not kept: the table is full

    def add(self, e: Entry, name: tuple) -> None:
        if len(self.table) >= MAX_DIRS:
            self.over = True
            return
        self.table[e.number] = (e.sequence, bool(e.flags & FLAG_USE), name[0], name[1], name[7])

    def _holds(self, number: int, seq: int) -> tuple | None:
        found = self.table.get(number)
        if found is None:
            return None
        # A directory that was deleted had its sequence number raised by one after the names under it were made.
        if found[0] == seq or (not found[1] and found[0] == (seq + 1) & 0xFFFF):
            return found
        return None

    def of_parent(self, number: int, seq: int) -> str:
        """The path of a file's parent directory: ``""`` for the root, ``<orphan>\\...`` for one that is gone."""
        if number == ROOT:
            return ""
        key = (number, seq)
        if key in self.paths:
            return self.paths[key]
        chain: list[tuple[int, int]] = []
        seen: set[int] = set()
        base: str | None = None  # the path the walk up ends in
        cur_number, cur_seq = number, seq
        while True:
            if cur_number == ROOT:
                base = ""
                break
            cached = self.paths.get((cur_number, cur_seq))
            if cached is not None:
                base = cached
                break
            found = self._holds(cur_number, cur_seq)
            if found is None or cur_number in seen or len(chain) >= MAX_DEPTH:
                if found is not None:
                    self.loops += 1
                base = "<orphan>"
                break
            seen.add(cur_number)
            chain.append((cur_number, cur_seq))
            cur_number, cur_seq = found[2], found[3]
        for number_i, seq_i in reversed(chain):
            name = self.table[number_i][4]
            base = f"{base}\\{name}"
            if len(self.paths) >= MAX_PATHS:
                self.paths.clear()
            self.paths[(number_i, seq_i)] = base
        return base

    def path(self, name: tuple, count: bool = False) -> str:
        parent = self.of_parent(name[0], name[1])
        if count and parent.startswith("<orphan>"):
            self.orphans += 1
        return f"{parent}\\{name[7]}"


# --------------------------------------------------------------------------- #
# Reading the file                                                            #
# --------------------------------------------------------------------------- #
class _Said:
    """Skips of a reason: the first MAX_LISTED one by one, then one that says how many more."""

    def __init__(self, ctx) -> None:
        self.ctx = ctx
        self.count: dict[str, int] = {}
        self.first_extra: dict[str, int] = {}

    def skip(self, reason: str, *, offset: int, length: int, lost: int, detail: str) -> None:
        n = self.count.get(reason, 0) + 1
        self.count[reason] = n
        if n <= MAX_LISTED:
            self.ctx.skip(reason, offset=offset, length=length, lost=lost, detail=detail)
        else:
            self.first_extra.setdefault(reason, offset)
            self.ctx.lost += lost  # said below, with the others

    def finish(self) -> None:
        for reason, n in self.count.items():
            if n > MAX_LISTED:
                more = n - MAX_LISTED
                self.ctx.skip(
                    reason,
                    offset=self.first_extra[reason],
                    lost=0,
                    detail=f"{more} more entries like these are not listed one by one; the first is at this offset",
                )


def _entry_size(first: bytes) -> tuple[int, bool]:
    if len(first) >= 32 and first[:4] == b"FILE":
        alloc = struct.unpack_from("<I", first, 28)[0]
        if alloc in SIZES:
            return alloc, False
    return DEFAULT_SIZE, True


def _release(buf: mmap.mmap, upto: int, done: int) -> int:
    """Give the pages of the map before ``upto`` back to the system, now and then: the file is read in order."""
    start, stop = done - done % mmap.PAGESIZE, upto - upto % mmap.PAGESIZE
    if stop - start < RELEASE or not hasattr(mmap, "MADV_DONTNEED"):
        return done
    try:
        buf.madvise(mmap.MADV_DONTNEED, start, stop - start)
    except (OSError, ValueError):
        return done
    return stop


def _slots(buf: mmap.mmap, size: int):
    """(slot, raw, status, fixed): status ``empty``, ``ok``, or the sentence that says why the slot is damaged."""
    total = len(buf)
    zero = bytes(size)
    released = 0
    for slot in range(total // size):
        if not slot % 4096:
            released = _release(buf, slot * size, released)
        raw = buf[slot * size : (slot + 1) * size]
        if raw == zero:
            yield slot, raw, "empty", None
            continue
        sig = raw[:4]
        if sig == b"BAAD":
            yield slot, raw, "the entry is marked BAAD (chkdsk found it damaged)", None
            continue
        if sig != b"FILE":
            yield slot, raw, "the entry does not start with FILE", None
            continue
        fixed = _fixup(raw)
        if isinstance(fixed, str):
            yield slot, raw, fixed, None
        else:
            yield slot, raw, "ok", fixed


def _data(e: Entry, name: tuple | None, dirs: _Dirs, number_of: int) -> tuple[dict[str, Any], int | None, bool]:
    """The ``data`` of the record, its ``ts`` and whether the path is an orphan's."""
    si = e.si
    data: dict[str, Any] = {
        "entry": number_of,
        "sequence": e.sequence,
        "baseEntry": e.base,
        "inUse": bool(e.flags & FLAG_USE),
        "isDirectory": bool(e.flags & FLAG_DIR),
        "hardLinks": e.links,
    }
    if name is not None:
        data["name"] = name[7]
        data["parentEntry"] = name[0]
        data["parentSequence"] = name[1]
        data["namespace"] = NS_NAME.get(name[6], str(name[6]))
        path = dirs.path(name, count=True)
        data["path"] = path
        data["orphan"] = path.startswith("<orphan>")
        data["fnCreated"], data["fnModified"], data["fnMftModified"], data["fnAccessed"] = (
            _iso(name[2]), _iso(name[3]), _iso(name[4]), _iso(name[5])
        )  # fmt: skip
    else:
        data["path"] = "<unnamed>"
        data["orphan"] = False
    if si is not None:
        data["siCreated"], data["siModified"], data["siMftModified"], data["siAccessed"] = (
            _iso(si[0]), _iso(si[1]), _iso(si[2]), _iso(si[3])
        )  # fmt: skip
        data["attributes"] = [label for bit, label in FILE_FLAGS if si[4] & bit]
        if si[5]:
            data["securityId"] = si[5]
        if si[6]:
            data["usn"] = si[6]
    data["siBeforeFn"] = bool(si is not None and name is not None and _hint(si, name))
    if e.size is not None:
        data["size"] = e.size
        data["allocatedSize"] = e.allocated
    data["ads"] = bool(e.streams)  # a named data stream: an equality filter finds the entries that have one
    if e.streams:
        data["streams"] = [{"name": n, "size": s} for n, s in e.streams]
    if e.zone is not None:
        data["zoneIdentifier"] = e.zone
        match = re.search(r"^ZoneId\s*=\s*(\d+)", e.zone, re.IGNORECASE | re.MULTILINE)
        if match:
            data["zoneId"] = int(match.group(1))
    if e.attr_list:
        data["hasAttributeList"] = True
    if e.merged:
        data["continuationEntries"] = e.merged
    others = []
    for other in e.names:
        if other is name:
            continue
        item: dict[str, Any] = {"name": other[7], "namespace": NS_NAME.get(other[6], str(other[6]))}
        if name is None or other[0] != name[0]:
            item["parentEntry"], item["parentSequence"] = other[0], other[1]
            item["path"] = dirs.path(other)
        others.append(item)
    if others:
        data["names"] = others[:MAX_NAMES]
        if len(others) > MAX_NAMES:
            data["namesLeftOut"] = len(others) - MAX_NAMES
    ts = _ms(si[0]) if si is not None else None
    return data, ts, bool(data["orphan"])


def parse(path: str, ctx, source: str) -> None:
    host = str(ctx.params.get("host") or "")
    ctx.source(NAME, VERSION, KIND, "ntfs.mft", host=host)
    total = os.path.getsize(path)
    if total == 0:
        ctx.skip("the file is empty", lost=0)
        ctx.end(in_file=0)
        return
    said = _Said(ctx)
    with open(path, "rb") as handle, mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as buf:
        size, assumed = _entry_size(buf[: min(total, 64)])
        if assumed:
            ctx.note("entry size assumed to be 1024 bytes", detail="the first entry does not say its size")
        slots = total // size
        tail = total - slots * size

        # Pass 1: the directories and the count. Memory: the directory table and nothing else.
        dirs = _Dirs()
        in_file = empty = extras_kept = extras_over = 0
        extras: dict[int, list[Entry]] = {}
        for slot, _raw, status, fixed in _slots(buf, size):
            if status == "empty":
                empty += 1
                continue
            in_file += 1
            if fixed is None:
                continue
            if struct.unpack_from("<Q", fixed, 32)[0] & 0xFFFFFFFFFFFF:
                # An entry that continues another: what it adds is merged into the base's record in pass 2.
                if extras_kept < MAX_EXTRAS:
                    extra = _decode(fixed, slot)
                    extras.setdefault(extra.base, []).append(extra)
                    extras_kept += 1
                else:
                    extras_over += 1
            elif fixed[22] & FLAG_DIR:
                e = _decode(fixed, slot)
                name = e.best()
                if name is not None:
                    dirs.add(e, name)
        if dirs.over:
            ctx.skip(
                "directories past the limit are not used for paths",
                lost=0,
                detail=f"the table keeps {MAX_DIRS} directories; paths below the others are <orphan>",
            )

        # Pass 2: every entry.
        stats = {"extension": 0, "bare": 0, "no_time": 0, "damaged": 0, "stale": 0}
        for slot, _raw, status, fixed in _slots(buf, size):
            offset = slot * size
            if status == "empty":
                continue
            if fixed is None:
                said.skip("entry cannot be read", offset=offset, length=size, lost=1, detail=f"entry {slot}: {status}")
                continue
            if struct.unpack_from("<Q", fixed, 32)[0] & 0xFFFFFFFFFFFF:
                stats["extension"] += 1
                continue
            e = _decode(fixed, slot)
            if slot in extras:
                for extra in extras.pop(slot):
                    if extra.base_seq == e.sequence:
                        _merge(e, extra)
                    else:
                        stats["stale"] += 1
            name = e.best()
            if name is None and e.si is None:
                stats["bare"] += 1
                continue
            if e.problem:
                stats["damaged"] += 1
                said.skip(
                    "attributes of an entry are damaged",
                    offset=offset,
                    length=size,
                    lost=0,
                    detail=f"entry {slot}: {e.problem}; what came before it is in the record",
                )
            data, ts, _orphan = _data(e, name, dirs, slot)
            if ts is None:
                stats["no_time"] += 1
            where = data["path"]
            ctx.record(
                key=f"mft:{host or '?'}:{slot}:{e.sequence}",
                type="file",
                ts=ts,
                host=host,
                summary=where if data["inUse"] else f"{where} [deleted]",
                data=data,
                loc={"offset": offset, "length": size, "entry": slot},
            )
        unmerged = sum(len(items) for items in extras.values()) + extras_over + stats["stale"]
        if tail:
            if buf[slots * size :].count(0) == tail:
                ctx.note("zeros after the last entry", detail=f"{tail} bytes")
            else:
                in_file += 1
                said.skip(
                    "entry cannot be read",
                    offset=slots * size,
                    length=tail,
                    lost=1,
                    detail="the file stops in the middle of an entry",
                )
    said.finish()
    if empty:
        ctx.note("unused entries (all zeros)", count=empty)
    if stats["extension"]:
        ctx.note(
            "entries that continue another entry",
            count=stats["extension"],
            detail="the names, streams and sizes they add are merged into the record of their base entry",
        )
    if unmerged:
        ctx.note(
            "continuation entries that were not merged",
            count=unmerged,
            detail="their base entry is not in the file, was reused, or the limit of continuation entries was reached",
        )
    if stats["bare"]:
        ctx.note("entries without a name or a time", count=stats["bare"], detail="reserved or freed entries")
    if stats["no_time"]:
        ctx.note("records without a creation time", count=stats["no_time"])
    if dirs.orphans:
        ctx.note(
            "names whose parent directory is gone",
            count=dirs.orphans,
            detail="their path starts with <orphan>: the parent entry was reused or is not in the file",
        )
    if dirs.loops:
        ctx.note("paths cut where directories loop or are deeper than 256", count=dirs.loops)
    ctx.end(in_file=in_file)


# --------------------------------------------------------------------------- #
# Showing an entry                                                            #
# --------------------------------------------------------------------------- #
ATTR_NAMES = {
    0x10: "$STANDARD_INFORMATION",
    0x20: "$ATTRIBUTE_LIST",
    0x30: "$FILE_NAME",
    0x40: "$OBJECT_ID",
    0x50: "$SECURITY_DESCRIPTOR",
    0x60: "$VOLUME_NAME",
    0x70: "$VOLUME_INFORMATION",
    0x80: "$DATA",
    0x90: "$INDEX_ROOT",
    0xA0: "$INDEX_ALLOCATION",
    0xB0: "$BITMAP",
    0xC0: "$REPARSE_POINT",
    0xD0: "$EA_INFORMATION",
    0xE0: "$EA",
    0x100: "$LOGGED_UTILITY_STREAM",
}


def view(path: str, source: str, loc: dict) -> dict:
    offset = viewing.loc_int(loc, "offset")
    length = viewing.loc_int(loc, "length")
    if length < 48 or length > 4 * 4096:
        raise BadLocator("The locator of the entry has no usable length")
    entry = loc.get("entry")
    entry = entry if isinstance(entry, int) and not isinstance(entry, bool) and entry >= 0 else offset // length
    size = os.path.getsize(path)
    if offset >= size:
        raise ViewError(f"The file ends at byte {size}: no entry at byte {offset}")
    with open(path, "rb") as handle:
        handle.seek(offset)
        raw = handle.read(length)
    where = {"offset": offset, "length": len(raw), "entry": entry}
    if len(raw) < length or raw[:4] != b"FILE":
        return {
            "kind": "text",
            "title": f"Entry {entry} at byte {offset}: not a readable entry, shown as the bytes of the file",
            "where": where,
            "text": viewing.hex_dump(raw, offset),
        }
    fixed = _fixup(raw)
    note = ""
    if isinstance(fixed, str):
        note = f"The fix-up is not applied: {fixed}."
        fixed = bytearray(raw)
    e = _decode(fixed, entry, view=True)
    lines = [
        f"Entry {entry}, sequence {e.sequence}, {'in use' if e.flags & FLAG_USE else 'deleted'}, "
        f"{'directory' if e.flags & FLAG_DIR else 'file'}, {e.links} hard link(s), "
        f"base entry {e.base or 'none'}, {e.used} of {length} bytes used",
    ]
    if note:
        lines.append(note)
    for kind, name, nonres, asize, aflags, pos in e.attrs:
        label = ATTR_NAMES.get(kind, f"type 0x{kind:x}")
        lines.append(
            f"  at byte {pos}: {label}{' ' + name if name else ''}, "
            f"{'non-resident' if nonres else 'resident'}, {asize} bytes, flags 0x{aflags:x}"
        )
    if e.si:
        for label, ticks in zip(("created", "modified", "MFT modified", "accessed"), e.si[:4], strict=True):
            lines.append(f"  $STANDARD_INFORMATION {label}: {_iso(ticks)}")
        lines.append(f"  $STANDARD_INFORMATION flags 0x{e.si[4]:x}, security id {e.si[5]}, USN {e.si[6]}")
    for n in e.names:
        lines.append(
            f"  $FILE_NAME {NS_NAME.get(n[6], n[6])}: {n[7]!r}, parent {n[0]} (sequence {n[1]}), "
            f"created {_iso(n[2])}, modified {_iso(n[3])}, MFT modified {_iso(n[4])}, accessed {_iso(n[5])}"
        )
    if e.size is not None:
        lines.append(f"  $DATA: {e.size} bytes, {e.allocated} allocated")
    for sname, ssize in e.streams:
        lines.append(f"  $DATA stream {sname!r}: {ssize} bytes")
    if e.zone is not None:
        lines.append("  Zone.Identifier: " + e.zone.replace("\r", "").replace("\n", " | "))
    if e.problem:
        lines.append(f"  The attributes are damaged: {e.problem}")
    text = "\n".join(lines) + f"\n\nBytes {offset}..{offset + len(raw)} of the file (as stored, before the fix-up):\n"
    return {
        "kind": "text",
        "title": f"Entry {entry} at byte {offset}",
        "where": where,
        "text": text + viewing.hex_dump(raw, offset),
    }

"""The NTFS change journal (``$UsnJrnl:$J``): what happened to each file, in order, as the volume saw it.

A journal is a stream of records (USN_RECORD_V2 and V3; V4 holds ranges of a file that changed, not names) one
after the other, each a multiple of 8 bytes long, with a sparse start: the stream begins at the oldest USN that is
still kept, and what came before it is zeros (a collected file keeps them, and can be many GB). The records are
read here, out of a memory map, with the standard library only; the scan is its own count.

* a run of zeros of 4096 bytes or more (the sparse start, an area the volume freed) and the shorter ones that pad a
  page are notes with their number of bytes, not skips: nothing was there;
* a V4 record (a range of a file, no name) is counted and noted with its number: its content is not decoded;
* a record whose length or version is wrong, whose name does not fit it or whose time is not one, is a skip with its
  offset and the length of the stretch that is passed over: the reader goes on at the next place where a record
  could start (8-byte steps, found without a loop in Python), and the skip says where;
* a last record that the file stops in the middle of is a skip too.

``ctx.end(in_file=...)`` is the number of records found: those read, the V4 ones, and one for each stretch the
scan had to pass over (a damaged stretch holds at least one).

Key: ``usn:<host>:<usn>``. A USN names a record of one volume's journal (it is its place in the stream), so the
same record read from another copy of the journal has the same key. When the same USN comes twice in one file
(a carved or tampered file) the second gets ``:o<offset>`` and a note counts them. ``ts`` is the time of the
record; ``data`` has the reasons by name, the attributes by name, the file and its parent as entry and sequence.

Hostile files: a header must pass the checks of length, version and name before a record is made of it; the
journal is never loaded (a memory map, and records are made one at a time); nothing is run.
"""

from __future__ import annotations

import mmap
import os
import re
import struct
import time
from functools import lru_cache
from typing import Any

from nik_forensics import viewing
from nik_forensics.parsers import BadLocator, ViewError

NAME = "usnjrnl"
VERSION = "1"
KIND = "disk"
SOURCES = ("ntfs.usnjrnl",)

ZERO_REPORT = 4096  # a run of zeros this long is a note of its own
MAX_RECLEN = 0x10000  # 64 KiB: a name of 255 characters makes a record of less than 600 bytes
MIN_RECLEN = 60
MAX_SEEN = 5_000_000  # USNs remembered to find a repeated one
SNIFF_LOOK = 4 << 30  # bytes of the start of a file that are looked through for a first record
MAX_LISTED = 1000
FILETIME_UNIX = 11_644_473_600
MIN_SEC, MAX_SEC = -62_135_596_800, 253_402_300_799
SANE_FROM, SANE_TO = 631_152_000, 7_258_118_400  # 1990 and 2200, Unix seconds: for a record found by resync

NONZERO = re.compile(rb"[^\x00]")
CHUNK = 1 << 20  # zeros are compared a megabyte at a time
PROBE = 4096  # the next record is almost always near: look there with the regular expression first
RELEASE = 64 << 20  # bytes of the map read before its pages are given back (the file is never held)
# Where a record can start after damage: major version 2, 3 or 4 and minor version 0, 4 bytes after the length.
VERSION_AT = re.compile(rb"[\x02-\x04]\x00\x00\x00")

REASONS = {
    0x1: "DATA_OVERWRITE",
    0x2: "DATA_EXTEND",
    0x4: "DATA_TRUNCATION",
    0x10: "NAMED_DATA_OVERWRITE",
    0x20: "NAMED_DATA_EXTEND",
    0x40: "NAMED_DATA_TRUNCATION",
    0x100: "FILE_CREATE",
    0x200: "FILE_DELETE",
    0x400: "EA_CHANGE",
    0x800: "SECURITY_CHANGE",
    0x1000: "RENAME_OLD_NAME",
    0x2000: "RENAME_NEW_NAME",
    0x4000: "INDEXABLE_CHANGE",
    0x8000: "BASIC_INFO_CHANGE",
    0x10000: "HARD_LINK_CHANGE",
    0x20000: "COMPRESSION_CHANGE",
    0x40000: "ENCRYPTION_CHANGE",
    0x80000: "OBJECT_ID_CHANGE",
    0x100000: "REPARSE_POINT_CHANGE",
    0x200000: "STREAM_CHANGE",
    0x400000: "TRANSACTED_CHANGE",
    0x800000: "INTEGRITY_CHANGE",
    0x80000000: "CLOSE",
}
SOURCE_INFO = {
    0x1: "DATA_MANAGEMENT",
    0x2: "AUXILIARY_DATA",
    0x4: "REPLICATION_MANAGEMENT",
    0x8: "CLIENT_REPLICATION_MANAGEMENT",
}
FILE_ATTRIBUTES = {
    0x1: "READONLY",
    0x2: "HIDDEN",
    0x4: "SYSTEM",
    0x10: "DIRECTORY",
    0x20: "ARCHIVE",
    0x40: "DEVICE",
    0x80: "NORMAL",
    0x100: "TEMPORARY",
    0x200: "SPARSE_FILE",
    0x400: "REPARSE_POINT",
    0x800: "COMPRESSED",
    0x1000: "OFFLINE",
    0x2000: "NOT_CONTENT_INDEXED",
    0x4000: "ENCRYPTED",
    0x8000: "INTEGRITY_STREAM",
    0x20000: "NO_SCRUB_DATA",
}

_NAME_OF_FILE = re.compile(
    r"^\$j(?:\.[a-z0-9]+)?$|usnjrnl(?:%3a|[^a-z0-9])*\$?j(?:\.[a-z0-9]+)?$|^\$extend.*\$j(?:\.[a-z0-9]+)?$",
    re.IGNORECASE,
)


# --------------------------------------------------------------------------- #
# One record                                                                  #
# --------------------------------------------------------------------------- #
def _names_of(value: int, table: dict[int, str]) -> list[str]:
    return [label for bit, label in table.items() if value & bit]


def _header(buf, pos: int, end: int) -> tuple[int, int] | str | None:
    """``(major, length)`` of the record at ``pos`` when the header is one that can be read; the string
    ``"short"`` when it is a header but the file stops before the record does; None when it is not one."""
    if pos + 8 > end:
        return None
    length, major, minor = struct.unpack_from("<IHH", buf, pos)
    if length % 8 or length < MIN_RECLEN or length > MAX_RECLEN or major not in (2, 3, 4) or minor != 0:
        return None
    if pos + length > end:
        return "short"
    return major, length


def _decode(buf, pos: int, major: int, length: int) -> dict[str, Any] | None:
    """The record, or None when its fields do not fit it (a name outside the record, an odd length of name)."""
    if major == 2:
        fref, par, usn, ticks, reason, source, security, attrs, nlen, noff = struct.unpack_from(
            "<QQQQIIIIHH", buf, pos + 8
        )
        fhi = phi = 0
    elif major == 3:
        fref, fhi, par, phi, usn, ticks, reason, source, security, attrs, nlen, noff = struct.unpack_from(
            "<QQQQQQIIIIHH", buf, pos + 8
        )
    else:
        return None
    floor = 60 if major == 2 else 76
    if noff < floor or nlen % 2 or noff + nlen > length:
        return None
    name = bytes(buf[pos + noff : pos + noff + nlen]).decode("utf-16-le", "replace")
    rec: dict[str, Any] = {
        "version": major,
        "usn": usn,
        "ticks": ticks,
        "fileEntry": fref & 0xFFFFFFFFFFFF,
        "fileSequence": fref >> 48,
        "parentEntry": par & 0xFFFFFFFFFFFF,
        "parentSequence": par >> 48,
        "name": name,
        "reasonFlags": reason,
        "sourceFlags": source,
        "securityId": security,
        "attributeFlags": attrs,
    }
    if fhi or phi:  # a 128-bit identifier (ReFS): the entry and sequence above are only its low 64 bits
        rec["fileId128"] = f"{fhi:016x}{fref:016x}"
        rec["parentId128"] = f"{phi:016x}{par:016x}"
    return rec


@lru_cache(maxsize=65_536)
def _second(seconds: int) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(seconds))


def _time(ticks: int) -> tuple[int | None, str | None]:
    """(epoch milliseconds, ISO text with 7 digits) of a FILETIME; None for 0 or a date outside years 1 to 9999."""
    if not ticks:
        return None, None
    seconds = ticks // 10_000_000 - FILETIME_UNIX
    if not MIN_SEC <= seconds <= MAX_SEC:
        return None, None
    return ticks // 10_000 - FILETIME_UNIX * 1000, f"{_second(seconds)}.{ticks % 10_000_000:07d}Z"


def _sane(ticks: int) -> bool:
    return SANE_FROM <= ticks // 10_000_000 - FILETIME_UNIX <= SANE_TO


# --------------------------------------------------------------------------- #
# Recognising the file                                                        #
# --------------------------------------------------------------------------- #
def _first_nonzero(buf, pos: int, end: int) -> int | None:
    """The place of the first byte from ``pos`` that is not zero (before ``end``). A sparse start can be many GB:
    it is compared a megabyte at a time, in C."""
    zero = bytes(CHUNK)
    released = pos
    while pos < end:
        stop = min(pos + CHUNK, end)
        released = _release(buf, pos, released)
        piece = buf[pos:stop]
        if piece != (zero if stop - pos == CHUNK else bytes(stop - pos)):
            return pos + NONZERO.search(piece).start()  # type: ignore[union-attr]
        pos = stop
    return None


def _next_nonzero(buf, pos: int, end: int) -> int | None:
    stop = min(pos + PROBE, end)
    match = NONZERO.search(buf, pos, stop)
    return match.start() if match else _first_nonzero(buf, stop, end)


def _release(buf, upto: int, done: int) -> int:
    """Give the pages of the map before ``upto`` back to the system, now and then: the file is read once, in order."""
    start, stop = done - done % mmap.PAGESIZE, upto - upto % mmap.PAGESIZE
    if stop - start < RELEASE or not hasattr(mmap, "MADV_DONTNEED"):
        return done
    try:
        buf.madvise(mmap.MADV_DONTNEED, start, stop - start)
    except (OSError, ValueError):
        return done
    return stop


def _first_record(buf, end: int) -> bool:
    """A journal: the first thing after the zeros is a record, and the next one is too (or the file ends)."""
    first = _first_nonzero(buf, 0, end)
    if first is None:
        return False
    pos = first & ~7
    head = _header(buf, pos, len(buf))
    if not isinstance(head, tuple) or head[0] == 4:
        return False
    record = _decode(buf, pos, *head)
    if record is None or not _sane(record["ticks"]):
        return False
    after = pos + head[1]
    if after + 8 > len(buf):
        return True
    nxt = _header(buf, after, len(buf))
    if not isinstance(nxt, tuple):
        return False
    return nxt[0] == 4 or (_decode(buf, after, *nxt) is not None)


def sniff(path: str, name: str, head: bytes) -> str | None:
    """By content: the first thing after the sparse start is a plausible record (bounded: ``SNIFF_LOOK`` bytes
    are looked through). By name: ``$J`` and the names the collectors give it."""
    try:
        size = os.path.getsize(path)
        if size >= MIN_RECLEN:
            with open(path, "rb") as handle, mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as buf:
                if _first_record(buf, min(size, SNIFF_LOOK)):
                    return "ntfs.usnjrnl"
    except (OSError, ValueError):
        pass
    base = (name or "").replace("\\", "/").rsplit("/", 1)[-1]
    return "ntfs.usnjrnl" if _NAME_OF_FILE.search(base) else None


# --------------------------------------------------------------------------- #
# Reading the file                                                            #
# --------------------------------------------------------------------------- #
def _resync(buf, pos: int, end: int) -> int:
    """The next place after ``pos`` where a record can start (8-byte steps), or ``end``. A candidate is a header
    that passes the checks, whose fields fit, and whose time is a time of this century."""
    at = pos + 1
    while at < end:
        match = VERSION_AT.search(buf, at + 4, end)
        if match is None:
            return end
        cand = match.start() - 4
        at = match.start() - 3  # the next search starts after this candidate whatever it is
        if cand < pos + 8 or cand % 8:
            continue
        head = _header(buf, cand, end)
        if isinstance(head, tuple) and head[0] != 4:
            record = _decode(buf, cand, *head)
            if record is not None and _sane(record["ticks"]):
                return cand
    return end


def _unreadable(ctx, listed: dict, offset: int, length: int, why: str) -> None:
    n = listed["n"] = listed.get("n", 0) + 1
    if n <= MAX_LISTED:
        ctx.skip("record cannot be read", offset=offset, length=length, lost=0, detail=why)
    else:
        listed.setdefault("first", offset)
        listed["bytes"] = listed.get("bytes", 0) + length


def parse(path: str, ctx, source: str) -> None:
    host = str(ctx.params.get("host") or "")
    ctx.source(NAME, VERSION, KIND, "ntfs.usnjrnl", host=host)
    size = os.path.getsize(path)
    if size == 0:
        ctx.skip("the file is empty", lost=0)
        ctx.end(in_file=0)
        return
    found = v4 = 0
    zero_runs = zero_bytes = pad_runs = pad_bytes = 0
    first_zero = None
    no_time = 0
    repeated = 0
    over_seen = False
    seen: set[int] = set()
    listed: dict[str, int] = {}
    with open(path, "rb") as handle, mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as buf:
        pos = released = 0
        while pos < size:
            found_at = _next_nonzero(buf, pos, size)
            if found_at is None:
                run = size - pos
                if run >= ZERO_REPORT:
                    zero_runs += 1
                    zero_bytes += run
                    first_zero = pos if first_zero is None else first_zero
                else:
                    pad_runs += 1
                    pad_bytes += run
                break
            start = found_at & ~7
            if start > pos:
                run = start - pos
                if run >= ZERO_REPORT:
                    zero_runs += 1
                    zero_bytes += run
                    first_zero = pos if first_zero is None else first_zero
                else:
                    pad_runs += 1
                    pad_bytes += run
            pos = start
            released = _release(buf, pos, released)
            head = _header(buf, pos, size)
            if head == "short":
                length = struct.unpack_from("<I", buf, pos)[0]
                found += 1
                ctx.skip(
                    "record cannot be read",
                    offset=pos,
                    length=size - pos,
                    lost=1,
                    detail=f"the file stops in the middle of a record of {length} bytes",
                )
                break
            if isinstance(head, tuple) and head[0] == 4:
                v4 += 1
                found += 1
                pos += head[1]
                continue
            record = _decode(buf, pos, *head) if isinstance(head, tuple) else None
            if record is None:
                why = (
                    "the length or the version of the record is wrong"
                    if head is None
                    else "the name does not fit the record"
                )
                end = _resync(buf, pos, size)
                found += 1
                _unreadable(
                    ctx,
                    listed,
                    pos,
                    end - pos,
                    f"{why}; the next record that can be read starts at byte {end}"
                    if end < size
                    else f"{why}; no record that can be read follows",
                )
                pos = end
                continue
            found += 1
            length = head[1]
            ms, iso = _time(record.pop("ticks"))
            if ms is None:
                no_time += 1
            usn = record["usn"]
            key = f"usn:{host or '?'}:{usn}"
            if usn in seen:
                repeated += 1
                key += f":o{pos}"
            elif len(seen) < MAX_SEEN:
                seen.add(usn)
            elif not over_seen:
                over_seen = True
            data = {k: v for k, v in record.items() if k not in ("reasonFlags", "sourceFlags", "attributeFlags")}
            data["time"] = iso
            data["reasons"] = _names_of(record["reasonFlags"], REASONS)
            data["reasonFlags"] = record["reasonFlags"]
            data["attributes"] = _names_of(record["attributeFlags"], FILE_ATTRIBUTES)
            data["sourceInfo"] = _names_of(record["sourceFlags"], SOURCE_INFO)
            ctx.record(
                key=key,
                type="usn",
                ts=ms,
                host=host,
                summary=f"{record['name']}: {', '.join(data['reasons']) or 'no reason'}",
                data=data,
                loc={"offset": pos, "length": length, "usn": usn},
            )
            pos += length
    if listed.get("n", 0) > MAX_LISTED:
        ctx.skip(
            "record cannot be read",
            offset=listed["first"],
            lost=0,
            detail=f"{listed['n'] - MAX_LISTED} more stretches like these ({listed['bytes']} bytes) are not listed "
            "one by one; the first is at this offset",
        )
    if zero_runs:
        ctx.note(
            "zeros of the sparse start or freed areas",
            count=zero_runs,
            detail=f"{zero_bytes} bytes in runs of {ZERO_REPORT} or more, the first at byte {first_zero}",
        )
    if pad_runs:
        ctx.note("zeros that pad pages between records", count=pad_runs, detail=f"{pad_bytes} bytes")
    if v4:
        ctx.note(
            "USN_RECORD_V4 records (ranges of a file that changed)",
            count=v4,
            detail="counted, not decoded: they hold no name",
        )
    if no_time:
        ctx.note("records without a valid time", count=no_time)
    if repeated:
        ctx.note(
            "records whose USN was already seen in the file",
            count=repeated,
            detail="the key of the later one ends in :o<offset>",
        )
    if over_seen:
        ctx.note(
            "repeated USNs are not looked for past the first 5000000 records",
            detail="a USN repeated after that has the same key as the first",
        )
    ctx.end(in_file=found)


# --------------------------------------------------------------------------- #
# Showing a record                                                            #
# --------------------------------------------------------------------------- #
def view(path: str, source: str, loc: dict) -> dict:
    offset = viewing.loc_int(loc, "offset")
    length = viewing.loc_int(loc, "length")
    if length < 8 or length > MAX_RECLEN:
        raise BadLocator("The locator of the record has no usable length")
    size = os.path.getsize(path)
    if offset >= size:
        raise ViewError(f"The file ends at byte {size}: no record at byte {offset}")
    with open(path, "rb") as handle:
        handle.seek(offset)
        raw = handle.read(length)
    where = {"offset": offset, "length": len(raw)}
    head = _header(raw, 0, len(raw))
    record = _decode(raw, 0, *head) if isinstance(head, tuple) and head[0] != 4 else None
    if record is None:
        return {
            "kind": "text",
            "title": f"Record at byte {offset}: not a readable record, shown as the bytes of the file",
            "where": where,
            "text": viewing.hex_dump(raw, offset),
        }
    ms, iso = _time(record["ticks"])
    lines = [
        f"USN {record['usn']} (version {record['version']}) at byte {offset}, {length} bytes",
        f"  time: {iso}",
        f"  name: {record['name']!r}",
        f"  file: entry {record['fileEntry']}, sequence {record['fileSequence']}",
        f"  parent: entry {record['parentEntry']}, sequence {record['parentSequence']}",
        f"  reasons: 0x{record['reasonFlags']:x} {', '.join(_names_of(record['reasonFlags'], REASONS))}",
        f"  attributes: 0x{record['attributeFlags']:x} "
        + ", ".join(_names_of(record["attributeFlags"], FILE_ATTRIBUTES)),
        f"  source info: 0x{record['sourceFlags']:x} {', '.join(_names_of(record['sourceFlags'], SOURCE_INFO))}",
        f"  security id: {record['securityId']}",
    ]
    return {
        "kind": "text",
        "title": f"USN record {record['usn']} at byte {offset}",
        "where": where,
        "text": "\n".join(lines) + "\n\nBytes of the record:\n" + viewing.hex_dump(raw, offset),
    }

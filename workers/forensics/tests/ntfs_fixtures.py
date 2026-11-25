"""Generators of NTFS files for the tests of the ``mft`` and ``usnjrnl`` parsers: harmless bytes, made here.

``make_mft`` builds a master file table whose entries have fix-ups (the end of each sector replaced by the
update sequence number, as on a volume), attributes in the order of a real entry and the damage a real table has;
it also returns what the parser has to say of it. ``make_usn`` builds a journal with a sparse start.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

ENTRY = 1024
UNIX_TO_FT = 116_444_736_000_000_000  # 100 ns between 1601 and 1970


def ft(unix_s: int, frac: int = 0) -> int:
    """A FILETIME of ``unix_s`` seconds after 1970 and ``frac`` hundreds of nanoseconds."""
    return UNIX_TO_FT + unix_s * 10_000_000 + frac


def u16(text: str) -> bytes:
    return text.encode("utf-16-le")


# --------------------------------------------------------------------------- #
# $MFT                                                                         #
# --------------------------------------------------------------------------- #
def resident(kind: int, content: bytes, name: str = "", aid: int = 0) -> bytes:
    nb = u16(name)
    name_off = 24 if nb else 0
    content_off = (24 + len(nb) + 7) & ~7
    total = (content_off + len(content) + 7) & ~7
    head = struct.pack("<IIBBHHH", kind, total, 0, len(name), name_off, 0, aid)
    head += struct.pack("<IHBB", len(content), content_off, 0, 0)
    body = head + nb
    body = body.ljust(content_off, b"\0") + content
    return body.ljust(total, b"\0")


def nonresident(kind: int, real: int, alloc: int, name: str = "", aid: int = 0, start_vcn: int = 0) -> bytes:
    nb = u16(name)
    name_off = 64 if nb else 0
    total = (64 + len(nb) + 8 + 7) & ~7  # a run list of one byte of zero at the end
    head = struct.pack("<IIBBHHH", kind, total, 1, len(name), name_off, 0, aid)
    head += struct.pack("<QQHHI", start_vcn, 0, 64 + len(nb), 0, 0)
    head += struct.pack("<QQQ", alloc, real, real)
    return (head + nb).ljust(total, b"\0")


def si_content(c: int, m: int, mm: int, a: int, flags: int = 0x20, sec: int = 0x101, usn: int = 0) -> bytes:
    body = struct.pack("<QQQQIIIIIIQQ", c, m, mm, a, flags, 0, 0, 0, 0, sec, 0, usn)
    return body[:72]


def fn_content(parent: int, pseq: int, name: str, ns: int, c: int, m: int, mm: int, a: int, real: int = 0) -> bytes:
    body = struct.pack("<QQQQQQQIIBB", parent | (pseq << 48), c, m, mm, a, real, real, 0x20, 0, len(name), ns)
    return body + u16(name)


@dataclass
class Spec:
    """One entry to build. ``names`` are ``(parent, parent_seq, name, namespace)``."""

    number: int
    seq: int = 1
    in_use: bool = True
    directory: bool = False
    names: list[tuple[int, int, str, int]] = field(default_factory=list)
    si: tuple[int, int, int, int] | None = None  # four FILETIMEs
    fn_times: tuple[int, int, int, int] | None = None  # four FILETIMEs; the times of every $FILE_NAME
    size: int | None = None  # unnamed $DATA; small ones are resident
    streams: list[tuple[str, bytes, int | None]] = field(default_factory=list)  # name, resident content, or size
    base: int = 0
    base_seq: int = 1  # the sequence of the base entry the reference names
    base_seq: int = 1  # the sequence of the base entry the reference names
    attr_list: bool = False
    raw_attrs: bytes | None = None  # replaces the attributes (to break them)


def build_entry(spec: Spec, size: int = ENTRY) -> bytes:
    attrs = b""
    if spec.raw_attrs is not None:
        attrs = spec.raw_attrs
    else:
        if spec.si:
            attrs += resident(0x10, si_content(*spec.si, usn=spec.number * 100), aid=0)
        if spec.attr_list:
            attrs += resident(0x20, b"\0" * 32, aid=1)
        times = spec.fn_times or spec.si or (0, 0, 0, 0)
        for parent, pseq, name, ns in spec.names:
            attrs += resident(0x30, fn_content(parent, pseq, name, ns, *times, real=spec.size or 0), aid=2)
        if spec.size is not None:
            if spec.size <= 400:
                attrs += resident(0x80, b"x" * spec.size, aid=3)
            else:
                attrs += nonresident(0x80, spec.size, (spec.size + 4095) & ~4095, aid=3)
        for name, content, real in spec.streams:
            if real is None:
                attrs += resident(0x80, content, name, aid=4)
            else:
                attrs += nonresident(0x80, real, (real + 4095) & ~4095, name, aid=4)
        if spec.directory:
            attrs += resident(0x90, b"\0" * 16, "$I30", aid=5)
    attrs += struct.pack("<II", 0xFFFFFFFF, 0)
    sectors = size // 512
    usa_off = 0x30
    first = (usa_off + 2 * (sectors + 1) + 7) & ~7
    used = first + len(attrs)
    assert used <= size, "the entry does not fit"
    flags = (1 if spec.in_use else 0) | (2 if spec.directory else 0)
    head = b"FILE" + struct.pack(
        "<HHQHHHHIIQHH",
        usa_off,
        sectors + 1,
        0,
        spec.seq,
        1,
        first,
        flags,
        used,
        size,
        spec.base | (spec.base_seq << 48 if spec.base else 0),
        0,
        0,
    )
    head += struct.pack("<I", spec.number)
    raw = bytearray(head.ljust(first, b"\0") + attrs)
    raw = raw.ljust(size, b"\0")
    return bytes(_apply_fixup(raw, 0xBEEF))


def _apply_fixup(raw: bytearray, usn: int) -> bytearray:
    sectors = len(raw) // 512
    struct.pack_into("<H", raw, 0x30, usn)
    for i in range(sectors):
        end = (i + 1) * 512
        raw[0x30 + 2 + 2 * i : 0x30 + 4 + 2 * i] = raw[end - 2 : end]
        struct.pack_into("<H", raw, end - 2, usn)
    return raw


@dataclass
class MftFixture:
    data: bytes
    host_slots: dict[str, int]  # what the tests look for, by a name
    expect: dict[str, int]


def make_mft() -> MftFixture:
    """A table of 64 slots with every kind of entry, and what the parser has to say of it."""
    t1 = ft(1_700_000_000, 1234567)  # the same second with a fraction
    t2 = ft(1_710_000_000, 7654321)
    t_old = ft(1_262_304_000)  # 2010-01-01, whole seconds
    slots: dict[int, bytes] = {}
    named: dict[str, int] = {}

    def put(spec: Spec, label: str = "") -> None:
        slots[spec.number] = build_entry(spec)
        if label:
            named[label] = spec.number

    live = (t1, t1, t1, t1)
    put(Spec(0, names=[(5, 5, "$MFT", 3)], si=live, size=ENTRY * 64), "mft")
    put(Spec(5, directory=True, names=[(5, 5, ".", 1)], si=live), "root")
    for n in range(6, 12):  # reserved entries with no attributes at all
        slots[n] = build_entry(Spec(n, in_use=False, raw_attrs=b""))
    put(Spec(30, names=[(40, 1, "report.docx", 1)], si=(t1, t2, t2, t2), size=123_456), "late_dir")  # its dir is later
    put(Spec(31, directory=True, names=[(5, 5, "Users", 1)], si=live), "users")
    put(Spec(32, directory=True, names=[(31, 1, "bob", 1)], si=live), "bob")
    put(
        Spec(
            33,
            names=[(32, 1, "setup.exe", 1), (32, 1, "SETUP~1.EXE", 2)],
            si=(t1, t2, t2, t2),
            size=5_000_000,
            streams=[
                ("Zone.Identifier", b"[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://example.test/setup.exe\r\n", None),
                ("hidden", b"", 777),
            ],
        ),
        "ads",
    )
    put(Spec(34, names=[(32, 1, "notes.txt", 1)], si=(t1, t1, t1, t1), size=12), "small")
    put(Spec(35, seq=3, in_use=False, names=[(32, 1, "deleted.txt", 1)], si=(t1, t1, t1, t1), size=900), "deleted")
    put(Spec(36, seq=4, in_use=False, directory=True, names=[(32, 1, "old", 1)], si=live), "deleted_dir")
    put(Spec(37, names=[(36, 3, "inside.txt", 1)], si=live, size=5), "in_deleted_dir")  # parent seq 3, dir now at 4
    put(Spec(38, names=[(900, 1, "lost.bin", 1)], si=live, size=70), "orphan")  # no entry 900
    put(Spec(39, names=[(32, 7, "stale.txt", 1)], si=live, size=3), "stale")  # entry 32 has sequence 1: reused
    put(Spec(40, directory=True, names=[(32, 1, "Documents", 1)], si=live), "late_dir_dir")
    put(Spec(41, names=[(32, 1, "orig.txt", 1), (40, 1, "link.txt", 1)], si=live, size=1), "hardlink")
    put(
        Spec(42, names=[(32, 1, "stomped.dll", 1)], si=(t_old, t_old, t_old, t_old), fn_times=(t1, t1, t1, t1), size=9),
        "stomped",
    )
    put(
        Spec(
            43,
            names=[(32, 1, "copied.dll", 1)],
            si=(t_old, t_old, t_old, t_old),
            fn_times=(t_old, t_old, t_old, t_old),
            size=9,
        ),
        "same_whole",
    )
    put(
        Spec(
            44,
            names=[(32, 1, "fraction.dll", 1)],
            si=(ft(1_262_304_000, 5), t_old, t_old, t_old),
            fn_times=(t1, t1, t1, t1),
            size=9,
        ),
        "fraction",
    )
    put(Spec(45, base=33, in_use=True, raw_attrs=resident(0x80, b"yy", "extra", aid=9)), "extension")
    # More continuation entries: a file name that the base does not hold, and one whose base was reused (sequence 9)
    second = fn_content(40, 1, "second_name.txt", 1, t1, t1, t1, t1)
    put(Spec(49, base=34, raw_attrs=resident(0x30, second, aid=7)), "extension_name")
    put(Spec(54, base=34, base_seq=9, raw_attrs=resident(0x80, b"zz", "stale", aid=8)), "extension_stale")
    put(Spec(46, names=[(32, 1, "no_creation.txt", 1)], si=(0, t1, t1, t1), size=4), "no_time")
    put(Spec(47, names=[(32, 1, "wide é中.txt", 1)], si=live, size=2), "unicode")
    broken = resident(0x10, si_content(t1, t1, t1, t1)) + resident(
        0x30, fn_content(32, 1, "cut.txt", 1, t1, t1, t1, t1)
    )
    broken += struct.pack("<II", 0x80, 0x7FFFFFF0)  # an attribute whose length goes far past the entry
    put(Spec(48, raw_attrs=broken), "chain")
    # Damage
    data = bytearray(build_entry(Spec(50, names=[(32, 1, "badsig.txt", 1)], si=live)))
    data[0:4] = b"FIL\x00"
    slots[50] = bytes(data)
    data = bytearray(build_entry(Spec(51, names=[(32, 1, "baad.txt", 1)], si=live)))
    data[0:4] = b"BAAD"
    slots[51] = bytes(data)
    data = bytearray(build_entry(Spec(52, names=[(32, 1, "fixup.txt", 1)], si=live)))
    data[510:512] = b"\x01\x02"  # the end of sector 0 no longer holds the update sequence number
    slots[52] = bytes(data)
    data = bytearray(build_entry(Spec(53, names=[(32, 1, "fixup2.txt", 1)], si=live)))
    data[1022:1024] = b"\x00\x00"  # the second sector
    slots[53] = bytes(data)
    out = bytearray()
    for n in range(0, 56):
        out += slots.get(n, bytes(ENTRY))
    out += build_entry(Spec(56, names=[(32, 1, "cut_short.txt", 1)], si=live))[:300]  # the file stops inside it
    expect = {
        "slots": 56,
        "in_file": 0,
    }
    non_empty = [n for n in range(56) if n in slots]
    expect["in_file"] = len(non_empty) + 1  # and the partial one at the end
    expect["empty"] = 56 - len(non_empty)
    return MftFixture(bytes(out), named, expect)


# --------------------------------------------------------------------------- #
# $J                                                                           #
# --------------------------------------------------------------------------- #
def usn_v2(
    usn: int, entry: int, seq: int, parent: int, pseq: int, name: str, reason: int, ticks: int, attrs: int = 0x20
) -> bytes:
    nb = u16(name)
    length = (60 + len(nb) + 7) & ~7
    head = struct.pack("<IHH", length, 2, 0)
    head += struct.pack(
        "<QQQQIIIIHH", entry | (seq << 48), parent | (pseq << 48), usn, ticks, reason, 0, 0x100, attrs, len(nb), 60
    )
    return (head + nb).ljust(length, b"\0")


def usn_v3(
    usn: int, entry: int, seq: int, parent: int, pseq: int, name: str, reason: int, ticks: int, hi: int = 0
) -> bytes:
    nb = u16(name)
    length = (76 + len(nb) + 7) & ~7
    head = struct.pack("<IHH", length, 3, 0)
    head += struct.pack(
        "<QQQQQQIIIIHH",
        entry | (seq << 48),
        hi,
        parent | (pseq << 48),
        0,
        usn,
        ticks,
        reason,
        0,
        0x100,
        0x20,
        len(nb),
        76,
    )
    return (head + nb).ljust(length, b"\0")


def usn_v4(usn: int, extents: int = 1) -> bytes:
    length = 48 + 16 * extents
    head = struct.pack("<IHH", length, 4, 0) + bytes(16) + struct.pack("<QIIIHH", usn, 0x2, 0, 4096, extents, 0)
    return head + struct.pack("<QQ", 0, 4096) * extents


@dataclass
class UsnFixture:
    data: bytes
    usns: list[int]  # the USNs the parser has to read, in order
    expect: dict[str, int]


def make_usn() -> UsnFixture:
    t = ft(1_700_000_000, 1234567)
    out = bytearray(bytes(1 << 16))  # the sparse start
    usns: list[int] = []

    def add(raw: bytes, usn: int | None = None) -> None:
        out.extend(raw)
        if usn is not None:
            usns.append(usn)

    base = len(out)
    add(usn_v2(base, 33, 1, 32, 1, "setup.exe", 0x100, t), base)
    add(usn_v2(base + 80, 33, 1, 32, 1, "setup.exe", 0x2 | 0x1, t + 10_000_000), base + 80)
    add(usn_v2(base + 160, 33, 1, 32, 1, "setup.exe", 0x80000000 | 0x100, t + 20_000_000), base + 160)
    add(usn_v3(base + 400, 34, 2, 32, 1, "notes.txt", 0x200, t + 30_000_000), base + 400)
    add(usn_v4(base + 500))
    out.extend(bytes(200))  # padding of a page
    add(usn_v2(base + 900, 35, 1, 32, 1, "renamed é.txt", 0x1000 | 0x2000, t + 40_000_000, 0x2), base + 900)
    out.extend(b"\xff" * 24 + struct.pack("<IHH", 64, 9, 0) + bytes(32))  # a header with a version that does not exist
    add(usn_v2(base + 1100, 36, 1, 32, 1, "after_garbage.txt", 0x100, t + 50_000_000), base + 1100)
    bad_name = bytearray(usn_v2(base + 1200, 37, 1, 32, 1, "bad_name.txt", 0x100, t))
    struct.pack_into("<HH", bad_name, 56, 400, 60)  # a name that runs out of the record
    add(bytes(bad_name))
    add(usn_v2(base + 1300, 38, 1, 32, 1, "after_bad_name.txt", 0x100, t + 60_000_000), base + 1300)
    out.extend(bytes(5000))  # a freed area
    add(usn_v2(base + 1400, 39, 1, 32, 1, "no_time.txt", 0x100, 0), base + 1400)
    add(usn_v2(base + 900, 35, 1, 32, 1, "repeat.txt", 0x100, t + 70_000_000))  # the USN of a record already seen
    usns.append(base + 900)
    cut = usn_v2(base + 1500, 40, 1, 32, 1, "truncated.txt", 0x100, t)
    out.extend(cut[:40])  # the file stops inside the last record
    return UsnFixture(
        bytes(out),
        usns,
        {"v4": 1, "zero_runs": 2, "found": len(usns) + 1 + 2 + 1, "skips": 3},
    )

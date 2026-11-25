"""Writers of the Windows artifacts the stage 6 artifact parsers read: shortcuts, jump lists, prefetch files.

Everything here makes harmless bytes from values: a shortcut with the structure of the format, a compound file with its
FAT and mini stream, a jump list on top of them, a prefetch file in the layout of versions 23 and 30. Nothing is
evidence and nothing is copied from a real file. The layouts follow the libyal documentation (liblnk, libolecf, libscca,
dtformats "Jump lists format").
"""

from __future__ import annotations

import struct
import uuid

CLSID = bytes.fromhex("0114020000000000c000000000000046")
EPOCH_TICKS = 116444736000000000
FREE, END, FAT_SECTOR = 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFD


def filetime(ms: int | None) -> int:
    """Milliseconds since the epoch as a FILETIME (0 for None)."""
    return 0 if ms is None else ms * 10000 + EPOCH_TICKS


# --------------------------------------------------------------------------- #
# Shortcuts                                                                   #
# --------------------------------------------------------------------------- #
def _string(text: str) -> bytes:
    return struct.pack("<H", len(text)) + text.encode("utf-16-le")


def droid_v1(mac: str = "00:1d:09:fa:5a:1c", ms: int = 1_247_531_342_000) -> str:
    """A version 1 UUID (what the tracker block holds) with the MAC as its node and ``ms`` as its time."""
    ticks = ms * 10000 + 0x01B21DD213814000
    node = int(mac.replace(":", ""), 16)
    value = uuid.UUID(
        fields=(ticks & 0xFFFFFFFF, (ticks >> 32) & 0xFFFF, ((ticks >> 48) & 0x0FFF) | 0x1000, 0x9D, 0x20, node)
    )
    return str(value).upper()


def _guid_bytes(text: str) -> bytes:
    return uuid.UUID(text).bytes_le


def lnk_bytes(
    target: str | None = r"C:\Users\alice\Documents\plan.docx",
    *,
    arguments: str = "",
    working_dir: str = "",
    icon: str = "",
    description: str = "",
    created: int | None = 1_600_000_000_000,
    accessed: int | None = 1_600_000_600_000,
    modified: int | None = 1_600_000_300_000,
    size: int = 12345,
    drive_type: int = 3,
    serial: int = 0x70ECFA33,
    label: str = "OS",
    share: str | None = None,
    machine: str | None = "wks-042",
    droid: str | None = None,
    id_list: bool = False,
    unicode: bool = True,
) -> bytes:
    """A shortcut: header, optional IDList, LinkInfo (local or network), string data, tracker block, terminal block."""
    flags = 0
    body = b""
    if id_list:
        flags |= 0x1
        item = b"\x1f\x50" + bytes.fromhex("e04fd020ea3a6910a2d808002b30309d")  # My Computer
        items = struct.pack("<H", len(item) + 2) + item
        body += struct.pack("<H", len(items) + 2) + items + b"\x00\x00"
    if target is not None or share is not None:
        flags |= 0x2
        if share is None:
            label_b = label.encode("cp1252") + b"\x00"
            volume = struct.pack("<IIII", 16 + len(label_b), drive_type, serial, 16) + label_b
            base = (target or "").encode("cp1252") + b"\x00"
            info_flags = 1
            header = 28
            vol_off = header
            base_off = vol_off + len(volume)
            suffix_off = base_off + len(base)
            info = volume + base + b"\x00"
            body += (
                struct.pack("<IIIIIII", header + len(info), header, info_flags, vol_off, base_off, 0, suffix_off) + info
            )
        else:
            name = share.encode("cp1252") + b"\x00"
            device = b"Z:\x00"
            net = struct.pack("<IIIII", 20 + len(name) + len(device), 3, 20, 20 + len(name), 0x20000) + name + device
            suffix = b"\x00"
            header = 28
            net_off = header
            suffix_off = net_off + len(net)
            body += (
                struct.pack("<IIIIIII", header + len(net) + len(suffix), header, 2, 0, 0, net_off, suffix_off)
                + net
                + suffix
            )
    for flag, text in ((0x4, description), (0x8, ""), (0x10, working_dir), (0x20, arguments), (0x40, icon)):
        if text:
            flags |= flag
            body += _string(text) if unicode else struct.pack("<H", len(text)) + text.encode("cp1252")
    if unicode:
        flags |= 0x80
    if machine is not None:
        tracker = struct.pack("<IIII", 0x60, 0xA0000003, 0x58, 0) + machine.encode("ascii").ljust(16, b"\x00")
        file_droid = droid or droid_v1()
        tracker += _guid_bytes("494CCBDA-98E8-45C8-B8CA-F64D464366C7") + _guid_bytes(file_droid)
        tracker += _guid_bytes("494CCBDA-98E8-45C8-B8CA-F64D464366C7") + _guid_bytes(file_droid)
        body += tracker
    body += struct.pack("<I", 0)
    header = (
        struct.pack("<I", 0x4C)
        + CLSID
        + struct.pack("<II", flags, 0x20)
        + struct.pack("<QQQ", filetime(created), filetime(accessed), filetime(modified))
        + struct.pack("<IiI", size, 0, 1)
        + b"\x00" * 12
    )
    assert len(header) == 0x4C
    return header + body


# --------------------------------------------------------------------------- #
# OLE compound files                                                          #
# --------------------------------------------------------------------------- #
def ole_bytes(streams: dict[str, bytes]) -> bytes:
    """A compound file (version 3: 512-byte sectors, 64-byte mini sectors, 4096-byte cutoff) with these streams in
    its root, under a degenerate directory tree (every node is the right sibling of the one before)."""
    sector, mini = 512, 64
    small = {name: data for name, data in streams.items() if len(data) < 4096}
    big = {name: data for name, data in streams.items() if len(data) >= 4096}

    def sectors(n: int, size: int) -> int:
        return max(0, -(-n // size))

    mini_stream = b""
    mini_fat: list[int] = []
    mini_start: dict[str, int] = {}
    for name, data in small.items():
        count = sectors(len(data), mini)
        mini_start[name] = len(mini_fat)
        for i in range(count):
            mini_fat.append(len(mini_fat) + 1 if i < count - 1 else END)
        mini_stream += data.ljust(count * mini, b"\x00")
    dir_entries = len(streams) + 1
    dir_sectors = sectors(dir_entries * 128, sector)
    mini_fat_sectors = sectors(len(mini_fat) * 4, sector)
    mini_stream_sectors = sectors(len(mini_stream), sector)
    big_sectors = {name: sectors(len(data), sector) for name, data in big.items()}
    data_sectors = dir_sectors + mini_fat_sectors + mini_stream_sectors + sum(big_sectors.values())
    fat_sectors = 1
    while fat_sectors * 128 < data_sectors + fat_sectors:
        fat_sectors += 1
    fat = [FREE] * (fat_sectors * 128)
    nxt = 0
    for _ in range(fat_sectors):
        fat[nxt] = FAT_SECTOR
        nxt += 1

    def chain(count: int) -> int:
        nonlocal nxt
        if count == 0:
            return END
        first = nxt
        for i in range(count):
            fat[nxt] = nxt + 1 if i < count - 1 else END
            nxt += 1
        return first

    dir_start = chain(dir_sectors)
    mini_fat_start = chain(mini_fat_sectors)
    mini_stream_start = chain(mini_stream_sectors)
    big_start = {name: chain(count) for name, count in big_sectors.items()}

    def entry(name: str, kind: int, left: int, right: int, child: int, start: int, size: int) -> bytes:
        raw = name.encode("utf-16-le")
        return (
            raw.ljust(64, b"\x00")
            + struct.pack("<HBB", len(raw) + 2 if name else 0, kind, 1)
            + struct.pack("<III", left, right, child)
            + b"\x00" * 16
            + struct.pack("<I", 0)
            + b"\x00" * 16
            + struct.pack("<IIII", start, size, 0, 0)[:12]
            + b"\x00" * 0
        )

    names = list(streams)
    directory = entry("Root Entry", 5, FREE, FREE, 1 if names else FREE, mini_stream_start, len(mini_stream))
    for i, name in enumerate(names):
        data = streams[name]
        start = mini_start[name] if name in small else big_start[name]
        directory += entry(name, 2, FREE, i + 2 if i + 1 < len(names) else FREE, FREE, start, len(data))
    directory = directory.ljust(dir_sectors * sector, b"\x00")
    # Free directory slots are "unused" entries: their sibling and child ids are FREE.
    free = entry("", 0, FREE, FREE, FREE, 0, 0)
    directory = directory[: dir_entries * 128] + free * (dir_sectors * 4 - dir_entries)
    difat = list(range(fat_sectors)) + [FREE] * (109 - fat_sectors)
    header = (
        bytes.fromhex("d0cf11e0a1b11ae1")
        + b"\x00" * 16
        + struct.pack("<HHHHH", 0x3E, 3, 0xFFFE, 9, 6)
        + b"\x00" * 6
        + struct.pack("<IIIIII", 0, fat_sectors, dir_start, 0, 4096, mini_fat_start if mini_fat else END)
        + struct.pack("<III", mini_fat_sectors, END, 0)
        + struct.pack("<109I", *difat)
    )
    assert len(header) == 512, len(header)
    body = bytearray()
    body += b"".join(struct.pack("<I", value) for value in fat)
    body += directory
    body += b"".join(struct.pack("<I", value) for value in mini_fat).ljust(mini_fat_sectors * sector, b"\xff")
    body += mini_stream.ljust(mini_stream_sectors * sector, b"\x00")
    for name, data in big.items():
        body += data.ljust(big_sectors[name] * sector, b"\x00")
    return header + bytes(body)


# --------------------------------------------------------------------------- #
# Jump lists                                                                  #
# --------------------------------------------------------------------------- #
def destlist_entry(
    entry_id: int,
    path: str,
    *,
    version: int = 3,
    host: str = "WKS-042",
    accessed: int | None = 1_600_000_900_000,
    pin: int = -1,
    count: int = 4,
) -> bytes:
    """One DestList entry in the layout of ``version`` (1: Windows 7, 114 bytes + path; 3 and later: 130 + path + 4)."""
    out = bytearray(114 if version == 1 else 130)
    out[8:24] = _guid_bytes("494CCBDA-98E8-45C8-B8CA-F64D464366C7")
    out[24:40] = _guid_bytes(droid_v1())
    out[40:56] = out[8:24]
    out[56:72] = out[24:40]
    out[72 : 72 + 16] = host.encode("ascii").ljust(16, b"\x00")
    struct.pack_into("<I", out, 88, entry_id)
    struct.pack_into("<Q", out, 100, filetime(accessed))
    struct.pack_into("<i", out, 108, pin)
    raw = path.encode("utf-16-le")
    if version == 1:
        struct.pack_into("<f", out, 96, float(count))
        struct.pack_into("<H", out, 112, len(raw) // 2)
        return bytes(out) + raw
    struct.pack_into("<I", out, 116, count)
    struct.pack_into("<H", out, 128, len(raw) // 2)
    return bytes(out) + raw + b"\x00" * 4


def destlist(entries: list[bytes], *, version: int = 3, pinned: int = 0, declared: int | None = None) -> bytes:
    header = struct.pack("<IIIIIIII", version, len(entries) if declared is None else declared, pinned, 0, 0, 0, 0, 0)
    return header + b"".join(entries)


def automatic_destinations(
    items: list[tuple[int, str, bytes | None]],
    *,
    version: int = 3,
    pinned_ids: tuple[int, ...] = (),
    extra_streams: dict[str, bytes] | None = None,
    declared: int | None = None,
) -> bytes:
    """An .automaticDestinations-ms file: ``items`` are (entry id, DestList path, shortcut or None for no stream)."""
    entries = [
        destlist_entry(
            entry_id,
            path,
            version=version,
            pin=0 if entry_id in pinned_ids else -1,
            accessed=1_600_001_000_000 + 1000 * entry_id,
            count=entry_id + 1,
        )
        for entry_id, path, _ in items
    ]
    streams: dict[str, bytes] = {
        "DestList": destlist(entries, version=version, pinned=len(pinned_ids), declared=declared)
    }
    for entry_id, _path, data in items:
        if data is not None:
            streams[f"{entry_id:x}"] = data
    streams.update(extra_streams or {})
    return ole_bytes(streams)


def custom_destinations(categories: list[tuple[int, str | int, list[bytes]]], *, footer: bool = True) -> bytes:
    """A .customDestinations-ms file: each category is (type, name for type 0 / identifier for type 1, shortcuts)."""
    out = struct.pack("<III", 2, len(categories), 0)
    for kind, label, links in categories:
        out += struct.pack("<I", kind)
        if kind == 0:
            out += _string(str(label)) + struct.pack("<I", len(links))
        elif kind == 1:
            out += struct.pack("<I", int(label))
        else:
            out += struct.pack("<I", len(links))
        if kind != 1:
            for link in links:
                out += CLSID + link
        out += struct.pack("<I", 0xBABFFBAB)
    return out


# --------------------------------------------------------------------------- #
# Prefetch                                                                    #
# --------------------------------------------------------------------------- #
def prefetch_bytes(
    version: int = 30,
    *,
    exe: str = "NOTEPAD.EXE",
    prefetch_hash: int = 0xD8414F97,
    run_count: int = 5,
    run_times: list[int] | None = None,
    files: list[str] | None = None,
    volumes: list[tuple[str, int, int]] | None = None,
) -> bytes:
    """An uncompressed prefetch file of ``version`` 23 (Windows 7) or 30 (Windows 10): header, file information,
    one metrics entry per file, the file name strings and the volume information (``volumes`` are device path,
    creation time in ms, serial)."""
    files = (
        files
        if files is not None
        else [r"\VOLUME{01d0}-70ECFA33\WINDOWS\SYSTEM32\NTDLL.DLL", rf"\VOLUME{{01d0}}-70ECFA33\WINDOWS\SYSTEM32\{exe}"]
    )
    volumes = (
        volumes if volumes is not None else [(r"\VOLUME{01d0e1a2b3c4d5e6-70ecfa33}", 1_500_000_000_000, 0x70ECFA33)]
    )
    run_times = run_times if run_times is not None else [1_600_000_000_000]
    info_size = 156 if version == 23 else 212  # Windows 10 "variant 1": the metrics start at byte 296
    volume_size = 104 if version == 23 else 96
    metrics_at = 84 + info_size
    metrics = b""
    strings = b""
    for name in files:
        raw = name.encode("utf-16-le") + b"\x00\x00"
        metrics += struct.pack("<IIIIIIQ", 0, 0, 0, len(strings), len(raw) // 2 - 1, 0x2, 0)
        strings += raw
    trace_at = metrics_at + len(metrics)
    trace = b"\x00" * 12  # one trace chain entry: the layout wants the array between the metrics and the strings
    strings_at = trace_at + len(trace)
    volumes_at = strings_at + len(strings)
    volumes_at += -volumes_at % 8
    volume_info = b""
    device_strings = b""
    device_at = volume_size * len(volumes)
    for device, created, serial in volumes:
        raw = device.encode("utf-16-le") + b"\x00\x00"
        volume_info += struct.pack(
            "<IIQI", device_at + len(device_strings), len(raw) // 2 - 1, filetime(created), serial
        )
        volume_info += struct.pack("<IIII", 0, 0, 0, 0).ljust(volume_size - 20, b"\x00")
        device_strings += raw
    volume_block = volume_info + device_strings
    total = volumes_at + len(volume_block)
    times = [filetime(t) for t in run_times]
    if version == 23:
        last = struct.pack("<Q", times[0] if times else 0)
        info = (
            struct.pack(
                "<IIIIIIIII",
                metrics_at,
                len(files),
                trace_at,
                1,
                strings_at,
                len(strings),
                volumes_at,
                len(volumes),
                len(volume_block),
            )
            + b"\x00" * 8
            + last
            + b"\x00" * 16
            + struct.pack("<I", run_count)
        )
    else:
        padded = (times + [0] * 8)[:8]
        info = (
            struct.pack(
                "<IIIIIIIII",
                metrics_at,
                len(files),
                trace_at,
                1,
                strings_at,
                len(strings),
                volumes_at,
                len(volumes),
                len(volume_block),
            )
            + b"\x00" * 8
            + struct.pack("<8Q", *padded)
            + b"\x00" * 8
            + struct.pack("<I", run_count)
        )
    info = info.ljust(info_size, b"\x00")
    header = (
        struct.pack("<I4sII", version, b"SCCA", 0x11, total)
        + exe.encode("utf-16-le").ljust(60, b"\x00")
        + struct.pack("<II", prefetch_hash, 0)
    )
    assert len(header) == 84, len(header)
    out = header + info + metrics + trace + strings
    out = out.ljust(volumes_at, b"\x00") + volume_block
    return out

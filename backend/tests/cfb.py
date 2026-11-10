"""A minimal compound file (OLE2 / CFB v3) writer, to build Outlook ``.msg``
fixtures: olefile only reads them. Streams under 4 KiB go to the mini stream
(64-byte sectors), as the format requires."""

from __future__ import annotations

import struct

SECTOR, MINI, CUTOFF = 512, 64, 4096
FREE, END, FATSECT, NOSTREAM = 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFD, 0xFFFFFFFF


def build(tree: dict) -> bytes:
    """``tree``: {name: bytes (stream) | dict (storage)}; returns the file."""
    entries: list[dict] = [{"name": "Root Entry", "type": 5, "data": b"", "children": []}]

    def add(parent: int, items: dict) -> None:
        for name, value in items.items():
            index = len(entries)
            storage = isinstance(value, dict)
            entries.append(
                {"name": name, "type": 1 if storage else 2, "data": b"" if storage else value, "children": []}
            )
            entries[parent]["children"].append(index)
            if storage:
                add(index, value)

    add(0, tree)

    # Small streams: into the mini stream (held by the root entry).
    mini, minifat = b"", []
    for entry in entries[1:]:
        data = entry["data"]
        if data and len(data) < CUTOFF:
            entry["start"] = len(minifat)
            count = -(-len(data) // MINI)
            minifat += [len(minifat) + i + 1 for i in range(count - 1)] + [END]
            mini += data.ljust(count * MINI, b"\0")
            entry["mini"] = True
    entries[0]["data"] = mini

    sectors: list[bytes] = []
    chains: list[tuple[int, int]] = []  # (first sector, count) per chain
    minifat_bytes = struct.pack(f"<{len(minifat)}I", *minifat) if minifat else b""
    minifat_bytes = minifat_bytes.ljust(-(-len(minifat_bytes) // SECTOR) * SECTOR, b"\xff")
    minifat_start = len(sectors) if minifat_bytes else END
    minifat_count = len(minifat_bytes) // SECTOR
    if minifat_count:
        chains.append((0, minifat_count))
        sectors += [minifat_bytes[i * SECTOR : (i + 1) * SECTOR] for i in range(minifat_count)]
    for entry in entries:
        if entry.get("mini"):
            continue
        data = entry["data"]
        if not data:
            entry["start"] = END
            continue
        entry["start"] = len(sectors)
        count = (len(data) + SECTOR - 1) // SECTOR
        chains.append((len(sectors), count))
        for i in range(count):
            sectors.append(data[i * SECTOR : (i + 1) * SECTOR].ljust(SECTOR, b"\0"))

    directory = b""
    for entry in entries:
        kids = entry["children"]
        # Children as a chain of right siblings (all black: a valid, if lopsided, tree).
        for position, kid in enumerate(kids):
            entries[kid]["right"] = kids[position + 1] if position + 1 < len(kids) else NOSTREAM
        name = entry["name"].encode("utf-16-le")
        directory += struct.pack(
            "<64sHBBIII16sIQQIQ",
            name.ljust(64, b"\0"),
            len(name) + 2,
            entry["type"],
            1,
            NOSTREAM,
            entry.get("right", NOSTREAM),
            kids[0] if kids else NOSTREAM,
            b"\0" * 16,
            0,
            0,
            0,
            entry["start"],
            len(entry["data"]),
        )
    directory = directory.ljust(-(-len(directory) // SECTOR) * SECTOR, b"\0")
    dir_start, dir_count = len(sectors), len(directory) // SECTOR
    chains.append((dir_start, dir_count))
    sectors += [directory[i * SECTOR : (i + 1) * SECTOR] for i in range(dir_count)]

    fat_count = 1
    while (len(sectors) + fat_count) > fat_count * (SECTOR // 4):
        fat_count += 1
    fat = [FREE] * (fat_count * SECTOR // 4)
    for start, count in chains:
        for i in range(count):
            fat[start + i] = start + i + 1 if i + 1 < count else END
    fat_start = len(sectors)
    for i in range(fat_count):
        fat[fat_start + i] = FATSECT
    fat_bytes = struct.pack(f"<{len(fat)}I", *fat)
    sectors += [fat_bytes[i * SECTOR : (i + 1) * SECTOR] for i in range(fat_count)]

    difat = [fat_start + i for i in range(fat_count)] + [FREE] * (109 - fat_count)
    header = struct.pack(
        "<8s16sHHHHH6sIIIIIIIII",
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
        b"\0" * 16,
        0x3E,
        3,
        0xFFFE,
        9,
        6,
        b"\0" * 6,
        0,
        fat_count,
        dir_start,
        0,
        CUTOFF,
        minifat_start,
        minifat_count,
        END,
        0,
    ) + struct.pack("<109I", *difat)
    return header + b"".join(sectors)

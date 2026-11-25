"""A minimal writer of registry hives (``regf``) for the tests: one ``hbin``, keys, values, subkey lists, big values.

    root = Node("ROOT", children=[Node("Select", values=[dword("Current", 1)])])
    data, where = build(root, name="\\\\SystemRoot\\\\System32\\\\Config\\\\SYSTEM")

``where`` maps the path of each key to the offset of its ``nk`` cell and ``path\\\\value`` to that of its ``vk``
cell, so a test can damage a cell it knows. Everything here is made at test time: harmless bytes, never evidence.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

EPOCH_DELTA = 11644473600


def filetime(unix_seconds: float) -> int:
    return int((unix_seconds + EPOCH_DELTA) * 10_000_000)


@dataclass
class Val:
    name: str
    type: int
    data: bytes


@dataclass
class Node:
    name: str
    values: list[Val] = field(default_factory=list)
    children: list[Node] = field(default_factory=list)
    written: float = 1_700_000_000.0  # unix seconds of the key's last write
    list_kind: bytes = b"lh"  # "lh", "lf" or "li": the kind of subkey list


def sz(name: str, text: str) -> Val:
    return Val(name, 1, (text + "\x00").encode("utf-16le"))


def expand(name: str, text: str) -> Val:
    return Val(name, 2, (text + "\x00").encode("utf-16le"))


def dword(name: str, number: int) -> Val:
    return Val(name, 4, struct.pack("<I", number))


def binary(name: str, data: bytes) -> Val:
    return Val(name, 3, data)


def _align(number: int) -> int:
    return (number + 7) & ~7


class _Cells:
    def __init__(self) -> None:
        self.data = bytearray(32)  # the hbin header, filled in at the end

    def add(self, content: bytes) -> int:
        offset = len(self.data)
        size = _align(len(content) + 4)
        self.data += struct.pack("<i", -size) + content + bytes(size - 4 - len(content))
        return offset


def build(
    root: Node,
    name: str = "\\SystemRoot\\System32\\Config\\SYSTEM",
    dirty: bool = False,
    big_block: int = 16344,
) -> tuple[bytes, dict[str, int]]:
    cells = _Cells()
    where: dict[str, int] = {}

    def write_value(path: str, val: Val) -> int:
        raw_name = val.name.encode("latin-1")
        if len(val.data) <= 4 and val.data:
            size_field = 0x80000000 | len(val.data)
            data_offset = struct.unpack("<I", val.data.ljust(4, b"\x00"))[0]
        elif len(val.data) > big_block:
            blocks = [cells.add(val.data[at : at + big_block]) for at in range(0, len(val.data), big_block)]
            listing = cells.add(struct.pack(f"<{len(blocks)}I", *blocks))
            data_offset = cells.add(b"db" + struct.pack("<HI", len(blocks), listing) + bytes(4))
            size_field = len(val.data)
        elif val.data:
            data_offset = cells.add(val.data)
            size_field = len(val.data)
        else:
            data_offset, size_field = 0xFFFFFFFF, 0
        head = b"vk" + struct.pack("<HIIIHH", len(raw_name), size_field, data_offset, val.type, 1, 0) + raw_name
        offset = cells.add(head)
        where[f"{path}\\{val.name}"] = offset
        return offset

    def write_key(node: Node, path: str, parent: int) -> int:
        child_offsets = [
            write_key(child, f"{path}\\{child.name}" if path else child.name, 0) for child in node.children
        ]
        value_offsets = [write_value(path, val) for val in node.values]
        value_list = cells.add(struct.pack(f"<{len(value_offsets)}I", *value_offsets)) if value_offsets else 0xFFFFFFFF
        if child_offsets:
            if node.list_kind == b"li":
                body = struct.pack(f"<{len(child_offsets)}I", *child_offsets)
            else:
                body = b"".join(struct.pack("<II", offset, 0) for offset in child_offsets)
            sub_list = cells.add(node.list_kind + struct.pack("<H", len(child_offsets)) + body)
        else:
            sub_list = 0xFFFFFFFF
        raw_name = node.name.encode("latin-1")
        flags = 0x20 | (0x0C if parent == 0xFFFFFFFF else 0)
        content = bytearray(76)
        content[0:2] = b"nk"
        struct.pack_into("<HQI", content, 2, flags, filetime(node.written), 0)
        struct.pack_into("<IIIII", content, 16, parent, len(child_offsets), 0, sub_list, 0xFFFFFFFF)
        struct.pack_into("<II", content, 36, len(value_offsets), value_list)
        struct.pack_into("<IIHH", content, 44, 0xFFFFFFFF, 0xFFFFFFFF, 0, 0)
        struct.pack_into("<HH", content, 72, len(raw_name), 0)
        offset = cells.add(bytes(content) + raw_name)
        where[path] = offset
        return offset

    # The children must know their parent, but only the root's "no parent" is read by the parser.
    root_offset = write_key(root, "", 0xFFFFFFFF)
    where[""] = root_offset
    body = cells.data
    # Pad to a block of 4096 with one free cell.
    total = (len(body) + 4095) & ~4095 or 4096
    rest = total - len(body)
    if 0 < rest < 8:
        total += 4096
        rest = total - len(body)
    if rest:
        body += struct.pack("<i", rest) + bytes(rest - 4)
    body[0:4] = b"hbin"
    struct.pack_into("<III", body, 4, 0, total, 0)
    header = bytearray(4096)
    header[0:4] = b"regf"
    struct.pack_into("<II", header, 4, 5, 4 if dirty else 5)
    struct.pack_into("<Q", header, 12, filetime(1_700_000_100))
    struct.pack_into("<IIII", header, 20, 1, 5, 0, 1)
    struct.pack_into("<III", header, 36, root_offset, total, 1)
    header[48:112] = name.encode("utf-16le")[:64].ljust(64, bytes(1))
    calc = 0
    for at in range(0, 508, 4):
        calc ^= struct.unpack_from("<I", header, at)[0]
    calc = {0xFFFFFFFF: 0xFFFFFFFE, 0: 1}.get(calc, calc)
    struct.pack_into("<I", header, 508, calc)
    return bytes(header) + bytes(body), where

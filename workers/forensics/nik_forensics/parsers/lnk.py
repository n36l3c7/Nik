"""Windows shortcuts (.lnk): what a user opened, from the shortcut Windows made for it.

One file is one record. The shortcut says where its target is (a local path, or a network share), with what
arguments and from which folder it starts, its icon, the volume the target was on (type, serial, label) and, from
the tracker block, the machine that made it and the MAC address of that machine (only when the file's droid is a
version 1 UUID, which carries the MAC of the node that made it).

**The times.** The header of a shortcut holds the three times of its *target* as they were when Windows wrote the
link: created, last accessed, last written. The shortcut file's own times are the file system's, not in the file.
The record's ``ts`` is the target's last access: Windows rewrites a link when the user opens the target, and that
is the moment a timeline wants; when the access time is zero (last-access updates are disabled on many volumes) the
last write is used, and then the creation. ``data.ts_from`` says which of the three it is; the three are always in
``data`` (``target_created``, ``target_accessed``, ``target_modified``).

**What it counts.** ``in_file`` is 1: the file is one shortcut. LnkParse3 reports damage only through warnings: they
are caught and said as a note ("shortcut parsed in part") with the first of them in its detail. A shortcut the
library cannot read at all is a skip. A second reading of the structure (``extent``) walks the header, the
IDList, the LinkInfo, the string data and the extra blocks by their sizes, with no library, and says where the
shortcut ends: that is how the jump list reader finds each shortcut in a custom destinations file, and how a shortcut
cut short, or with bytes after its end, is told.

The record's key is ``lnk:<host>:<sha1 of the file>``: the same shortcut found in two places is one record.
``loc`` is ``{"offset": 0, "length": n}``: the file itself. Every file is hostile: a file larger than ``MAX_SIZE``
is not read.
"""

from __future__ import annotations

import hashlib
import io
import os
import struct
import warnings
from typing import Any

from nik_forensics import viewing
from nik_forensics.parsers import ViewError

NAME = "lnk"
VERSION = "1"
KIND = "endpoint"
SOURCES = ("windows.fileaccess.lnk",)

SOURCE = SOURCES[0]
HEADER = 0x4C
# The class identifier of a shell link, as the header (and a custom destinations entry) holds it.
CLSID = bytes.fromhex("0114020000000000c000000000000046")
MAX_SIZE = 8 * 1024 * 1024  # a shortcut is a few KiB; with its property stores, a few tens
# FILETIME ticks (100 ns) between 1601-01-01 and 1970-01-01, and the largest time a calendar prints.
EPOCH_TICKS = 116444736000000000
MAX_MS = 253402300799000

_FLAG_IDLIST, _FLAG_INFO, _FLAG_NAME, _FLAG_RELATIVE = 0x1, 0x2, 0x4, 0x8
_FLAG_WORKING, _FLAG_ARGS, _FLAG_ICON, _FLAG_UNICODE = 0x10, 0x20, 0x40, 0x80
_STRING_FLAGS = (_FLAG_NAME, _FLAG_RELATIVE, _FLAG_WORKING, _FLAG_ARGS, _FLAG_ICON)


def sniff(path: str, name: str, head: bytes) -> str | None:
    """A shortcut by its header: a size of 0x4C and the shell link class identifier."""
    if len(head) >= 20 and struct.unpack_from("<I", head, 0)[0] == HEADER and head[4:20] == CLSID:
        return SOURCE
    return None


# --------------------------------------------------------------------------- #
# Times                                                                       #
# --------------------------------------------------------------------------- #
def filetime_ms(ticks: int) -> int | None:
    """A FILETIME (100 ns since 1601) as milliseconds since the epoch; None for zero or a time no calendar prints."""
    if ticks <= 0:
        return None
    ms = (ticks - EPOCH_TICKS) // 10000
    return ms if -MAX_MS <= ms <= MAX_MS else None


def guid_text(raw: bytes) -> str:
    """A GUID in its on-disk (mixed endian) form, as upper-case text."""
    a, b, c = struct.unpack_from("<IHH", raw, 0)
    return f"{a:08X}-{b:04X}-{c:04X}-{raw[8:10].hex().upper()}-{raw[10:16].hex().upper()}"


# --------------------------------------------------------------------------- #
# The structure, with no library                                              #
# --------------------------------------------------------------------------- #
def extent(data: bytes | memoryview, start: int = 0) -> tuple[int, str]:
    """Where the shortcut that begins at ``start`` ends: ``(length, "")``, or ``(bytes seen, why)`` when its structure
    runs past the end of ``data`` or is not a shortcut. Follows the sizes the format gives: the header (76 bytes), the
    IDList (a size), the LinkInfo (a size), up to five strings (a count of characters), the extra blocks (a size each,
    a size under four ends them). Reads nothing it does not need."""
    size = len(data)
    if start + HEADER > size:
        return size - start, "the header is cut short"
    if struct.unpack_from("<I", data, start)[0] != HEADER or bytes(data[start + 4 : start + 20]) != CLSID:
        return 0, "not a shell link header"
    flags = struct.unpack_from("<I", data, start + 20)[0]
    at = start + HEADER
    if flags & _FLAG_IDLIST:
        if at + 2 > size:
            return size - start, "the IDList is cut short"
        at += 2 + struct.unpack_from("<H", data, at)[0]
    if flags & _FLAG_INFO:
        if at + 4 > size:
            return size - start, "the LinkInfo is cut short"
        info = struct.unpack_from("<I", data, at)[0]
        if info < 4:
            return at - start, "the LinkInfo has no size"
        at += info
    unit = 2 if flags & _FLAG_UNICODE else 1
    for flag in _STRING_FLAGS:
        if flags & flag:
            if at + 2 > size:
                return size - start, "the string data is cut short"
            at += 2 + struct.unpack_from("<H", data, at)[0] * unit
    while True:
        if at + 4 > size:
            return min(at, size) - start, "the extra data is cut short"
        block = struct.unpack_from("<I", data, at)[0]
        if block < 4:  # the terminal block: four bytes
            at += 4
            break
        at += block
    if at > size:
        return size - start, "the shortcut is cut short"
    return at - start, ""


# --------------------------------------------------------------------------- #
# One shortcut                                                                #
# --------------------------------------------------------------------------- #
def _text(value: Any) -> str:
    return "" if value is None else str(value).strip("\x00").strip()


def _mac_of(droid: str) -> tuple[str, int | None]:
    """The MAC address and the time inside a version 1 UUID (the file droid of the tracker block), else empty."""
    import uuid

    try:
        parsed = uuid.UUID(droid)
    except (ValueError, AttributeError, TypeError):
        return "", None
    if parsed.version != 1:
        return "", None
    node = f"{parsed.node:012x}"
    moment = (parsed.time - 0x01B21DD213814000) // 10000  # 100 ns since 1582-10-15, to ms since 1970
    return ":".join(node[i : i + 2] for i in range(0, 12, 2)), moment if -MAX_MS <= moment <= MAX_MS else None


def _id_list_path(items: list[Any]) -> str:
    """A path from the shell items of the IDList (the volume, then the folders and the file), when there is no
    LinkInfo to say it: the names the items carry (8.3 names when no long one is stored)."""
    parts: list[str] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        name = item.get("volume_name") or item.get("primary_name") or item.get("long_name")
        if name:
            parts.append(str(name).rstrip("\\"))
    return "\\".join(parts)


def decode(data: bytes) -> dict[str, Any]:
    """The fields of one shortcut (``data`` is its bytes) and what went wrong in reading it.

    ``{"fields": {...}, "problems": [...], "length": n}``; raises ``ValueError`` when it is not a shortcut at all
    or the library cannot read it. ``problems`` are the library's warnings and the sentences of ``extent``."""
    import LnkParse3

    length, why = extent(data)
    if not length and why:
        raise ValueError(why)
    problems: list[str] = [why] if why else []
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        try:
            parsed = LnkParse3.lnk_file(io.BytesIO(data)).get_json()
        except Exception as exc:  # noqa: BLE001 - LnkParse3 raises whatever the bytes make it raise
            raise ValueError(f"{type(exc).__name__}: {str(exc)[:200]}") from None
    problems += [str(item.message)[:200] for item in caught]
    if not why and len(data) > length:
        problems.append(f"{len(data) - length} bytes after the end of the shortcut")

    flags, attributes = struct.unpack_from("<II", data, 20)
    created, accessed, modified = (filetime_ms(struct.unpack_from("<Q", data, at)[0]) for at in (28, 36, 44))
    size, icon_index, show = struct.unpack_from("<IiI", data, 52)
    if accessed is not None:
        ts, ts_from = accessed, "accessed"
    elif modified is not None:
        ts, ts_from = modified, "modified"
    else:
        ts, ts_from = created, "created" if created is not None else ""

    info = parsed.get("link_info") or {}
    place = info.get("location_info") or {}
    strings = parsed.get("data") or {}
    extra = parsed.get("extra") or {}
    local = _text(info.get("local_base_path_unicode") or info.get("local_base_path"))
    suffix = _text(info.get("common_path_suffix_unicode") or info.get("common_path_suffix"))
    share = _text(place.get("net_name_unicode") or place.get("net_name"))
    environment = extra.get("ENVIRONMENTAL_VARIABLES_LOCATION_BLOCK") or {}
    if local:
        target, target_from = local + suffix, "local base path"
    elif share:
        target, target_from = share + ("\\" + suffix if suffix else ""), "network share"
    elif _text(environment.get("target_unicode") or environment.get("target_ansi")):
        target, target_from = _text(environment.get("target_unicode") or environment.get("target_ansi")), "environment"
    elif _id_list_path((parsed.get("target") or {}).get("items") or []):
        target, target_from = _id_list_path(parsed["target"]["items"]), "item list"
    else:
        target, target_from = (
            _text(strings.get("relative_path")),
            "relative path" if strings.get("relative_path") else "",
        )

    tracker = extra.get("DISTRIBUTED_LINK_TRACKER_BLOCK") or {}
    mac, droid_time = _mac_of(_text(tracker.get("droid_file_identifier")))
    fields: dict[str, Any] = {
        "target": target,
        "target_from": target_from,
        "arguments": _text(strings.get("command_line_arguments")),
        "working_dir": _text(strings.get("working_directory")),
        "icon": _text(strings.get("icon_location")),
        "description": _text(strings.get("description")),
        "relative_path": _text(strings.get("relative_path")),
        "target_created": created,
        "target_accessed": accessed,
        "target_modified": modified,
        "target_size": size,
        "target_attributes": parsed.get("header", {}).get("file_flags") or [],
        "attributes": attributes,
        "icon_index": icon_index,
        "show_command": show,
        "link_flags": parsed.get("header", {}).get("link_flags") or [],
        "location": _text(info.get("location")),
        "drive_type": _text(place.get("drive_type")),
        "drive_serial": _text(place.get("drive_serial_number")),
        "drive_label": _text(place.get("volume_label_unicode") or place.get("volume_label")),
        "network_share": share,
        "network_device": _text(place.get("device_name_unicode") or place.get("device_name")),
        "machine_id": _text(tracker.get("machine_identifier")),
        "mac": mac,
        "droid_file": _text(tracker.get("droid_file_identifier")),
        "droid_volume": _text(tracker.get("droid_volume_identifier")),
        "droid_birth_file": _text(tracker.get("birth_droid_file_identifier")),
        "droid_birth_volume": _text(tracker.get("birth_droid_volume_identifier")),
        "droid_time": droid_time,
        "extra_blocks": sorted(extra),
        "ts_from": ts_from,
    }
    if flags & _FLAG_IDLIST and (parsed.get("target") or {}).get("items"):
        fields["item_list"] = [
            str(item.get("class", "")) for item in parsed["target"]["items"] if isinstance(item, dict)
        ]
    return {"fields": fields, "ts": ts, "problems": problems, "length": length, "json": parsed}


def summary_of(fields: dict[str, Any], fallback: str = "") -> str:
    target = fields.get("target") or fallback
    args = fields.get("arguments")
    return f"{target} {args}".strip()[:600] if args else str(target)[:600]


# --------------------------------------------------------------------------- #
# Reading a file                                                              #
# --------------------------------------------------------------------------- #
def parse(path: str, ctx, source: str) -> None:
    host = str(ctx.params.get("host") or "")
    username = str(ctx.params.get("username") or "")
    ctx.source(NAME, VERSION, KIND, SOURCE, host=host, username=username)
    size = os.path.getsize(path)
    if size > MAX_SIZE:
        ctx.skip(
            "file too large to read as a shortcut", lost=0, length=size, detail=f"{size} bytes, the limit is {MAX_SIZE}"
        )
        ctx.end(in_file=None)
        return
    with open(path, "rb") as handle:
        raw = handle.read(MAX_SIZE + 1)
    try:
        found = decode(raw)
    except ValueError as exc:
        ctx.skip("shortcut cannot be read", lost=1, offset=0, length=len(raw), detail=str(exc))
        ctx.end(in_file=1)
        return
    fields = found["fields"]
    digest = hashlib.sha1(raw).hexdigest()  # noqa: S324 - a name for the file's content, not a security measure
    ctx.record(
        key=f"lnk:{host}:{digest}",
        type="lnk",
        ts=found["ts"],
        host=host,
        username=username,
        summary=summary_of(fields, str(ctx.params.get("file_name") or "")),
        data={**fields, "name": str(ctx.params.get("file_name") or ""), "sha1": digest},
        loc={"offset": 0, "length": len(raw)},
    )
    if found["ts"] is None:
        ctx.note("shortcut without a time", detail="the header holds no time of the target")
    if found["problems"]:
        ctx.note(
            "shortcut parsed in part",
            count=len(found["problems"]),
            detail="; ".join(found["problems"])[:450],
        )
    ctx.end(in_file=1)


# --------------------------------------------------------------------------- #
# The view of a record                                                        #
# --------------------------------------------------------------------------- #
def rows_of(raw: dict[str, Any]) -> list[list[str]]:
    """The parts of a decoded shortcut as name/value pairs: the header's, then each part as JSON."""
    rows: list[list[str]] = []
    for name in ("header", "target", "link_info", "data", "extra"):
        value = raw.get(name)
        if value:
            rows.append([name, viewing.pretty(value)])
    return rows


def view(path: str, source: str, loc: dict) -> dict:
    """The shortcut as the library reads it, and its bytes in hex (up to the first 64 KiB)."""
    if os.path.getsize(path) > MAX_SIZE:
        raise ViewError(f"The file is larger than {MAX_SIZE} bytes: it is not read as a shortcut")
    with open(path, "rb") as handle:
        raw = handle.read(MAX_SIZE + 1)
    try:
        found = decode(raw)
    except ValueError as exc:
        raise ViewError(f"The file cannot be read as a shortcut: {exc}") from None
    rows = rows_of(found["json"])
    if found["problems"]:
        rows.insert(0, ["problems", "\n".join(found["problems"])])
    return {
        "kind": "fields",
        "title": "The shortcut and its bytes",
        "where": {"offset": 0, "length": len(raw)},
        "rows": rows,
        "text": viewing.hex_dump(raw[:65536], 0),
    }

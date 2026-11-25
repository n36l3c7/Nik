"""Jump lists: the files an application opened, as Windows keeps them for the taskbar.

Two files, both named after the application (``<app id>.automaticDestinations-ms`` and ``.customDestinations-ms``):

    automatic   an OLE compound file (read with olefile). Its ``DestList`` stream lists the entries (a 32-byte
                header, then 114-byte (version 1, Windows 7) or 130-byte (version 3 and later, Windows 10) fixed parts
                each followed by the path); each entry's own stream, named by its entry number in hexadecimal, is a
                shortcut, decoded by ``lnk.py``.
    custom      a sequence of shortcuts that Windows writes itself: a header (version 2, the number of categories),
                then categories (a type, a name or an identifier, a count, and for each entry the shell link class
                identifier and the shortcut), each ending with the signature 0xBABFFBAB. It is read by that structure
                (the size of a shortcut comes from ``lnk.extent``), never by looking for the shortcut's signature.

A record is one entry: the application (id and, for the few the table here knows, its name), the target, whether it
is pinned, how many times it was opened, the DestList's last access (``ts``; for a custom destinations file, which has
none, the shortcut's own target time, as ``lnk.py`` chooses it), its position in the list (``position``: the order of
the file, the most recently used first for Windows) and the machine name the entry carries. ``in_file`` is the number of
entries the DestList header says it holds (automatic) or the entries the categories declare (custom), plus, for an
automatic file, the shortcut streams that the DestList does not list (kept as records with ``listed`` false: they are
what an entry that was dropped from the list leaves behind).

What cannot be read is a skip with its place: a DestList cut short or of a version not known, a shortcut stream that
does not decode (the entry is still a record, from the DestList), a category whose footer is not where the structure
says, an entry that is not a shortcut. A custom file that stops being readable stops there, and the entries it declared
and did not reach are the ``lost`` of the skip.

The key is ``jl:<host>:<app id>:<entry>``: the entry number in hexadecimal for an automatic file, the category and a
hash
of the shortcut for a custom one. ``loc`` is ``{"stream", "offset"}`` (automatic: the stream's name and the entry's
offset in the DestList) or ``{"offset", "length"}`` (custom: where the shortcut is). Files are hostile: sizes and
counts are bounded, nothing is executed.
"""

from __future__ import annotations

import hashlib
import os
import re
import struct
from typing import Any

from nik_forensics import viewing
from nik_forensics.parsers import BadLocator, ViewError, lnk

NAME = "jumplist"
VERSION = "1"
KIND = "endpoint"
SOURCES = ("windows.fileaccess.jumplist",)

SOURCE = SOURCES[0]
OLE_MAGIC = bytes.fromhex("d0cf11e0a1b11ae1")
FOOTER = 0xBABFFBAB
MAX_FILE = 64 * 1024 * 1024
MAX_STREAM = 16 * 1024 * 1024
MAX_CATEGORIES = 1000
FILE_NAME = re.compile(r"^([0-9a-f]{16})\.(automatic|custom)destinations-ms$", re.I)
_STREAM_NAME = re.compile(r"^[1-9a-f][0-9a-f]*$")
# olefile raises OSError for most damage and lets ValueError, struct.error and IndexError out of its own tables.
_OLE_ERRORS = (OSError, ValueError, struct.error, IndexError, KeyError, OverflowError)

# Applications whose id is well known (the id is a hash of the application's path and name). Small on purpose.
APP_NAMES = {
    "1b4dd67f29cb1962": "Windows Explorer",
    "f01b4d95cf55d32a": "Windows Explorer",
    "5f7b5f1e01b83767": "Quick Access",
    "9b9cdc69c1c24e2b": "Notepad (64-bit)",
    "12dc1ea8e34b5a6": "Microsoft Paint",
    "5d696d521de238c3": "Google Chrome",
    "1bc392b8e104a00e": "Remote Desktop",
    "7e4dca80246863e3": "Control Panel",
}


def _is_custom(head: bytes) -> bool:
    if len(head) < 12:
        return False
    version, categories, empty = struct.unpack_from("<III", head, 0)
    return version == 2 and 0 < categories <= MAX_CATEGORIES and empty == 0


def sniff(path: str, name: str, head: bytes) -> str | None:
    base = re.split(r"[\\/]", name or "")[-1].lower()
    if head.startswith(OLE_MAGIC):
        if base.endswith(".automaticdestinations-ms"):
            return SOURCE
        if os.path.getsize(path) <= MAX_FILE:
            import olefile

            try:
                ole = olefile.OleFileIO(path)
            except OSError:
                return None
            try:
                return SOURCE if ole.exists("DestList") else None
            finally:
                ole.close()
        return None
    if _is_custom(head) and (base.endswith(".customdestinations-ms") or lnk.CLSID in head):
        return SOURCE
    return None


# --------------------------------------------------------------------------- #
# The DestList stream                                                         #
# --------------------------------------------------------------------------- #
def read_destlist(data: bytes) -> tuple[dict[str, Any], list[dict[str, Any]], list[tuple[str, int, int]]]:
    """The DestList stream as ``(header, entries, problems)``. ``problems`` are ``(reason, offset, lost)``: what was
    not read, from where, and how many entries it cost (0 when not known). Entries carry their ``offset``."""
    problems: list[tuple[str, int, int]] = []
    if not data:
        return {"version": 0, "entries": 0, "pinned": 0}, [], problems  # an empty list: legitimate
    if len(data) < 32:
        return {"version": 0, "entries": 0, "pinned": 0}, [], [("DestList is shorter than its header", 0, 0)]
    version, declared, pinned = struct.unpack_from("<III", data, 0)
    header = {
        "version": version,
        "entries": declared,
        "pinned": pinned,
        "last_entry": struct.unpack_from("<I", data, 16)[0],
    }
    if version not in (1, 3, 4, 5, 6, 7):
        return header, [], [(f"DestList version {version} is not known", 32, declared)]
    fixed = 114 if version == 1 else 130
    entries: list[dict[str, Any]] = []
    at = 32
    for index in range(declared):
        if at + fixed > len(data):
            problems.append(("DestList entry is cut short", at, declared - index))
            return header, entries, problems
        if version == 1:
            count = struct.unpack_from("<f", data, at + 96)[0]
            count = int(count) if count == count and 0 <= count < 2**31 else None
            chars = struct.unpack_from("<H", data, at + 112)[0]
        else:
            count = struct.unpack_from("<I", data, at + 116)[0]
            chars = struct.unpack_from("<H", data, at + 128)[0]
        end = at + fixed + chars * 2
        if end > len(data):
            problems.append(("DestList path runs past the end of the stream", at, declared - index))
            return header, entries, problems
        pin = struct.unpack_from("<i", data, at + 108)[0]
        entries.append(
            {
                "offset": at,
                "entry_id": struct.unpack_from("<I", data, at + 88)[0],
                "host": data[at + 72 : at + 88].split(b"\x00")[0].decode("latin-1"),
                "access_count": count,
                "last_access": lnk.filetime_ms(struct.unpack_from("<Q", data, at + 100)[0]),
                "pinned": pin != -1,
                "pin_order": pin if pin != -1 else None,
                "path": data[at + fixed : end].decode("utf-16-le", "replace"),
                "droid_volume": lnk.guid_text(data[at + 8 : at + 24]),
                "droid_file": lnk.guid_text(data[at + 24 : at + 40]),
            }
        )
        at = end + (0 if version == 1 else 4)
    if at < len(data):
        problems.append(("bytes after the last DestList entry", at, 0))
    return header, entries, problems


# --------------------------------------------------------------------------- #
# What is made of a file                                                      #
# --------------------------------------------------------------------------- #
def _appid(file_name: str) -> str:
    found = FILE_NAME.match(re.split(r"[\\/]", file_name or "")[-1])
    return found.group(1).lower() if found else ""


class _Out:
    def __init__(self, ctx, path: str, kind: str) -> None:
        self.ctx = ctx
        self.host = str(ctx.params.get("host") or "")
        self.username = str(ctx.params.get("username") or "")
        self.appid = _appid(str(ctx.params.get("file_name") or ""))
        if not self.appid:
            with open(path, "rb") as handle:
                self.fallback = "file-" + hashlib.sha1(handle.read(1 << 20)).hexdigest()[:12]  # noqa: S324
        else:
            self.fallback = ""
        self.kind = kind
        self.app = self.appid or self.fallback
        self.seen: set[str] = set()
        self.no_time = 0
        self.partial = 0

    def put(self, entry: str, ts: int | None, fields: dict[str, Any], problems: list[str], loc: dict[str, Any]) -> None:
        key = f"jl:{self.host}:{self.app}:{entry}"
        while key in self.seen:
            key += "+"
        self.seen.add(key)
        if ts is None:
            self.no_time += 1
        if problems:
            self.partial += 1
        name = APP_NAMES.get(self.appid, "")
        target = str(fields.get("target") or "")
        self.ctx.record(
            key=key,
            type="jumplist",
            ts=ts,
            host=self.host,
            username=self.username,
            summary=f"{name or self.app}: {target}"[:600],
            data={"app_id": self.appid, "app_name": name, "jumplist": self.kind, **fields},
            loc=loc,
        )

    def finish(self, in_file: int | None) -> None:
        if self.no_time:
            self.ctx.note("entry without a time", count=self.no_time, detail="the list holds no time for it")
        if self.partial:
            self.ctx.note(
                "shortcut parsed in part", count=self.partial, detail="the library warned about these entries"
            )
        if not self.appid:
            self.ctx.note(
                "file name is not an application id",
                detail=f"the entries are keyed by {self.fallback}, a hash of the start of the file",
            )
        self.ctx.end(in_file=in_file)


def _link_fields(found: dict[str, Any]) -> dict[str, Any]:
    keep = dict(found["fields"])
    keep.pop("extra_blocks", None)
    return keep


# -- automatic destinations ------------------------------------------------------ #
def _read_automatic(path: str, ctx, out: _Out) -> int | None:
    import olefile

    try:
        ole = olefile.OleFileIO(path)
    except _OLE_ERRORS as exc:
        ctx.skip("compound file cannot be opened", lost=0, detail=f"{type(exc).__name__}: {str(exc)[:200]}")
        return None
    try:
        try:
            streams = [item[0] for item in ole.listdir(streams=True, storages=False) if len(item) == 1]
            if "DestList" not in streams:
                ctx.skip("no DestList stream", lost=0, detail="the compound file is not a jump list")
                return None
            if ole.get_size("DestList") > MAX_STREAM:
                ctx.skip("DestList too large to read", lost=0, length=ole.get_size("DestList"))
                return None
            stream_bytes = ole.openstream("DestList").read()
        except _OLE_ERRORS as exc:
            ctx.skip("DestList cannot be read", lost=0, detail=f"{type(exc).__name__}: {str(exc)[:200]}")
            return None
        header, entries, problems = read_destlist(stream_bytes)
        for reason, offset, lost in problems:
            ctx.skip(reason, offset=offset, lost=lost, detail=f"DestList version {header['version']}")
        by_name = {name.lower(): name for name in streams if _STREAM_NAME.match(name.lower())}
        used: set[str] = set()
        missing = 0
        for position, entry in enumerate(entries):
            name = f"{entry['entry_id']:x}"
            stream = by_name.get(name)
            fields: dict[str, Any] = {
                "entry_id": entry["entry_id"],
                "listed": True,
                "position": position,
                "pinned": entry["pinned"],
                "pin_order": entry["pin_order"],
                "access_count": entry["access_count"],
                "last_access": entry["last_access"],
                "host_name": entry["host"],
                "destlist_path": entry["path"],
                "target": entry["path"],
                "has_shortcut": False,
            }
            problems_of: list[str] = []
            if stream is None:
                missing += 1
            else:
                used.add(stream)
                _shortcut_into(ole, stream, fields, problems_of, ctx, entry["entry_id"])
            out.put(name, entry["last_access"], fields, problems_of, {"stream": name, "offset": entry["offset"]})
        if missing:
            ctx.note(
                "entry without a shortcut stream", count=missing, detail="the record is made from the DestList alone"
            )
        unlisted = 0
        for name in sorted(set(by_name.values()) - used, key=lambda text: int(text, 16)):
            unlisted += 1
            fields = {"entry_id": int(name, 16), "listed": False, "position": None, "has_shortcut": False}
            problems_of = []
            ts = _shortcut_into(ole, name, fields, problems_of, ctx, int(name, 16))
            out.put(name.lower(), ts, fields, problems_of, {"stream": name})
        if unlisted:
            ctx.note(
                "shortcut stream not in the DestList",
                count=unlisted,
                detail="kept as records with listed false: entries the list no longer names",
            )
        return header["entries"] + unlisted
    finally:
        ole.close()


def _shortcut_into(ole, stream: str, fields: dict[str, Any], problems: list[str], ctx, entry_id: int) -> int | None:
    """Decode the shortcut of one entry into ``fields`` and give its own time; a stream that does not decode is a skip
    (the entry stays, from the DestList)."""
    try:
        size = ole.get_size(stream)
        if size > lnk.MAX_SIZE:
            ctx.skip("shortcut stream too large to read", lost=0, length=size, detail=f"entry {entry_id:x}")
            return None
        raw = ole.openstream(stream).read()
    except _OLE_ERRORS as exc:
        ctx.skip(
            "shortcut stream cannot be read",
            lost=0,
            detail=f"entry {entry_id:x}: {type(exc).__name__}: {str(exc)[:200]}",
        )
        return None
    try:
        found = lnk.decode(raw)
    except ValueError as exc:
        ctx.skip("shortcut of an entry cannot be read", lost=0, length=len(raw), detail=f"entry {entry_id:x}: {exc}")
        return None
    problems.extend(found["problems"])
    keep = _link_fields(found)
    destlist_target = fields.get("target")
    fields.update(keep)
    fields["target"] = keep["target"] or destlist_target
    fields["has_shortcut"] = True
    return found["ts"]  # the shortcut's own time: the only one an unlisted stream has


# -- custom destinations ---------------------------------------------------------- #
def _read_custom(path: str, ctx, out: _Out) -> int | None:
    size = os.path.getsize(path)
    if size > MAX_FILE:
        ctx.skip("file too large to read", lost=0, length=size, detail=f"{size} bytes, the limit is {MAX_FILE}")
        return None
    with open(path, "rb") as handle:
        data = handle.read(MAX_FILE + 1)
    if len(data) < 12 or struct.unpack_from("<I", data, 0)[0] != 2:
        ctx.skip("custom destinations header not known", lost=0, offset=0, detail="expected version 2")
        return None
    categories = struct.unpack_from("<I", data, 4)[0]
    if categories > MAX_CATEGORIES:
        ctx.skip("too many categories", lost=0, offset=4, detail=f"{categories}, the limit is {MAX_CATEGORIES}")
        return None
    at = 12
    declared = 0
    for category in range(categories):
        if at + 4 > len(data):
            ctx.skip("category header cut short", offset=at, lost=0, detail=f"category {category} of {categories}")
            return declared
        kind = struct.unpack_from("<I", data, at)[0]
        at += 4
        label = ""
        count = 0
        if kind == 0:
            if at + 2 > len(data):
                ctx.skip("category header cut short", offset=at, lost=0, detail=f"category {category}")
                return declared
            chars = struct.unpack_from("<H", data, at)[0]
            if at + 2 + chars * 2 + 4 > len(data):
                ctx.skip("category header cut short", offset=at, lost=0, detail=f"category {category}")
                return declared
            label = data[at + 2 : at + 2 + chars * 2].decode("utf-16-le", "replace")
            at += 2 + chars * 2
            count = struct.unpack_from("<I", data, at)[0]
            at += 4
        elif kind in (1, 2):
            if at + 4 > len(data):
                ctx.skip("category header cut short", offset=at, lost=0, detail=f"category {category}")
                return declared
            value = struct.unpack_from("<I", data, at)[0]
            at += 4
            if kind == 1:
                label = {1: "Frequent", 2: "Recent"}.get(value, f"known category {value}")
            else:
                label, count = "Tasks", value
        else:
            ctx.skip("category type not known", offset=at - 4, lost=0, detail=f"category {category}: type {kind}")
            return declared
        declared += count
        for index in range(count):
            if data[at : at + 16] != lnk.CLSID:
                ctx.skip(
                    "entry is not a shortcut",
                    offset=at,
                    lost=count - index,
                    detail=f"category {category} ({label}), entry {index}: its class identifier is not a shell link's",
                )
                return declared
            start = at + 16
            length, why = lnk.extent(data, start)
            if why:
                ctx.skip(
                    "shortcut of an entry is cut short or damaged",
                    offset=start,
                    length=len(data) - start,
                    lost=count - index,
                    detail=f"category {category} ({label}), entry {index}: {why}",
                )
                return declared
            raw = data[start : start + length]
            at = start + length
            try:
                found = lnk.decode(raw)
            except ValueError as exc:
                ctx.skip(
                    "shortcut of an entry cannot be read",
                    offset=start,
                    length=length,
                    detail=f"category {category} ({label}), entry {index}: {exc}",
                )
                continue
            fields = _link_fields(found)
            fields.update(
                {"category": label, "category_type": kind, "position": index, "pinned": None, "has_shortcut": True}
            )
            digest = hashlib.sha1(raw).hexdigest()[:16]  # noqa: S324
            out.put(
                f"c{category}-{digest}", found["ts"], fields, found["problems"], {"offset": start, "length": length}
            )
        if at + 4 > len(data) or struct.unpack_from("<I", data, at)[0] != FOOTER:
            ctx.skip(
                "category footer is not where the structure says",
                offset=at,
                lost=0,
                detail=f"category {category} ({label})",
            )
            return declared
        at += 4
    if at < len(data):
        ctx.skip("bytes after the last category", offset=at, length=len(data) - at, lost=0)
    return declared


def parse(path: str, ctx, source: str) -> None:
    host = str(ctx.params.get("host") or "")
    ctx.source(NAME, VERSION, KIND, SOURCE, host=host, username=str(ctx.params.get("username") or ""))
    with open(path, "rb") as handle:
        head = handle.read(8)
    custom = not head.startswith(OLE_MAGIC)
    out = _Out(ctx, path, "custom" if custom else "automatic")
    if not custom and os.path.getsize(path) > MAX_FILE:
        ctx.skip(
            "file too large to read", lost=0, length=os.path.getsize(path), detail=f"the limit is {MAX_FILE} bytes"
        )
        out.finish(None)
        return
    in_file = _read_custom(path, ctx, out) if custom else _read_automatic(path, ctx, out)
    out.finish(in_file)


# --------------------------------------------------------------------------- #
# The view of a record                                                        #
# --------------------------------------------------------------------------- #
def view(path: str, source: str, loc: dict) -> dict:
    """The shortcut of the entry as the library reads it (an automatic list: the DestList entry too), and its bytes."""
    if "stream" in loc:
        import olefile

        name = loc.get("stream")
        if not isinstance(name, str) or not _STREAM_NAME.match(name.lower()):
            raise BadLocator("The locator of the record has no stream name")
        try:
            ole = olefile.OleFileIO(path)
        except _OLE_ERRORS as exc:
            raise ViewError(f"The file cannot be opened as a compound file: {type(exc).__name__}") from None
        try:
            if not ole.exists(name) or ole.get_size(name) > lnk.MAX_SIZE:
                raise ViewError(f"The compound file holds no stream {name} that can be shown")
            raw = ole.openstream(name).read()
            rows: list[list[str]] = []
            if ole.exists("DestList") and ole.get_size("DestList") <= MAX_STREAM:
                _header, entries, _problems = read_destlist(ole.openstream("DestList").read())
                wanted = int(name, 16)
                for entry in entries:
                    if entry["entry_id"] == wanted:
                        rows = [[f"destlist {key}", viewing.as_text(value)] for key, value in entry.items()]
                        break
        except _OLE_ERRORS as exc:
            raise ViewError(f"The compound file cannot be read: {type(exc).__name__}") from None
        finally:
            ole.close()
        where: dict[str, Any] = {"stream": name}
    else:
        offset, length = (viewing.loc_int(loc, key) for key in ("offset", "length"))
        if length > lnk.MAX_SIZE or offset + length > os.path.getsize(path):
            raise ViewError("The shortcut the locator names is not in this file")
        with open(path, "rb") as handle:
            handle.seek(offset)
            raw = handle.read(length)
        rows = []
        where = {"offset": offset, "length": length}
    try:
        found = lnk.decode(raw)
        rows += lnk.rows_of(found["json"])
        if found["problems"]:
            rows.insert(0, ["problems", "\n".join(found["problems"])])
    except ValueError as exc:
        rows.append(["shortcut", f"cannot be read: {exc}"])
    return {
        "kind": "fields",
        "title": "The entry of the jump list and its shortcut",
        "where": where,
        "rows": rows,
        "text": viewing.hex_dump(raw[:65536], 0),
    }

"""Windows registry hives (``regf``): SYSTEM, SOFTWARE, NTUSER.DAT, UsrClass.dat and Amcache.hve.

One file holds several sources and the person gives one file, so the parser reads **everything it knows from the
hive it is given** and writes each record with the source it belongs to (``ctx.record(source=...)``, the ``src``
of the line). The sources are the names of the endpoint page:

    windows.registry.hive                 the umbrella a person picks for "a hive, read what is in it"
    windows.execution.amcache             Amcache.hve: InventoryApplicationFile (SHA-1 as an indicator),
                                          InventoryApplication
    windows.execution.shimcache           SYSTEM: AppCompatCache, one record per entry (the time is the FILE's last
                                          modified time, not a time of execution)
    windows.execution.userassist          NTUSER.DAT: UserAssist (ROT13 decoded), run count, focus time, last run
    windows.execution.bam-hive            SYSTEM: BAM and DAM (path, user SID, last run)
    windows.persistence.runkeys-hive      SOFTWARE (and its Wow6432Node) and NTUSER.DAT: Run, RunOnce
    windows.persistence.services-hive     SYSTEM: Services (ImagePath, ServiceDll, Start, Type, ObjectName)
    windows.usb.usbstor-hive              SYSTEM: USBSTOR devices and their first install, last arrival, last removal
    windows.usb.mounteddevices            SYSTEM: MountedDevices (letter or volume GUID, the device it names)
    windows.fileaccess.recentdocs         NTUSER.DAT: RecentDocs (the most recent entry of each key has its time)

A specific source reads only that source; the umbrella (and a file with no source) reads every source of the kind of
hive the file is. Which hive it is, is decided by its root keys first and its own name field second.

What is counted and what is said. The hive is walked cell by cell (``Hive.scan``), independently of the keys the
readers follow: a block or a cell that does not make sense is a skip with its offset; the counts of keys and values in
the cells are a note. ``in_file`` is what the structures the readers followed say they hold (the values of a Run key,
the subkeys of Services…): ``read`` plus the skips that lost something gives it back. A cell the readers could not read
is a skip with its offset; a value larger than 16 MiB is read to that size and said; a hive that takes more than ten
minutes stops there and says what was left. A hive whose two sequence numbers differ is **dirty**: it is read as it
is and a note says its transaction logs (``.LOG1`` and ``.LOG2``, not given: one file is) were not applied, so the
newest changes may be missing.

Keys are ``reg:<host or ?>:<hive kind>:<key path>:<value name>`` (a record of a key, not of a value, has an empty value
name; a ShimCache entry has the time and the path of the file after ``AppCompatCache``). The place of a record
(``loc``) is the key path, the value name and the offset of the key's cell; ``view`` shows that key with its values.

Standard library, and regipy (MIT, with an Apache-2.0 ShimCache parser) for the cache formats older than Windows 8.
"""

from __future__ import annotations

import struct
from typing import Any

from nik_forensics import viewing
from nik_forensics.parsers import BadLocator, ViewError
from nik_forensics.parsers.hive_parts import readers
from nik_forensics.parsers.hive_parts.readers import ALL_SOURCES, SOURCES_OF_KIND, UMBRELLA, Reader
from nik_forensics.parsers.hive_parts.regf import CellError, Hive, LimitHit, RegfError, decode, iso

NAME = "hive"
VERSION = "1"
KIND = "endpoint"
SOURCES = (UMBRELLA, *ALL_SOURCES)

# What a hive may be given in all (ten minutes); a bigger or slower one is read as far as the time goes.
SECONDS = 600.0


def _silent(*_args: object) -> None:
    return None


def detect_kind(hive: Hive) -> str:
    """ "system", "software", "ntuser", "usrclass", "amcache", or "" for a hive Nik reads nothing of."""
    try:
        root = hive.root()
        top = {key.name.casefold() for key in hive.iter_subkeys(root, _silent)}
        if "controlset001" in top or "select" in top:
            return "system"
        if "root" in top:
            sub = hive.find("Root", _silent)
            inside = {key.name.casefold() for key in hive.iter_subkeys(sub, _silent)} if sub is not None else set()
            if inside & {"inventoryapplicationfile", "inventoryapplication", "file", "inventorydevicepnp"}:
                return "amcache"
        if "local settings" in top or "clsid" in top:
            return "usrclass"
        if "software" in top or "appevents" in top or "volatile environment" in top:
            return "ntuser"
        if "microsoft" in top or ("wow6432node" in top and "classes" in top):
            return "software"
    except (CellError, LimitHit):
        pass
    # The name field holds 32 characters: "\SystemRoot\System32\Config\SYSTEM" is kept as "...\Config\SYST".
    last = hive.name.casefold().replace("/", "\\").rsplit("\\", 1)[-1]
    if last in ("amcache.hve", "usrclass.dat", "ntuser.dat"):
        return {"amcache.hve": "amcache", "usrclass.dat": "usrclass", "ntuser.dat": "ntuser"}[last]
    if len(last) >= 3 and "system".startswith(last):
        return "system"
    if len(last) >= 4 and "software".startswith(last):
        return "software"
    return ""


def sniff(path: str, name: str, head: bytes) -> str | None:
    """A registry hive, by its ``regf`` header: the umbrella source (which sources it holds depends on the hive)."""
    if head[:4] != b"regf":
        return None
    try:
        with Hive(path) as hive:
            hive.root()
    except (RegfError, CellError, OSError, struct.error):
        return None
    return UMBRELLA


def parse(path: str, ctx: Any, source: str) -> None:
    if source not in SOURCES:
        raise ValueError(f"The hive parser has no source called {source}")
    hive = Hive(path, SECONDS)  # a file that is not a hive raises: the file is reported as not read
    try:
        _parse(hive, ctx, source)
    finally:
        hive.close()


def _parse(hive: Hive, ctx: Any, source: str) -> None:
    ctx.params = ctx.params or {}
    kind = detect_kind(hive)
    host = str(ctx.params.get("host") or "")
    username = str(ctx.params.get("username") or "")
    helper = Reader(ctx, hive, kind, host)
    try:
        if kind == "system":
            helper.pick_control_set()
            host = host or helper.computer_name()
            helper.host = host
    except LimitHit:
        pass
    ctx.source(NAME, VERSION, KIND, source, host=host, username=username)

    def where(offset: int, reason: str, lost: int, length: int | None = None) -> None:
        ctx.skip(reason, offset=offset, length=length, lost=lost, detail="walking every cell of the hive")

    stopped = False
    try:
        counts = hive.scan(where)
    except LimitHit:
        counts = {}
        stopped = True
    if hive.dirty:
        ctx.note(
            "hive is dirty, its transaction logs were not given",
            detail=f"sequence numbers {hive.seq1} and {hive.seq2} differ: the newest changes may be missing",
        )
    if not hive.checksum_ok:
        ctx.note("checksum of the hive header does not match", detail="the header may be damaged; the cells were read")
    if counts:
        ctx.note(
            "cells of the hive counted",
            detail=(
                f"{counts['keys']} keys and {counts['values']} values in {counts['blocks']} blocks of cells "
                f"({counts['free']} free cells); hive name {hive.name or 'none'}, kind {kind or 'not known'}"
            ),
        )

    wanted = list(SOURCES_OF_KIND.get(kind, ())) if source == UMBRELLA else [source]
    if source == UMBRELLA and not wanted:
        ctx.note(
            "no source of Nik reads this hive",
            detail=f"kind {kind or 'not known'}: Nik reads SYSTEM, SOFTWARE, NTUSER.DAT and Amcache.hve",
        )
    elif source != UMBRELLA and source not in SOURCES_OF_KIND.get(kind, ()):
        ctx.note(
            "this hive does not hold the source asked for",
            detail=f"{source} is not in a {kind or 'unknown'} hive; nothing was read",
        )
        wanted = []
    methods = {
        "amcache": helper.read_amcache,
        "shimcache": helper.read_shimcache,
        "userassist": helper.read_userassist,
        "bam-hive": helper.read_bam,
        "runkeys-hive": helper.read_runkeys,
        "services-hive": helper.read_services,
        "usbstor-hive": helper.read_usbstor,
        "mounteddevices": helper.read_mounteddevices,
        "recentdocs": helper.read_recentdocs,
    }
    left = []
    for name in wanted:
        if stopped:
            left.append(name)
            continue
        try:
            methods[readers.short_id(name)](name)
        except LimitHit:
            stopped = True
            left.append(name)
        except (CellError, struct.error, ValueError, IndexError, OverflowError) as error:
            ctx.skip(
                "a source could not be read to its end",
                lost=0,
                detail=f"{name}: {type(error).__name__}: {str(error)[:200]}",
            )
    if stopped:
        ctx.skip(
            "the time given to the hive is over, the rest is not read",
            lost=0,
            detail=f"not read: {', '.join(left) or 'the end of the last source'}",
        )
    for reason, count in helper.notes.items():
        if count > 0:
            ctx.note(reason, count=count)
    for sid, count in helper.no_time.items():
        ctx.note(f"{sid} records without a time", count=count, detail="the format keeps no time for them")
    ctx.end(in_file=None if stopped else max(0, helper.expected))


# --------------------------------------------------------------------------- #
# The view of a record                                                        #
# --------------------------------------------------------------------------- #
MAX_ROWS = 400
PREVIEW = 64
VALUE_TYPES = {
    0: "none",
    1: "string",
    2: "string with variables",
    3: "binary",
    4: "dword",
    5: "dword, big endian",
    6: "link",
    7: "list of strings",
    11: "qword",
}


def _preview(hive: Hive, value: Any) -> str:
    kind = VALUE_TYPES.get(value.type, f"type {value.type}")
    if value.size > 64 * 1024:
        return f"{kind}, {value.size} bytes (too large to show here)"
    try:
        raw, _more = hive.data(value)
    except CellError as error:
        return f"{kind}, cannot be read: {error.reason}"
    shown = decode(value.type, raw)
    if isinstance(shown, bytes):
        text = shown[:PREVIEW].hex() + (" …" if len(shown) > PREVIEW else "")
        return f"{kind}, {len(shown)} bytes: {text}"
    if isinstance(shown, list):
        shown = "; ".join(shown)
    return f"{kind}: {shown}"


def view(path: str, source: str, loc: dict) -> dict:
    """The key a record came from, with its values: the offset of its cell (``loc["offset"]``) finds it."""
    if source not in SOURCES:
        raise ViewError(f"The hive parser has no source called {source}")
    offset = viewing.loc_int(loc, "offset")
    key_path = loc.get("key")
    if not isinstance(key_path, str):
        raise BadLocator("The locator of the record has no key path")
    try:
        hive = Hive(path)
    except RegfError as error:
        raise ViewError(f"The file is not a registry hive: {error}") from None
    try:
        try:
            key = hive.key(offset)
        except CellError as error:
            raise ViewError(f"The hive has no key at offset {offset}: {error.reason}") from None
        if key.name.casefold() != key_path.rsplit("\\", 1)[-1].casefold() and key_path:
            raise ViewError(f"The key at offset {offset} is {key.name}, not the key of the record")
        chosen = str(loc.get("value") or "")
        rows: list[list[str]] = [
            ["key", key_path],
            ["last write of the key", iso(key.ts) or "no time"],
            ["offset of the key cell", f"{offset:#x}"],
            ["subkeys", str(key.subkey_count)],
            ["values", str(key.value_count)],
        ]
        if loc.get("path_of_entry"):
            rows.append(["entry of the cache", f"position {loc.get('position')}: {loc['path_of_entry']}"])
        values = []
        try:
            values = list(hive.iter_values(key, _silent))
        except LimitHit:
            pass
        values.sort(key=lambda value: value.name != chosen)  # the value of the record first
        for value in values[:MAX_ROWS]:
            label = value.name or "(default)"
            rows.append(
                [
                    f"value {label}" + ("  <- this record" if chosen and value.name == chosen else ""),
                    _preview(hive, value),
                ]
            )
        if len(values) > MAX_ROWS:
            rows.append(["more values", f"{len(values) - MAX_ROWS} not shown"])
    finally:
        hive.close()
    return viewing.fit(
        {
            "kind": "fields",
            "title": f"The key {key_path} of the registry hive",
            "where": {"offset": offset, "key": key_path, "value": chosen},
            "rows": rows,
        }
    )

"""Windows prefetch files (.pf): which programs ran, when, and what each loaded.

Read with libscca (``pyscca``, LGPL-3.0, imported and never changed), which also unpacks the Windows 10 and 11 files
(``MAM`` compression, formats 17 to 31). One ``.pf`` is one file and one executable: a Windows prefetch folder holds
hundreds of them, each small, and each is imported on its own.

**Records.** One per recorded run time: Windows keeps the last eight (the last one for formats 17 and 23). A record
holds the executable name, the prefetch hash, the run count, the volumes the program touched (serial, creation time,
device path), and ``run_index`` (0 is the newest). The record of the **most recent** run also holds, in its ``data``,
the files the program loaded (``files``, at most ``MAX_FILES``: a longer list is a skip that says how many were left
out, the viewer shows them all) and ``executable_path``, the loaded file whose name is the executable's. libscca gives
the loaded files and no directory strings.

The key is ``pf:<host>:<executable>:<hash>:<run time in ms>``. ``ts`` is that run time.

**What it counts.** ``in_file`` is the number of stored run times that are not zero: libscca returns the eight slots,
the empty ones as zero, and a format that stores fewer than eight refuses the index (an error taken as the end of the
list). A run count above the stored times is a note (the older runs have no time kept). A file with no time at all is
one record without ``ts`` (and ``in_file`` 1): the file says the program ran, and that is kept. libscca is
all-or-nothing: a file it refuses is a skip with its sentence and nothing else.

Every file is hostile: a file larger than ``MAX_SIZE`` is not read, and a ``MAM`` file that says it expands to more than
``MAX_UNPACKED`` bytes is refused before the library sees it.
"""

from __future__ import annotations

import io
import os
import re
import struct
from datetime import datetime, timezone
from typing import Any

from nik_forensics import viewing
from nik_forensics.parsers import ViewError
from nik_forensics.parsers.lnk import filetime_ms

NAME = "prefetch"
VERSION = "1"
KIND = "endpoint"
SOURCES = ("windows.execution.prefetch",)

SOURCE = SOURCES[0]
MAX_SIZE = 16 * 1024 * 1024
MAX_UNPACKED = 64 * 1024 * 1024
MAX_FILES = 2000
WINDOWS = {17: "Windows XP", 23: "Windows Vista or 7", 26: "Windows 8", 30: "Windows 10", 31: "Windows 11"}


def sniff(path: str, name: str, head: bytes) -> str | None:
    """``SCCA`` at byte 4 (an uncompressed file), or ``MAM`` and a name that ends in ``.pf`` (a compressed one)."""
    if len(head) >= 8 and head[4:8] == b"SCCA":
        return SOURCE
    if head[:4] == b"MAM\x04" and (name or "").lower().endswith(".pf"):
        return SOURCE
    return None


def _open(data: bytes):
    """The libscca file for ``data``, or a ``ValueError`` that says why not."""
    import pyscca

    if data[:4] == b"MAM\x04" and len(data) >= 8 and struct.unpack_from("<I", data, 4)[0] > MAX_UNPACKED:
        raise ValueError(
            f"the file says it expands to {struct.unpack_from('<I', data, 4)[0]} bytes, the limit is {MAX_UNPACKED}"
        )
    handle = pyscca.file()
    try:
        handle.open_file_object(io.BytesIO(data))
    except (OSError, ValueError) as exc:
        raise ValueError(re.sub(r"\s+", " ", str(exc))[:300]) from None
    return handle


def _run_times(handle) -> list[int]:
    """The stored run times as FILETIMEs, newest first, the zero slots left out."""
    times: list[int] = []
    for index in range(8):
        try:
            value = handle.get_last_run_time_as_integer(index)
        except (OSError, IndexError, ValueError):  # a format that keeps fewer than eight
            break
        if value:
            times.append(value)
    return times


def _volumes(handle) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    for index in range(handle.number_of_volumes):
        try:
            volume = handle.get_volume_information(index)
            found.append(
                {
                    "serial": f"{volume.serial_number:08X}",
                    "created": filetime_ms(volume.get_creation_time_as_integer()),
                    "device_path": volume.device_path,
                }
            )
        except (OSError, ValueError) as exc:
            found.append({"error": re.sub(r"\s+", " ", str(exc))[:200]})
    return found


def _read(path: str) -> tuple[bytes, Any]:
    size = os.path.getsize(path)
    if size > MAX_SIZE:
        raise ValueError(f"the file is {size} bytes, the limit is {MAX_SIZE}")
    with open(path, "rb") as handle:
        data = handle.read(MAX_SIZE + 1)
    return data, _open(data)


def parse(path: str, ctx, source: str) -> None:
    host = str(ctx.params.get("host") or "")
    username = str(ctx.params.get("username") or "")
    ctx.source(NAME, VERSION, KIND, SOURCE, host=host, username=username)
    try:
        data, handle = _read(path)
    except ValueError as exc:
        ctx.skip("prefetch file cannot be read", lost=0, detail=str(exc))
        ctx.end(in_file=None)
        return
    try:
        executable = str(handle.executable_filename or "")
        prefetch_hash = f"{handle.prefetch_hash:08X}"
        run_count = int(handle.run_count)
        format_version = int(handle.format_version)
        times = _run_times(handle)
        volumes = _volumes(handle)
        names: list[str] = []
        unreadable = 0
        for index in range(handle.number_of_filenames):
            try:
                names.append(str(handle.get_filename(index)))
            except (OSError, ValueError):
                unreadable += 1
    finally:
        handle.close()
    in_path = next((name for name in names if name.upper().endswith("\\" + executable.upper())), "")
    newest = max(times) if times else None
    common = {
        "executable": executable,
        "prefetch_hash": prefetch_hash,
        "run_count": run_count,
        "format_version": format_version,
        "windows": WINDOWS.get(format_version, ""),
        "volumes": volumes,
        "executable_path": in_path,
        "files_total": len(names),
    }
    shown = names[:MAX_FILES]
    for index, ticks in enumerate(times or [0]):
        ts = filetime_ms(ticks)
        record = dict(common, run_index=index)
        if ticks == newest or not times:
            record["files"] = shown
        ctx.record(
            key=f"pf:{host}:{executable}:{prefetch_hash}:{ts if ts is not None else ticks}",
            type="prefetch",
            ts=ts,
            host=host,
            username=username,
            summary=f"{executable} ran, run count {run_count}" if index == 0 else f"{executable} ran",
            data=record,
            loc={"offset": 0, "length": len(data), "run": index},
        )
    if not times:
        ctx.note("no run time stored", detail=f"{executable}: run count {run_count}, no time kept in the file")
    elif run_count > len(times):
        ctx.note(
            "run count above the stored run times",
            count=run_count - len(times),
            detail=f"{executable}: {run_count} runs, the file keeps the time of {len(times)}",
        )
    if len(names) > MAX_FILES:
        ctx.skip(
            "list of loaded files cut",
            lost=0,
            detail=f"{len(names) - MAX_FILES} of {len(names)} file names left out of the record; "
            "the viewer shows them all",
        )
    if unreadable:
        ctx.skip("loaded file names that cannot be read", lost=unreadable, detail=f"{unreadable} of the names")
    ctx.end(in_file=max(len(times), 1))


# --------------------------------------------------------------------------- #
# The view of a record                                                        #
# --------------------------------------------------------------------------- #
def _iso(ms: int | None) -> str:
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).isoformat() if ms is not None else ""


def view(path: str, source: str, loc: dict) -> dict:
    """The header fields of the file (executable, hash, format, run count, every run time, the volumes) and, as text,
    the strings it holds: the files it loaded, one a line."""
    try:
        data, handle = _read(path)
    except ValueError as exc:
        raise ViewError(f"The file cannot be read as a prefetch file: {exc}") from None
    try:
        times = _run_times(handle)
        rows = [
            ["executable", str(handle.executable_filename)],
            ["prefetch hash", f"{handle.prefetch_hash:08X}"],
            ["format version", f"{handle.format_version} ({WINDOWS.get(int(handle.format_version), 'not known')})"],
            ["run count", str(handle.run_count)],
        ]
        rows += [[f"run time {index}", _iso(filetime_ms(ticks))] for index, ticks in enumerate(times)]
        for index, volume in enumerate(_volumes(handle)):
            rows.append([f"volume {index}", viewing.as_text(volume)])
        names = []
        for index in range(handle.number_of_filenames):
            try:
                names.append(str(handle.get_filename(index)))
            except (OSError, ValueError):
                names.append("(cannot be read)")
    finally:
        handle.close()
    return {
        "kind": "fields",
        "title": "The prefetch file: its header and the files it loaded",
        "where": {"offset": 0, "length": len(data)},
        "rows": rows,
        "text": "\n".join(names),
    }

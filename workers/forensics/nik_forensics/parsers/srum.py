"""SRUM (``SRUDB.dat``): the System Resource Usage Monitor's database, what each program did on the host.

An ESE database, read with libesedb (``pyesedb``, LGPL-3.0, imported and never changed). Windows writes one row per
program, user and hour. Two tables are read, and each gives its own source (a record carries it, ``source=``):

    {973F5D5C-1D90-4944-BE8E-24B94231A174}   network data usage       windows.network.srum-network
        program, user, interface (LUID, profile), bytes sent and received
    {D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}   application resource usage   windows.network.srum-apps
        program, user, foreground and background CPU cycles, face time, context switches, bytes read and written

``SruDbIdMapTable`` turns the numbers a row holds into names: a program (UTF-16 text: a path, a service, a package
name) and a user (a binary SID, shown as ``S-1-5-...``); ``username`` of a record is that SID. A number the table does
not hold is kept as a number (a note counts them).

**Times.** ``TimeStamp`` is an OLE automation date (days since 1899-12-30, a double), UTC, the end of the hour the row
sums. A row whose time is empty or out of range is kept without ``ts`` (a note counts them).

**What it counts.** ``in_file`` is the sum of the record counts of the two tables as the database's own catalogue says
them. Rows are streamed (one at a time, never a table in memory) and at most ``MAX_ROWS`` of a table are read: the rest
is a skip that says how many. A row libesedb cannot read is a skip with the table and its position; the first
``MAX_SKIPS`` of a table are said one by one, the others in one skip with their number. A table that is not in the
database is a note; one that cannot be opened is a skip. libesedb does **not** replay the log files (``SRU*.log``):
a database that was not closed cleanly (state in its header is not "clean shutdown") is a note that the newest rows may
be missing. The columns of a table are read by name and type, so a column a newer Windows adds is kept, under its
name in snake case.

The key is ``srum:<host>:<table>:<AutoIncId>`` with ``<table>`` ``network`` or ``apps``. ``loc`` is
``{"table", "index", "id"}``: the table's short name, the row's position in the table, its AutoIncId. Every file is
hostile: nothing is executed, rows are bounded, and the ids table is read up to ``MAX_IDS`` entries.
"""

from __future__ import annotations

import math
import re
import struct
from datetime import datetime, timezone
from typing import Any

from nik_forensics import viewing
from nik_forensics.parsers import BadLocator, ViewError
from nik_forensics.parsers.lnk import MAX_MS

NAME = "srum"
VERSION = "1"
KIND = "endpoint"
SOURCES = ("windows.network.srum-network", "windows.network.srum-apps")

ESE_SIGNATURE = bytes.fromhex("efcdab89")
MAX_ROWS = 500_000
MAX_SKIPS = 50
MAX_IDS = 1_000_000
MAX_BLOB = 4096  # an id's blob is a path or a SID: a longer one is cut
ID_TABLE = "SruDbIdMapTable"
OLE_EPOCH_DAYS = 25569.0  # days from 1899-12-30 to 1970-01-01
CLEAN_SHUTDOWN = 3
STATES = {1: "just created", 2: "dirty shutdown", 3: "clean shutdown", 4: "being converted", 5: "force detach"}

# short name -> (table GUID, source, columns that are not data fields of their own)
TABLES = {
    "network": ("{973F5D5C-1D90-4944-BE8E-24B94231A174}", "windows.network.srum-network"),
    "apps": ("{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}", "windows.network.srum-apps"),
}
_RENAMED = {"BytesRecvd": "bytes_received", "L2ProfileId": "profile_id", "L2ProfileFlags": "profile_flags"}
_HEAD = {"AutoIncId", "TimeStamp", "AppId", "UserId"}

# pyesedb column types
_BOOLEAN, _U8, _I16, _I32, _CURRENCY, _F32, _F64, _DATE = 1, 2, 3, 4, 5, 6, 7, 8
_TEXT, _LARGE_TEXT, _U32, _I64, _GUID, _U16 = 10, 12, 14, 15, 16, 17


def ese_header(head: bytes) -> dict[str, int] | None:
    """The fields of an ESE database's header that we use, None when it is not one."""
    if len(head) < 240 or head[4:8] != ESE_SIGNATURE:
        return None
    return {
        "type": struct.unpack_from("<I", head, 12)[0],
        "state": struct.unpack_from("<I", head, 52)[0],
        "page_size": struct.unpack_from("<I", head, 236)[0],
    }


def sniff(path: str, name: str, head: bytes) -> str | None:
    """An ESE database that is SRUDB: by its name, or by holding the ids table (the file is opened to look)."""
    header = ese_header(head)
    if header is None or header["type"] != 0:
        return None
    if re.split(r"[\\/]", name or "")[-1].lower().startswith("srudb"):
        return SOURCES[0]
    try:
        db = _open_db(path)
    except (OSError, ValueError):
        return None
    try:
        return SOURCES[0] if _table(db, ID_TABLE) is not None else None
    finally:
        db.close()


def _open_db(path: str):
    import pyesedb

    db = pyesedb.file()
    try:
        db.open(path)
    except (OSError, ValueError) as exc:
        raise ValueError(one_line(exc, 300)) from None
    return db


def _table(db, name: str):
    """The table called ``name`` (the name is compared as the database spells it), None when there is none."""
    for index in range(db.number_of_tables):
        try:
            table = db.get_table(index)
        except (OSError, ValueError):
            continue
        if str(table.name).lower() == name.lower():
            return table
    return None


# --------------------------------------------------------------------------- #
# Values                                                                      #
# --------------------------------------------------------------------------- #
def one_line(text: Any, limit: int = 200) -> str:
    """A library error as one short line."""
    return re.sub(r"\s+", " ", str(text))[:limit]


def snake(name: str) -> str:
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name).lower()


def decode_value(kind: int, raw: bytes | None) -> Any:
    """A column's raw bytes as a Python value, by the column's type (nothing is asked of the library for it)."""
    if raw is None:
        return None
    try:
        if kind == _BOOLEAN:
            return bool(raw[0]) if raw else None
        if kind == _U8:
            return raw[0] if raw else None
        if kind == _I16 and len(raw) == 2:
            return struct.unpack("<h", raw)[0]
        if kind == _U16 and len(raw) == 2:
            return struct.unpack("<H", raw)[0]
        if kind == _I32 and len(raw) == 4:
            return struct.unpack("<i", raw)[0]
        if kind == _U32 and len(raw) == 4:
            return struct.unpack("<I", raw)[0]
        if kind in (_I64, _CURRENCY) and len(raw) == 8:
            return struct.unpack("<q", raw)[0]
        if kind == _F32 and len(raw) == 4:
            return struct.unpack("<f", raw)[0]
        if kind in (_F64, _DATE) and len(raw) == 8:
            return struct.unpack("<d", raw)[0]
        if kind in (_TEXT, _LARGE_TEXT):
            return raw.decode("utf-8", "replace").rstrip("\x00")
    except (struct.error, IndexError):
        return raw.hex()
    return raw.hex()


def ole_ms(days: Any) -> int | None:
    """An OLE automation date as milliseconds since the epoch, None when empty or not a time anyone can print."""
    if not isinstance(days, float) or not math.isfinite(days) or days == 0.0:
        return None
    ms = round((days - OLE_EPOCH_DAYS) * 86_400_000)
    return ms if -MAX_MS <= ms <= MAX_MS else None


def sid_text(blob: bytes) -> str:
    """A binary SID as ``S-1-5-21-...``; the blob as hex when it is not one."""
    try:
        revision, count = blob[0], blob[1]
        if count > 15 or len(blob) < 8 + 4 * count:
            return blob.hex()
        authority = int.from_bytes(blob[2:8], "big")
        subs = struct.unpack_from(f"<{count}I", blob, 8)
        return f"S-{revision}-{authority}" + "".join(f"-{value}" for value in subs)
    except (IndexError, struct.error):
        return blob.hex()


def id_text(id_type: Any, blob: bytes | None) -> str:
    """What an ids-table entry names: a SID (type 3) or UTF-16 text (the others)."""
    if not blob:
        return ""
    if id_type == 3:
        return sid_text(blob)
    return blob.decode("utf-16-le", "replace").rstrip("\x00")


def read_ids(db, ctx=None) -> dict[int, str]:
    """The ids table as ``{IdIndex: name}``; ``ctx`` is told when it is missing, cut or has rows that cannot be read."""
    table = _table(db, ID_TABLE)
    if table is None:
        if ctx is not None:
            ctx.note("ids table missing", detail=f"{ID_TABLE} is not in the database: programs and users stay numbers")
        return {}
    ids: dict[int, str] = {}
    bad = 0
    total = table.number_of_records
    for index in range(min(total, MAX_IDS)):
        try:
            record = table.get_record(index)
            id_type = decode_value(_U8, record.get_value_data(0))
            key = decode_value(_I32, record.get_value_data(1))
            blob = record.get_value_data(2)
        except (OSError, ValueError):
            bad += 1
            continue
        if isinstance(key, int):
            ids[key] = id_text(id_type, blob[:MAX_BLOB] if blob else blob)
    if ctx is not None:
        if bad:
            ctx.skip(
                "rows of the ids table cannot be read",
                lost=0,
                detail=f"{bad} of {total}: their programs and users stay numbers",
            )
        if total > MAX_IDS:
            ctx.skip("ids table cut", lost=0, detail=f"{total - MAX_IDS} of {total} entries left out")
    return ids


# --------------------------------------------------------------------------- #
# Reading                                                                     #
# --------------------------------------------------------------------------- #
def _row(table, columns: list[tuple[str, int]], index: int) -> dict[str, Any]:
    record = table.get_record(index)
    return {name: decode_value(kind, record.get_value_data(position)) for position, (name, kind) in enumerate(columns)}


def _columns(table) -> list[tuple[str, int]]:
    return [(str(table.get_column(i).name), int(table.get_column(i).type)) for i in range(table.number_of_columns)]


def _fields(table_key: str, row: dict[str, Any], ids: dict[int, str]) -> tuple[dict[str, Any], int]:
    """The ``data`` of a row; and how many of its two ids the ids table could not name."""
    app_id, user_id = row.get("AppId"), row.get("UserId")
    missing = 0
    app = ids.get(app_id) if isinstance(app_id, int) else None
    user = ids.get(user_id) if isinstance(user_id, int) else None
    missing += app is None and app_id is not None
    missing += user is None and user_id is not None
    data: dict[str, Any] = {
        "table": table_key,
        "app": app or "",
        "app_id": app_id,
        "user": user or "",
        "user_id": user_id,
    }
    for name, value in row.items():
        if name in _HEAD:
            continue
        if name == "InterfaceLuid" and isinstance(value, int):
            luid = value & 0xFFFFFFFFFFFFFFFF
            data["interface_luid"] = f"0x{luid:016x}"
            data["interface_index"] = (luid >> 24) & 0xFFFFFF
            data["interface_type"] = luid >> 48
            continue
        data[_RENAMED.get(name) or snake(name)] = value
    if (
        table_key == "network"
        and isinstance(data.get("bytes_sent"), int)
        and isinstance(data.get("bytes_received"), int)
    ):
        data["bytes_total"] = data["bytes_sent"] + data["bytes_received"]
    return data, int(missing)


def _human(count: Any) -> str:
    if not isinstance(count, int):
        return "?"
    size = float(count)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return str(count)


def _summary(table_key: str, data: dict[str, Any]) -> str:
    app = data["app"] or f"program #{data['app_id']}"
    if table_key == "network":
        return f"{app}: {_human(data.get('bytes_sent'))} sent, {_human(data.get('bytes_received'))} received"
    read, written = _human(data.get("foreground_bytes_read")), _human(data.get("foreground_bytes_written"))
    return f"{app}: {read} read, {written} written"


def parse(path: str, ctx, source: str) -> None:
    host = str(ctx.params.get("host") or "")
    ctx.source(NAME, VERSION, KIND, source if source in SOURCES else SOURCES[0], host=host)
    with open(path, "rb") as handle:
        header = ese_header(handle.read(4096))
    if header is None or header["type"] != 0:
        ctx.skip("not an ESE database", lost=0, detail="the header has no ESE signature, or it is a streaming file")
        ctx.end(in_file=None)
        return
    if header["state"] != CLEAN_SHUTDOWN:
        ctx.note(
            "database not closed cleanly",
            detail=(
                f"state: {STATES.get(header['state'], header['state'])}. The log files (SRU*.log) are not replayed: "
                "the newest rows may be missing"
            ),
        )
    try:
        db = _open_db(path)
    except ValueError as exc:
        ctx.skip("database cannot be opened", lost=0, detail=str(exc))
        ctx.end(in_file=None)
        return
    try:
        ids = read_ids(db, ctx)
        in_file = 0
        unnamed = no_time = bad_time = 0
        for key, (guid, src) in TABLES.items():
            table = _table(db, guid)
            if table is None:
                ctx.note(
                    "table not in the database", detail=f"{guid} ({src}) is not there: this Windows did not keep it"
                )
                continue
            try:
                columns = _columns(table)
                total = int(table.number_of_records)
            except (OSError, ValueError) as exc:
                ctx.skip("table cannot be opened", lost=0, detail=f"{guid}: {one_line(exc)}")
                continue
            in_file += total
            names = {name for name, _kind in columns}
            if "TimeStamp" not in names or "AppId" not in names:
                ctx.skip(
                    "table has not the columns it should",
                    lost=total,
                    detail=f"{guid}: {', '.join(sorted(names))[:300]}",
                )
                continue
            bad = 0
            for index in range(min(total, MAX_ROWS)):
                try:
                    row = _row(table, columns, index)
                except (OSError, ValueError) as exc:
                    bad += 1
                    if bad <= MAX_SKIPS:
                        ctx.skip(
                            "row cannot be read",
                            lost=1,
                            detail=f"{guid}, row {index} of {total}: {one_line(exc)}",
                        )
                    continue
                days = row.get("TimeStamp")
                ts = ole_ms(days)
                if ts is None:
                    no_time += 1
                    bad_time += days not in (None, 0.0)
                data, missing = _fields(key, row, ids)
                unnamed += missing
                row_id = row.get("AutoIncId")
                ctx.record(
                    key=f"srum:{host}:{key}:{row_id if isinstance(row_id, int) else f'r{index}'}",
                    type=f"srum-{key}",
                    ts=ts,
                    host=host,
                    username=data["user"],
                    summary=_summary(key, data),
                    data=data,
                    loc={"table": key, "index": index, "id": row_id},
                    source=src,
                )
            if bad > MAX_SKIPS:
                ctx.skip(
                    "more rows that cannot be read",
                    lost=bad - MAX_SKIPS,
                    detail=f"{guid}: {bad} in all, the first {MAX_SKIPS} are said one by one",
                )
            if total > MAX_ROWS:
                ctx.skip(
                    "row limit reached",
                    lost=total - MAX_ROWS,
                    detail=f"{guid}: the first {MAX_ROWS} of {total} rows are read",
                )
        if no_time:
            ctx.note(
                "row without a usable time", count=no_time, detail=f"{bad_time} of them hold a value that is not a time"
            )
        if unnamed:
            ctx.note("id not in the ids table", count=unnamed, detail="a program or user stays a number")
        ctx.end(in_file=in_file)
    finally:
        db.close()


# --------------------------------------------------------------------------- #
# The view of a record                                                        #
# --------------------------------------------------------------------------- #
def view(path: str, source: str, loc: dict) -> dict:
    """The whole row, every column by its name as the database holds it, and the program and the user it names."""
    key = loc.get("table")
    if key not in TABLES:
        raise BadLocator("The locator of the record names no SRUM table")
    index = viewing.loc_int(loc, "index")
    try:
        db = _open_db(path)
    except ValueError as exc:
        raise ViewError(f"The file cannot be opened as an ESE database: {exc}") from None
    try:
        table = _table(db, TABLES[key][0])
        if table is None:
            raise ViewError(f"The database has no table {TABLES[key][0]}")
        if index >= table.number_of_records:
            raise ViewError(f"The table holds no row {index} (it holds {table.number_of_records})")
        columns = _columns(table)
        try:
            row = _row(table, columns, index)
        except (OSError, ValueError) as exc:
            raise ViewError(f"The row cannot be read: {one_line(exc)}") from None
        wanted = {row.get("AppId"), row.get("UserId")} - {None}
        names = {key_: value for key_, value in read_ids(db).items() if key_ in wanted} if wanted else {}
    finally:
        db.close()
    rows = [[name, viewing.as_text(row.get(name))] for name, _kind in columns]
    rows.append(["AppId names", names.get(row.get("AppId"), "(not in the ids table)")])
    rows.append(["UserId names", names.get(row.get("UserId"), "(not in the ids table)")])
    days = row.get("TimeStamp")
    if isinstance(days, float):
        moment = ole_ms(days)
        rows.append(
            [
                "TimeStamp as a date",
                datetime.fromtimestamp(moment / 1000, tz=timezone.utc).isoformat()
                if moment is not None
                else "(not a time)",
            ]
        )
    return {
        "kind": "fields",
        "title": f"Row {index} of the table {TABLES[key][0]}",
        "where": {"table": key, "index": index},
        "rows": rows,
    }

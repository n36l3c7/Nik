"""What a registry hive holds that Nik reads: the readers of each source, on top of ``regf.Hive``.

One ``Reader`` per parse. It holds the hive, the host and the counts, and each ``read_*`` method reads one source
and writes its records with ``Reader.put`` (the key is ``reg:<host>:<hive kind>:<key path>:<value name>``, the
locator the key path, the value name and the offset of the key's cell). What is counted:

    expected   the items the structures the readers followed say they hold (the values of a Run key, the subkeys
               of Services…): the ``in_file`` of the parse. A value that is not an entry (the MRU list of
               RecentDocs, the version of BAM) is taken off again and said in a note.
    lost       every cell that could not be read, with its offset: a skip.

Times are the key's last write unless the source has its own; every record says which in ``ts_is``.
"""

from __future__ import annotations

import codecs
import re
import struct
from collections import defaultdict
from typing import Any

from nik_forensics.parsers.hive_parts.regf import (
    CellError,
    Hive,
    Key,
    Value,
    decode,
    filetime_ms,
    iso,
)

# What a person picks for "a hive, read what is in it": every source the kind of the hive has.
UMBRELLA = "windows.registry.hive"
SOURCES_OF_KIND = {
    "system": (
        "windows.execution.shimcache",
        "windows.execution.bam-hive",
        "windows.persistence.services-hive",
        "windows.usb.usbstor-hive",
        "windows.usb.mounteddevices",
    ),
    "software": ("windows.persistence.runkeys-hive",),
    "ntuser": (
        "windows.persistence.runkeys-hive",
        "windows.execution.userassist",
        "windows.fileaccess.recentdocs",
    ),
    "amcache": ("windows.execution.amcache",),
    "usrclass": (),
}
ALL_SOURCES = (
    "windows.execution.amcache",
    "windows.execution.shimcache",
    "windows.execution.userassist",
    "windows.execution.bam-hive",
    "windows.persistence.runkeys-hive",
    "windows.persistence.services-hive",
    "windows.usb.usbstor-hive",
    "windows.usb.mounteddevices",
    "windows.fileaccess.recentdocs",
)

RUN_KEYS = (
    "Microsoft\\Windows\\CurrentVersion\\Run",
    "Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
    "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
    "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
)
USERASSIST = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist"
RECENTDOCS = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs"
SHIM_KEYS = ("Control\\Session Manager\\AppCompatCache", "Control\\Session Manager\\AppCompatibility")
USB_PROPERTIES = "Properties\\{83da6326-97a6-4088-9453-a1923f573b29}"
USB_TIMES = (("0064", "install_date"), ("0065", "first_install"), ("0066", "last_arrival"), ("0067", "last_removal"))
START = {0: "boot", 1: "system", 2: "automatic", 3: "manual", 4: "disabled"}
SERVICE_TYPE = {
    1: "kernel driver",
    2: "file system driver",
    16: "own process",
    32: "shared process",
    96: "user service",
    272: "own process, interactive",
    288: "shared process, interactive",
}
MAX_TEXT = 4000  # bytes of a binary value shown as text
_USB_DEVICE = re.compile(r"^(?P<class>[^&]*)&Ven_(?P<vendor>[^&]*)&Prod_(?P<product>[^&]*)(?:&Rev_(?P<rev>.*))?$", re.I)
_HEX40 = re.compile(r"^[0-9a-fA-F]{40}$")


def short_id(source: str) -> str:
    return source.rsplit(".", 1)[1]


def text_of(value: Any) -> str:
    """A value as text. A string is kept whole (the context cuts it and the record says so); bytes are cut."""
    if isinstance(value, bytes):
        return value[:MAX_TEXT].hex()
    if isinstance(value, list):
        return "; ".join(str(part) for part in value)
    return str(value)


def jsonable(value: Any) -> Any:
    """A value for the data of a record: text, numbers, bytes as hex (the context cuts what is too long)."""
    if isinstance(value, bytes):
        return value[:256].hex()
    return value


class Reader:
    def __init__(self, ctx: Any, hive: Hive, kind: str, host: str) -> None:
        self.ctx = ctx
        self.hive = hive
        self.kind = kind
        self.host = host
        self.username = str(ctx.params.get("username") or "")
        self.expected = 0
        self.notes: dict[str, int] = defaultdict(int)
        self.no_time: dict[str, int] = defaultdict(int)
        self.read_keys = 0
        self.read_values = 0
        self.cs = ""  # the control set of a SYSTEM hive: "ControlSet001"
        self._said: set[tuple[int, str, int]] = set()

    # -- what a reader says --------------------------------------------------- #
    def reporter(self, where: str, counts: bool = True, navigating: bool = False):
        """What a walk says about a cell it could not read: a skip with its offset. A cell is said once however many
        walks pass it. ``counts``: the cell is one of the items the reader expects (a value of a Run key, a service),
        so it costs ``lost`` of them; a cell of a key that only has a record made from it costs none that is known.
        ``navigating``: the walk only looks for a key on the way to another and says what it meets with a lost of 0;
        the walk that reads that key's children says it again with the loss."""

        def report(offset: int, reason: str, lost: int, length: int | None = None) -> None:
            lost = lost if counts and not navigating else 0
            if (offset, reason, lost) in self._said:
                return
            self._said.add((offset, reason, lost))
            what = f"looking for {where}" if navigating else where
            self.ctx.skip(reason, offset=offset, length=length, lost=lost, detail=f"while reading {what}"[:480])

        return report

    def note(self, reason: str, count: int = 1) -> None:
        self.notes[reason] += count

    def not_entry(self, reason: str, count: int = 1) -> None:
        """A value that is not an entry of the source: counted by the key, taken off, said in a note."""
        self.expected -= count
        self.note(reason, count)

    def put(
        self,
        source: str,
        key_path: str,
        value_name: str,
        key: Key,
        *,
        ts: int | None,
        ts_is: str,
        summary: str,
        data: dict[str, Any],
        key_name: str = "",
        loc_more: dict[str, Any] | None = None,
        ioc: list[tuple[str, str]] | None = None,
        username: str = "",
    ) -> None:
        sid = short_id(source)
        if ts is None:
            self.no_time[sid] += 1
        self.ctx.record(
            key=f"reg:{self.host or '?'}:{self.kind}:{key_path}:{key_name or value_name}",
            type=sid,
            ts=ts,
            host=self.host,
            username=username or self.username,
            summary=summary,
            data={
                "category": source.split(".")[1],
                "os": "windows",
                "hive": self.kind,
                "key": key_path,
                "key_last_write": iso(key.ts),
                "ts_is": ts_is if ts is not None else "",
                **data,
            },
            loc={"key": key_path, "value": value_name, "offset": key.offset, **(loc_more or {})},
            ioc=ioc or (),
            source=source,
        )

    # -- helpers -------------------------------------------------------------- #
    def value_data(self, value: Value, path: str, lost: int) -> tuple[bytes | None, bool]:
        """The bytes of a value; None (and a skip with ``lost``) when its cells cannot be read. A value past the
        reader's size cap is cut and said in a skip that loses nothing known."""
        try:
            raw, more = self.hive.data(value)
        except CellError as error:
            self.ctx.skip(
                f"value data: {error.reason}", offset=error.offset, lost=lost, detail=f"{path}\\{value.name}"[:480]
            )
            return None, False
        if more:
            self.ctx.skip(
                "value is larger than the reader keeps, its start was read",
                offset=value.offset,
                lost=0,
                detail=f"{path}\\{value.name}: {value.size} bytes, {len(raw)} read",
            )
        return raw, more

    def values_of(self, key: Key, path: str) -> dict[str, tuple[int, Any]]:
        """All the values of a key by name (without case): (type, decoded). A value that cannot be read is a
        skip with lost 0: the record the key makes is kept without it."""
        out: dict[str, tuple[int, Any]] = {}
        for value in self.hive.iter_values(key, self.reporter(path, counts=False)):
            raw, _more = self.value_data(value, path, 0)
            if raw is not None:
                out[value.name.casefold()] = (value.type, decode(value.type, raw))
        return out

    def find(self, path: str, start: Key | None = None) -> Key | None:
        return self.hive.find(path, self.reporter(path, navigating=True), start)

    def subkeys(self, key: Key, path: str) -> list[Key]:
        return list(self.hive.iter_subkeys(key, self.reporter(path, counts=False)))

    # -- the hive's own facts ------------------------------------------------- #
    def pick_control_set(self) -> None:
        select = self.find("Select")
        number = 0
        if select is not None:
            for value in self.hive.iter_values(select, self.reporter("Select", counts=False)):
                if value.name.casefold() == "current":
                    raw, _ = self.value_data(value, "Select", 0)
                    if raw is not None and isinstance(decode(value.type, raw), int):
                        number = int(decode(value.type, raw))
        for candidate in ([number] if number else []) + [1]:
            name = f"ControlSet{candidate:03d}"
            if self.find(name) is not None:
                self.cs = name
                return
        self.note("system hive without a control set")

    def computer_name(self) -> str:
        if not self.cs:
            return ""
        key = self.find(f"{self.cs}\\Control\\ComputerName\\ComputerName")
        if key is None:
            return ""
        for value in self.hive.iter_values(key, self.reporter("ComputerName", counts=False)):
            if value.name.casefold() == "computername":
                raw, _ = self.value_data(value, "ComputerName", 0)
                return text_of(decode(value.type, raw)) if raw is not None else ""
        return ""

    # -- Run and RunOnce ------------------------------------------------------ #
    def read_runkeys(self, source: str) -> None:
        base = "" if self.kind == "software" else "Software\\"
        top = self.find("Software") if base else self.hive.root()
        if top is None:
            return
        for relative in RUN_KEYS:
            path = base + relative
            key = self.find(relative, top)
            if key is None:
                continue
            self.expected += key.value_count
            for value in self.hive.iter_values(key, self.reporter(path)):
                raw, _ = self.value_data(value, path, 1)
                if raw is None:
                    continue
                command = text_of(decode(value.type, raw))
                name = value.name or "(default)"
                self.put(
                    source,
                    path,
                    value.name,
                    key,
                    ts=key.ts,
                    ts_is="last write of the key",
                    summary=f"{name} — {command}"[:300],
                    data={"name": name, "command": command, "kind": relative.rsplit("\\", 1)[1], "location": path},
                    loc_more={},
                )

    # -- Services ------------------------------------------------------------- #
    def read_services(self, source: str) -> None:
        if not self.cs:
            return
        path = f"{self.cs}\\Services"
        top = self.find(path)
        if top is None:
            return
        self.expected += top.subkey_count
        for service in self.hive.iter_subkeys(top, self.reporter(path)):
            spath = f"{path}\\{service.name}"
            values = self.values_of(service, spath)
            dll = ""
            parameters = self.find("Parameters", service)
            if parameters is not None:
                dll = text_of(self.values_of(parameters, spath + "\\Parameters").get("servicedll", (0, ""))[1])
            image = text_of(values.get("imagepath", (0, ""))[1])
            start = values.get("start", (0, None))[1]
            vtype = values.get("type", (0, None))[1]
            data = {
                "name": service.name,
                "display_name": text_of(values.get("displayname", (0, ""))[1]),
                "image_path": image,
                "service_dll": dll,
                "start": start if isinstance(start, int) else None,
                "start_label": START.get(start, "") if isinstance(start, int) else "",
                "service_type": vtype if isinstance(vtype, int) else None,
                "type_label": SERVICE_TYPE.get(vtype, "") if isinstance(vtype, int) else "",
                "object_name": text_of(values.get("objectname", (0, ""))[1]),
            }
            self.put(
                source,
                spath,
                "",
                service,
                ts=service.ts,
                ts_is="last write of the key",
                summary=f"{service.name} — {image or dll}"[:300] if image or dll else service.name,
                data=data,
            )

    # -- USBSTOR and MountedDevices ------------------------------------------- #
    def read_usbstor(self, source: str) -> None:
        if not self.cs:
            return
        path = f"{self.cs}\\Enum\\USBSTOR"
        top = self.find(path)
        if top is None:
            return
        for device in self.hive.iter_subkeys(top, self.reporter(path, counts=False)):
            dpath = f"{path}\\{device.name}"
            self.expected += device.subkey_count
            match = _USB_DEVICE.match(device.name)
            for instance in self.hive.iter_subkeys(device, self.reporter(dpath)):
                ipath = f"{dpath}\\{instance.name}"
                values = self.values_of(instance, ipath)
                times: dict[str, int | None] = {}
                for sub, label in USB_TIMES:
                    stamp = self.find(f"{USB_PROPERTIES}\\{sub}", instance)
                    times[label] = self._usb_time(stamp, ipath) if stamp is not None else None
                ts, ts_is = instance.ts, "last write of the key"
                for label, why in (
                    ("last_arrival", "last arrival of the device"),
                    ("first_install", "first install of the device"),
                    ("install_date", "install date of the device"),
                ):
                    if times.get(label) is not None:
                        ts, ts_is = times[label], why
                        break
                friendly = text_of(values.get("friendlyname", (0, ""))[1])
                serial = instance.name
                data = {
                    "device_class": device.name.split("&", 1)[0],
                    "vendor": match.group("vendor") if match else "",
                    "product": match.group("product") if match else "",
                    "revision": (match.group("rev") or "") if match else "",
                    "serial": serial,
                    "serial_is_unique": "&" not in serial[1:2] if len(serial) > 1 else False,
                    "friendly_name": friendly,
                    "class_guid": text_of(values.get("classguid", (0, ""))[1]),
                    "container_id": text_of(values.get("containerid", (0, ""))[1]),
                    **{label: iso(stamp) for label, stamp in times.items()},
                    **{f"{label}_ms": stamp for label, stamp in times.items() if stamp is not None},
                }
                what = friendly or device.name
                self.put(source, ipath, "", instance, ts=ts, ts_is=ts_is, summary=f"{what} — {serial}"[:300], data=data)

    def _usb_time(self, key: Key, path: str) -> int | None:
        for value in self.hive.iter_values(key, self.reporter(path, counts=False)):
            raw, _ = self.value_data(value, path, 0)
            if raw is not None and len(raw) >= 8:
                return filetime_ms(struct.unpack_from("<Q", raw)[0])
        return None

    def read_mounteddevices(self, source: str) -> None:
        key = self.find("MountedDevices")
        if key is None:
            return
        path = "MountedDevices"
        self.expected += key.value_count
        for value in self.hive.iter_values(key, self.reporter(path)):
            raw, _ = self.value_data(value, path, 1)
            if raw is None:
                continue
            letter = ""
            guid = ""
            if value.name.lower().startswith("\\dosdevices\\"):
                letter = value.name.rsplit("\\", 1)[1]
            else:
                found = re.search(r"\{[0-9a-fA-F-]{36}\}", value.name)
                guid = found.group(0) if found else value.name
            device, signature = "", ""
            if len(raw) == 12:
                signature = f"{struct.unpack_from('<I', raw)[0]:08x} at offset {struct.unpack_from('<Q', raw, 4)[0]}"
            else:
                try:
                    guess = raw.decode("utf-16le")
                except UnicodeDecodeError:
                    guess = ""
                if guess and guess.isprintable():
                    device = guess
            data = {
                "drive_letter": letter,
                "volume_guid": guid,
                "device": device,
                "disk_signature": signature,
                "usb": "usbstor" in device.lower(),
            }
            if not device and not signature:
                data["raw"] = raw[:64].hex()
            self.put(
                source,
                path,
                value.name,
                key,
                ts=None,
                ts_is="",
                summary=f"{letter or guid} — {device or signature or 'binary id'}"[:300],
                data=data,
            )

    # -- UserAssist ----------------------------------------------------------- #
    def read_userassist(self, source: str) -> None:
        top = self.find(USERASSIST)
        if top is None:
            return
        for group in self.hive.iter_subkeys(top, self.reporter(USERASSIST, counts=False)):
            count = self.find("Count", group)
            if count is None:
                continue
            cpath = f"{USERASSIST}\\{group.name}\\Count"
            self.expected += count.value_count
            for value in self.hive.iter_values(count, self.reporter(cpath)):
                raw, _ = self.value_data(value, cpath, 1)
                if raw is None:
                    continue
                name = codecs.decode(value.name, "rot13")
                data: dict[str, Any] = {"name": name, "group": group.name, "program": name}
                ts = None
                if len(raw) == 72:
                    session, runs, focus_count, focus_ms = struct.unpack_from("<IIII", raw, 0)
                    ts = filetime_ms(struct.unpack_from("<Q", raw, 60)[0])
                    data.update(session=session, run_count=runs, focus_count=focus_count, focus_time_ms=focus_ms)
                elif len(raw) == 16:  # Windows XP: the count starts at 5
                    session, runs = struct.unpack_from("<II", raw, 0)
                    ts = filetime_ms(struct.unpack_from("<Q", raw, 8)[0])
                    data.update(session=session, run_count=max(0, runs - 5))
                else:
                    data["raw"] = raw[:96].hex()
                    self.note("userassist values of a size that is not known (kept as bytes)")
                self.put(
                    source,
                    cpath,
                    value.name,
                    count,
                    ts=ts,
                    ts_is="last run",
                    summary=f"{name} — run {data['run_count']} times" if "run_count" in data else name,
                    data=data,
                )

    # -- BAM / DAM ------------------------------------------------------------ #
    def read_bam(self, source: str) -> None:
        if not self.cs:
            return
        for kind in ("bam", "dam"):
            for relative in (f"Services\\{kind}\\State\\UserSettings", f"Services\\{kind}\\UserSettings"):
                path = f"{self.cs}\\{relative}"
                top = self.find(path)
                if top is None:
                    continue
                for sid in self.hive.iter_subkeys(top, self.reporter(path, counts=False)):
                    spath = f"{path}\\{sid.name}"
                    self.expected += sid.value_count
                    for value in self.hive.iter_values(sid, self.reporter(spath)):
                        if value.type != 3 and value.type != 0:
                            self.not_entry("bam values that are not entries (version, sequence number)")
                            continue
                        raw, _ = self.value_data(value, spath, 1)
                        if raw is None:
                            continue
                        if len(raw) < 8:
                            self.not_entry("bam values that are not entries (version, sequence number)")
                            continue
                        ts = filetime_ms(struct.unpack_from("<Q", raw)[0])
                        self.put(
                            source,
                            spath,
                            value.name,
                            sid,
                            ts=ts,
                            ts_is="last run",
                            summary=f"{value.name} — {sid.name}"[:300],
                            data={"path": value.name, "name": value.name, "user_sid": sid.name, "kind": kind},
                            username=sid.name,
                        )
                break  # the first layout the hive has

    # -- RecentDocs ----------------------------------------------------------- #
    def read_recentdocs(self, source: str) -> None:
        top = self.find(RECENTDOCS)
        if top is None:
            return
        for key, extension in [(top, "")] + [(sub, sub.name) for sub in self.subkeys(top, RECENTDOCS)]:
            path = RECENTDOCS if not extension else f"{RECENTDOCS}\\{extension}"
            entries: list[tuple[Value, bytes]] = []
            order: list[int] = []
            self.expected += key.value_count
            for value in self.hive.iter_values(key, self.reporter(path)):
                raw, _ = self.value_data(value, path, 1)
                if raw is None:
                    continue
                if value.name.casefold() == "mrulistex":
                    order = [n for n in struct.unpack_from(f"<{len(raw) // 4}I", raw, 0)]
                    order = order[: order.index(0xFFFFFFFF)] if 0xFFFFFFFF in order else order
                    self.not_entry("recentdocs values that are the order of the list, not entries")
                elif value.name.isdigit():
                    entries.append((value, raw))
                else:
                    self.not_entry("recentdocs values that are not entries")
            position = {number: place for place, number in enumerate(order)}
            for value, raw in entries:
                cut = raw.find(b"\x00\x00")
                while cut != -1 and cut % 2:
                    cut = raw.find(b"\x00\x00", cut + 1)
                name = raw[: cut if cut != -1 else len(raw)].decode("utf-16le", "replace")
                place = position.get(int(value.name))
                self.put(
                    source,
                    path,
                    value.name,
                    key,
                    ts=key.ts if place == 0 else None,
                    ts_is="last write of the key, the most recent entry of it",
                    summary=f"{name} — {extension or 'all'}"[:300],
                    data={
                        "name": name,
                        "target": name,
                        "extension": extension or "(all)",
                        "mru_position": place,
                        "kind": "recent document",
                    },
                )

    # -- Amcache -------------------------------------------------------------- #
    def read_amcache(self, source: str) -> None:
        old = self.find("Root\\File")
        if old is not None:
            # Entries that exist and are not read: a skip that loses no known number of records.
            self.ctx.skip(
                "amcache entries in the format of Windows 7 and 8 are not read",
                offset=old.offset,
                lost=0,
                detail=f"the key Root\\File holds {old.subkey_count} volumes of entries; Nik reads the Inventory keys",
            )
        for table, fields in (
            (
                "InventoryApplicationFile",
                {
                    "lowercaselongpath": "path",
                    "name": "name",
                    "publisher": "publisher",
                    "productname": "product",
                    "productversion": "product_version",
                    "version": "version",
                    "size": "size",
                    "linkdate": "link_date",
                    "binarytype": "binary_type",
                    "isoscomponent": "is_os_component",
                    "programid": "program_id",
                    "longpathhash": "path_hash",
                    "language": "language",
                },
            ),
            (
                "InventoryApplication",
                {
                    "name": "name",
                    "version": "version",
                    "publisher": "publisher",
                    "installdate": "install_date",
                    "rootdirpath": "install_path",
                    "source": "install_source",
                    "programid": "program_id",
                    "type": "type",
                    "msipackagecode": "msi_package",
                },
            ),
        ):
            path = f"Root\\{table}"
            top = self.find(path)
            if top is None:
                continue
            self.expected += top.subkey_count
            for entry in self.hive.iter_subkeys(top, self.reporter(path)):
                epath = f"{path}\\{entry.name}"
                values = self.values_of(entry, epath)
                data: dict[str, Any] = {}
                other: dict[str, Any] = {}
                for name, (_type, decoded) in values.items():
                    if name == "fileid":
                        continue
                    if name in fields:
                        data[fields[name]] = jsonable(decoded)
                    else:
                        other[name] = jsonable(decoded)
                ioc = []
                if table == "InventoryApplicationFile":
                    file_id = text_of(values.get("fileid", (0, ""))[1])
                    sha1 = file_id[4:] if len(file_id) == 44 and file_id.startswith("0000") else file_id
                    if _HEX40.match(sha1):
                        data["sha1"] = sha1.lower()
                        ioc = [("sha1", sha1.lower())]
                    elif file_id:
                        data["file_id"] = file_id
                    shown = data.get("path") or data.get("name") or entry.name
                else:
                    shown = data.get("name") or entry.name
                if other:
                    data["other"] = other
                self.put(
                    source,
                    epath,
                    "",
                    entry,
                    ts=entry.ts,
                    ts_is="last write of the key",
                    summary=f"{shown}"[:300],
                    data={"table": table, **data},
                    ioc=ioc,
                )

    # -- ShimCache ------------------------------------------------------------ #
    def read_shimcache(self, source: str) -> None:
        if not self.cs:
            return
        for relative in SHIM_KEYS:
            path = f"{self.cs}\\{relative}"
            key = self.find(path)
            if key is None:
                continue
            for value in self.hive.iter_values(key, self.reporter(path, counts=False)):
                if value.name.casefold() != "appcompatcache":
                    continue
                raw, _ = self.value_data(value, path, 0)
                if raw is None:
                    self.ctx.skip("shimcache value cannot be read", offset=value.offset, lost=0, detail=path)
                    return
                self._shim_entries(source, path, key, value, raw)
                return

    def _shim_entries(self, source: str, path: str, key: Key, value: Value, raw: bytes) -> None:
        entries, problem = shim_entries(raw)
        seen: dict[str, int] = defaultdict(int)
        for position, entry in enumerate(entries):
            ts = filetime_ms(entry["filetime"]) if entry.get("filetime") else None
            base = f"{value.name}|{ts or 0}|{entry['path']}"
            seen[base] += 1
            name = base if seen[base] == 1 else f"{base}#{seen[base]}"
            self.expected += 1
            data = {"path": entry["path"], "name": re.split(r"[\\/]", entry["path"])[-1], "position": position}
            if "executed" in entry:
                data["executed"] = entry["executed"]
            self.put(
                source,
                path,
                value.name,
                key,
                ts=ts,
                ts_is="last modified time of the file, not a time of execution",
                summary=entry["path"][:300],
                data={**data, "format": entry["format"]},
                key_name=name,
                loc_more={"position": position, "path_of_entry": entry["path"][:200]},
            )
        declared = entries[0].get("declared") if entries else None
        missing = max(0, declared - len(entries)) if declared is not None else 0
        if problem:
            self.expected += missing
            self.ctx.skip(
                "shimcache stops at an entry that cannot be read",
                offset=key.offset,
                lost=missing,
                detail=f"{problem}; {len(entries)} entries before it were read",
            )
        elif missing:
            self.expected += missing
            self.ctx.skip(
                "shimcache has fewer entries than its header says",
                offset=key.offset,
                lost=missing,
                detail=f"header: {declared}, read: {len(entries)}",
            )


# --------------------------------------------------------------------------- #
# The AppCompatCache value                                                    #
# --------------------------------------------------------------------------- #
def shim_entries(raw: bytes) -> tuple[list[dict[str, Any]], str]:
    """The entries of an AppCompatCache value and a sentence about where it stopped ("" when it did not).

    Windows 10 and 8/8.1 (the ``10ts`` / ``00ts`` entries) are read here, so that an entry without a time or a
    cut entry is seen; the older formats (XP, 2003, Vista, 7) by the library that ships a parser for them (regipy,
    Apache-2.0 part), whose entries are counted against the number the header gives."""
    if len(raw) < 16:
        return [], "the value is shorter than any cache header" if raw else ""
    for start in (0x30, 0x34):
        if len(raw) > start + 4 and raw[start : start + 4] == b"10ts":
            return _shim_walk(raw, start, b"10ts", "windows 10", False)
    if len(raw) > 0x84 and raw[0x80:0x84] in (b"00ts", b"10ts"):
        return _shim_walk(raw, 0x80, raw[0x80:0x84], "windows 8", True)
    try:
        from regipy.plugins.system.external.ShimCacheParser import get_shimcache_entries
    except Exception as error:  # noqa: BLE001
        return [], f"the older cache formats need regipy: {type(error).__name__}"
    magic = struct.unpack_from("<I", raw)[0]
    declared = struct.unpack_from("<I", raw, 8 if magic == 0xDEADBEEF else 4)[0]
    entries: list[dict[str, Any]] = []
    try:
        for found in get_shimcache_entries(raw):
            when = found.get("last_mod_date") or found.get("last_mod_time")
            stamp = int(when.timestamp() * 10_000_000) + 116444736000000000 if hasattr(when, "timestamp") else 0
            entry = {
                "path": str(found.get("path", "")),
                "filetime": stamp,
                "format": f"older ({magic:#x})",
                "declared": declared,
            }
            if found.get("exec_flag") in ("True", "False"):
                entry["executed"] = found["exec_flag"] == "True"
            entries.append(entry)
            if len(entries) > 100_000:
                return entries, "more than 100000 entries"
    except Exception as error:  # noqa: BLE001 - the library raises plain exceptions on a cut value
        return entries, f"{type(error).__name__}: {str(error)[:120]}"
    if magic not in (0xBADC0FFE, 0xBADC0FEE, 0xDEADBEEF):
        return [], "the cache format is not known"
    return entries, ""


def _shim_walk(raw: bytes, start: int, magic: bytes, label: str, win8: bool) -> tuple[list[dict[str, Any]], str]:
    entries: list[dict[str, Any]] = []
    at = start
    while at + 12 <= len(raw):
        if raw[at : at + 4] != magic:
            if any(raw[at : at + 64]) or any(raw[at:]):
                return entries, f"bytes that are not an entry at byte {at} of the value"
            break
        entry_length = struct.unpack_from("<I", raw, at + 8)[0]
        body = raw[at + 12 : at + 12 + entry_length]
        if len(body) < entry_length or entry_length < 2:
            return entries, f"entry cut short at byte {at} of the value"
        path_length = struct.unpack_from("<H", body)[0]
        if 2 + path_length > len(body):
            return entries, f"path longer than its entry at byte {at} of the value"
        path = body[2 : 2 + path_length].decode("utf-16le", "replace") if path_length else ""
        cursor = 2 + path_length
        filetime, executed = 0, None
        if win8:
            if cursor + 2 > len(body):
                return entries, f"entry cut short at byte {at} of the value"
            package = struct.unpack_from("<H", body, cursor)[0]
            cursor += 2 + package
            if cursor + 20 > len(body):
                return entries, f"entry cut short at byte {at} of the value"
            flags = struct.unpack_from("<I", body, cursor)[0]
            filetime = struct.unpack_from("<Q", body, cursor + 8)[0]
            executed = bool(flags & 2)
        elif cursor + 8 <= len(body):
            filetime = struct.unpack_from("<Q", body, cursor)[0]
        else:
            return entries, f"entry cut short at byte {at} of the value"
        entry: dict[str, Any] = {"path": path or "(no path)", "filetime": filetime, "format": label}
        if executed is not None:
            entry["executed"] = executed
        entries.append(entry)
        at += 12 + entry_length
        if len(entries) > 100_000:
            return entries, "more than 100000 entries"
    return entries, ""

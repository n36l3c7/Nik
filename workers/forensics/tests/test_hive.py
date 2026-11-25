"""The registry hive parser: every source, the integrity checks, the view. Run in the worker's image.

Every hive is made here at test time by ``hive_builder.py`` (a minimal ``regf`` writer): harmless bytes, never evidence.
"""

from __future__ import annotations

import codecs
import io
import json
import os
import struct
import sys

import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "tests"))

import hive_builder as hb  # noqa: E402
from hive_builder import Node, Val, binary, dword, expand, sz  # noqa: E402

from nik_forensics import parsers  # noqa: E402
from nik_forensics.context import Context  # noqa: E402
from nik_forensics.parsers import ViewError, hive  # noqa: E402
from nik_forensics.parsers.hive_parts import regf  # noqa: E402

UMBRELLA = "windows.registry.hive"
CMD = "\\Device\\HarddiskVolume3\\Windows\\System32\\cmd.exe"
USB_DEVICE = "Disk&Ven_SanDisk&Prod_Cruzer&Rev_1.00"
PROPS = "{83da6326-97a6-4088-9453-a1923f573b29}"


def ft(seconds: float) -> bytes:
    return struct.pack("<Q", hb.filetime(seconds))


def ms(seconds: float) -> int:
    return int(seconds * 1000)


# --------------------------------------------------------------------------- #
# The hives                                                                   #
# --------------------------------------------------------------------------- #
def shim10(entries: list[tuple[str, float]], header: int = 0x30) -> bytes:
    out = bytearray(header)
    struct.pack_into("<I", out, 0, header)
    for path, seconds in entries:
        raw = path.encode("utf-16le")
        body = struct.pack("<H", len(raw)) + raw + struct.pack("<Q", hb.filetime(seconds) if seconds else 0) + bytes(4)
        out += b"10ts" + struct.pack("<II", 0, len(body)) + body
    return bytes(out)


def shim8(entries: list[tuple[str, float, bool]]) -> bytes:
    out = bytearray(0x80)
    for path, seconds, executed in entries:
        raw = path.encode("utf-16le")
        body = struct.pack("<H", len(raw)) + raw + struct.pack("<H", 0)
        body += struct.pack("<II", 2 if executed else 0, 0) + struct.pack("<Q", hb.filetime(seconds)) + bytes(4)
        out += b"00ts" + struct.pack("<II", 0, len(body)) + body
    return bytes(out)


def shim7(entries: list[tuple[str, float, bool]], declared: int | None = None) -> bytes:
    """Windows 7 / 2008 R2, 64-bit: a header of 0x80 bytes, entries of 0x30, the paths after them."""
    out = bytearray(0x80)
    struct.pack_into("<II", out, 0, 0xBADC0FEE, len(entries) if declared is None else declared)
    paths = bytearray()
    base = 0x80 + 0x30 * len(entries)
    for path, seconds, executed in entries:
        raw = path.encode("utf-16le")
        stamp = hb.filetime(seconds)
        out += struct.pack(
            "<2H4xQ4L2Q", len(raw), len(raw) + 2, base + len(paths), stamp & 0xFFFFFFFF, stamp >> 32,
            2 if executed else 0, 0, 0, 0,
        )  # fmt: skip
        paths += raw
    return bytes(out) + bytes(paths)


def system_hive(shim: bytes | None = None, **options) -> tuple[bytes, dict[str, int]]:
    shim = (
        shim
        if shim is not None
        else shim10(
            [
                ("C:\\Windows\\System32\\cmd.exe", 1_690_000_000),
                ("C:\\Tools\\psexec.exe", 1_600_000_000),
                ("C:\\Odd\\app.exe", 0),
            ]
        )
    )
    services = Node(
        "Services",
        list_kind=b"li",
        children=[
            Node(
                "Spooler",
                written=1_650_000_000,
                values=[
                    expand("ImagePath", "%SystemRoot%\\System32\\spoolsv.exe"),
                    sz("DisplayName", "Print Spooler"),
                    dword("Start", 2),
                    dword("Type", 16),
                    sz("ObjectName", "LocalSystem"),
                ],
            ),
            Node(
                "Dnscache",
                values=[
                    expand("ImagePath", "%SystemRoot%\\system32\\svchost.exe -k NetworkService"),
                    dword("Start", 2),
                    dword("Type", 32),
                ],
                children=[Node("Parameters", values=[expand("ServiceDll", "%SystemRoot%\\System32\\dnsrslvr.dll")])],
            ),
            Node(
                "bam",
                children=[
                    Node(
                        "State",
                        children=[
                            Node(
                                "UserSettings",
                                children=[
                                    Node(
                                        "S-1-5-21-1-2-3-1001",
                                        values=[
                                            binary(CMD, ft(1_699_000_000) + bytes(16)),
                                            dword("Version", 1),
                                            dword("SequenceNumber", 5),
                                        ],
                                    )
                                ],
                            )
                        ],
                    )
                ],
            ),
        ],
    )
    props = Node(
        "Properties",
        children=[
            Node(
                PROPS,
                children=[
                    Node("0064", values=[Val("", 16, ft(1_600_000_100))]),
                    Node("0065", values=[Val("", 16, ft(1_600_000_200))]),
                    Node("0066", values=[Val("", 16, ft(1_650_000_300))]),
                    Node("0067", values=[Val("", 16, ft(1_650_000_400))]),
                ],
            )
        ],
    )
    usb = Node(
        "Enum",
        children=[
            Node(
                "USBSTOR",
                children=[
                    Node(
                        USB_DEVICE,
                        children=[
                            Node(
                                "4C530001230412&0",
                                values=[sz("FriendlyName", "SanDisk Cruzer USB Device"), sz("ClassGUID", "{4d36e967}")],
                                children=[props],
                            )
                        ],
                    )
                ],
            )
        ],
    )
    control = Node(
        "Control",
        children=[
            Node("ComputerName", children=[Node("ComputerName", values=[sz("ComputerName", "WKS-9")])]),
            Node("Session Manager", children=[Node("AppCompatCache", values=[binary("AppCompatCache", shim)])]),
        ],
    )
    device = "\\??\\USBSTOR#" + USB_DEVICE + "#4C530001230412&0#{53f56307}"
    mounted = Node(
        "MountedDevices",
        values=[
            binary("\\DosDevices\\C:", struct.pack("<IQ", 0xDEADBEEF, 1048576)),
            binary("\\DosDevices\\E:", device.encode("utf-16le")),
            binary("\\??\\Volume{12345678-1234-1234-1234-123456789abc}", device.encode("utf-16le")),
        ],
    )
    root = Node(
        "ROOT",
        children=[
            Node("ControlSet001", children=[control, services, usb]),
            Node("Select", values=[dword("Current", 1)]),
            mounted,
        ],
    )
    return hb.build(root, **options)


def ua_value(count: int, focus_count: int, focus_ms: int, seconds: float) -> bytes:
    return struct.pack("<IIII", 0, count, focus_count, focus_ms) + bytes(44) + ft(seconds) + bytes(4)


def doc(name: str) -> bytes:
    return name.encode("utf-16le") + b"\x00\x00" + b"\x14\x00\x1f\x00shellitem"


def ntuser_hive(**options) -> tuple[bytes, dict[str, int]]:
    current = Node(
        "CurrentVersion",
        children=[
            Node(
                "Run",
                written=1_660_000_000,
                values=[sz("OneDrive", "C:\\Users\\a\\OneDrive.exe /background"), sz("Updater", "C:\\Temp\\upd.exe")],
            ),
            Node("RunOnce", written=1_660_000_500, values=[sz("Setup", "C:\\Temp\\setup.exe")]),
            Node(
                "Explorer",
                children=[
                    Node(
                        "UserAssist",
                        children=[
                            Node(
                                "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}",
                                children=[
                                    Node(
                                        "Count",
                                        values=[
                                            binary(
                                                codecs.encode("C:\\Windows\\System32\\cmd.exe", "rot13"),
                                                ua_value(7, 3, 125000, 1_670_000_000),
                                            ),
                                            binary(
                                                codecs.encode("OLDPROG.EXE", "rot13"),
                                                struct.pack("<II", 0, 9) + ft(1_300_000_000),
                                            ),
                                            binary(codecs.encode("ODD", "rot13"), b"abc"),
                                        ],
                                    )
                                ],
                            )
                        ],
                    ),
                    Node(
                        "RecentDocs",
                        written=1_680_000_000,
                        children=[
                            Node(
                                ".txt",
                                written=1_680_000_100,
                                values=[
                                    binary("MRUListEx", struct.pack("<II", 0, 0xFFFFFFFF)),
                                    binary("0", doc("notes.txt")),
                                ],
                            )
                        ],
                        values=[
                            binary("MRUListEx", struct.pack("<IIII", 2, 0, 1, 0xFFFFFFFF)),
                            binary("0", doc("report.docx")),
                            binary("1", doc("plan.xlsx")),
                            binary("2", doc("invoice.pdf")),
                        ],
                    ),
                ],
            ),
        ],
    )
    root = Node(
        "ROOT",
        children=[
            Node("Environment"),
            Node("Software", children=[Node("Microsoft", children=[Node("Windows", children=[current])])]),
        ],
    )
    return hb.build(root, name="\\??\\C:\\Users\\a\\ntuser.dat", **options)


def software_hive(**options) -> tuple[bytes, dict[str, int]]:
    def run(command: str) -> Node:
        return Node(
            "Microsoft",
            children=[
                Node(
                    "Windows", children=[Node("CurrentVersion", children=[Node("Run", values=[sz("Agent", command)])])]
                )
            ],
        )

    root = Node(
        "ROOT",
        children=[
            run("C:\\Program Files\\Agent\\agent.exe"),
            Node("Wow6432Node", children=[run("C:\\Old\\agent32.exe")]),
        ],
    )
    return hb.build(root, name="\\REGISTRY\\MACHINE\\SOFTWARE", **options)


def amcache_hive(**options) -> tuple[bytes, dict[str, int]]:
    sha = "0123456789abcdef0123456789abcdef01234567"
    files = Node(
        "InventoryApplicationFile",
        children=[
            Node(
                "cmd.exe|0123abcd",
                written=1_690_000_000,
                values=[
                    sz("FileId", "0000" + sha),
                    sz("LowerCaseLongPath", "c:\\windows\\system32\\cmd.exe"),
                    sz("Name", "cmd.exe"),
                    Val("Size", 11, struct.pack("<Q", 289792)),
                    sz("LinkDate", "04/01/2023 10:11:12"),
                    sz("Publisher", "microsoft corporation"),
                    sz("ProductName", "microsoft windows operating system"),
                ],
            ),
            Node("tool.exe|ffff", written=1_691_000_000, values=[sz("Name", "tool.exe"), sz("FileId", "not a hash")]),
        ],
    )
    apps = Node(
        "InventoryApplication",
        children=[
            Node(
                "0000abcd",
                written=1_692_000_000,
                values=[
                    sz("Name", "7-Zip"),
                    sz("Version", "23.01"),
                    sz("Publisher", "Igor Pavlov"),
                    sz("InstallDate", "2023-05-01"),
                ],
            )
        ],
    )
    root = Node("ROOT", children=[Node("Root", children=[files, apps])])
    return hb.build(root, name="amcache.hve", **options)


def usrclass_hive() -> bytes:
    root = Node("ROOT", children=[Node("Local Settings"), Node("CLSID")])
    return hb.build(root, name="\\??\\C:\\Users\\a\\UsrClass.dat")[0]


# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #
def write(tmp_path, name: str, data: bytes | str) -> str:
    path = tmp_path / name
    path.write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))
    return str(path)


def said(path: str, source: str = UMBRELLA, params: dict | None = None) -> list[dict]:
    out = io.BytesIO()
    hive.parse(path, Context(out, {"host": "WKS-1"} if params is None else params), source)
    return [json.loads(line) for line in out.getvalue().splitlines() if line]


def records(found: list[dict], source: str | None = None) -> list[dict]:
    return [e for e in found if e["t"] == "r" and (source is None or e["src"] == source)]


def notes(found: list[dict]) -> dict[str, int]:
    return {e["reason"]: e["count"] for e in found if e["t"] == "note"}


def skips(found: list[dict]) -> list[dict]:
    return [e for e in found if e["t"] == "skip"]


def end(found: list[dict]) -> dict:
    return next(e for e in found if e["t"] == "end")


def by_type(found: list[dict], kind: str) -> list[dict]:
    return [e for e in records(found) if e["type"] == kind]


# --------------------------------------------------------------------------- #
# The parser, its sources, how it recognises a hive                           #
# --------------------------------------------------------------------------- #
def test_the_sources_and_where_the_parser_is_found():
    assert (hive.NAME, hive.VERSION, hive.KIND) == ("hive", "1", "endpoint")
    assert set(hive.SOURCES) == {
        UMBRELLA,
        "windows.execution.amcache",
        "windows.execution.shimcache",
        "windows.execution.userassist",
        "windows.execution.bam-hive",
        "windows.persistence.runkeys-hive",
        "windows.persistence.services-hive",
        "windows.usb.usbstor-hive",
        "windows.usb.mounteddevices",
        "windows.fileaccess.recentdocs",
    }
    for source in hive.SOURCES:
        assert parsers.by_source("endpoint", source) is hive


@pytest.mark.parametrize(
    ("make", "kind"),
    [
        (lambda: system_hive()[0], "system"),
        (lambda: software_hive()[0], "software"),
        (lambda: ntuser_hive()[0], "ntuser"),
        (lambda: amcache_hive()[0], "amcache"),
        (lambda: usrclass_hive(), "usrclass"),
    ],
)
def test_each_hive_is_recognised_by_its_root_keys(tmp_path, make, kind):
    path = write(tmp_path, "any-name.bin", make())
    head = open(path, "rb").read(4096)
    assert hive.sniff(path, "any-name.bin", head) == UMBRELLA
    assert parsers.recognise(path, "any-name.bin") == (hive, UMBRELLA)
    with regf.Hive(path) as opened:
        assert hive.detect_kind(opened) == kind


def test_a_hive_with_no_known_root_is_known_by_its_name_field(tmp_path):
    data, _ = hb.build(Node("ROOT", children=[Node("Odd")]), name="\\SystemRoot\\System32\\Config\\SYSTEM")
    with regf.Hive(write(tmp_path, "odd", data)) as opened:
        assert hive.detect_kind(opened) == "system"
    data, _ = hb.build(Node("ROOT", children=[Node("Odd")]), name="SAM")
    path = write(tmp_path, "sam", data)
    with regf.Hive(path) as opened:
        assert hive.detect_kind(opened) == ""
    found = said(path)
    assert "no source of Nik reads this hive" in notes(found)
    assert records(found) == [] and end(found)["in_file"] == 0


def test_what_is_not_a_hive_is_not_sniffed(tmp_path):
    for name, data in (("a.txt", "regf is only a word here"), ("b.bin", b"regf" + b"\x00" * 100), ("c.bin", b"")):
        path = write(tmp_path, name, data)
        assert hive.sniff(path, name, data[:4096] if isinstance(data, bytes) else data.encode()[:4096]) is None
    # A header that says regf, with the rest of a hive that is not one: no root key.
    path = write(tmp_path, "d.bin", b"regf" + b"\x00" * 8000)
    assert hive.sniff(path, "d.bin", b"regf" + b"\x00" * 4092) is None
    with pytest.raises(regf.RegfError):
        said(write(tmp_path, "e.bin", b"not a hive at all" * 500))


# --------------------------------------------------------------------------- #
# What each source reads                                                      #
# --------------------------------------------------------------------------- #
def test_system_hive_gives_five_sources_and_its_host(tmp_path):
    path = write(tmp_path, "SYSTEM", system_hive()[0])
    found = said(path, params={})
    source = next(e for e in found if e["t"] == "source")
    assert (source["parser"], source["kind"], source["source"], source["host"]) == (
        "hive",
        "endpoint",
        UMBRELLA,
        "WKS-9",
    )
    assert {e["src"] for e in records(found)} == {
        "windows.execution.shimcache",
        "windows.execution.bam-hive",
        "windows.persistence.services-hive",
        "windows.usb.usbstor-hive",
        "windows.usb.mounteddevices",
    }
    assert all(e["host"] == "WKS-9" and e["key"].startswith("reg:WKS-9:system:") for e in records(found))
    # Clean hive: what the structures say they hold is what was read, and nothing was lost.
    assert skips(found) == []
    assert end(found)["in_file"] == end(found)["read"] == len(records(found)) == 11


def test_run_keys_of_ntuser_and_software(tmp_path):
    found = said(write(tmp_path, "NTUSER.DAT", ntuser_hive()[0]), "windows.persistence.runkeys-hive")
    rows = {r["data"]["name"]: r for r in records(found)}
    assert set(rows) == {"OneDrive", "Updater", "Setup"}
    run = rows["OneDrive"]
    assert (
        run["ts"] == ms(1_660_000_000)
        and run["type"] == "runkeys-hive"
        and run["src"] == "windows.persistence.runkeys-hive"
    )
    assert run["data"]["command"] == "C:\\Users\\a\\OneDrive.exe /background"
    assert run["data"]["kind"] == "Run" and rows["Setup"]["data"]["kind"] == "RunOnce"
    assert run["key"] == "reg:WKS-1:ntuser:Software\\Microsoft\\Windows\\CurrentVersion\\Run:OneDrive"
    assert (
        run["loc"]["key"] == "Software\\Microsoft\\Windows\\CurrentVersion\\Run" and run["loc"]["value"] == "OneDrive"
    )
    assert run["ioc"] == [] and end(found)["in_file"] == 3

    found = said(write(tmp_path, "SOFTWARE", software_hive()[0]), "windows.persistence.runkeys-hive")
    keys = sorted(r["key"] for r in records(found))
    assert keys == [
        "reg:WKS-1:software:Microsoft\\Windows\\CurrentVersion\\Run:Agent",
        "reg:WKS-1:software:Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run:Agent",
    ]


def test_services(tmp_path):
    found = said(write(tmp_path, "SYSTEM", system_hive()[0]), "windows.persistence.services-hive")
    rows = {r["data"]["name"]: r for r in records(found)}
    assert set(rows) == {"Spooler", "Dnscache", "bam"}
    spooler = rows["Spooler"]
    assert spooler["ts"] == ms(1_650_000_000)
    assert spooler["data"]["image_path"] == "%SystemRoot%\\System32\\spoolsv.exe"
    assert (spooler["data"]["display_name"], spooler["data"]["object_name"]) == ("Print Spooler", "LocalSystem")
    assert (spooler["data"]["start"], spooler["data"]["start_label"], spooler["data"]["type_label"]) == (
        2,
        "automatic",
        "own process",
    )
    assert rows["Dnscache"]["data"]["service_dll"] == "%SystemRoot%\\System32\\dnsrslvr.dll"
    assert spooler["key"] == "reg:WKS-1:system:ControlSet001\\Services\\Spooler:"
    assert end(found)["in_file"] == 3


def test_usbstor_and_mounteddevices(tmp_path):
    path = write(tmp_path, "SYSTEM", system_hive()[0])
    (device,) = records(said(path, "windows.usb.usbstor-hive"))
    data = device["data"]
    assert (data["vendor"], data["product"], data["revision"], data["device_class"]) == (
        "SanDisk",
        "Cruzer",
        "1.00",
        "Disk",
    )
    assert data["serial"] == "4C530001230412&0" and data["friendly_name"] == "SanDisk Cruzer USB Device"
    assert data["serial_is_unique"] is True
    assert (data["install_date_ms"], data["first_install_ms"]) == (ms(1_600_000_100), ms(1_600_000_200))
    assert (data["last_arrival_ms"], data["last_removal_ms"]) == (ms(1_650_000_300), ms(1_650_000_400))
    assert device["ts"] == ms(1_650_000_300) and "last arrival" in data["ts_is"]

    found = said(path, "windows.usb.mounteddevices")
    rows = {(r["data"]["drive_letter"] or r["data"]["volume_guid"]): r for r in records(found)}
    assert set(rows) == {"C:", "E:", "{12345678-1234-1234-1234-123456789abc}"}
    assert rows["C:"]["data"]["disk_signature"].startswith("deadbeef") and rows["C:"]["data"]["usb"] is False
    assert rows["E:"]["data"]["usb"] is True and "USBSTOR" in rows["E:"]["data"]["device"]
    assert all(r["ts"] is None for r in rows.values())
    assert notes(found)["mounteddevices records without a time"] == 3


def test_a_device_without_property_times_has_the_time_of_its_key(tmp_path):
    root = Node(
        "ROOT",
        children=[
            Node("Select", values=[dword("Current", 1)]),
            Node(
                "ControlSet001",
                children=[
                    Node(
                        "Enum",
                        children=[
                            Node(
                                "USBSTOR",
                                children=[Node(USB_DEVICE, children=[Node("6&1a2b3c&0", written=1_500_000_000)])],
                            )
                        ],
                    )
                ],
            ),
        ],
    )
    path = write(tmp_path, "SYSTEM", hb.build(root)[0])
    (device,) = records(said(path, "windows.usb.usbstor-hive"))
    assert device["ts"] == ms(1_500_000_000) and device["data"]["ts_is"] == "last write of the key"
    assert device["data"]["serial_is_unique"] is False and device["data"]["last_arrival"] == ""


def test_userassist(tmp_path):
    found = said(write(tmp_path, "NTUSER.DAT", ntuser_hive()[0]), "windows.execution.userassist")
    rows = {r["data"]["name"]: r for r in records(found)}
    assert set(rows) == {"C:\\Windows\\System32\\cmd.exe", "OLDPROG.EXE", "ODD"}
    cmd = rows["C:\\Windows\\System32\\cmd.exe"]
    assert cmd["ts"] == ms(1_670_000_000) and cmd["data"]["run_count"] == 7
    assert (cmd["data"]["focus_count"], cmd["data"]["focus_time_ms"]) == (3, 125000)
    assert rows["OLDPROG.EXE"]["data"]["run_count"] == 4 and rows["OLDPROG.EXE"]["ts"] == ms(1_300_000_000)
    assert rows["ODD"]["ts"] is None and rows["ODD"]["data"]["raw"] == "616263"
    assert "userassist values of a size that is not known (kept as bytes)" in notes(found)
    assert end(found)["in_file"] == end(found)["read"] == 3


def test_recentdocs_gives_the_time_of_the_key_to_the_first_of_each_only(tmp_path):
    found = said(write(tmp_path, "NTUSER.DAT", ntuser_hive()[0]), "windows.fileaccess.recentdocs")
    rows = {(r["data"]["extension"], r["data"]["name"]): r for r in records(found)}
    assert set(rows) == {
        ("(all)", "invoice.pdf"),
        ("(all)", "report.docx"),
        ("(all)", "plan.xlsx"),
        (".txt", "notes.txt"),
    }
    assert [rows[("(all)", n)]["data"]["mru_position"] for n in ("invoice.pdf", "report.docx", "plan.xlsx")] == [
        0,
        1,
        2,
    ]
    assert rows[("(all)", "invoice.pdf")]["ts"] == ms(1_680_000_000)
    assert rows[("(all)", "report.docx")]["ts"] is None and rows[(".txt", "notes.txt")]["ts"] == ms(1_680_000_100)
    assert notes(found)["recentdocs records without a time"] == 2
    assert notes(found)["recentdocs values that are the order of the list, not entries"] == 2
    assert end(found)["in_file"] == end(found)["read"] == 4


def test_bam(tmp_path):
    found = said(write(tmp_path, "SYSTEM", system_hive()[0]), "windows.execution.bam-hive")
    (row,) = records(found)
    assert row["ts"] == ms(1_699_000_000) and row["data"]["path"] == CMD and row["username"] == "S-1-5-21-1-2-3-1001"
    assert row["data"]["user_sid"] == "S-1-5-21-1-2-3-1001" and row["data"]["kind"] == "bam"
    assert notes(found)["bam values that are not entries (version, sequence number)"] == 2
    assert end(found)["in_file"] == 1


def test_amcache(tmp_path):
    found = said(write(tmp_path, "Amcache.hve", amcache_hive()[0]), "windows.execution.amcache")
    rows = {r["data"]["name"]: r for r in records(found)}
    assert set(rows) == {"cmd.exe", "tool.exe", "7-Zip"}
    cmd = rows["cmd.exe"]
    sha = "0123456789abcdef0123456789abcdef01234567"
    assert cmd["ioc"] == [["sha1", sha]] and cmd["data"]["sha1"] == sha
    assert cmd["ts"] == ms(1_690_000_000) and cmd["data"]["path"] == "c:\\windows\\system32\\cmd.exe"
    assert (cmd["data"]["size"], cmd["data"]["link_date"], cmd["data"]["publisher"]) == (
        289792,
        "04/01/2023 10:11:12",
        "microsoft corporation",
    )
    assert rows["tool.exe"]["ioc"] == [] and rows["tool.exe"]["data"]["file_id"] == "not a hash"
    app = rows["7-Zip"]
    assert (app["data"]["version"], app["data"]["publisher"], app["data"]["install_date"]) == (
        "23.01",
        "Igor Pavlov",
        "2023-05-01",
    )
    assert app["data"]["table"] == "InventoryApplication" and app["ts"] == ms(1_692_000_000)
    assert end(found)["in_file"] == 3


def test_shimcache_windows_10_one_record_each_with_the_time_of_the_file(tmp_path):
    found = said(write(tmp_path, "SYSTEM", system_hive()[0]), "windows.execution.shimcache")
    rows = records(found)
    assert [r["data"]["position"] for r in rows] == [0, 1, 2]
    assert rows[0]["data"]["path"] == "C:\\Windows\\System32\\cmd.exe" and rows[0]["ts"] == ms(1_690_000_000)
    assert "not a time of execution" in rows[0]["data"]["ts_is"]
    assert rows[2]["ts"] is None  # an entry the cache keeps without a time is kept without one
    assert "executed" not in rows[0]["data"]
    assert notes(found)["shimcache records without a time"] == 1
    assert rows[0]["key"].startswith(
        "reg:WKS-1:system:ControlSet001\\Control\\Session Manager\\AppCompatCache:AppCompatCache|"
    )
    assert end(found)["in_file"] == 3 and skips(found) == []


def test_shimcache_windows_8_and_7(tmp_path):
    eight = shim8([("C:\\a.exe", 1_600_000_000, True), ("C:\\b.exe", 1_500_000_000, False)])
    rows = records(said(write(tmp_path, "S8", system_hive(eight)[0]), "windows.execution.shimcache"))
    assert [(r["data"]["path"], r["data"]["executed"], r["ts"]) for r in rows] == [
        ("C:\\a.exe", True, ms(1_600_000_000)),
        ("C:\\b.exe", False, ms(1_500_000_000)),
    ]
    seven = shim7([("\\??\\C:\\x.exe", 1_400_000_000, True), ("\\??\\C:\\y.exe", 1_300_000_000, False)])
    found = said(write(tmp_path, "S7", system_hive(seven)[0]), "windows.execution.shimcache")
    assert [(r["data"]["path"], r["data"]["executed"]) for r in records(found)] == [
        ("\\??\\C:\\x.exe", True),
        ("\\??\\C:\\y.exe", False),
    ]
    assert skips(found) == []
    # The header says three entries and the cache holds two: the missing one is a loss, said with its number.
    short = shim7([("\\??\\C:\\x.exe", 1_400_000_000, True)], declared=3)
    found = said(write(tmp_path, "S7b", system_hive(short)[0]), "windows.execution.shimcache")
    (skip,) = skips(found)
    assert skip["reason"] == "shimcache stops at an entry that cannot be read" and skip["lost"] == 2
    assert end(found)["in_file"] == len(records(found)) + skip["lost"] == 3


def test_a_big_shimcache_value_is_read_from_its_blocks(tmp_path):
    entries = [(f"C:\\Windows\\Temp\\file{n:04d}.exe", 1_600_000_000 + n) for n in range(300)]
    blob = shim10(entries)
    assert len(blob) > 16344
    found = said(write(tmp_path, "SYSTEM", system_hive(blob)[0]), "windows.execution.shimcache")
    rows = records(found)
    assert [r["data"]["path"] for r in rows] == [e[0] for e in entries]
    assert len({r["key"] for r in rows}) == 300 and skips(found) == []


def test_a_cut_shimcache_says_where_it_stops(tmp_path):
    blob = shim10([("C:\\a.exe", 1_600_000_000), ("C:\\b.exe", 1_600_000_001)])
    found = said(write(tmp_path, "SYSTEM", system_hive(blob[:-9])[0]), "windows.execution.shimcache")
    assert len(records(found)) == 1
    (skip,) = skips(found)
    assert skip["reason"] == "shimcache stops at an entry that cannot be read" and skip["lost"] == 0
    assert "entry cut short" in skip["detail"]


# --------------------------------------------------------------------------- #
# Integrity                                                                   #
# --------------------------------------------------------------------------- #
def test_a_dirty_hive_is_read_and_a_note_says_its_logs_were_not_given(tmp_path):
    clean = said(write(tmp_path, "clean", ntuser_hive()[0]))
    found = said(write(tmp_path, "dirty", ntuser_hive(dirty=True)[0]))
    assert "hive is dirty, its transaction logs were not given" in notes(found)
    assert "hive is dirty, its transaction logs were not given" not in notes(clean)
    assert len(records(found)) == len(records(clean)) and skips(found) == []


def test_the_cells_of_the_hive_are_counted_on_their_own(tmp_path):
    found = said(write(tmp_path, "NTUSER.DAT", ntuser_hive()[0]))
    detail = next(e["detail"] for e in found if e["t"] == "note" and e["reason"] == "cells of the hive counted")
    assert " keys and " in detail and "values in 1 blocks of cells" in detail
    # root, Environment, Software, Microsoft, Windows, CurrentVersion, Run, RunOnce, Explorer, UserAssist, guid, Count,
    # RecentDocs, .txt
    assert detail.startswith("14 keys and 12 values")


def test_a_damaged_key_cell_is_a_skip_with_its_offset_and_the_rest_is_read(tmp_path):
    data, where = system_hive()
    bad = where["ControlSet001\\Services\\Dnscache"]
    data = bytearray(data)
    struct.pack_into("<i", data, 4096 + bad, 0)  # a cell of size zero
    found = said(write(tmp_path, "SYSTEM", bytes(data)), "windows.persistence.services-hive")
    assert {r["data"]["name"] for r in records(found)} == {"Spooler", "bam"}
    lost = [s for s in skips(found) if s["offset"] == bad and s["lost"] == 1]
    assert lost and lost[0]["reason"].startswith("subkey:")
    # The cell walk finds it too: a size that is not valid, where the walk stopped in that block.
    assert any(s["offset"] == bad and "not valid" in s["reason"] for s in skips(found))
    assert end(found)["in_file"] == 3 and end(found)["read"] == 2
    # However many walks passed the cell (the one that looks for the key on its way, the one that reads Services), the
    # loss is counted once: what was read and what was lost give what the key says it holds.
    assert sum(s["lost"] for s in skips(found)) == 1


def test_a_value_whose_data_cannot_be_read_keeps_the_record_without_it(tmp_path):
    data, where = system_hive()
    vk = where["ControlSet001\\Services\\Spooler\\ImagePath"]
    data = bytearray(data)
    struct.pack_into("<I", data, 4096 + vk + 4 + 8, 0x7FFFFFF0)  # the offset of its data
    found = said(write(tmp_path, "SYSTEM", bytes(data)), "windows.persistence.services-hive")
    spooler = next(r for r in records(found) if r["data"]["name"] == "Spooler")
    assert spooler["data"]["image_path"] == "" and spooler["data"]["display_name"] == "Print Spooler"
    (skip,) = skips(found)
    assert skip["lost"] == 0 and skip["offset"] == 0x7FFFFFF0 and "past the end" in skip["reason"]


def test_a_run_value_that_cannot_be_read_is_a_loss_of_one(tmp_path):
    data, where = ntuser_hive()
    vk = where["Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater"]
    data = bytearray(data)
    struct.pack_into("<I", data, 4096 + vk + 4 + 8, 0x7FFFFFF0)
    found = said(write(tmp_path, "NTUSER.DAT", bytes(data)), "windows.persistence.runkeys-hive")
    assert {r["data"]["name"] for r in records(found)} == {"OneDrive", "Setup"}
    (skip,) = skips(found)
    assert skip["lost"] == 1 and "Updater" in skip["detail"]
    assert end(found)["in_file"] == 3


def test_a_cut_file_says_that_it_ends_before_its_data(tmp_path):
    data, _ = ntuser_hive()
    found = said(write(tmp_path, "cut", data[: len(data) - 3000]))
    reasons = {s["reason"] for s in skips(found)}
    assert "the file ends before the data its header declares" in reasons
    assert "the last block of cells is cut short" in reasons


def test_a_huge_value_is_cut_at_the_limit_and_said(tmp_path, monkeypatch):
    text = "A" * 100_000
    root = Node(
        "ROOT",
        children=[
            Node(
                "Software",
                children=[
                    Node(
                        "Microsoft",
                        children=[
                            Node(
                                "Windows",
                                children=[
                                    Node(
                                        "CurrentVersion",
                                        children=[Node("Run", values=[sz("Big", text), sz("Small", "x.exe")])],
                                    )
                                ],
                            )
                        ],
                    )
                ],
            )
        ],
    )
    path = write(tmp_path, "NTUSER.DAT", hb.build(root)[0])
    whole = records(said(path, "windows.persistence.runkeys-hive"))
    assert {r["data"]["name"] for r in whole} == {"Big", "Small"} and skips(whole) == []
    big = next(r for r in whole if r["data"]["name"] == "Big")
    assert big["trunc"] is True and len(big["data"]["command"]) == 8000  # the context cuts it and says so
    monkeypatch.setattr(regf, "MAX_DATA", 30_000)
    found = said(path, "windows.persistence.runkeys-hive")
    (skip,) = skips(found)
    assert skip["reason"] == "value is larger than the reader keeps, its start was read" and skip["lost"] == 0
    assert "200002 bytes" in skip["detail"] and "30000 read" in skip["detail"]
    assert len(records(found)) == 2


def test_the_time_given_to_a_hive_is_bounded(tmp_path, monkeypatch):
    path = write(tmp_path, "SYSTEM", system_hive()[0])
    monkeypatch.setattr(hive, "SECONDS", -1.0)
    found = said(path)
    (skip,) = skips(found)
    assert skip["reason"] == "the time given to the hive is over, the rest is not read"
    assert end(found)["in_file"] is None and records(found) == []


def test_a_source_the_hive_does_not_hold_is_a_note_not_a_loss(tmp_path):
    found = said(write(tmp_path, "NTUSER.DAT", ntuser_hive()[0]), "windows.execution.amcache")
    assert "this hive does not hold the source asked for" in notes(found)
    assert records(found) == [] and skips(found) == [] and end(found)["in_file"] == 0
    found = said(write(tmp_path, "UsrClass.dat", usrclass_hive()))
    assert "no source of Nik reads this hive" in notes(found)
    with pytest.raises(ValueError):
        said(write(tmp_path, "x", ntuser_hive()[0]), "windows.run_keys")


def test_a_hive_read_again_gives_the_same_keys_and_no_two_alike(tmp_path):
    path = write(tmp_path, "SYSTEM", system_hive()[0])
    first = [r["key"] for r in records(said(path))]
    again = [r["key"] for r in records(said(write(tmp_path, "copy-of-it", system_hive()[0])))]
    assert first == again and len(set(first)) == len(first)
    # The same file as a whole and by one source: the same record has the same key.
    only = [r["key"] for r in records(said(path, "windows.persistence.services-hive"))]
    assert set(only) <= set(first)
    # A path of more than 300 characters keeps its start and ends in a hash.
    deep = "x" * 120
    root = Node(
        "ROOT",
        children=[
            Node("Select", values=[dword("Current", 1)]),
            Node("ControlSet001", children=[Node("Services", children=[Node(deep, children=[Node(deep)])])]),
        ],
    )
    long_path = write(tmp_path, "long", hb.build(root)[0])
    (record,) = records(said(long_path, "windows.persistence.services-hive"))
    assert len(record["key"]) <= 300 and record["key"].startswith(
        "reg:WKS-1:system:ControlSet001\\Services\\" + "x" * 50
    )


# --------------------------------------------------------------------------- #
# The view                                                                    #
# --------------------------------------------------------------------------- #
def test_the_view_shows_the_key_with_its_values_and_the_value_of_the_record(tmp_path):
    path = write(tmp_path, "NTUSER.DAT", ntuser_hive()[0])
    row = next(r for r in records(said(path)) if r["data"].get("name") == "Updater")
    shown = hive.view(path, row["src"], row["loc"])
    assert shown["kind"] == "fields" and shown["where"]["offset"] == row["loc"]["offset"]
    rows = dict(shown["rows"])
    assert rows["key"] == "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    assert rows["last write of the key"] == "2022-08-08 23:06:40" and rows["values"] == "2"
    assert rows["value Updater  <- this record"] == "string: C:\\Temp\\upd.exe"
    assert rows["value OneDrive"].endswith("OneDrive.exe /background")
    assert shown["rows"][5][0].startswith("value Updater")  # the record's own value comes first
    assert "offset of the key cell" in rows


def test_the_view_of_a_shimcache_entry_names_the_entry_and_hex_dumps_the_blob(tmp_path):
    path = write(tmp_path, "SYSTEM", system_hive()[0])
    row = next(r for r in records(said(path)) if r["type"] == "shimcache")
    shown = hive.view(path, row["src"], row["loc"])
    rows = dict(shown["rows"])
    assert rows["entry of the cache"].startswith("position 0: C:\\Windows\\System32\\cmd.exe")
    assert rows["value AppCompatCache  <- this record"].startswith("binary,")


def test_the_view_refuses_what_it_cannot_find(tmp_path):
    path = write(tmp_path, "NTUSER.DAT", ntuser_hive()[0])
    with pytest.raises(ViewError):
        hive.view(path, UMBRELLA, {"key": "Software", "offset": 8})  # no cell there
    with pytest.raises(parsers.BadLocator):
        hive.view(path, UMBRELLA, {"key": "Software"})
    row = records(said(path))[0]
    with pytest.raises(ViewError):  # a cell that is another key than the record's
        hive.view(path, UMBRELLA, {**row["loc"], "key": "Other\\Place"})
    with pytest.raises(ViewError):
        hive.view(write(tmp_path, "t.txt", "text"), UMBRELLA, row["loc"])


def test_a_record_carries_its_source_and_the_context_says_it():
    out = io.BytesIO()
    ctx = Context(out)
    ctx.source("hive", "1", "endpoint", UMBRELLA)
    ctx.record(key="k1", type="x", source="windows.execution.shimcache")
    ctx.record(key="k2", type="x")
    ctx.end()
    lines = [json.loads(line) for line in out.getvalue().splitlines()]
    assert lines[1]["src"] == "windows.execution.shimcache" and "src" not in lines[2]


def test_blocks_with_a_bad_header_are_one_skip_for_the_run_with_its_length(tmp_path):
    entries = [(f"C:\\Windows\\Temp\file{n:04d}.exe", 1_600_000_000 + n) for n in range(300)]
    data = bytearray(system_hive(shim10(entries))[0])
    pages = (len(data) - 4096) // 4096
    assert pages >= 5
    data[4096:4100] = bytes(4)  # the magic of the only block of cells
    found = said(write(tmp_path, "SYSTEM", bytes(data)))
    (run,) = [s for s in skips(found) if s["reason"] == "block of cells has a bad header"]
    assert run["offset"] == 0 and run["length"] == pages * 4096 and run["lost"] == 0
    assert len(records(found, "windows.execution.shimcache")) == 300  # the keys are found by their offsets


def test_old_amcache_entries_are_said_not_to_be_read(tmp_path):
    root = Node(
        "ROOT", children=[Node("Root", children=[Node("InventoryApplication"), Node("File", children=[Node("{vol}")])])]
    )
    found = said(write(tmp_path, "Amcache.hve", hb.build(root, name="amcache.hve")[0]), "windows.execution.amcache")
    (skip,) = skips(found)
    assert skip["reason"] == "amcache entries in the format of Windows 7 and 8 are not read" and skip["lost"] == 0

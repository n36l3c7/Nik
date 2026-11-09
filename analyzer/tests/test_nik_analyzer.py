"""Analyzer transforms on recorded rizin output, plus a live run when rizin is installed."""

from __future__ import annotations

import json
import shutil
import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from nik_analyzer import analyze, build_function, callee_name, is_import, summarize_info  # noqa: E402

FIXTURE = json.loads((Path(__file__).parent / "fixtures" / "tiny_pe_rizin.json").read_text())

# x86: entry0 tests eax, conditionally calls a helper, returns; the helper zeroes eax.
TINY_CODE = bytes.fromhex("5589e585c07405e8030000005dc39031c0c3")


def tiny_pe(code: bytes = TINY_CODE) -> bytes:
    """A valid PE32 whose single .text section starts with `code` (entry point)."""
    dos = bytearray(b"MZ" + b"\0" * 58 + struct.pack("<I", 0x80))
    dos += b"\0" * (0x80 - len(dos))
    file_header = struct.pack("<HHIIIHH", 0x014C, 1, 0x5F5E1000, 0, 0, 0xE0, 0x0102)
    optional = struct.pack(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
        0x10B, 14, 0, 0x200, 0, 0, 0x1000, 0x1000, 0x2000, 0x400000, 0x1000, 0x200,
        6, 0, 0, 0, 6, 0, 0, 0x2000, 0x200, 0, 2, 0x8140, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
    )  # fmt: skip
    optional += b"\0" * 128
    section = struct.pack("<8sIIIIIIHHI", b".text\0\0\0", len(code), 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
    image = bytearray(dos + b"PE\0\0" + file_header + optional + section)
    image += b"\0" * (0x200 - len(image))
    return bytes(image) + code + b"\0" * (0x200 - len(code))


def build_all(fixture: dict) -> list[dict]:
    names = {f["offset"]: f["name"] for f in fixture["aflj"]}
    return [
        build_function(f, fixture["afbj"][str(f["offset"])], fixture["pdfj"][str(f["offset"])], names)
        for f in fixture["aflj"]
    ]


def test_functions_calls_and_cfg_from_recorded_output():
    entry, helper = build_all(FIXTURE)
    assert (entry["name"], entry["kind"], entry["blocks"], entry["cc"]) == ("entry0", "function", 3, 2)
    assert entry["calls"] == [{"addr": 0x40100F, "name": "fcn.0040100f", "at": 0x401007}]
    blocks = entry["cfg"]["blocks"]
    assert [b["addr"] for b in blocks] == [0x401000, 0x401007, 0x40100C]
    first = blocks[0]
    assert (first["jump"], first["fail"]) == (0x40100C, 0x401007)  # conditional: taken / not taken
    assert [op["text"] for op in first["ops"]] == ["push ebp", "mov ebp, esp", "test eax, eax", "jz 0x40100c"]
    assert blocks[2]["ops"][-1]["type"] == "ret"
    assert helper["calls"] == [] and helper["indegree"] == 1
    assert entry["cfg"]["truncated"] is False


def test_names_and_info_helpers():
    assert (
        callee_name({"disasm": "call dword [sym.imp.KERNEL32.dll_VirtualAllocEx]"})
        == "sym.imp.KERNEL32.dll_VirtualAllocEx"
    )
    assert callee_name({"disasm": "call qword ptr [rip + 0x20]"}) == "rip + 0x20"
    assert callee_name({"disasm": "call fcn.00401000"}) == "fcn.00401000"
    assert is_import("sym.imp.puts") and not is_import("fcn.00401000") and not is_import("main")
    info = summarize_info(FIXTURE["ij"])
    assert info["arch"] == "x86" and info["bits"] == 32 and info["os"] == "windows"


def test_imports_have_no_cfg():
    imp = build_function({"offset": 0x1030, "name": "sym.imp.puts", "size": 6, "nbbs": 1}, None, None, {})
    assert imp["kind"] == "import" and "cfg" not in imp and imp["calls"] == []


@pytest.mark.skipif(shutil.which("rizin") is None, reason="rizin is not installed")
def test_live_analysis(tmp_path):
    sample = tmp_path / "tiny.bin"
    sample.write_bytes(tiny_pe())
    result = analyze(str(sample), timeout=60)
    names = [f["name"] for f in result["functions"]]
    assert "entry0" in names and result["entry"] == 0x401000
    assert result["engine"]["name"] == "rizin" and result["engine"]["version"][0].isdigit()

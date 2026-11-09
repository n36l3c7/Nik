"""Analyzer transforms on recorded rizin output, plus a live run when rizin is installed."""

from __future__ import annotations

import json
import shutil
import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from nik_analyzer import (  # noqa: E402
    AnalysisError,
    DataIndex,
    analyze,
    build_decompiled,
    build_function,
    callee_name,
    decompile_functions,
    decompile_one,
    disassemble_functions,
    is_import,
    pointer_holders,
    rust_paths,
    summarize_info,
)

FIXTURE = json.loads((Path(__file__).parent / "fixtures" / "tiny_pe_rizin.json").read_text())
PDGJ = json.loads((Path(__file__).parent / "fixtures" / "tiny_pe_pdgj.json").read_text())

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


def test_rust_paths_are_anchored_where_the_str_points():
    merged = (
        r"FieldSet corrupted (this is a bug)C:\Users\Dev\.cargo\registry\src\index.crates.io-1949cf8c6b5b557f"
        r"\hyper-0.14.32\src\proto\h1\role.rs"
    )
    assert [(merged[o : o + 3], c) for o, c in rust_paths(merged)] == [("C:\\", "hyper")]
    rustc = "see http://x/y then /rustc/" + "a" * 40 + "/library/core/src/str/mod.rs"
    assert [(rustc[o : o + 7], c) for o, c in rust_paths(rustc)] == [("/rustc/", "std")]
    unix = "oops/home/dev/.cargo/registry/src/index.crates.io-6f17d22bba15001f/tokio-1.40.0/src/runtime/mod.rs"
    assert [(unix[o : o + 5], c) for o, c in rust_paths(unix)] == [("/home", "tokio")]
    spaced = r"C:\Users\John Doe\.cargo\registry\src\index.crates.io-x\zip-0.6.6\src\read.rs"
    assert rust_paths(spaced) == [(0, "zip")]
    assert rust_paths("library/alloc/src/raw_vec.rs") == [(0, "std")]
    assert rust_paths("no paths here, just C:\\Windows\\System32") == []


def test_data_index_links_code_to_strings_and_crates():
    # A tiny image: .rdata at 0x1000 (file offset 0x400) holds a merged string with a
    # crate path at +4, a Location struct at 0x1100 pointing at the path, and a URL.
    path = r"C:\x\.cargo\registry\src\i-1\reqwest-0.12.4\src\lib.rs"
    blob = b"bug)" + path.encode() + b"http://185.220.101.47/gate.php"
    rdata = bytearray(0x200)
    rdata[0 : len(blob)] = blob
    rdata[0x100:0x108] = struct.pack("<Q", 0x1004)  # Location.file.ptr
    data = b"\0" * 0x400 + bytes(rdata)
    strings = [
        {"vaddr": 0x1000, "paddr": 0x400, "size": len(blob), "string": blob.decode()},
    ]
    sections = [{"name": ".rdata", "vaddr": 0x1000, "paddr": 0x400, "size": 0x200}]
    index = DataIndex(strings, sections, data)
    assert index.paths == {0x1004: "reqwest"} and index.crates == {"reqwest": 1}
    assert index.holders == {0x1100: 0x1004}
    url_at = 0x1000 + 4 + len(path)
    assert index.resolve(url_at) == (0x400 + 4 + len(path), None)  # a string, no crate
    assert index.resolve(0x1100) == (0x404, "reqwest")  # the Location struct
    assert index.resolve(0x5000) == (None, None) and index.resolve(None) == (None, None)

    ops = [
        {"offset": 0x10, "type": "lea", "disasm": "lea rcx, [0x1100]", "ptr": 0x1100},
        {"offset": 0x17, "type": "lea", "disasm": "lea rdx, [url]", "ptr": url_at},
        {"offset": 0x1E, "type": "lea", "disasm": "lea rdx, [url]", "ptr": url_at},  # counted once
        {"offset": 0x25, "type": "ret", "disasm": "ret"},
    ]
    fn = build_function(
        {"offset": 0x10, "name": "fcn.00000010", "realsz": 0x16, "nbbs": 1},
        [{"addr": 0x10, "size": 0x16}],
        {"ops": ops},
        {},
        index,
    )
    assert fn["crates"] == {"reqwest": 1}
    assert fn["strings"] == [0x404, 0x400 + 4 + len(path)]
    plain = build_function({"offset": 0x10, "name": "f", "realsz": 1}, [], {"ops": []}, {}, index)
    assert "strings" not in plain and "crates" not in plain


def test_pointer_holders_reads_32_and_64_bit_pointers_in_data_sections_only():
    raw = struct.pack("<QI", 0xAAAA, 0xBBBB) + b"\0" * 4
    data = raw + raw
    sections = [
        {"name": ".rdata", "vaddr": 0x100, "paddr": 0, "size": 16},
        {"name": ".text", "vaddr": 0x200, "paddr": 16, "size": 16},
    ]
    assert pointer_holders(data, sections, {0xAAAA: "x", 0xBBBB: "y"}) == {0x100: 0xAAAA, 0x108: 0xBBBB}
    assert pointer_holders(data, sections, {}) == {}


def test_imports_have_no_cfg():
    imp = build_function({"offset": 0x1030, "name": "sym.imp.puts", "size": 6, "nbbs": 1}, None, None, {})
    assert imp["kind"] == "import" and "cfg" not in imp and imp["calls"] == []


def test_decompiled_code_spans_and_call_targets():
    entry = build_decompiled(PDGJ[str(0x401000)])
    code = entry["code"]
    assert code.startswith("void entry0(void)") and code.endswith("}")
    assert "fcn.0040100f();" in code and entry["truncated"] is False
    spans = [(code[s[0] : s[1]], *s[2:]) for s in entry["spans"]]
    assert spans[:3] == [("void", "t"), ("entry0", "f", 0x401000), ("void", "k")]  # return type, name, params
    assert ("fcn.0040100f", "f", 0x40100F) in spans  # a call becomes a link to its function
    assert ("if", "k") in spans and ("return", "k") in spans and ("in_EAX", "v") in spans
    assert ("// [00] -r-x section size 4096 named .text", "c") in spans  # one span, not one per word
    starts = [s[0] for s in entry["spans"]]
    assert starts == sorted(starts)
    assert all(a[1] <= b[0] for a, b in zip(entry["spans"], entry["spans"][1:]))  # no overlap
    assert build_decompiled({"code": "\n  \n", "annotations": []}) is None
    assert build_decompiled(None) is None


class FakeSession:
    """Stands in for Session: canned answers per address, crashes on demand, records the order.

    ``crash`` maps an address to how many times it crashes before answering.
    """

    def __init__(self, answers, crash=None, clock=None, cost=0.0, max_restarts=3):
        self.answers, self.crash, self.clock, self.cost = answers, dict(crash or {}), clock, cost
        self.asked, self.restarts, self.max_restarts = [], 0, max_restarts

    def cmdj(self, command):
        addr = int(command.split("@")[1])
        self.asked.append(addr)
        if self.clock is not None:
            self.clock.now += self.cost
        if self.crash.get(addr, 0) > 0:
            self.crash[addr] -= 1
            raise AnalysisError("rizin stopped unexpectedly")
        return self.answers.get(addr)

    def restart(self):
        if self.restarts >= self.max_restarts:
            raise AnalysisError("rizin crashed too many times")
        self.restarts += 1

    def kill(self):
        pass


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


FUNCTIONS = [
    {"addr": 0x10, "kind": "function", "size": 900},
    {"addr": 0x20, "kind": "import", "size": 6},
    {"addr": 0x30, "kind": "function", "size": 50},
    {"addr": 0x40, "kind": "function", "size": 400},
    {"addr": 0x50, "kind": "function", "size": 10},
]
CODE = {"code": "int f(void)\n{\n    return 0;\n}", "annotations": []}


ALL_CODE = {a: CODE for a in (0x10, 0x30, 0x40, 0x50)}


def test_decompile_pass_order_budget_and_crashes():
    clock = Clock()
    session = FakeSession(ALL_CODE, clock=clock, cost=1.0)
    decompiled, stats = decompile_functions(session, FUNCTIONS, deadline=100, first=(0x40, None), clock=clock)
    assert session.asked == [0x40, 0x50, 0x30, 0x10]  # entry first, then smallest; imports never
    assert set(decompiled) == {"16", "48", "64", "80"}
    assert stats == {"engine": "rz-ghidra", "done": 4, "failed": 0, "total": 4, "stopped": None}

    clock = Clock()
    session = FakeSession(ALL_CODE, clock=clock, cost=1.0)
    decompiled, stats = decompile_functions(session, FUNCTIONS, deadline=2, clock=clock)
    assert session.asked == [0x50, 0x30] and stats["stopped"] == "time" and stats["done"] == 2

    # A crash skips that function, restarts the session and goes on.
    session = FakeSession(ALL_CODE, crash={0x30: 1})
    decompiled, stats = decompile_functions(session, FUNCTIONS, deadline=float("inf"))
    assert set(decompiled) == {"16", "64", "80"} and session.restarts == 1
    assert (stats["done"], stats["failed"], stats["stopped"]) == (3, 1, None)

    # Out of restarts: the pass stops and keeps what it has.
    session = FakeSession(ALL_CODE, crash={0x50: 1, 0x30: 1}, max_restarts=1)
    decompiled, stats = decompile_functions(session, FUNCTIONS, deadline=float("inf"))
    assert decompiled == {} and stats["stopped"] == "error"


def test_disassembly_survives_rizin_crashes():
    names = {f["offset"]: f["name"] for f in FIXTURE["aflj"]}

    class Recorded(FakeSession):
        """Answers afbj / pdfj from the recorded rizin output."""

        def cmdj(self, command):
            result = super().cmdj(command)
            kind, at = command.split(" @ ")
            return FIXTURE[kind][at] if result is None else result

    # entry0 crashes once (cumulative crash): retried in a fresh session, fully built.
    session = Recorded({}, crash={0x401000: 1})
    results = disassemble_functions(session, FIXTURE["aflj"], names)
    assert session.restarts == 1 and "skipped" not in results[0]
    assert len(results[0]["cfg"]["blocks"]) == 3

    # entry0 crashes twice: kept without CFG and marked skipped; the helper is unaffected.
    session = Recorded({}, crash={0x401000: 2})
    results = disassemble_functions(session, FIXTURE["aflj"], names)
    assert results[0]["skipped"].startswith("rizin crashed") and results[0]["cfg"]["blocks"] == []
    assert results[1]["name"] == "fcn.0040100f" and "skipped" not in results[1]

    with pytest.raises(AnalysisError):  # no restarts left
        disassemble_functions(Recorded({}, crash={0x401000: 2}, max_restarts=1), FIXTURE["aflj"], names)


@pytest.mark.skipif(shutil.which("rizin") is None, reason="rizin is not installed")
def test_live_analysis(tmp_path):
    sample = tmp_path / "tiny.bin"
    sample.write_bytes(tiny_pe())
    result = analyze(str(sample), timeout=60)
    names = [f["name"] for f in result["functions"]]
    assert "entry0" in names and result["entry"] == 0x401000
    assert result["engine"]["name"] == "rizin" and result["engine"]["version"][0].isdigit()
    assert result["decompile"]["stopped"] is None and result["decompile"]["done"] == result["decompile"]["total"]
    assert result["decompiled"][str(0x401000)]["code"].startswith("void entry0")
    one = decompile_one(str(sample), 0x40100F, timeout=60)
    assert one["engine"] == "rz-ghidra" and "return 0;" in one["code"]
    with pytest.raises(AnalysisError):
        decompile_one(str(sample), 0x401001, timeout=60)  # not a function start

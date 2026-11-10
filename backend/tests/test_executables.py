"""Executable structure parsers, YARA scanning and the admin rules API."""

from __future__ import annotations

import struct

from fastapi.testclient import TestClient

from app.malware import yara_rules
from app.parsing.executables import parse_elf, parse_macho, parse_pe, parse_structure
from tests.conftest import make_key


def minimal_pe(payload: bytes = b"", dll: bool = False) -> bytes:
    """A valid PE32 with one `.text` section holding `payload`."""
    dos = bytearray(b"MZ" + b"\0" * 58 + struct.pack("<I", 0x80))
    dos += b"\0" * (0x80 - len(dos))
    characteristics = 0x2102 if dll else 0x0102
    file_header = struct.pack("<HHIIIHH", 0x014C, 1, 0x5F5E1000, 0, 0, 0xE0, characteristics)
    section_align, file_align = 0x1000, 0x200
    raw_size = max(file_align, (len(payload) + file_align - 1) // file_align * file_align)
    headers_size = 0x200
    optional = struct.pack(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
        0x10B,
        14,
        0,
        raw_size,
        0,
        0,
        0x1000,
        0x1000,
        0x2000,
        0x400000,
        section_align,
        file_align,
        6,
        0,
        0,
        0,
        6,
        0,
        0,
        0x2000,
        headers_size,
        0,
        2,
        0x8140,
        0x100000,
        0x1000,
        0x100000,
        0x1000,
        0,
        16,
    )
    optional += b"\0" * (16 * 8)  # empty data directories
    section = struct.pack(
        "<8sIIIIIIHHI", b".text\0\0\0", len(payload) or 1, 0x1000, raw_size, headers_size, 0, 0, 0, 0, 0x60000020
    )
    pe = bytearray(dos + b"PE\0\0" + file_header + optional + section)
    pe += b"\0" * (headers_size - len(pe))
    pe += payload + b"\0" * (raw_size - len(payload))
    return bytes(pe)


def minimal_elf64(payload: bytes = b"") -> bytes:
    """ELF64 x86-64 executable with one PT_LOAD segment and no section headers."""
    header = struct.pack(
        "<16sHHIQQQIHHHHHH", b"\x7fELF\x02\x01\x01" + b"\0" * 9, 2, 62, 1, 0x401000, 64, 0, 0, 64, 56, 1, 64, 0, 0
    )
    phdr = struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000, 120 + len(payload), 120 + len(payload), 0x1000)
    return header + phdr + payload


def minimal_macho64() -> bytes:
    """Mach-O 64-bit executable with one LC_LOAD_DYLIB and an LC_MAIN."""
    dylib_name = b"/usr/lib/libSystem.B.dylib\0"
    dylib_cmd_size = (24 + len(dylib_name) + 7) // 8 * 8
    dylib_cmd = struct.pack("<IIIIII", 0xC, dylib_cmd_size, 24, 0, 0, 0) + dylib_name
    dylib_cmd += b"\0" * (dylib_cmd_size - len(dylib_cmd))
    main_cmd = struct.pack("<IIQQ", 0x80000028, 24, 0x1000, 0)
    header = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x01000007, 3, 2, 2, len(dylib_cmd) + len(main_cmd), 0, 0)
    return header + dylib_cmd + main_cmd


def test_parse_pe_sections_and_flags():
    info = parse_pe(minimal_pe(b"\x90" * 64 + b"VirtualAllocEx\0"))
    assert info["format"] == "pe" and info["machine"] == "i386"
    assert info["is64"] is False and info["isDll"] is False
    assert info["subsystem"] == "windows gui"
    assert info["compiledAt"] == "2020-09-13T12:26:40Z"
    assert [s["name"] for s in info["sections"]] == [".text"]
    assert info["sections"][0]["executable"] is True
    assert info["imphash"] is None and info["imports"] == []
    assert info["signed"] is False
    assert parse_pe(minimal_pe(dll=True))["isDll"] is True


def test_parse_elf_segments():
    info = parse_elf(minimal_elf64(b"/bin/sh\0"))
    assert info["format"] == "elf" and info["is64"] and info["machine"] == "x86-64"
    assert info["type"] == "executable" and info["entryPoint"] == 0x401000
    assert info["segments"][0]["type"] == "LOAD" and info["segments"][0]["flags"] == "rx"
    assert info["sections"] == [] and info["stripped"] is True


def test_parse_macho_dylibs():
    info = parse_macho(minimal_macho64())
    assert info["format"] == "macho" and info["cpu"] == "x86-64" and info["type"] == "executable"
    assert info["imports"] == [{"library": "/usr/lib/libSystem.B.dylib", "name": ""}]
    assert info["entryPoint"] == 0x1000
    assert "LOAD_DYLIB" in info["loadCommands"] and "MAIN" in info["loadCommands"]


def test_parse_structure_tolerates_garbage():
    assert parse_structure("pdf", b"%PDF") is None
    broken = parse_structure("pe32", b"MZ" + b"\0" * 200)
    assert broken["format"] == "pe" and broken["warnings"]


def test_builtin_yara_rules_compile_and_match(client: TestClient):
    from app.core.db import SessionLocal

    with SessionLocal() as db:
        assert yara_rules.compiled_rules(db) is not None
        hits = {m["rule"] for m in yara_rules.scan(db, b"powershell.exe -nop -w hidden -EncodedCommand AAAA")}
        assert "powershell_encoded_command" in hits
        assert yara_rules.scan(db, b"nothing to see here") == []
    assert yara_rules.validate("rule broken { condition: $x }")  # undefined string → error
    assert yara_rules.validate('rule ok { strings: $a = "x" condition: $a }') == []


def test_admin_yara_rules_api_and_reanalyse(admin: TestClient):
    analyst = make_key(admin, role="analyst")
    admin_key = make_key(admin, role="admin")
    rule = {
        "name": "Team rules",
        "source": 'rule team_marker { meta: severity = "high" strings: $m = "NIKTEAM" condition: $m }',
    }

    assert admin.post("/api/yara-rules", headers=analyst, json=rule).status_code == 403
    r = admin.post("/api/yara-rules", headers=admin_key, json={**rule, "source": "rule nope { condition: $x }"})
    assert r.status_code == 400 and "does not compile" in r.json()["detail"]
    r = admin.post("/api/yara-rules", headers=admin_key, json=rule)
    assert r.status_code == 201 and r.json()["ruleNames"] == ["team_marker"]
    rule_id = r.json()["id"]
    listing = admin.get("/api/yara-rules", headers=analyst).json()
    assert [x["name"] for x in listing["rules"]] == ["Team rules"] and listing["builtin"]

    # A sample uploaded now matches the admin rule; the structure is parsed too.
    admin.post("/api/incidents", headers=analyst, json={"id": "y1", "name": "y1", "data": {}})
    data = minimal_pe(b"NIKTEAM payload")
    sha = admin.post("/api/incidents/y1/samples", headers=analyst, files={"file": ("a.exe", data)}).json()["sample"][
        "sha256"
    ]
    detail = admin.get(f"/api/samples/{sha}", headers=analyst).json()
    assert detail["analysis"]["structure"]["format"] == "pe"
    assert [m["rule"] for m in detail["analysis"]["yara"]] == ["team_marker"]
    assert detail["analysis"]["yara"][0]["meta"]["severity"] == "high"
    assert detail["analysis"]["analysisVersion"] == 2

    # Disable the rule and re-analyse: the match disappears.
    r = admin.put(f"/api/yara-rules/{rule_id}", headers=admin_key, json={**rule, "enabled": False})
    assert r.status_code == 200 and r.json()["enabled"] is False
    again = admin.post(f"/api/samples/{sha}/reanalyse", headers=analyst).json()
    assert again["analysis"]["yara"] == []

    assert admin.delete(f"/api/yara-rules/{rule_id}", headers=admin_key).status_code == 204
    assert admin.get("/api/yara-rules", headers=analyst).json()["rules"] == []
    actions = {e["action"] for e in admin.get("/api/audit", headers=analyst).json()["entries"]}
    assert {"yara.add", "yara.update", "yara.delete", "sample.reanalyse"} <= actions

"""Structure of executable files: PE (via pefile), ELF and Mach-O (own parsers).

Everything here reads headers and tables from bytes; nothing is loaded or
run. Malformed input is the norm for malware, so every parser catches its own
errors and reports them in ``warnings`` instead of failing the analysis.

The result is JSON-serialisable: ``{"format", ..., "sections": [...],
"imports": [...], "warnings": [...]}``, with format-specific keys.
"""

from __future__ import annotations

import logging
import struct
from datetime import datetime, timezone
from typing import Any

import pefile

from .malware import entropy

logger = logging.getLogger("nik.executables")

SECTION_LIMIT = 96
IMPORT_LIMIT = 4000
EXPORT_LIMIT = 2000


def _iso(timestamp: int) -> str | None:
    try:
        return datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return None


def _text(value: bytes | None) -> str:
    return (value or b"").rstrip(b"\0").decode("latin-1", errors="replace")


# ---------------------------------------------------------------------------
# PE
# ---------------------------------------------------------------------------
_PE_SUBSYSTEMS = {
    1: "native",
    2: "windows gui",
    3: "windows console",
    9: "windows ce",
    10: "efi application",
    16: "windows boot",
}


def parse_pe(data: bytes) -> dict[str, Any]:
    pe = pefile.PE(data=data, fast_load=True)
    try:
        pe.parse_data_directories(
            directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"],
            ]
        )
        fh, oh = pe.FILE_HEADER, pe.OPTIONAL_HEADER
        machine = pefile.MACHINE_TYPE.get(fh.Machine, f"0x{fh.Machine:04x}").replace("IMAGE_FILE_MACHINE_", "").lower()
        sections = []
        for section in pe.sections[:SECTION_LIMIT]:
            raw = section.get_data()
            sections.append(
                {
                    "name": _text(section.Name),
                    "virtualAddress": section.VirtualAddress,
                    "virtualSize": section.Misc_VirtualSize,
                    "rawSize": section.SizeOfRawData,
                    "rawOffset": section.PointerToRawData,
                    "entropy": entropy(raw),
                    "executable": bool(section.Characteristics & 0x20000000),
                    "writable": bool(section.Characteristics & 0x80000000),
                }
            )
        imports = []
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            dll = _text(entry.dll)
            for imp in entry.imports:
                if len(imports) >= IMPORT_LIMIT:
                    break
                imports.append({"library": dll, "name": _text(imp.name) if imp.name else f"ordinal {imp.ordinal}"})
        exports = []
        export_dir = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
        if export_dir is not None:
            for sym in export_dir.symbols[:EXPORT_LIMIT]:
                exports.append(
                    {"name": _text(sym.name) if sym.name else f"ordinal {sym.ordinal}", "address": sym.address}
                )
        resources = []
        for res_type in getattr(getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None), "entries", []):
            type_name = (
                _text(res_type.name.string)
                if res_type.name
                else pefile.RESOURCE_TYPE.get(res_type.id, str(res_type.id))
            )
            count = sum(
                len(getattr(e, "directory", None).entries) if hasattr(e, "directory") else 1
                for e in res_type.directory.entries
            )
            resources.append({"type": str(type_name).replace("RT_", ""), "count": count})
        security = oh.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
        pdb_path = None
        for debug in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []):
            entry = getattr(debug, "entry", None)
            if entry is not None and hasattr(entry, "PdbFileName"):
                pdb_path = _text(entry.PdbFileName)
                break
        imphash = pe.get_imphash() or None
        rich_header = pe.parse_rich_header()
        warnings = list(pe.get_warnings())
        return {
            "format": "pe",
            "machine": machine,
            "is64": pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS,
            "isDll": pe.is_dll(),
            "isDriver": pe.is_driver(),
            "subsystem": _PE_SUBSYSTEMS.get(oh.Subsystem, str(oh.Subsystem)),
            "compiledAt": _iso(fh.TimeDateStamp),
            "compileTimestamp": fh.TimeDateStamp,
            "entryPoint": oh.AddressOfEntryPoint,
            "imageBase": oh.ImageBase,
            "sectionCount": fh.NumberOfSections,
            "sections": sections,
            "imports": imports,
            "importCount": sum(len(e.imports) for e in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])),
            "imphash": imphash,
            "exports": exports,
            "exportCount": len(export_dir.symbols) if export_dir is not None else 0,
            "resources": resources,
            "signed": bool(security.VirtualAddress and security.Size),
            "richHeader": bool(rich_header),
            "pdbPath": pdb_path,
            "checksumOk": oh.CheckSum == 0 or oh.CheckSum == pe.generate_checksum(),
            "warnings": warnings[:20],
        }
    finally:
        pe.close()


# ---------------------------------------------------------------------------
# ELF
# ---------------------------------------------------------------------------
_ELF_TYPES = {1: "relocatable", 2: "executable", 3: "shared object", 4: "core"}
_ELF_MACHINES = {3: "x86", 8: "mips", 20: "powerpc", 40: "arm", 62: "x86-64", 183: "aarch64", 243: "riscv"}
_PT_TYPES = {
    1: "LOAD",
    2: "DYNAMIC",
    3: "INTERP",
    4: "NOTE",
    6: "PHDR",
    7: "TLS",
    0x6474E551: "GNU_STACK",
    0x6474E552: "GNU_RELRO",
}


def parse_elf(data: bytes) -> dict[str, Any]:
    if len(data) < 52 or data[:4] != b"\x7fELF":
        raise ValueError("Not an ELF file.")
    is64 = data[4] == 2
    little = data[5] == 1
    end = "<" if little else ">"
    warnings: list[str] = []
    if is64:
        e_type, e_machine, _ver, e_entry, e_phoff, e_shoff = struct.unpack_from(end + "HHIQQQ", data, 16)
        _flags, _ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(
            end + "IHHHHHH", data, 48
        )
    else:
        e_type, e_machine, _ver, e_entry, e_phoff, e_shoff = struct.unpack_from(end + "HHIIII", data, 16)
        _flags, _ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(
            end + "IHHHHHH", data, 36
        )

    segments = []
    interpreter = None
    for i in range(min(e_phnum, SECTION_LIMIT)):
        off = e_phoff + i * e_phentsize
        if off + e_phentsize > len(data):
            warnings.append("Program header table runs past the end of the file.")
            break
        if is64:
            p_type, p_flags, p_offset, p_vaddr, _paddr, p_filesz, p_memsz, _align = struct.unpack_from(
                end + "IIQQQQQQ", data, off
            )
        else:
            p_type, p_offset, p_vaddr, _paddr, p_filesz, p_memsz, p_flags, _align = struct.unpack_from(
                end + "IIIIIIII", data, off
            )
        segments.append(
            {
                "type": _PT_TYPES.get(p_type, f"0x{p_type:x}"),
                "offset": p_offset,
                "virtualAddress": p_vaddr,
                "fileSize": p_filesz,
                "memorySize": p_memsz,
                "flags": "".join(ch for ch, bit in (("r", 4), ("w", 2), ("x", 1)) if p_flags & bit),
            }
        )
        if p_type == 3 and p_offset + p_filesz <= len(data):
            interpreter = _text(data[p_offset : p_offset + p_filesz])

    sections = []
    raw_sections = []
    for i in range(min(e_shnum, SECTION_LIMIT)):
        off = e_shoff + i * e_shentsize
        if off + e_shentsize > len(data):
            warnings.append("Section header table runs past the end of the file.")
            break
        if is64:
            sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, _info, _align, _entsize = (
                struct.unpack_from(end + "IIQQQQIIQQ", data, off)
            )
        else:
            sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, _info, _align, _entsize = (
                struct.unpack_from(end + "IIIIIIIIII", data, off)
            )
        raw_sections.append((sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link))

    def string_at(table_offset: int, index: int) -> str:
        start = table_offset + index
        if start >= len(data):
            return ""
        stop = data.find(b"\0", start)
        return _text(data[start : stop if stop != -1 else len(data)])

    shstr_offset = raw_sections[e_shstrndx][4] if e_shstrndx < len(raw_sections) else None
    for sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, _link in raw_sections:
        name = string_at(shstr_offset, sh_name) if shstr_offset is not None else ""
        has_bytes = sh_type != 8 and sh_offset + sh_size <= len(data)  # SHT_NOBITS has no file content
        sections.append(
            {
                "name": name,
                "virtualAddress": sh_addr,
                "rawOffset": sh_offset,
                "rawSize": sh_size,
                "entropy": entropy(data[sh_offset : sh_offset + sh_size]) if has_bytes and sh_size else 0.0,
                "executable": bool(sh_flags & 0x4),
                "writable": bool(sh_flags & 0x1),
            }
        )

    # Shared libraries: DT_NEEDED entries of .dynamic, names in the linked string table.
    needed = []
    for _sh_name, sh_type, _flags, _addr, sh_offset, sh_size, sh_link in raw_sections:
        if sh_type != 6 or sh_link >= len(raw_sections):  # SHT_DYNAMIC
            continue
        strtab_offset = raw_sections[sh_link][4]
        entry_size = 16 if is64 else 8
        fmt = end + ("qQ" if is64 else "iI")
        for pos in range(sh_offset, min(sh_offset + sh_size, len(data) - entry_size + 1), entry_size):
            d_tag, d_val = struct.unpack_from(fmt, data, pos)
            if d_tag == 0:
                break
            if d_tag == 1:
                needed.append(string_at(strtab_offset, d_val))

    return {
        "format": "elf",
        "is64": is64,
        "littleEndian": little,
        "type": _ELF_TYPES.get(e_type, f"0x{e_type:x}"),
        "machine": _ELF_MACHINES.get(e_machine, f"0x{e_machine:x}"),
        "entryPoint": e_entry,
        "interpreter": interpreter,
        "sectionCount": e_shnum,
        "sections": sections,
        "segments": segments,
        "imports": [{"library": lib, "name": ""} for lib in needed],
        "importCount": len(needed),
        "stripped": not any(s["name"] == ".symtab" for s in sections),
        "warnings": warnings,
    }


# ---------------------------------------------------------------------------
# Mach-O
# ---------------------------------------------------------------------------
_MACHO_CPU = {7: "x86", 0x01000007: "x86-64", 12: "arm", 0x0100000C: "arm64", 18: "powerpc"}
_MACHO_FILETYPES = {1: "object", 2: "executable", 6: "dylib", 8: "bundle", 9: "dylib stub", 10: "dsym", 11: "kext"}
_LC_NAMES = {
    0x1: "SEGMENT",
    0x19: "SEGMENT_64",
    0x2: "SYMTAB",
    0xB: "DYSYMTAB",
    0xC: "LOAD_DYLIB",
    0xD: "ID_DYLIB",
    0xE: "LOAD_DYLINKER",
    0x80000018: "LOAD_WEAK_DYLIB",
    0x8000001C: "RPATH",
    0x80000028: "MAIN",
    0x1D: "CODE_SIGNATURE",
    0x21: "ENCRYPTION_INFO",
    0x2C: "ENCRYPTION_INFO_64",
    0x24: "VERSION_MIN_MACOSX",
    0x32: "BUILD_VERSION",
    0x26: "FUNCTION_STARTS",
    0x29: "DATA_IN_CODE",
    0x2A: "SOURCE_VERSION",
    0x1B: "UUID",
    0x22: "DYLD_INFO",
    0x80000022: "DYLD_INFO_ONLY",
    0x80000033: "DYLD_EXPORTS_TRIE",
    0x80000034: "DYLD_CHAINED_FIXUPS",
}


def _parse_macho_slice(data: bytes) -> dict[str, Any]:
    magic = data[:4]
    if magic in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf"):
        end = ">"
    elif magic in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        end = "<"
    else:
        raise ValueError("Not a Mach-O slice.")
    is64 = magic in (b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe")
    header_fmt = end + ("IiiIIII" + ("I" if is64 else ""))
    fields = struct.unpack_from(header_fmt, data, 0)
    _magic, cputype, _cpusub, filetype, ncmds, _sizeofcmds, _flags = fields[:7]
    offset = struct.calcsize(header_fmt)
    commands, dylibs, segments, sections = [], [], [], []
    warnings: list[str] = []
    entry_point = None
    encrypted = False
    signed = False
    rpaths = []
    for _ in range(min(ncmds, 512)):
        if offset + 8 > len(data):
            warnings.append("Load commands run past the end of the file.")
            break
        cmd, cmdsize = struct.unpack_from(end + "II", data, offset)
        if cmdsize < 8 or offset + cmdsize > len(data):
            warnings.append("A load command has an invalid size.")
            break
        name = _LC_NAMES.get(cmd, f"0x{cmd:x}")
        commands.append(name)
        if cmd in (0xC, 0xD, 0x80000018):
            str_off = struct.unpack_from(end + "I", data, offset + 8)[0]
            dylibs.append(_text(data[offset + str_off : offset + cmdsize]))
        elif cmd == 0x8000001C:
            str_off = struct.unpack_from(end + "I", data, offset + 8)[0]
            rpaths.append(_text(data[offset + str_off : offset + cmdsize]))
        elif cmd in (0x1, 0x19):
            if cmd == 0x19:
                segname, vmaddr, vmsize, fileoff, filesize, _maxprot, initprot, nsects, _sflags = struct.unpack_from(
                    end + "16sQQQQiiII", data, offset + 8
                )
                sect_size, sect_fmt = 80, end + "16s16sQQIIIIIIII"
            else:
                segname, vmaddr, vmsize, fileoff, filesize, _maxprot, initprot, nsects, _sflags = struct.unpack_from(
                    end + "16sIIIIiiII", data, offset + 8
                )
                sect_size, sect_fmt = 68, end + "16s16sIIIIIIIII"
            segments.append(
                {
                    "name": _text(segname),
                    "virtualAddress": vmaddr,
                    "memorySize": vmsize,
                    "offset": fileoff,
                    "fileSize": filesize,
                    "flags": "".join(ch for ch, bit in (("r", 1), ("w", 2), ("x", 4)) if initprot & bit),
                }
            )
            sect_off = offset + (72 if cmd == 0x19 else 56)
            for _s in range(min(nsects, SECTION_LIMIT)):
                if sect_off + sect_size > len(data):
                    break
                sect = struct.unpack_from(sect_fmt, data, sect_off)
                sectname, segname_s, addr, size, s_offset = sect[0], sect[1], sect[2], sect[3], sect[4]
                has_bytes = s_offset + size <= len(data) and size > 0
                sections.append(
                    {
                        "name": f"{_text(segname_s)},{_text(sectname)}",
                        "virtualAddress": addr,
                        "rawOffset": s_offset,
                        "rawSize": size,
                        "entropy": entropy(data[s_offset : s_offset + size]) if has_bytes else 0.0,
                        "executable": "x" in segments[-1]["flags"],
                        "writable": "w" in segments[-1]["flags"],
                    }
                )
                sect_off += sect_size
        elif cmd == 0x80000028:
            entry_point = struct.unpack_from(end + "Q", data, offset + 8)[0]
        elif cmd in (0x21, 0x2C):
            cryptid = struct.unpack_from(end + "III", data, offset + 8)[2]
            encrypted = cryptid != 0
        elif cmd == 0x1D:
            signed = True
        offset += cmdsize
    return {
        "format": "macho",
        "is64": is64,
        "cpu": _MACHO_CPU.get(cputype, f"0x{cputype:x}"),
        "type": _MACHO_FILETYPES.get(filetype, str(filetype)),
        "entryPoint": entry_point,
        "loadCommands": commands,
        "segments": segments,
        "sectionCount": len(sections),
        "sections": sections,
        "imports": [{"library": lib, "name": ""} for lib in dylibs],
        "importCount": len(dylibs),
        "rpaths": rpaths,
        "signed": signed,
        "encrypted": encrypted,
        "warnings": warnings,
    }


def parse_macho(data: bytes) -> dict[str, Any]:
    if data[:4] == b"\xca\xfe\xba\xbe":
        nfat = struct.unpack_from(">I", data, 4)[0]
        slices = []
        for i in range(min(nfat, 16)):
            cputype, _sub, offset, size, _align = struct.unpack_from(">iiIII", data, 8 + i * 20)
            if offset + size <= len(data):
                slices.append({"cpu": _MACHO_CPU.get(cputype, f"0x{cputype:x}"), "offset": offset, "size": size})
        first = next((s for s in slices if s["cpu"] in ("arm64", "x86-64")), slices[0] if slices else None)
        detail = (
            _parse_macho_slice(data[first["offset"] : first["offset"] + first["size"]])
            if first
            else {"format": "macho", "warnings": ["Empty universal binary."]}
        )
        detail["universal"] = slices
        return detail
    return _parse_macho_slice(data)


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------
def parse_structure(type_id: str, data: bytes) -> dict[str, Any] | None:
    """Structure for the executable formats, ``None`` for anything else; errors become warnings."""
    parser = {"pe32": parse_pe, "pe64": parse_pe, "pe": parse_pe, "elf": parse_elf, "macho": parse_macho}.get(type_id)
    if parser is None:
        return None
    try:
        return parser(data)
    except Exception:  # malformed headers are expected in malware
        # The parser's own message stays in the server log: it can carry internals.
        logger.info("Could not parse the %s structure", type_id, exc_info=True)
        return {
            "format": parser.__name__.replace("parse_", ""),
            "warnings": ["Could not parse the structure: the headers are malformed or truncated."],
        }

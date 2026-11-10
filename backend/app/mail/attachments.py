"""What each attachment really is, and why it may be dangerous.

Nothing here opens an attachment with the program it is meant for: the bytes
are hashed, typed from their magic bytes, and read by parsers that do not
execute anything (oletools for Office macros, the zip directory, the text of
an ``.ics`` invitation, Pillow and zxing for QR codes in images).
"""

from __future__ import annotations

import io
import re
import zipfile
from typing import Any

from ..parsing.malware import detect_type, hashes
from .content import qr_codes

MACRO_SOURCE_MAX = 64 * 1024
ZIP_ENTRIES_MAX = 200
QR_IMAGE_MAX = 10 * 1024 * 1024

# Extensions that run code when opened (or hand it to something that does).
EXECUTABLE = {
    "exe", "scr", "com", "pif", "cpl", "msi", "msp", "dll", "bat", "cmd", "ps1", "psm1", "vbs", "vbe", "js", "jse",
    "wsf", "wsh", "hta", "jar", "lnk", "reg", "inf", "scf", "url", "iso", "img", "vhd", "vhdx", "appx", "msix",
    "application", "chm", "xll", "library-ms", "settingcontent-ms", "one", "svg",
}  # fmt: skip
MACRO_ENABLED = {"docm", "dotm", "xlsm", "xltm", "xlsb", "xlam", "pptm", "potm", "ppsm", "sldm"}
OFFICE = {"doc", "dot", "xls", "xlt", "ppt", "pps", "docx", "xlsx", "pptx", "rtf", "odt", "ods", "odp"} | MACRO_ENABLED
ARCHIVES = {"zip", "rar", "7z", "gz", "tgz", "tar", "cab", "ace", "arj", "z", "bz2", "xz", "lzh"}
HTML = {"html", "htm", "shtml", "xhtml", "mht", "mhtml"}

# File type id (from the magic bytes) → the extensions it may carry.
_TYPE_EXTENSIONS = {
    "pe32": EXECUTABLE | {"sys", "ocx", "drv"},
    "pe64": EXECUTABLE | {"sys", "ocx", "drv"},
    "pe": EXECUTABLE | {"sys", "ocx", "drv"},
    "mz": EXECUTABLE,
    "elf": {"elf", "so", "bin", "o"},
    "pdf": {"pdf"},
    "zip": {"zip", "docx", "xlsx", "pptx", "docm", "xlsm", "pptm", "dotm", "xltm", "xlam", "potm", "ppsm", "jar", "apk",
            "odt", "ods", "odp", "xpi", "appx", "msix", "vsix", "kmz", "epub", "one", "xps", "oxps", "cbz", "ipa"},
    "rar": {"rar", "cbr"},
    "7z": {"7z"},
    "gzip": {"gz", "tgz"},
    "ole": {"doc", "dot", "xls", "xlt", "ppt", "pps", "msg", "msi", "msp", "pub", "vsd", "xla", "mpp", "one"},
    "rtf": {"rtf", "doc"},
    "cab": {"cab", "msu"},
}  # fmt: skip


def extension(name: str) -> str:
    base = (name or "").rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower().strip(" .")
    return base.rsplit(".", 1)[-1] if "." in base else ""


def _double_extension(name: str) -> str | None:
    parts = (name or "").lower().strip(" .").split(".")
    if len(parts) >= 3 and parts[-1] in EXECUTABLE and len(parts[-2]) in (2, 3, 4) and parts[-2].isalpha():
        return f".{parts[-2]}.{parts[-1]}"
    return None


def _hidden_name(name: str) -> str | None:
    """Right-to-left override and padding tricks that hide the real extension."""
    if "‮" in (name or ""):
        return "right-to-left override in the name"
    if re.search(r"\s{5,}\.\w+$", name or ""):
        return "spaces pad the real extension out of view"
    return None


# --------------------------------------------------------------------------- #
# Office macros                                                               #
# --------------------------------------------------------------------------- #
def macros(name: str, data: bytes) -> dict[str, Any] | None:
    """VBA and Excel 4 (XLM) macros with olevba's keyword analysis, or None."""
    try:
        from oletools.olevba import VBA_Parser
    except ImportError:  # pragma: no cover - a requirement
        return None
    try:
        parser = VBA_Parser(name or "attachment", data=data, relaxed=True)
    except Exception:  # noqa: BLE001 - not an Office file olevba reads
        return None
    try:
        if not parser.detect_vba_macros():
            return None
        modules, source = [], []
        size = 0
        for _subfile, _stream, module, code in parser.extract_all_macros():
            text = code if isinstance(code, str) else code.decode("utf-8", "replace")
            modules.append(module)
            if size < MACRO_SOURCE_MAX:
                chunk = f"' ---- {module} ----\n{text}\n"
                source.append(chunk[: MACRO_SOURCE_MAX - size])
                size += len(chunk)
        findings = []
        for kind, keyword, description in parser.analyze_macros() or []:
            if kind in ("AutoExec", "Suspicious", "IOC", "Hex String", "Base64 String", "Dridex String", "VBA string"):
                findings.append({"type": kind, "keyword": str(keyword)[:200], "description": str(description)[:300]})
        return {
            "modules": sorted(set(modules)),
            "xlm": bool(getattr(parser, "xlm_macros", None)),
            "autoexec": sorted({f["keyword"] for f in findings if f["type"] == "AutoExec"}),
            "suspicious": sorted({f["keyword"] for f in findings if f["type"] == "Suspicious"}),
            "findings": findings[:100],
            "source": "".join(source),
            "truncated": size > MACRO_SOURCE_MAX,
        }
    except Exception:  # noqa: BLE001 - a malformed project: say there are macros, without details
        return {
            "modules": [],
            "xlm": False,
            "autoexec": [],
            "suspicious": [],
            "findings": [],
            "source": "",
            "truncated": False,
        }
    finally:
        parser.close()


# --------------------------------------------------------------------------- #
# Zip archives                                                                #
# --------------------------------------------------------------------------- #
_PASSWORD_HINT = re.compile(
    r"(?:password|passwort|pass|pwd|parola chiave|codice|kennwort|contraseña|mot de passe)"
    r"\s*(?:is|è|:|=|-)?\s*[:\-]?\s*"
    r"[\"'«“]?([^\s\"'»”<>,;]{3,40})",
    re.IGNORECASE,
)


def passwords_in(text: str) -> list[str]:
    """Candidate archive passwords written in the message ("password: 1234")."""
    found = []
    for match in _PASSWORD_HINT.finditer(text or ""):
        word = match.group(1).rstrip(".")
        if word.lower() not in ("is", "the", "for", "per", "del", "della") and word not in found:
            found.append(word)
    return found[:10]


def zip_listing(data: bytes, passwords: list[str]) -> dict[str, Any] | None:
    import pyzipper

    try:
        archive = pyzipper.AESZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, OSError, ValueError, NotImplementedError):
        return None
    with archive:
        infos = archive.infolist()
        encrypted = any(info.flag_bits & 0x1 for info in infos)
        password = None
        if encrypted:
            probe = next((info for info in infos if info.flag_bits & 0x1 and not info.is_dir()), None)
            for candidate in [*passwords, "infected", "malware", "virus"]:
                try:
                    archive.setpassword(candidate.encode())
                    with archive.open(probe) as handle:
                        handle.read(1)
                    password = candidate
                    break
                except (RuntimeError, zipfile.BadZipFile, ValueError, OSError):
                    continue
            archive.setpassword(None)
        entries = []
        for info in infos[:ZIP_ENTRIES_MAX]:
            if info.is_dir():
                continue
            ext = extension(info.filename)
            entry = {
                "name": info.filename,
                "size": info.file_size,
                "compressed": info.compress_size,
                "encrypted": bool(info.flag_bits & 0x1),
                "risky": ext in EXECUTABLE or ext in MACRO_ENABLED or ext in HTML,
            }
            # The real type of the members, when the archive can be read (it
            # is never extracted to disk).
            if info.file_size <= 50 * 1024 * 1024 and (not entry["encrypted"] or password):
                try:
                    if password:
                        archive.setpassword(password.encode())
                    with archive.open(info) as handle:
                        head = handle.read(4096)
                    entry["type"] = detect_type(head)
                except (RuntimeError, zipfile.BadZipFile, ValueError, OSError, NotImplementedError):
                    pass
            entries.append(entry)
        return {
            "entries": entries,
            "total": len(infos),
            "encrypted": encrypted,
            "password": password,
            # Zip bombs: a tiny file expanding to gigabytes.
            "ratio": round(sum(i.file_size for i in infos) / max(1, len(data)), 1),
        }


# --------------------------------------------------------------------------- #
# Calendar invitations                                                        #
# --------------------------------------------------------------------------- #
def calendar(data: bytes) -> dict[str, Any] | None:
    text = data.decode("utf-8", "replace")
    if "BEGIN:VCALENDAR" not in text.upper():
        return None
    unfolded = re.sub(r"\r?\n[ \t]", "", text)
    fields: dict[str, str] = {}
    for line in unfolded.splitlines():
        key, _, value = line.partition(":")
        name = key.split(";", 1)[0].upper()
        if name in ("SUMMARY", "ORGANIZER", "DTSTART", "DTEND", "LOCATION", "DESCRIPTION", "URL", "METHOD"):
            fields.setdefault(name.lower(), value.replace("\\n", "\n").replace("\\,", ",")[:2000])
    fields["urls"] = sorted(set(re.findall(r"https?://[^\s\"'<>\\]+", unfolded)))[:50]
    return fields


# --------------------------------------------------------------------------- #
def inspect(attachment: dict[str, Any], body_text: str) -> dict[str, Any]:
    """The analysis of one attachment (the bytes stay out of the result)."""
    data: bytes = attachment.get("data") or b""
    name = attachment.get("name") or "attachment"
    ext = extension(name)
    kind = detect_type(data) if data else {"id": "empty", "label": "Empty"}
    out: dict[str, Any] = {
        "name": name,
        "contentType": attachment.get("content_type"),
        "contentId": attachment.get("content_id"),
        "inline": attachment.get("disposition") == "inline",
        "size": len(data),
        "extension": ext,
        "type": kind,
        "hashes": hashes(data) if data else None,
        "findings": [],
    }
    findings = out["findings"]

    def flag(code: str, severity: str, text: str) -> None:
        findings.append({"id": code, "label": text, "severity": severity})

    if ext in EXECUTABLE:
        flag("executable", "high", f".{ext} files run code when opened")
    if kind["id"] in ("pe32", "pe64", "pe", "mz", "elf", "macho") and ext not in EXECUTABLE | {"sys", "ocx", "drv"}:
        flag("disguised-executable", "high", f"an executable ({kind['label']}) named .{ext or '(no extension)'}")
    elif kind["id"] in _TYPE_EXTENSIONS and ext and ext not in _TYPE_EXTENSIONS[kind["id"]] and ext not in EXECUTABLE:
        flag("type-mismatch", "medium", f"the content is {kind['label']}, not .{ext}")
    double = _double_extension(name)
    if double:
        flag("double-extension", "high", f"double extension {double}")
    hidden = _hidden_name(name)
    if hidden:
        flag("hidden-extension", "high", hidden)
    if ext in MACRO_ENABLED:
        flag("macro-enabled", "medium", f".{ext} is a macro-enabled Office format")
    if ext in HTML:
        flag("html", "medium", "an HTML attachment opens a local page (credential forms, smuggled downloads)")

    if data and (ext in OFFICE or kind["id"] in ("ole", "zip", "rtf")) and ext not in ARCHIVES:
        found = macros(name, data)
        if found is not None:
            out["macros"] = found
            severity = "high" if found["autoexec"] else "medium"
            flag(
                "macros",
                severity,
                "VBA macros" + (" that run on open: " + ", ".join(found["autoexec"][:3]) if found["autoexec"] else ""),
            )
            if found["xlm"]:
                flag("xlm-macros", "high", "Excel 4 (XLM) macros")
    if data and kind["id"] == "zip" and (ext in ARCHIVES or ext == ""):
        listing = zip_listing(data, passwords_in(body_text))
        if listing is not None:
            out["archive"] = listing
            if listing["encrypted"]:
                flag(
                    "encrypted-archive",
                    "high",
                    "a password-protected archive (hides its content from mail filters)"
                    + (f"; password found in the message: {listing['password']}" if listing["password"] else ""),
                )
            risky = [e["name"] for e in listing["entries"] if e["risky"]]
            if risky:
                flag("archive-executable", "high", "the archive holds " + ", ".join(risky[:3]))
            if listing["ratio"] > 100:
                flag("zip-bomb", "medium", f"expands {listing['ratio']}× its size")
    if data and (ext == "ics" or (attachment.get("content_type") or "").startswith("text/calendar")):
        invite = calendar(data)
        if invite is not None:
            out["calendar"] = invite
            if invite.get("urls"):
                flag("calendar-links", "low", f"the invitation holds {len(invite['urls'])} link(s)")
    if data and kind["id"] == "pdf":
        head = data[: 4 * 1024 * 1024]
        actions = sorted(
            {
                m.decode()
                for m in re.findall(rb"/(JavaScript|JS|OpenAction|Launch|EmbeddedFile|AA|URI|SubmitForm)\b", head)
            }
        )
        if actions:
            out["pdf"] = {
                "actions": actions,
                "urls": sorted({u.decode("latin-1") for u in re.findall(rb"/URI\s*\(([^)]{4,500})\)", head)})[:50],
            }
            dangerous = [a for a in actions if a in ("JavaScript", "JS", "Launch", "EmbeddedFile", "OpenAction")]
            if dangerous:
                flag("pdf-active", "medium", "PDF with " + ", ".join(dangerous))
    if data and (attachment.get("content_type") or "").startswith("image/") and len(data) <= QR_IMAGE_MAX:
        codes = qr_codes(data)
        if codes:
            out["qrCodes"] = codes
            flag("qr-code", "medium", "a QR code pointing to " + codes[0][:120])
    if attachment.get("nested"):
        flag("attached-message", "low", "an attached e-mail (analysed below)")
    return out

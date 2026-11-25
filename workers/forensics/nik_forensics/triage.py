"""Collections: a triage zip (KAPE, Velociraptor) opened safely, and what a bare file is (7.0, stage 6).

A collection is a **zip** and nothing else: an image of a disk (VHDX, VHD, E01) or the native storage of Plaso
is recognised and refused with a sentence that says how to turn it into something Nik reads (``refusal``).

What this module holds, apart from the process that unpacks (``unpack_job.py``):

* ``describe(path)``: what the place of a file in a triage tree says of it: the user, the host, the browser
  profile, and the section and the source it is when its content cannot say (a text log, a hive). A table of
  well-known paths, the same for a KAPE target and a Velociraptor artifact;
* ``is_executable(head, name)``: programs and scripts, by their first bytes and their extension. They are
  listed, never kept and never read;
* ``Archive``: the members of a zip, with the limits that make a hostile zip harmless (said below).

**The limits of an unpack**, whatever the zip says of itself:

* no name is ever used as a path: a member is written under a number in a folder of the job, so a name with
  ``..``, an absolute path or a drive cannot leave it (it is listed, and skipped when it climbs out). No
  symbolic link is followed or made: a member that is one is skipped;
* a member of more than ``MEMBER_MAX`` bytes, or one that would take the total over what the caller allows
  (``total``), is skipped with its reason, and so are the members after the total is reached;
* a member that expands more than ``RATIO_MAX`` times when it is larger than ``RATIO_FROM`` bytes is skipped as
  a bomb; a zip whose members overlap (more compressed bytes than the file has) is refused whole;
* a member is read no further than its size says (the library stops there): a header that lies cannot make it
  expand;
* an archive inside the collection is not opened: it is listed as the file it is;
* an encrypted member is skipped with the reason; the password ``infected`` is tried when every member is
  encrypted with the old zip encryption (the library cannot open AES);
* at most ``MAX_MEMBERS`` members are listed; the rest are counted and said.
"""

from __future__ import annotations

import os
import posixpath
import re
import struct
import zipfile
from typing import Any
from urllib.parse import unquote

MAX_MEMBERS = 20_000
MEMBER_MAX = 8 * 1024**3
RATIO_MAX = 2000
RATIO_FROM = 1024**3
MAX_PATH = 1000
PASSWORD = b"infected"
ARCHIVE_SENTENCE = "an archive inside the collection: it is not opened (unzip it and send the files)"

_DISK = (
    "Nik reads files, not disk images. Mount the image (read-only), collect the folders you need with KAPE or "
    "Velociraptor, and send that zip"
)
_PLASO = (
    "Nik reads the output of psort, not the storage file of Plaso. Export it with "
    "`psort.py -o json_line -w timeline.jsonl file.plaso` (or `-o dynamic` for a CSV) and send that file"
)
_ARCHIVE = "Nik opens collections that are zip files. Send a zip (7-Zip and tar archives are not opened)"
_UNKNOWN = "No parser of Nik reads this file"

_SQLITE = b"SQLite format 3\x00"
_ARCHIVE_MAGICS = (
    b"PK\x03\x04",
    b"PK\x05\x06",
    b"7z\xbc\xaf\x27\x1c",
    b"Rar!\x1a\x07",
    b"\x1f\x8b\x08",
    b"BZh",
    b"\xfd7zXZ\x00",
)
_ARCHIVE_EXTENSIONS = (".zip", ".7z", ".rar", ".tar", ".tgz", ".gz", ".bz2", ".xz", ".cab", ".iso", ".jar")


def is_zip(head: bytes) -> bool:
    return head.startswith((b"PK\x03\x04", b"PK\x05\x06"))


def refusal(path: str, name: str, head: bytes) -> str | None:
    """The sentence for a file Nik knows it cannot read and can say how to make readable; None otherwise."""
    base = posixpath.basename((name or "").replace("\\", "/")).lower()
    if head.startswith(b"vhdxfile") or base.endswith(".vhdx"):
        return "This is a VHDX disk image. " + _DISK
    if head.startswith(b"conectix") or base.endswith(".vhd"):
        return "This is a VHD disk image. " + _DISK
    if head.startswith((b"EVF\x09\x0d\x0a\xff\x00", b"EVF2\x0d\x0a\x81\x00")) or base.endswith(
        (".e01", ".ex01", ".l01")
    ):
        return "This is an EnCase (E01) disk image. " + _DISK
    if base.endswith((".dd", ".raw", ".img", ".vmdk", ".vdi", ".qcow2", ".aff4")) and not head.startswith(_SQLITE):
        return "This looks like a disk image. " + _DISK
    if base.endswith(".plaso") or (head.startswith(_SQLITE) and _is_plaso_database(path)):
        return "This is a Plaso storage file. " + _PLASO
    if head.startswith(_ARCHIVE_MAGICS[2:]) or base.endswith((".7z", ".rar", ".tar", ".tgz", ".tar.gz")):
        return _ARCHIVE
    return None


def _is_plaso_database(path: str) -> bool:
    """A SQLite file with the tables Plaso's storage has (the check is a read of the schema, nothing is run)."""
    from nik_forensics import sqlite_safe

    try:
        conn = sqlite_safe.open_ro(path)
    except Exception:  # noqa: BLE001 - a file that cannot be opened is not one
        return False
    try:
        return {"event_data", "metadata"} <= sqlite_safe.tables(conn)
    except Exception:  # noqa: BLE001
        return False
    finally:
        conn.close()


def what_is(path: str, name: str) -> dict[str, Any]:
    """What a bare file is: ``{"container": "zip"}``, ``{"parser", "version", "kind", "source"}`` or
    ``{"refused": sentence}`` (a file Nik cannot read and can say how to convert), ``{"unknown": sentence}``."""
    from nik_forensics import parsers

    with open(path, "rb") as handle:
        head = handle.read(4096)
    said = refusal(path, name, head)
    if said:
        return {"refused": said}
    if is_zip(head):
        return {"container": "zip", "kind": "collection", "source": "collection.zip"}
    try:
        module, source = parsers.recognise(path, name)
    except parsers.UnknownParser:
        return {
            "unknown": _UNKNOWN
            + ": it is not an event log, a browser or shell history, a registry hive, a Plaso export or another file "
            "Nik knows"
        }
    return {"parser": module.NAME, "version": module.VERSION, "kind": module.KIND, "source": source}


# --------------------------------------------------------------------------- #
# Executables                                                                 #
# --------------------------------------------------------------------------- #
_SCRIPT_EXTENSIONS = (
    ".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl", ".msi", ".com", ".efi", ".so", ".dylib", ".ko",
    ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".sh", ".py", ".pl", ".jar",
)  # fmt: skip
_MACHO = (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe")


def is_executable(head: bytes, name: str) -> bool:
    """A program (Windows PE, ELF, Mach-O), or a script by its extension or its ``#!`` line."""
    if head.startswith(b"MZ") and len(head) >= 64:
        offset = struct.unpack_from("<I", head, 60)[0]
        if offset + 4 <= len(head):
            return head[offset : offset + 4] == b"PE\x00\x00"
        return True  # the header lies beyond what was looked at: an MZ file this size is a program
    if head.startswith(b"\x7fELF") or head.startswith(_MACHO) or head.startswith(b"#!"):
        return True
    return posixpath.basename(name.lower()).endswith(_SCRIPT_EXTENSIONS)


def is_archive(head: bytes, name: str) -> bool:
    base = posixpath.basename(name.lower())
    if head.startswith(_ARCHIVE_MAGICS):
        return not base.endswith((".docx", ".xlsx", ".pptx", ".odt"))  # a document is a file, not a collection
    return base.endswith(_ARCHIVE_EXTENSIONS)


# --------------------------------------------------------------------------- #
# The place of a file in a triage tree                                        #
# --------------------------------------------------------------------------- #
_IGNORED_ROOTS = {
    "uploads", "auto", "ntfs", "file", "registry", "accessor", "vss", "mft", "collection", "results", "files",
    "triage", "output", "kape", "velociraptor",
}  # fmt: skip
_DRIVE = re.compile(r"^[a-z](:|\$)?$")
_NOT_USERS = {"public", "default", "default user", "all users", "shared", "guest", "desktop.ini"}
_PROFILE = re.compile(r"^(default|profile \d+|guest profile|system profile)$", re.I)
_BROWSERS = (
    ("brave", ("bravesoftware", "brave-browser")),
    ("edge", ("microsoft/edge", "microsoft-edge", "microsoft edge")),
    ("opera", ("opera software", "com.operasoftware", "/opera/")),
    ("chrome", ("google/chrome", "google-chrome", "/chromium/", "chromium/")),
)
_CHROMIUM_FILES = {"history": "history", "shortcuts": "shortcuts", "bookmarks": "bookmarks"}
_VELOCIRAPTOR_NAME = re.compile(r"^collection-(.+?)-\d{4}-\d{2}-\d{2}", re.I)


def _clean(path: str) -> list[str]:
    text = unquote(path.replace("\\", "/"))
    return [part for part in text.split("/") if part not in ("", ".")]


def host_of(parts: list[str], zip_name: str = "") -> str:
    """The machine a Velociraptor or KAPE tree says it is: a folder before the drive (``HOST/C/Windows``), else the
    name of a Velociraptor collection (``Collection-HOST-2024-05-01T...zip``)."""
    for index, part in enumerate(parts[:6]):
        if _DRIVE.fullmatch(part.lower()) and index:
            held = [item for item in parts[:index] if item.lower() not in _IGNORED_ROOTS and not item.startswith("\\")]
            if len(held) == 1 and len(held[0]) <= 255 and not held[0].lower().endswith((".dat", ".zip")):
                return held[0]
            break
    found = _VELOCIRAPTOR_NAME.match(posixpath.basename(zip_name.replace("\\", "/")))
    return found.group(1)[:255] if found else ""


def user_of(parts: list[str]) -> str:
    """The account a path says it is of: ``Users/<u>``, ``home/<u>``, a service profile, ``root``."""
    lower = [part.lower() for part in parts]
    for index in range(len(parts) - 2):  # a user folder has something below it
        if lower[index] in ("users", "home", "documents and settings") and lower[index + 1] not in _NOT_USERS:
            return parts[index + 1][:255]
        if lower[index] == "serviceprofiles":
            return parts[index + 1][:255]
    if "systemprofile" in lower[:-1] and "config" in lower:
        return "SYSTEM"
    for index in range(min(len(parts) - 1, 4)):
        if lower[index] == "root" and all(part in _IGNORED_ROOTS for part in lower[:index]):
            return "root"
    return ""


def _browser_of(parts: list[str], lower: list[str]) -> tuple[str, str, str]:
    """(source, profile, what) of a browser file named by its place; empty when the place says none."""
    joined = "/" + "/".join(lower[:-1]) + "/"
    base = lower[-1]
    if "mozilla/firefox" in joined or ".mozilla/firefox" in joined or "/firefox/profiles/" in joined:
        if base == "places.sqlite":
            profile = parts[-2] if len(parts) > 1 else ""
            return "firefox.places", profile[:120], "places"
        return "", "", ""
    if "library/safari" in joined:
        return ("safari.history", "", "history") if base == "history.db" else ("", "", "")
    for browser, markers in _BROWSERS:
        if any(marker in joined for marker in markers):
            what = _CHROMIUM_FILES.get(base)
            if what is None:
                return "", "", ""
            profile = parts[-2] if len(parts) > 1 and (_PROFILE.fullmatch(parts[-2]) or len(parts) > 2) else ""
            if browser == "opera" and not _PROFILE.fullmatch(profile or ""):
                profile = profile if "opera" in profile.lower() else ""
            return f"{browser}.{what}", profile[:120], what
    return "", "", ""


# A hive found by its place is read whole: the hive parser writes every record the hive holds (run keys, services, USB,
# UserAssist, ShimCache, BAM, Amcache…), each with its own source.
HIVE = "windows.registry.hive"
_LOG_NAMES = (
    (re.compile(r"(^|/)var/log/(auth\.log|secure|auth)(\.\d+)?$"), "syslog", "linux.auth"),
    (re.compile(r"(^|/)var/log/audit/audit\.log(\.\d+)?$"), "syslog", "linux.audit"),
    (re.compile(r"(^|/)\.bash_history$"), "commands", "bash"),
    (re.compile(r"(^|/)\.(zsh_history|zhistory)$"), "commands", "zsh"),
    (re.compile(r"(^|/)fish_history$"), "commands", "fish"),
    (re.compile(r"(^|/)consolehost_history\.txt$"), "commands", "powershell"),
    (re.compile(r"(^|/)windows/system32/winevt/logs/[^/]+\.evtx$"), "eventlog", "evtx"),
    (re.compile(r"\.evtx$"), "eventlog", "evtx"),
    (re.compile(r"(^|/)windows/prefetch/[^/]+\.pf$"), "endpoint", "windows.execution.prefetch"),
    (re.compile(r"(^|/)windows/appcompat/programs/amcache\.hve$"), "endpoint", HIVE),
    (re.compile(r"(^|/)windows/system32/config/system$"), "endpoint", HIVE),
    (re.compile(r"(^|/)windows/system32/config/software$"), "endpoint", HIVE),
    (re.compile(r"(^|/)(ntuser\.dat|usrclass\.dat)$"), "endpoint", HIVE),
    (re.compile(r"(^|/)windows/system32/sru/srudb\.dat$"), "endpoint", "windows.network.srum-network"),
    (re.compile(r"\.lnk$"), "endpoint", "windows.fileaccess.lnk"),
    (re.compile(r"\.(automatic|custom)destinations-ms$"), "endpoint", "windows.fileaccess.jumplist"),
    (re.compile(r"(^|/)\$mft$"), "disk", "ntfs.mft"),
    (re.compile(r"(^|/)\$extend/(\$usnjrnl[%$:]?\$?)?\$j$|(^|/)\$j$|(^|/)\$usnjrnl[:$_]+\$j$"), "disk", "ntfs.usnjrnl"),
)  # fmt: skip


def describe(path: str, zip_name: str = "") -> dict[str, str]:
    """What the place of a file in a triage tree says: ``kind`` and ``source`` (empty when it says none),
    ``host``, ``username``, ``profile``. The content of the file is looked at first by the caller: this is
    what is left when the content cannot say, and what names the user and the machine."""
    parts = _clean(path)
    lower = [part.lower() for part in parts]
    found = {"kind": "", "source": "", "host": host_of(parts, zip_name), "username": user_of(parts), "profile": ""}
    if not parts:
        return found
    joined = "/".join(lower)
    source, profile, _what = _browser_of(parts, lower)
    if source:
        found.update(kind="browser", source=source, profile=profile)
        return found
    for pattern, kind, name in _LOG_NAMES:
        if pattern.search(joined):
            found.update(kind=kind, source=name)
            break
    return found


# --------------------------------------------------------------------------- #
# Names                                                                       #
# --------------------------------------------------------------------------- #
class OddPath(Exception):
    """A name that cannot be kept as text of a listing: the sentence says why."""


def display_name(info: zipfile.ZipInfo) -> str:
    """The name of a member as text that is safe to keep and show. A name without the UTF-8 flag that is
    valid UTF-8 was written by a tool that forgot the flag: read as UTF-8; otherwise as the library decoded it
    (CP437). Control characters become ``?``; separators are ``/``; a leading ``/``, ``./`` or drive goes."""
    name = info.filename
    if not info.flag_bits & 0x800:
        try:
            name = name.encode("cp437").decode("utf-8")
        except UnicodeError:
            pass
    name = name.encode("utf-8", "replace").decode("utf-8")
    name = "".join("?" if ord(char) < 32 or ord(char) == 127 else char for char in name)
    name = name.replace("\\", "/")
    name = re.sub(r"^[A-Za-z]:(?=/|$)", "", name)
    return name.lstrip("/")


def refuse_name(name: str) -> str | None:
    """A reason to skip a member by its name alone: it climbs out of the folder, or is too long to keep."""
    if ".." in name.split("/"):
        return "its path climbs out of the folder (..)"
    if len(name) > MAX_PATH:
        return f"its path is longer than {MAX_PATH} characters"
    return None


def is_symlink(info: zipfile.ZipInfo) -> bool:
    mode = info.external_attr >> 16
    return (mode & 0o170000) == 0o120000


class Archive:
    """The members of a zip, opened for reading only. ``members()`` gives the files (never a folder)."""

    def __init__(self, path: str) -> None:
        self.zip = zipfile.ZipFile(path)  # BadZipFile for what is not one
        self.size = os.path.getsize(path)
        self.password: bytes | None = None

    def overlapping(self) -> bool:
        """More compressed bytes than the file holds: members share data, the way a zip bomb does."""
        return sum(info.compress_size for info in self.zip.infolist()) > self.size

    def members(self) -> list[zipfile.ZipInfo]:
        return [info for info in self.zip.infolist() if not info.is_dir()]

    def try_password(self, members: list[zipfile.ZipInfo]) -> bool:
        """Every member is encrypted: whether the usual password for malware (``infected``) opens them."""
        if not members or not all(info.flag_bits & 0x1 for info in members):
            return False
        for info in members:
            if info.compress_type == 99:  # AES, which the standard library cannot open
                return False
        for info in members:
            if info.file_size == 0:
                continue
            try:
                with self.zip.open(info, pwd=PASSWORD) as handle:
                    handle.read(1)
            except (RuntimeError, zipfile.BadZipFile, EOFError, OSError):
                return False
            break
        self.password = PASSWORD
        return True

    def open(self, info: zipfile.ZipInfo):
        return self.zip.open(info, pwd=self.password)

    def close(self) -> None:
        self.zip.close()

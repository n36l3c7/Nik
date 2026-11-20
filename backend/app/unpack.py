"""Taking the files out of an archive, in memory.

A product that hands over files it collected often hands them over as one
archive, protected by a password (the fetched files of an EDR, the samples of
a sandbox). ``members`` reads such an archive and gives the files inside it
as bytes, for whoever called to keep each as an artifact of its own. It is
unpacking and nothing else:

- **Nothing is run, opened or written.** A member is read into memory and
  returned; nothing is extracted to a disk, and no member is given to a
  program that understands what it is.
- **A name is data.** The name of a member is returned as a text, cleaned of
  control characters. No path is ever built from it: ``../../etc/passwd``,
  ``C:\\Windows\\x``, ``CON`` and ``/dev/null`` are four names like any other.
- **Nothing is followed.** A directory is passed over, a symbolic link is
  skipped and said so, and an archive inside the archive is a file like the
  others: it is not unpacked.
- **It is bounded.** An archive holds so many members at most; what it gives
  is, together, no larger than an upload; a member that inflates far more
  than files do is skipped as a bomb. What a member says of its own size is
  not believed: reading stops at the limit whatever the directory claims.

Zip only, plain or protected: the classic ZipCrypto and WinZip AES (AE-1 and
AE-2), which ``pyzipper`` reads. A wrong password is said without repeating
it.
"""

from __future__ import annotations

import io
import re
import stat
import zipfile
import zlib
from dataclasses import dataclass, field

import pyzipper

FORMATS = ("zip",)
MEMBERS_MAX = 200  # members of one archive
RATIO_MAX = 200  # a member that inflates more than this many times is not unpacked
RATIO_FROM = 1024 * 1024  # … once it is larger than this: a small file of zeroes is not a bomb
NAME_MAX = 500
SKIPPED_MAX = 100
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class UnpackError(Exception):
    """An archive that is not unpacked at all, with a sentence that is safe to show."""

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


@dataclass
class Member:
    name: str  # as the archive says it, cleaned: a text, never a path
    data: bytes


@dataclass
class Unpacked:
    members: list[Member] = field(default_factory=list)
    skipped: list[dict[str, str]] = field(default_factory=list)  # {name, reason}

    def skip(self, name: str, reason: str) -> None:
        if len(self.skipped) < SKIPPED_MAX:
            self.skipped.append({"name": name, "reason": reason})


def clean_name(raw: str) -> str:
    """The name of a member as a text to show: no control character, of a length a person reads."""
    return " ".join(_CONTROL.sub(" ", str(raw or "")).split())[:NAME_MAX]


def file_name(name: str) -> str:
    """What a member is called as a file of its own: the last part of its name in the archive."""
    return name.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1][:200]


def _megabytes(size: int) -> str:
    return f"{max(1, size // (1024 * 1024))} MB"


def members(data: bytes, password: str = "", *, limit: int, fmt: str = "zip") -> Unpacked:
    """The files of an archive, as bytes. ``limit`` is the size of an upload: no member is larger,
    and all of them together are not. Raises ``UnpackError`` when the archive is not one, is
    protected and the password does not open it, or is over what an archive may hold."""
    if fmt not in FORMATS:
        raise UnpackError("Only a zip archive is unpacked")
    try:
        archive = pyzipper.AESZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, pyzipper.BadZipFile, ValueError, OSError, NotImplementedError):
        raise UnpackError("The file is not a zip archive Nik can read: nothing was unpacked") from None
    found = Unpacked()
    with archive:
        listed = [info for info in archive.infolist() if not info.is_dir()]
        if len(listed) > MEMBERS_MAX:
            raise UnpackError(
                f"The archive holds {len(listed)} files, more than the {MEMBERS_MAX} that are unpacked: "
                "nothing was unpacked"
            )
        if any(info.flag_bits & 0x1 for info in listed):
            if not password:
                raise UnpackError("The archive is protected by a password and none was given: nothing was unpacked")
            archive.setpassword(password.encode("utf-8"))
        total = 0
        for info in listed:
            name = clean_name(info.filename) or "(no name)"
            if stat.S_ISLNK(info.external_attr >> 16):
                found.skip(name, "It is a link: links are not followed")
                continue
            if info.file_size == 0:
                found.skip(name, "It is empty")
                continue
            if info.file_size > limit:
                found.skip(name, f"It is larger than the {_megabytes(limit)} limit of an upload")
                continue
            packed = max(1, info.compress_size)
            if info.file_size > RATIO_FROM and info.file_size / packed > RATIO_MAX:
                found.skip(name, f"It is packed more than {RATIO_MAX} times over: it is not unpacked")
                continue
            try:
                with archive.open(info) as handle:
                    # What the directory says of the size is not believed: reading stops at the limit.
                    content = handle.read(min(info.file_size, limit) + 1)
            except RuntimeError as error:
                # pyzipper and zipfile say "Bad password" this way; anything else is a member that cannot be read.
                if "password" in str(error).lower():
                    raise UnpackError("The password does not open the archive: nothing was unpacked") from None
                found.skip(name, "It could not be read")
                continue
            except (zipfile.BadZipFile, pyzipper.BadZipFile) as error:
                # A wrong ZipCrypto password that passes the one check byte ends as a bad checksum.
                if info.flag_bits & 0x1 and "crc" in str(error).lower():
                    raise UnpackError("The password does not open the archive: nothing was unpacked") from None
                found.skip(name, "It is damaged")
                continue
            except (NotImplementedError, zlib.error, EOFError, OSError, ValueError):
                found.skip(name, "It is packed in a way Nik does not read")
                continue
            if len(content) > info.file_size:
                found.skip(name, "It holds more than the archive says: it is not unpacked")
                continue
            total += len(content)
            if total > limit:
                raise UnpackError(
                    f"The archive holds more than the {_megabytes(limit)} limit of an upload once unpacked: "
                    "nothing was unpacked"
                )
            found.members.append(Member(name=name, data=content))
    return found

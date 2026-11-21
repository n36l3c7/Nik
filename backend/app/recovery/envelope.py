"""What leaves the host is sealed: a segment of the log, a base backup.

The log of PostgreSQL holds everything the database holds, in clear. Nothing
of it leaves the host that way: each segment and each base backup is written
as a backup of 6.7 is (``app/backups/container.py``: AES-256-GCM in chunks, a
header that is authenticated, parts with their size and checksum, a
manifest), under the backup passphrase. So one format and one passphrase
open everything that is on the second host, and ``container.py`` alone reads
any of it where Nik is not installed.

**Why the whole container for a segment of 16 MB.** A lighter envelope of
the same primitives would save about three hundred bytes of header and
manifest and nothing else: a segment is compressed before it is sealed
(``wal-archive.sh``), so one closed by the timer is some tens of kilobytes
and travels as two chunks. What does cost is deriving the key: scrypt takes
a tenth of a second and 32 MB for each new salt. So the key is derived once
and used for the files of the next hours (``Sealer``), each under a nonce of
its own; and whoever opens them derives it once for each salt it meets
(``Opener``).

**A passphrase that changes.** A standby learns the new passphrase from the
database it replays, so it must be able to open the segment that carries the
change with the one it already has. ``Sealer.for_segment`` therefore goes on
using the earlier passphrase up to the segment the change was written in,
and the new one after it.
"""

from __future__ import annotations

import functools
import hashlib
import os
import time
from collections.abc import Iterable
from pathlib import Path
from typing import Any, BinaryIO

from ..backups.container import CHUNK, PASSPHRASE, BackupError, Key, Reader, Secrets, Writer, key_id

# How long one derived key seals files: a new salt, and so a new key, a few times a day.
KEY_LIFE = 6 * 3600
OPENING = ".opening"
# Not a secret: it keeps the mark of a passphrase apart from every other use of the same derivation.
MARK_SALT = b"nik recovery passphrase"


@functools.lru_cache(maxsize=4)
def fingerprint(passphrase: str) -> str:
    """What tells one passphrase from another in a row of settings, without being the passphrase.

    It is written in the database, where a quick hash would let whoever reads it try passphrases
    at leisure: it is derived as slowly as the key of a backup is, once for a passphrase."""
    derived = hashlib.scrypt(passphrase.encode("utf-8"), salt=MARK_SALT, n=2**14, r=8, p=1, maxmem=2**26, dklen=8)
    return derived.hex()


class Sealer:
    """Derives the key of the envelopes from a passphrase, once every few hours."""

    def __init__(self) -> None:
        self._keys: dict[str, tuple[float, Key]] = {}

    def key(self, passphrase: str, now: float | None = None) -> Key:
        now = time.time() if now is None else now
        mark = fingerprint(passphrase)
        held = self._keys.get(mark)
        if held is None or not 0 <= now - held[0] <= KEY_LIFE:
            held = (now, Key.new(PASSPHRASE, passphrase))
            self._keys.pop(mark, None)
            self._keys[mark] = held
            # Two passphrases at most: the current one and the one before it.
            while len(self._keys) > 2:
                self._keys.pop(next(iter(self._keys)))
        return held[1]


class Opener:
    """What envelopes are opened with: every passphrase to try, each key derived once for each salt."""

    def __init__(self, secrets: Secrets) -> None:
        self._secrets = secrets
        self._derived: dict[tuple[str, str], bytes] = {}

    def key_for(self, spec: dict[str, Any]) -> bytes:
        mark = (str(spec.get("salt")), str(spec.get("id")))
        if mark not in self._derived:
            key = self._secrets.key_for(spec)
            if len(self._derived) > 64:
                self._derived.clear()
            self._derived[mark] = key
        return self._derived[mark]


def passphrase_for(segment: str, current: str, change: dict[str, Any] | None, earlier: str | None) -> str:
    """The passphrase a segment is sealed under: the earlier one up to the segment a change of
    passphrase was written in, the current one after it."""
    if change and earlier and segment <= str(change.get("upTo") or ""):
        return earlier
    return current


def seal(out: BinaryIO, key: Key, about: dict[str, Any], parts: Iterable[tuple[str, Path]]) -> dict[str, Any]:
    """Write the files named as parts of one envelope onto ``out``. Returns its manifest."""
    writer = Writer(out, key, about)
    for name, path in parts:
        with writer.part(name) as part, open(path, "rb") as source:
            for piece in iter(lambda source=source: source.read(CHUNK), b""):
                part.write(piece)
    return writer.finish({key: value for key, value in about.items() if key != "kind"})


def seal_file(source: Path, target: Path, key: Key, about: dict[str, Any], part: str) -> dict[str, Any]:
    with open(target, "wb") as out:
        return seal(out, key, about, [(part, source)])


class Hashing:
    """A file being written, counted and hashed as it goes by (what was sent, to compare with what arrived)."""

    def __init__(self, out: BinaryIO) -> None:
        self._out = out
        self.size = 0
        self.digest = hashlib.sha256()

    def write(self, data: bytes) -> int:
        self._out.write(data)
        self.digest.update(data)
        self.size += len(data)
        return len(data)


def unseal(source: BinaryIO, secrets: Secrets | Opener, folder: Path, expect: str = "") -> dict[str, Any]:
    """Open an envelope and write its parts into ``folder``, each beside its place first. Returns
    the header and the manifest. Nothing is left when it does not open or is not whole."""
    reader = Reader(source, secrets)  # type: ignore[arg-type] - an Opener has the one method a Reader uses
    kind = reader.header.get("kind")
    if expect and kind != expect:
        raise BackupError(f"This file is a {kind or 'backup'}, not a {expect} of the archive")
    written: list[Path] = []
    try:
        for part in reader.parts():
            name = part.name
            if "/" in name or "\\" in name or name.startswith(".") or not name:
                raise BackupError("The file names a part that is not one of the archive")
            # A name of its own: two processes may open the same file at once (a standby that is
            # being promoted), and each then moves a whole file into place.
            place = folder / f"{name}.{os.getpid()}{OPENING}"
            written.append(place)
            with open(place, "wb") as out:
                for piece in iter(lambda part=part: part.read(CHUNK), b""):
                    out.write(piece)
        for place in written:
            place.chmod(0o644)
            place.replace(place.with_name(place.name[: -len(f".{os.getpid()}{OPENING}")]))
    except BaseException:
        for place in written:
            place.unlink(missing_ok=True)
        raise
    return {"header": reader.header, "manifest": reader.manifest}


__all__ = ["KEY_LIFE", "Hashing", "Opener", "Sealer", "fingerprint", "key_id", "passphrase_for", "seal", "unseal"]

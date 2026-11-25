"""The pool: the files of the store a backup does not write twice (7.0).

Some files of the store are named by the SHA-256 of what they hold and never
change once written: the samples (``<sha256>.bin``), the e-mails
(``<sha256>.mail``) and, from 7.0, the originals of host evidence
(``_evidence/<sha256>.bin``), which can be tens of gigabytes. Until 7.0 every
backup held every one of them again. Now each is written once, into the pool
beside the backups, and a backup only says which ones it needs:

    <backup directory>/pool-<generation>/<first two hex digits>/<sha256>.nikblob

**A file of the pool** is a file in the format of a backup (``container.py``
reads it alone) with one part, ``blob``. Its key is derived from the key of
the pool and a salt of its own.

**The key of the pool** is 32 random bytes, made by the server and kept with
the settings of the backups, encrypted like the passphrase. Every backup that
names files of the pool carries it as its part ``pool-key``: a backup, its
passphrase and the pool folder beside it are all a restore needs, on any
host. ``generation`` is the id of that key. Setting another passphrase starts
another generation: a passphrase that was given up must not open what is
written after it. The first backup after that writes every file again, and
the folder of the generation before goes when no backup that is kept names it.

**What a backup holds of it**: the part ``store.pool``, one JSON line for each
file of the store that is in the pool (``path``, ``size``, ``sha256``); the
index of the store lists those files like the others, marked ``"pool": true``.

A file whose content is not what its name says is not put in the pool: it goes
into the backup like any other file, and stays what the store holds.
"""

from __future__ import annotations

import hashlib
import os
import re
import secrets as random
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO

from .container import (
    CHUNK,
    PARTIAL,
    POOL,
    BackupError,
    Damaged,
    Key,
    Reader,
    Secrets,
    Writer,
    key_id,
    read_header,
)

KEY_PART = "pool-key"
LIST_PART = "store.pool"
BLOB_PART = "blob"
SUFFIX = ".nikblob"
FOLDER = re.compile(r"^pool-([0-9a-f]{16})$")
_SHA = "[0-9a-f]{64}"
_POOLED = re.compile(rf"^(?:_evidence/({_SHA})\.bin|({_SHA})\.bin|({_SHA})\.mail)$")


def sha_of(name: str) -> str | None:
    """The SHA-256 a file of the store is named by, when it is one the pool takes."""
    found = _POOLED.fullmatch(name)
    return next(filter(None, found.groups())) if found else None


def new_key() -> str:
    return random.token_hex(32)


def generation(key_hex: str) -> str:
    return key_id(bytes.fromhex(key_hex))


def folder_of(base: Path, gen: str) -> Path:
    return base / f"pool-{gen}"


def blob_path(base: Path, gen: str, sha256: str) -> Path:
    return folder_of(base, gen) / sha256[:2] / f"{sha256}{SUFFIX}"


@dataclass
class Target:
    """The pool a backup being written puts files into: its key, and where it is."""

    key: str
    base: Path
    # What this backup put there (sha256 → stored size), for the rows and the restore test.
    written: dict[str, int] = field(default_factory=dict)
    # Every file of the store this backup names in the pool (sha256 → size of the content).
    named: dict[str, int] = field(default_factory=dict)

    @property
    def gen(self) -> str:
        return generation(self.key)

    def has(self, sha256: str) -> bool:
        return blob_path(self.base, self.gen, sha256).is_file()

    def put(self, sha256: str, handle: BinaryIO) -> bool:
        """Write what ``handle`` gives as the file of the pool named ``sha256``. False, and nothing
        written, when the content is not what the name says."""
        path = blob_path(self.base, self.gen, sha256)
        path.parent.mkdir(parents=True, exist_ok=True)
        partial = Path(f"{path}{PARTIAL}")
        digest = hashlib.sha256()
        try:
            with open(partial, "wb") as out:
                writer = Writer(out, Key.new(POOL, self.key), {"kind": "blob"})
                with writer.part(BLOB_PART) as part:
                    for piece in iter(lambda: handle.read(CHUNK), b""):
                        digest.update(piece)
                        part.write(piece)
                writer.finish({"kind": "blob", "sha256": digest.hexdigest()})
                out.flush()
                os.fsync(out.fileno())
            if digest.hexdigest() != sha256:
                partial.unlink(missing_ok=True)
                # Nothing of a pool is left where no file went into it.
                for folder in (path.parent, path.parent.parent):
                    try:
                        folder.rmdir()
                    except OSError:
                        break
                return False
            os.replace(partial, path)
        except BaseException:
            try:
                partial.unlink(missing_ok=True)
            except OSError:
                pass
            raise
        self.written[sha256] = path.stat().st_size
        return True


def read(path: Path, sha256: str, size: int, key_hex: str) -> Iterator[bytes]:
    """The content of a file of the pool, piece by piece. Every chunk is checked as it is read, and
    the end raises ``Damaged`` when the whole is not ``size`` bytes with that SHA-256: a caller
    that writes what it is given writes into a place it can throw away."""
    name = path.name
    present(path)
    with open(path, "rb") as source:
        reader = Reader(source, Secrets(pool_keys=(key_hex,)))
        digest = hashlib.sha256()
        total = 0
        for part in reader.parts():
            if part.name != BLOB_PART:
                raise Damaged(f"The file {name} of the pool is not one: it holds {part.name}")
            for piece in iter(lambda part=part: part.read(CHUNK), b""):
                digest.update(piece)
                total += len(piece)
                yield piece
        if total != size or digest.hexdigest() != sha256:
            raise Damaged(f"The file {name} of the pool does not hold what its name says")


def check(path: Path, sha256: str, size: int, key_hex: str) -> None:
    """Read a file of the pool whole and compare it with its name. Raises what ``read`` raises."""
    for _piece in read(path, sha256, size, key_hex):
        pass


def present(path: Path) -> None:
    """The least a restore asks before it changes anything: the file is there and is a file of a pool."""
    try:
        with open(path, "rb") as source:
            header, _start = read_header(source)
    except FileNotFoundError:
        raise BackupError(
            f"The pool does not hold {path.name}: the folder {path.parent.parent.name} must sit beside the backup"
        ) from None
    if (header.get("key") or {}).get("from") != POOL:
        raise Damaged(f"The file {path.name} of the pool is not one")


def entries(part: Any) -> list[dict[str, Any]]:
    """The lines of a ``store.pool`` part."""
    import json

    raw = b"".join(iter(lambda: part.read(CHUNK), b""))
    try:
        found = [json.loads(line) for line in raw.split(b"\n") if line]
    except ValueError:
        raise BackupError("The list of the files of the pool in the backup cannot be read") from None
    for entry in found:
        if (
            not isinstance(entry, dict)
            or not re.fullmatch(_SHA, str(entry.get("sha256") or ""))
            or not isinstance(entry.get("size"), int)
            or sha_of(str(entry.get("path") or "")) != entry["sha256"]
        ):
            raise BackupError("The list of the files of the pool in the backup cannot be read")
    return found

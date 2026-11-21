"""The store of files inside a backup.

The store holds what analysts uploaded: samples that are **live malware**,
e-mails, captures. Nothing here opens a file as anything but bytes: a file is
read, hashed and written, and that is all.

It is written as two parts. ``store.tar`` is a POSIX tar of every regular
file and folder under the store, made while the files are read (nothing is
copied anywhere first). ``store.index`` follows it: one JSON line for each
file with its path, its size and the SHA-256 of what went into the tar.

**The store is sealed; the backup does not hold it sealed.** On the disk every
file of the store is encrypted under the store key of the server
(``core/store.py``). Each is decrypted as it is read into the tar, so what a
backup holds is the files themselves, protected by the backup alone (its
passphrase): a backup is read with its passphrase and nothing else, on a host
that never had this server's store key. That is the point of a backup, and
the store key may be lost with the host. Coming back, every file is sealed
again as it is written, under the store key of the server that restores. So
the sizes and the checksums of the index are those of the files, whatever
key they sit under, and a backup taken before 6.8 (files in clear on the
disk) is the same thing as one taken after.

A file that disappears between being listed and being read is left out (an
analyst deleted it meanwhile); one that changes size while it is read stops
the backup, which the next run takes again. Links are not followed and not
kept: the store has none.

Reading it back, every file of the tar is hashed as it goes by and compared
with its line of the index, whatever the size of the store: the whole backup
is decrypted to check it anyway, and hashing what is already in hand costs
little beside that.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import tarfile
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO

from ..core import store as sealed_store
from .container import CHUNK, BackupError, Part, Writer

TAR_PART = "store.tar"
INDEX_PART = "store.index"
LEFTOVERS = (".part", ".sealing")


class _Hashing:
    """A file being read into the tar: counts and hashes what goes by."""

    def __init__(self, handle: BinaryIO, size: int) -> None:
        self._handle, self._left = handle, size
        self.digest = hashlib.sha256()

    def read(self, size: int = -1) -> bytes:
        if self._left <= 0:
            return b""
        data = self._handle.read(self._left if size is None or size < 0 else min(size, self._left))
        self._left -= len(data)
        self.digest.update(data)
        return data


def _walk(root: Path):
    """Every folder and regular file under the store, parents first, in a steady order."""
    for folder, folders, names in os.walk(root, followlinks=False):
        folders.sort()
        relative = Path(folder).relative_to(root)
        if relative.parts:
            yield relative.as_posix(), Path(folder), True
        for name in sorted(names):
            yield (relative / name).as_posix(), Path(folder, name), False


def pack(writer: Writer, root: str | os.PathLike) -> dict[str, Any]:
    """Write the store at ``root`` as parts of a backup. Returns ``{"files", "bytes"}``."""
    root = Path(root)
    index: list[dict[str, Any]] = []
    total = 0
    with writer.part(TAR_PART) as part:
        with tarfile.open(fileobj=part, mode="w|", format=tarfile.PAX_FORMAT, bufsize=CHUNK) as tar:
            for name, path, is_folder in _walk(root) if root.is_dir() else ():
                try:
                    found = os.lstat(path)
                except OSError:
                    continue
                info = tarfile.TarInfo(name)
                info.mtime = int(found.st_mtime)
                info.mode = stat.S_IMODE(found.st_mode)
                if is_folder:
                    info.type = tarfile.DIRTYPE
                    tar.addfile(info)
                    continue
                if not stat.S_ISREG(found.st_mode):
                    continue
                if name.endswith(LEFTOVERS) or name.startswith("_transfer/"):
                    continue  # what an interrupted write left: never a file of the store
                try:
                    # Decrypted as it is read: the content, whatever it sits under on the disk.
                    handle = sealed_store.open(path, name)
                except FileNotFoundError:
                    continue
                except sealed_store.SealError as error:
                    # A backup that left a damaged file out would look whole: it fails, and says which.
                    raise BackupError(f"A file of the store cannot be read: {error}") from None
                with handle:
                    info.size = handle.seek(0, os.SEEK_END)
                    handle.seek(0)
                    reader = _Hashing(handle, info.size)
                    try:
                        tar.addfile(info, reader)
                    except sealed_store.SealError as error:
                        raise BackupError(f"A file of the store cannot be read: {error}") from None
                    except OSError as error:
                        raise BackupError(f"A file of the store changed while it was read ({name}): {error}") from None
                index.append({"path": name, "size": info.size, "sha256": reader.digest.hexdigest()})
                total += info.size
    with writer.part(INDEX_PART) as part:
        for entry in index:
            part.write(json.dumps(entry, sort_keys=True).encode("utf-8") + b"\n")
    return {"files": len(index), "bytes": total}


def _inside(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise BackupError(f"The backup names a file outside the store ({name}): nothing more is read from it")
    return path


class Unpacker:
    """Reads the two parts of the store as they go by: checks them, and writes them when given a place.

        unpacker = Unpacker(target)        # target=None: only check
        for part in reader.parts():
            unpacker.take(part)
        checks = unpacker.finish(reader.manifest)

    With a target, files are written under it as their bytes arrive; the
    comparison with the index comes at the end, so a restore that fails it
    has written files: the caller writes into an empty place and says so.
    """

    def __init__(self, target: str | os.PathLike | None = None) -> None:
        self.target = Path(target) if target is not None else None
        self.seen: dict[str, tuple[int, str]] = {}
        self._index: dict[str, tuple[int, str]] | None = None
        self._tar_seen = False

    def take(self, part: Part) -> bool:
        if part.name == TAR_PART:
            self._tar_seen = True
            self._read_tar(part)
            return True
        if part.name == INDEX_PART:
            self._index = {}
            held = b""
            for piece in iter(lambda: part.read(CHUNK), b""):
                *lines, held = (held + piece).split(b"\n")
                for line in lines:
                    self._index_line(line)
            if held:
                self._index_line(held)
            return True
        return False

    def _index_line(self, line: bytes) -> None:
        try:
            entry = json.loads(line)
            self._index[str(entry["path"])] = (int(entry["size"]), str(entry["sha256"]))
        except (ValueError, KeyError, TypeError):
            raise BackupError("The index of the store in the backup cannot be read") from None

    def _read_tar(self, part: Part) -> None:
        try:
            with tarfile.open(fileobj=part, mode="r|", bufsize=CHUNK) as tar:
                for member in tar:
                    relative = _inside(member.name)
                    place = self.target.joinpath(*relative.parts) if self.target is not None else None
                    if member.isdir():
                        if place is not None:
                            place.mkdir(parents=True, exist_ok=True)
                        continue
                    if not member.isreg():
                        raise BackupError(f"The backup holds something that is not a file ({member.name})")
                    source = tar.extractfile(member)
                    digest = hashlib.sha256()
                    size = 0
                    writing = out = None
                    if place is not None:
                        place.parent.mkdir(parents=True, exist_ok=True)
                        # Sealed as it arrives, under the store key of this server: never in clear
                        # on its disk, whatever the server that made the backup kept it under.
                        writing = sealed_store.writing(place, name=relative.as_posix())
                        out = writing.__enter__()
                    try:
                        for piece in iter(lambda source=source: source.read(CHUNK), b""):
                            digest.update(piece)
                            size += len(piece)
                            if out is not None:
                                out.write(piece)
                    except BaseException as error:
                        if writing is not None:
                            writing.__exit__(type(error), error, error.__traceback__)
                        raise
                    if writing is not None:
                        writing.__exit__(None, None, None)
                    self.seen[relative.as_posix()] = (size, digest.hexdigest())
        except tarfile.TarError as error:
            raise BackupError(f"The store in the backup cannot be read: {error}") from None

    def finish(self, manifest: dict[str, Any]) -> list[str]:
        if not self._tar_seen or self._index is None:
            raise BackupError("The backup does not hold the store of files")
        if self.seen != self._index:
            wrong = sorted(
                path for path in set(self.seen) | set(self._index) if self.seen.get(path) != self._index.get(path)
            )
            raise BackupError(
                f"{len(wrong)} file(s) of the store are not what was read when the backup was taken: "
                + ", ".join(wrong[:5])
            )
        described = manifest.get("store") if isinstance(manifest.get("store"), dict) else {}
        total = sum(size for size, _digest in self.seen.values())
        if described.get("files") != len(self.seen) or described.get("bytes") != total:
            raise BackupError("The store in the backup does not hold what its manifest says")
        return [f"{len(self.seen)} files of the store ({total} bytes), each compared with its checksum"]


def is_empty(root: str | os.PathLike) -> bool:
    root = Path(root)
    return not root.exists() or not any(root.iterdir())


def measure(root: str | os.PathLike) -> int:
    """How many bytes the store holds (for the room a backup needs). As they are on the disk: a
    sealed file is a fifth of a thousandth larger than what it holds."""
    total = 0
    for folder, _folders, names in os.walk(root, onerror=lambda _error: None):
        for name in names:
            try:
                total += os.lstat(os.path.join(folder, name)).st_size
            except OSError:
                continue
    return total

"""The file a backup is: format 1.

This module needs Python 3.11 and the ``cryptography`` package, and nothing
of Nik: it can be copied out and run alone to read a backup where Nik is not
installed (``python container.py list FILE``, ``python container.py extract
FILE DIRECTORY``).

A backup is written once, from start to end, and read the same way: nothing
in it needs a seek, so a store of tens of gigabytes goes through a buffer of
one megabyte and never through memory or a second file.

The file::

    magic        8 bytes    b"NIKBAK1\\n"
    header size  4 bytes    unsigned, big-endian
    header       JSON       not secret, not encrypted, authenticated (below)
    chunks                  the encrypted stream, until the chunk marked last

The header::

    {"format": 1, "cipher": "AES-256-GCM", "chunk": 1048576,
     "nonce": "<7 bytes, base64>",
     "key": {"from": "passphrase", "kdf": "scrypt", "n": 32768, "r": 8, "p": 1,
             "salt": "<16 bytes, base64>", "id": "<16 hex digits>"},
     "kind": "full", "name": "nik-20261120-023000", "createdAt": "...", "nik": "6.7.0"}

``key.from`` says what the key is derived from: ``passphrase`` (the backup
passphrase, through scrypt) or ``secret-key`` (the ``SECRET_KEY`` of the
server, through HKDF-SHA256 with ``salt`` and the info ``nik backup``: what a
snapshot before an upgrade uses while no passphrase is set). ``key.id`` is
the first 16 hex digits of ``SHA-256(b"nik backup key id" + key)``: it tells
a wrong passphrase from a damaged file before anything is read.

A chunk::

    last         1 byte     0, or 1 for the last chunk of the file
    size         4 bytes    of what follows
    data                    AES-256-GCM of at most ``chunk`` bytes, with its 16-byte tag

Its nonce is ``nonce`` + the number of the chunk (4 bytes, from 0) + ``last``;
its associated data is the SHA-256 of everything before the first chunk. So
a chunk that is changed, moved, repeated or left out, a file that is cut
short, and a header that is changed all fail the same check.

The decrypted stream is a sequence of records::

    b"P"  name size (2 bytes)  name              a part begins
    b"D"  size (4 bytes)       bytes             some of its content
    b"Z"  size (4 bytes)       bytes             some of its content, compressed with zlib
    b"E"  size (8 bytes)       SHA-256 (32)      the part ends: its size and checksum
    b"M"  size (4 bytes)       JSON              the manifest, once, last

The parts of a backup of Nik, in order: ``db/schema.json``, then one part for
each table (``db/<table>.copy``, the text format of PostgreSQL's ``COPY``) or
``db/sqlite`` (the database file of a development server), ``store.tar`` (the
store of files, a POSIX tar), ``store.index`` (one JSON line for each file:
path, size, SHA-256) and, only when the administrator asked for it,
``secret-key``. The manifest repeats the size and checksum of every part.

The size and the checksum of a part are those of its content as it was before
compression. A ``Z`` record never holds more than one megabyte once expanded.
Content that does not shrink (most samples are packed already) is written as
``D`` records, and the writer stops trying for a while when it meets some.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import struct
import zlib
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any, BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"NIKBAK1\n"
FORMAT = 1
CHUNK = 1024 * 1024
TAG = 16
MAX_HEADER = 64 * 1024
MAX_MANIFEST = 64 * 1024 * 1024
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**15, 8, 1
PASSPHRASE, SECRET_KEY = "passphrase", "secret-key"
SUFFIX = ".nikbak"
PARTIAL = ".partial"


class BackupError(Exception):
    """A backup that cannot be written or read: a sentence a person can act on."""


class WrongKey(BackupError):
    """None of the passphrases (or keys) given is the one the backup was made with."""


class Damaged(BackupError):
    """The file is not what was written: changed, cut short, or not a backup."""


# --------------------------------------------------------------------------- #
# Keys                                                                        #
# --------------------------------------------------------------------------- #
def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(text: Any) -> bytes:
    try:
        return base64.b64decode(str(text), validate=True)
    except ValueError:
        raise Damaged("The header of the backup cannot be read") from None


def key_id(key: bytes) -> str:
    return hashlib.sha256(b"nik backup key id" + key).hexdigest()[:16]


def _derive(spec: dict[str, Any], secret: str) -> bytes:
    salt = _unb64(spec.get("salt"))
    if spec.get("from") == PASSPHRASE and spec.get("kdf") == "scrypt":
        n, r, p = int(spec.get("n", 0)), int(spec.get("r", 0)), int(spec.get("p", 0))
        # What a hostile header may ask of this machine is bounded: 1 GB of memory at most.
        if n < 2 or n & (n - 1) or not 1 <= r <= 32 or not 1 <= p <= 16 or 128 * n * r > 2**30:
            raise Damaged("The header of the backup asks for a key derivation Nik does not do")
        return Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(secret.encode("utf-8"))
    if spec.get("from") == SECRET_KEY and spec.get("kdf") == "hkdf-sha256":
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"nik backup").derive(secret.encode("utf-8"))
    raise Damaged("The backup was encrypted in a way this version of Nik does not know")


@dataclass(frozen=True)
class Key:
    """The key of one backup and how it was derived (what the header says of it)."""

    key: bytes
    spec: dict[str, Any]

    @classmethod
    def new(cls, source: str, secret: str) -> Key:
        """A key for a new backup: a salt of its own, so no two files share a key."""
        if not secret:
            raise BackupError("There is nothing to derive the key of the backup from")
        spec: dict[str, Any] = {"from": source, "salt": _b64(os.urandom(16))}
        if source == PASSPHRASE:
            spec |= {"kdf": "scrypt", "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P}
        else:
            spec |= {"kdf": "hkdf-sha256"}
        key = _derive(spec, secret)
        return cls(key, spec | {"id": key_id(key)})


@dataclass(frozen=True)
class Secrets:
    """What a backup may be opened with: every passphrase and every ``SECRET_KEY`` to try."""

    passphrases: tuple[str, ...] = ()
    secret_keys: tuple[str, ...] = ()

    def key_for(self, spec: dict[str, Any]) -> bytes:
        source = spec.get("from")
        candidates = self.passphrases if source == PASSPHRASE else self.secret_keys
        for secret in candidates:
            if not secret:
                continue
            key = _derive(spec, secret)
            if key_id(key) == spec.get("id"):
                return key
        if source == PASSPHRASE:
            raise WrongKey(
                "This is not the passphrase the backup was made with"
                if candidates
                else "The backup is encrypted with the backup passphrase, and none was given"
            )
        raise WrongKey(
            "The backup was encrypted with the SECRET_KEY of the server that made it, and the one given is another"
            if candidates
            else "The backup was encrypted with the SECRET_KEY of the server that made it: give that key"
        )


# --------------------------------------------------------------------------- #
# Writing                                                                     #
# --------------------------------------------------------------------------- #
class _Sealer:
    """Encrypts what it is given, one chunk at a time, onto ``out``."""

    def __init__(self, out: BinaryIO, key: bytes, nonce: bytes, aad: bytes, chunk: int) -> None:
        self._out, self._aead, self._nonce, self._aad, self._chunk = out, AESGCM(key), nonce, aad, chunk
        self._held = bytearray()
        self._count = 0

    def _emit(self, data: bytes, last: bool) -> None:
        flag = b"\x01" if last else b"\x00"
        nonce = self._nonce + struct.pack(">I", self._count) + flag
        sealed = self._aead.encrypt(nonce, data, self._aad)
        self._out.write(flag + struct.pack(">I", len(sealed)) + sealed)
        self._count += 1

    def write(self, data: bytes | memoryview) -> None:
        self._held += data
        # Strictly more than a chunk: the last one is only known when the stream ends.
        while len(self._held) > self._chunk:
            self._emit(bytes(self._held[: self._chunk]), last=False)
            del self._held[: self._chunk]

    def close(self) -> None:
        self._emit(bytes(self._held), last=True)
        self._held.clear()


class PartWriter:
    """One part being written: ``write`` its content; its size and checksum are kept."""

    def __init__(self, name: str, sealer: _Sealer) -> None:
        self.name, self._sealer = name, sealer
        self.size = 0
        self._digest = hashlib.sha256()
        self._held = bytearray()
        self._skip = 0  # pieces still written as they are, after one that did not shrink

    def _piece(self, piece: bytes) -> None:
        self._digest.update(piece)
        self.size += len(piece)
        if self._skip:
            self._skip -= 1
        elif len(piece) >= 256:
            packed = zlib.compress(piece, 1)
            if len(packed) * 10 <= len(piece) * 9:
                self._sealer.write(b"Z" + struct.pack(">I", len(packed)))
                self._sealer.write(packed)
                return
            self._skip = 15
        self._sealer.write(b"D" + struct.pack(">I", len(piece)))
        self._sealer.write(piece)

    def write(self, data: bytes | memoryview) -> int:
        # Gathered into whole megabytes: rows arrive a few bytes at a time, and a record for
        # each would cost more than the rows do.
        self._held += data
        while len(self._held) >= CHUNK:
            self._piece(bytes(self._held[:CHUNK]))
            del self._held[:CHUNK]
        return len(data)

    def close(self) -> None:
        if self._held:
            self._piece(bytes(self._held))
            self._held.clear()

    @property
    def sha256(self) -> str:
        return self._digest.hexdigest()


class Writer:
    """Writes a backup onto ``out`` (a file open for writing): parts, then the manifest.

        writer = Writer(out, key, {"kind": "full", ...})
        with writer.part("db/users.copy") as part:
            part.write(...)
        writer.finish({"nik": "6.7.0", ...})

    ``finish`` adds the size and checksum of every part to the manifest it is given.
    """

    def __init__(self, out: BinaryIO, key: Key, about: dict[str, Any] | None = None, chunk: int = CHUNK) -> None:
        nonce = os.urandom(7)
        header = {
            **(about or {}),
            "format": FORMAT,
            "cipher": "AES-256-GCM",
            "chunk": chunk,
            "nonce": _b64(nonce),
            "key": key.spec,
        }
        raw = json.dumps(header, sort_keys=True).encode("utf-8")
        start = MAGIC + struct.pack(">I", len(raw)) + raw
        out.write(start)
        self.header = header
        self.parts: list[dict[str, Any]] = []
        self._sealer = _Sealer(out, key.key, nonce, hashlib.sha256(start).digest(), chunk)
        self._open: PartWriter | None = None
        self._done = False

    def part(self, name: str) -> _PartContext:
        if self._open is not None or self._done:
            raise BackupError("A part of the backup is still being written")
        return _PartContext(self, name)

    def _begin(self, name: str) -> PartWriter:
        raw = name.encode("utf-8")
        self._sealer.write(b"P" + struct.pack(">H", len(raw)) + raw)
        self._open = PartWriter(name, self._sealer)
        return self._open

    def _end(self) -> None:
        part, self._open = self._open, None
        part.close()
        self._sealer.write(b"E" + struct.pack(">Q", part.size) + part._digest.digest())
        self.parts.append({"name": part.name, "size": part.size, "sha256": part.sha256})

    def finish(self, manifest: dict[str, Any]) -> dict[str, Any]:
        """Write the manifest and the last chunk. Returns the manifest as written."""
        if self._open is not None or self._done:
            raise BackupError("A part of the backup is still being written")
        manifest = {**manifest, "format": FORMAT, "parts": self.parts}
        raw = json.dumps(manifest, sort_keys=True).encode("utf-8")
        self._sealer.write(b"M" + struct.pack(">I", len(raw)) + raw)
        self._sealer.close()
        self._done = True
        return manifest


class _PartContext:
    def __init__(self, writer: Writer, name: str) -> None:
        self._writer, self._name = writer, name

    def __enter__(self) -> PartWriter:
        return self._writer._begin(self._name)

    def __exit__(self, kind, *_rest) -> None:
        # A part that failed half-way is not closed: the file is thrown away by whoever wrote it.
        if kind is None:
            self._writer._end()


# --------------------------------------------------------------------------- #
# Reading                                                                     #
# --------------------------------------------------------------------------- #
def _exactly(source: BinaryIO, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        piece = source.read(size - len(data))
        if not piece:
            break
        data += piece
    return bytes(data)


def read_header(source: BinaryIO) -> tuple[dict[str, Any], bytes]:
    """The header of a backup, and the bytes it was read from (they are authenticated with every chunk)."""
    magic = _exactly(source, len(MAGIC))
    if magic != MAGIC:
        raise Damaged("This is not a backup of Nik")
    raw_size = _exactly(source, 4)
    if len(raw_size) != 4:
        raise Damaged("The backup is cut short: it has no header")
    (size,) = struct.unpack(">I", raw_size)
    if not 2 <= size <= MAX_HEADER:
        raise Damaged("The header of the backup cannot be read")
    raw = _exactly(source, size)
    if len(raw) != size:
        raise Damaged("The backup is cut short: its header is incomplete")
    try:
        header = json.loads(raw)
    except ValueError:
        raise Damaged("The header of the backup cannot be read") from None
    if not isinstance(header, dict) or not isinstance(header.get("key"), dict):
        raise Damaged("The header of the backup cannot be read")
    if header.get("format") != FORMAT or header.get("cipher") != "AES-256-GCM":
        raise Damaged(
            f"The backup is in format {header.get('format')!r}, which this version of Nik does not read "
            "(it was made by a later one)"
        )
    return header, magic + raw_size + raw


class _Opener:
    """The decrypted stream of a backup, read in pieces of the size asked for."""

    def __init__(self, source: BinaryIO, key: bytes, header: dict[str, Any], aad: bytes) -> None:
        self._source, self._aead, self._aad = source, AESGCM(key), aad
        self._nonce = _unb64(header.get("nonce"))
        self._chunk = int(header.get("chunk") or 0)
        if len(self._nonce) != 7 or not 1 <= self._chunk <= 64 * CHUNK:
            raise Damaged("The header of the backup cannot be read")
        self._held = b""
        self._at = 0
        self._count = 0
        self._ended = False

    def _next(self) -> bool:
        if self._ended:
            return False
        start = _exactly(self._source, 5)
        if len(start) != 5:
            raise Damaged("The backup is cut short: its end is missing")
        last = start[0]
        (size,) = struct.unpack(">I", start[1:])
        if last not in (0, 1) or not TAG <= size <= self._chunk + TAG:
            raise Damaged("The backup is damaged")
        sealed = _exactly(self._source, size)
        if len(sealed) != size:
            raise Damaged("The backup is cut short: its end is missing")
        nonce = self._nonce + struct.pack(">I", self._count) + bytes([last])
        try:
            self._held = self._aead.decrypt(nonce, sealed, self._aad)
        except InvalidTag:
            raise Damaged(f"The backup is damaged: chunk {self._count + 1} is not what was written") from None
        self._at = 0
        self._count += 1
        if last:
            self._ended = True
            if self._source.read(1):
                raise Damaged("The backup is damaged: there is something after its end")
        return True

    def read(self, size: int) -> bytes:
        """Up to ``size`` bytes; fewer only at the end of the stream."""
        pieces = []
        while size > 0:
            if self._at >= len(self._held) and not self._next():
                break
            piece = self._held[self._at : self._at + size]
            self._at += len(piece)
            size -= len(piece)
            pieces.append(piece)
        return b"".join(pieces)

    def exactly(self, size: int) -> bytes:
        data = self.read(size)
        if len(data) != size:
            raise Damaged("The backup is damaged: a record is incomplete")
        return data

    def at_end(self) -> bool:
        while self._at >= len(self._held):
            if not self._next():
                return True
        return False


class Part(io.RawIOBase):
    """One part of a backup being read: a file to read from, once, forward.

    Its size and checksum are checked when its end is reached; a part that is
    not read to its end by its consumer is read to it by ``Reader`` before the
    next one, so every byte of a backup that is walked through is verified.
    """

    def __init__(self, name: str, opener: _Opener) -> None:
        super().__init__()
        self.name = name
        self.size = 0
        self._opener = opener
        self._digest = hashlib.sha256()
        self._left = 0  # of the data record being read
        self._expanded = b""  # a compressed record, once expanded, and how far it was read
        self._expanded_at = 0
        self._ended = False
        self.sha256 = ""

    def readable(self) -> bool:
        return True

    def _record(self) -> bool:
        """Step to the next data record of the part; False at its end."""
        kind = self._opener.exactly(1)
        if kind == b"D":
            (self._left,) = struct.unpack(">I", self._opener.exactly(4))
            return True
        if kind == b"Z":
            (size,) = struct.unpack(">I", self._opener.exactly(4))
            if size > 2 * CHUNK:
                raise Damaged(f"The backup is damaged: a record of {self.name} is too large")
            expander = zlib.decompressobj()
            try:
                self._expanded = expander.decompress(self._opener.exactly(size), CHUNK + 1)
            except zlib.error:
                raise Damaged(f"The backup is damaged: a record of {self.name} does not expand") from None
            if len(self._expanded) > CHUNK or not expander.eof:
                raise Damaged(f"The backup is damaged: a record of {self.name} is too large")
            self._expanded_at = 0
            self._left = len(self._expanded)
            return True
        if kind != b"E":
            raise Damaged(f"The backup is damaged: the part {self.name} does not end")
        (size,) = struct.unpack(">Q", self._opener.exactly(8))
        digest = self._opener.exactly(32)
        self._ended = True
        self.sha256 = self._digest.hexdigest()
        if size != self.size or digest != self._digest.digest():
            raise Damaged(f"The backup is damaged: the part {self.name} is not what was written")
        return False

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            return b"".join(iter(lambda: self.read(CHUNK), b""))
        pieces = []
        while size > 0 and not self._ended:
            if self._left == 0 and not self._record():
                break
            if self._expanded:
                piece = self._expanded[self._expanded_at : self._expanded_at + min(size, self._left)]
                self._expanded_at += len(piece)
                if self._expanded_at >= len(self._expanded):
                    self._expanded = b""
            else:
                piece = self._opener.exactly(min(size, self._left))
            self._left -= len(piece)
            size -= len(piece)
            self._digest.update(piece)
            self.size += len(piece)
            pieces.append(piece)
        return b"".join(pieces)

    def readinto(self, buffer) -> int:
        data = self.read(len(buffer))
        buffer[: len(data)] = data
        return len(data)

    def drain(self) -> None:
        while not self._ended and self.read(CHUNK):
            pass


class Reader:
    """Reads a backup from ``source`` (a file open for reading).

        reader = Reader(source, Secrets(passphrases=("...",)))
        for part in reader.parts():
            ...                      # part.name, part.read(n)
        reader.manifest              # once every part has gone by

    Walking through all the parts verifies the whole file: every chunk, the
    size and checksum of every part, and that the manifest lists exactly the
    parts that were found.
    """

    def __init__(self, source: BinaryIO, secrets: Secrets) -> None:
        self.header, start = read_header(source)
        key = secrets.key_for(self.header["key"])
        self._opener = _Opener(source, key, self.header, hashlib.sha256(start).digest())
        self.manifest: dict[str, Any] | None = None
        self.found: list[dict[str, Any]] = []

    def parts(self) -> Iterator[Part]:
        while True:
            kind = self._opener.exactly(1)
            if kind == b"P":
                (size,) = struct.unpack(">H", self._opener.exactly(2))
                try:
                    name = self._opener.exactly(size).decode("utf-8")
                except UnicodeDecodeError:
                    raise Damaged("The backup is damaged: a part has no readable name") from None
                part = Part(name, self._opener)
                yield part
                part.drain()
                self.found.append({"name": part.name, "size": part.size, "sha256": part.sha256})
                continue
            if kind != b"M":
                raise Damaged("The backup is damaged: a record is not one Nik writes")
            (size,) = struct.unpack(">I", self._opener.exactly(4))
            if size > MAX_MANIFEST:
                raise Damaged("The backup is damaged: its manifest is too large")
            try:
                manifest = json.loads(self._opener.exactly(size))
            except ValueError:
                raise Damaged("The backup is damaged: its manifest cannot be read") from None
            if not isinstance(manifest, dict):
                raise Damaged("The backup is damaged: its manifest cannot be read")
            if not self._opener.at_end():
                raise Damaged("The backup is damaged: there is something after its manifest")
            if manifest.get("parts") != self.found:
                raise Damaged("The backup is damaged: its manifest does not list the parts it holds")
            self.manifest = manifest
            return


def walk(source: BinaryIO, secrets: Secrets, each: Callable[[Part], None] | None = None) -> dict[str, Any]:
    """Read a whole backup, handing every part to ``each``. Returns its manifest."""
    reader = Reader(source, secrets)
    for part in reader.parts():
        if each is not None:
            each(part)
    return reader.manifest


def peek(path: str | os.PathLike) -> dict[str, Any]:
    """The header of the backup at ``path``: what can be known of it without its key."""
    with open(path, "rb") as source:
        return read_header(source)[0]


# --------------------------------------------------------------------------- #
# Alone, where Nik is not installed                                           #
# --------------------------------------------------------------------------- #
def _safe_name(name: str) -> str:
    cleaned = "/".join(piece for piece in name.replace("\\", "/").split("/") if piece not in ("", ".", ".."))
    if not cleaned:
        raise Damaged("The backup is damaged: a part has no usable name")
    return cleaned


def _asked_secrets():
    import getpass

    passphrase = os.environ.get("NIK_BACKUP_PASSPHRASE", "")
    path = os.environ.get("NIK_BACKUP_PASSPHRASE_FILE", "")
    if not passphrase and path:
        with open(path, encoding="utf-8") as handle:
            passphrase = handle.read().strip("\r\n")
    secret_key = os.environ.get("SECRET_KEY", "")
    return Secrets(
        passphrases=(passphrase,) if passphrase else (),
        secret_keys=(secret_key,) if secret_key else (),
    ), getpass


def main(argv: list[str] | None = None) -> int:
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        prog="container.py",
        description="Read a backup of Nik. The passphrase is asked for, or read from NIK_BACKUP_PASSPHRASE or "
        "the file named by NIK_BACKUP_PASSPHRASE_FILE; a snapshot made before an upgrade with no passphrase "
        "set needs SECRET_KEY instead.",
    )
    parser.add_argument("command", choices=("list", "extract"))
    parser.add_argument("file")
    parser.add_argument("directory", nargs="?", help="where extract writes the parts")
    parser.add_argument(
        "--with-secret-key", action="store_true", help="also write the SECRET_KEY the backup holds, if it holds one"
    )
    args = parser.parse_args(argv)
    if args.command == "extract" and not args.directory:
        parser.error("extract needs the directory to write to")
    secrets, getpass = _asked_secrets()
    try:
        with open(args.file, "rb") as source:
            header, _start = read_header(source)
        if header["key"].get("from") == PASSPHRASE and not secrets.passphrases:
            secrets = Secrets(passphrases=(getpass.getpass("Backup passphrase: "),), secret_keys=secrets.secret_keys)

        def each(part: Part) -> None:
            if args.command == "list":
                part.drain()
                print(f"{part.size:>16}  {part.sha256}  {part.name}")
                return
            if part.name == "secret-key" and not args.with_secret_key:
                return
            target = os.path.join(args.directory, *_safe_name(part.name).split("/"))
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, "wb") as out:
                for piece in iter(lambda: part.read(CHUNK), b""):
                    out.write(piece)

        if args.command == "extract":
            os.makedirs(args.directory, exist_ok=True)
        with open(args.file, "rb") as source:
            manifest = walk(source, secrets, each)
        if args.command == "extract":
            with open(os.path.join(args.directory, "manifest.json"), "w", encoding="utf-8") as out:
                json.dump(manifest, out, indent=2, sort_keys=True)
        else:
            shown = {key: value for key, value in manifest.items() if key != "parts"}
            print(json.dumps(shown, indent=2, sort_keys=True))
    except (BackupError, OSError) as error:
        print(f"container.py: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

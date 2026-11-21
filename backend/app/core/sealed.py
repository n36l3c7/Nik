"""A file of the store as it is on the disk: sealed, format 1.

This module needs the ``cryptography`` package and nothing of Nik.

Every file of the store is encrypted with a key of its own, drawn at random
when the file is written. That key is kept in the head of the file, wrapped
with the **store key** of the server, which is in no database. So changing
the store key rewrites a few bytes at the head of each file and never the
files themselves, and a file is as large as what it holds plus a small fixed
cost.

The file::

    magic        8 bytes    b"NIKSEAL1"
    chunk        4 bytes    unsigned, big-endian: the size of a chunk of content (65536)
    reserved     4 bytes    zero
    slot         68 bytes   the key of the file, wrapped by a store key
    slot         68 bytes   a second one, used while the store key is being changed
    chunks                  the content, until the end of the file

A slot::

    key id       8 bytes    which store key wrapped it (all zero: the slot is empty)
    nonce        12 bytes   random
    wrapped      48 bytes   AES-256-GCM of the 32-byte key of the file, with its tag

A chunk is AES-256-GCM of at most ``chunk`` bytes of content, with its 16-byte
tag. Every chunk but the last holds exactly ``chunk`` bytes, so chunk ``n``
starts at ``152 + n * (chunk + 16)``: reading the middle of a file decrypts
the chunks that hold it and no other. The nonce of a chunk is one byte that
says whether it is the last (1) or not (0), three zero bytes, and its number
(8 bytes, from 0). A file always has a last chunk, which may be empty.

What is authenticated with every chunk and with the wrapped key is the
SHA-256 of the magic, the chunk size and the **name** of the file (its path
inside the store, ``<sha256>.bin`` or ``_captures/<id>/capture.pcap``). So a
chunk that is changed, moved, repeated or left out fails; a file that is cut
short fails (its new last chunk was not written as the last); bytes added at
the end fail; and a file put in the place of another fails, although both
are files Nik wrote.

The key of a file is used for that file's content once: writing a file again
draws a new key. Nonces therefore never repeat under a key.

A store key is any string of 32 characters or more. What wraps is derived
from it with HKDF-SHA256 (info ``nik store key``); its id is the first 8
bytes of ``SHA-256(b"nik store key id" + derived key)``. The id tells a file
sealed under another key from a damaged one.
"""

from __future__ import annotations

import errno
import hashlib
import io
import os
import struct
from collections.abc import Iterable
from dataclasses import dataclass
from typing import BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC = b"NIKSEAL1"
CHUNK = 64 * 1024
TAG = 16
KEY_BYTES = 32
SLOT = 8 + 12 + KEY_BYTES + TAG
SLOTS = 2
PREFIX = len(MAGIC) + 8
HEADER = PREFIX + SLOTS * SLOT
EMPTY_ID = b"\x00" * 8
MAX_CHUNK = 16 * 1024 * 1024


class SealError(Exception):
    """A sealed file that cannot be read or written."""


class Damaged(SealError):
    """The file is not what was written: changed, cut short, moved, or not a sealed file."""


class WrongKey(SealError):
    """The file was sealed under a store key this server does not hold."""


@dataclass(frozen=True)
class StoreKey:
    """What wraps the keys of the files, derived from the store key, and its id."""

    wrapping: bytes
    id: bytes

    @classmethod
    def derive(cls, secret: str) -> StoreKey:
        if not secret:
            raise SealError("There is no store key")
        wrapping = HKDF(algorithm=hashes.SHA256(), length=KEY_BYTES, salt=None, info=b"nik store key").derive(
            secret.encode("utf-8")
        )
        return cls(wrapping, hashlib.sha256(b"nik store key id" + wrapping).digest()[:8])

    @property
    def fingerprint(self) -> str:
        """What two people compare to check they speak of the same key: never part of the key."""
        return fingerprint("STORE_KEY", self.id)


def fingerprint(name: str, key_id: bytes) -> str:
    digest = hashlib.sha256(b"nik key fingerprint\x00" + name.encode("ascii") + b"\x00" + key_id).hexdigest()
    return f"{digest[:4]}-{digest[4:8]}"


@dataclass(frozen=True)
class Keyring:
    """The store key files are sealed under, and the earlier ones files may still be under."""

    current: StoreKey
    previous: tuple[StoreKey, ...] = ()

    @classmethod
    def of(cls, secret: str, previous: Iterable[str] = ()) -> Keyring:
        return cls(StoreKey.derive(secret), tuple(StoreKey.derive(value) for value in previous if value))

    def all(self) -> tuple[StoreKey, ...]:
        return (self.current, *self.previous)


# --------------------------------------------------------------------------- #
# The head of a file                                                          #
# --------------------------------------------------------------------------- #
def is_sealed(head: bytes) -> bool:
    return head[: len(MAGIC)] == MAGIC


def _bound(name: str, chunk: int) -> bytes:
    """What every chunk and every slot of the file is authenticated with."""
    return hashlib.sha256(MAGIC + struct.pack(">I", chunk) + name.encode("utf-8")).digest()


def _wrap(key: StoreKey, file_key: bytes, bound: bytes) -> bytes:
    nonce = os.urandom(12)
    return key.id + nonce + AESGCM(key.wrapping).encrypt(nonce, file_key, b"nik store file key" + bound)


def _unwrap(key: StoreKey, slot: bytes, bound: bytes) -> bytes:
    try:
        return AESGCM(key.wrapping).decrypt(slot[8:20], slot[20:], b"nik store file key" + bound)
    except InvalidTag:
        raise Damaged("the head of the file was changed, or the file was put in the place of another") from None


@dataclass(frozen=True)
class Head:
    chunk: int
    slots: tuple[bytes, ...]

    def key_ids(self) -> list[bytes]:
        return [slot[:8] for slot in self.slots if slot[:8] != EMPTY_ID]


def parse_head(raw: bytes) -> Head:
    if len(raw) < HEADER or not is_sealed(raw):
        raise Damaged("it is not a sealed file of Nik, or it was cut short")
    chunk, reserved = struct.unpack(">II", raw[len(MAGIC) : PREFIX])
    if not 0 < chunk <= MAX_CHUNK or reserved:
        raise Damaged("its head cannot be read")
    return Head(chunk, tuple(raw[PREFIX + n * SLOT : PREFIX + (n + 1) * SLOT] for n in range(SLOTS)))


def read_head(path: str | os.PathLike) -> Head:
    with open(path, "rb") as handle:
        return parse_head(handle.read(HEADER))


def _open_slot(head: Head, name: str, keyring: Keyring) -> tuple[int, bytes]:
    """The first slot a key of the ring opens, and the key of the file it holds. A slot that was
    half-written (the server stopped while the store key was being changed) does not open: the
    other one still does."""
    bound = _bound(name, head.chunk)
    failed: Damaged | None = None
    for key in keyring.all():
        for number, slot in enumerate(head.slots):
            if slot[:8] == key.id:
                try:
                    return number, _unwrap(key, slot, bound)
                except Damaged as error:
                    failed = error
    if failed is not None:
        raise failed
    if not head.key_ids():
        raise Damaged("its head holds no key")
    raise WrongKey("it was sealed under a store key that is not the one of this server")


def file_key(head: Head, name: str, keyring: Keyring) -> bytes:
    """The key of the file, unwrapped by whichever store key of the ring wrapped it."""
    return _open_slot(head, name, keyring)[1]


def plain_size(sealed_size: int, chunk: int = CHUNK) -> int:
    """How many bytes of content a sealed file of this size holds."""
    body = sealed_size - HEADER
    if body < TAG:
        raise Damaged("it was cut short")
    chunks = -(-body // (chunk + TAG))
    size = body - chunks * TAG
    if size < 0 or (chunks > 1 and size <= (chunks - 1) * chunk):
        # More than one chunk, and the last would be empty or less than its tag.
        raise Damaged("it was cut short")
    return size


def sealed_size(size: int, chunk: int = CHUNK) -> int:
    """How large a file of ``size`` bytes of content is once sealed."""
    return HEADER + size + max(1, -(-size // chunk)) * TAG


def _nonce(number: int, last: bool) -> bytes:
    return (b"\x01" if last else b"\x00") + b"\x00\x00\x00" + struct.pack(">Q", number)


# --------------------------------------------------------------------------- #
# Writing                                                                     #
# --------------------------------------------------------------------------- #
class Writer:
    """Seals what it is given onto ``out`` (a file open for writing, at its start).

    ``close`` writes the last chunk: a file whose writer was not closed is not
    a file, and reading it fails.
    """

    def __init__(self, out: BinaryIO, name: str, key: StoreKey, chunk: int = CHUNK) -> None:
        self._out, self._chunk = out, chunk
        self._bound = _bound(name, chunk)
        file_key = AESGCM.generate_key(bit_length=256)
        self._aead = AESGCM(file_key)
        out.write(MAGIC + struct.pack(">II", chunk, 0) + _wrap(key, file_key, self._bound) + b"\x00" * SLOT)
        self._held = bytearray()
        self._count = 0
        self.size = 0
        self._closed = False

    def _emit(self, data: bytes, last: bool) -> None:
        self._out.write(self._aead.encrypt(_nonce(self._count, last), data, self._bound))
        self._count += 1

    def write(self, data: bytes | bytearray | memoryview) -> int:
        if self._closed:
            raise SealError("The file is already sealed")
        self._held += data
        self.size += len(data)
        # Strictly more than a chunk is held before one is written: the last is known at the end only.
        while len(self._held) > self._chunk:
            self._emit(bytes(self._held[: self._chunk]), last=False)
            del self._held[: self._chunk]
        return len(data)

    def close(self) -> None:
        if not self._closed:
            self._emit(bytes(self._held), last=True)
            self._held.clear()
            self._closed = True


# --------------------------------------------------------------------------- #
# Reading                                                                     #
# --------------------------------------------------------------------------- #
class Reader(io.RawIOBase):
    """The content of a sealed file, read and sought like a file open for reading.

    Opening it checks the head and the last chunk, so a file that was cut
    short is refused before a byte is given. Every chunk is checked when it
    is read: what does not authenticate raises ``Damaged`` and is never
    returned.
    """

    def __init__(self, raw: BinaryIO, name: str, keyring: Keyring, close_raw: bool = True) -> None:
        super().__init__()
        self._raw, self._close_raw = raw, close_raw
        self.name = name
        try:
            raw.seek(0)
            head = parse_head(raw.read(HEADER))
            self.chunk = head.chunk
            self._bound = _bound(name, head.chunk)
            self._aead = AESGCM(file_key(head, name, keyring))
            total = raw.seek(0, os.SEEK_END)
            self.size = plain_size(total, self.chunk)
            self._chunks = max(1, -(-self.size // self.chunk))
            self._held: tuple[int, bytes] | None = None
            self._position = 0
            # The end of the file is where it was written to end.
            self._load(self._chunks - 1)
        except BaseException:
            if close_raw:
                raw.close()
            raise

    def _load(self, number: int) -> bytes:
        if self._held is not None and self._held[0] == number:
            return self._held[1]
        last = number == self._chunks - 1
        self._raw.seek(HEADER + number * (self.chunk + TAG))
        sealed = self._raw.read(self.chunk + TAG)
        try:
            data = self._aead.decrypt(_nonce(number, last), sealed, self._bound)
        except InvalidTag:
            raise Damaged("its content was changed, or it was cut short") from None
        expected = self.size - number * self.chunk if last else self.chunk
        if len(data) != expected:
            raise Damaged("its content was changed, or it was cut short")
        self._held = (number, data)
        return data

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self._position

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        if whence == os.SEEK_CUR:
            offset += self._position
        elif whence == os.SEEK_END:
            offset += self.size
        elif whence != os.SEEK_SET:
            raise ValueError("Unknown whence")
        if offset < 0:
            # As a file of the system answers it: what seeks from the end of a short file (zipfile)
            # expects this error and no other.
            raise OSError(errno.EINVAL, "A position before the start of the file")
        self._position = offset
        return offset

    def readinto(self, buffer) -> int:
        if self._position >= self.size:
            return 0
        number, inside = divmod(self._position, self.chunk)
        data = self._load(number)
        piece = data[inside : inside + len(buffer)]
        buffer[: len(piece)] = piece
        self._position += len(piece)
        return len(piece)

    def close(self) -> None:
        if not self.closed and self._close_raw:
            self._raw.close()
        super().close()


def open_sealed(path: str | os.PathLike, name: str, keyring: Keyring) -> io.BufferedReader:
    """The content of the sealed file at ``path``, as a file open for reading (``.raw.size`` is its size)."""
    raw = open(path, "rb")  # noqa: SIM115 - the reader owns it and closes it
    return io.BufferedReader(Reader(raw, name, keyring), buffer_size=CHUNK)


# --------------------------------------------------------------------------- #
# Changing the store key                                                      #
# --------------------------------------------------------------------------- #
def needs_rewrap(head: Head, keyring: Keyring) -> bool:
    """Whether the file is not yet under the current store key alone."""
    return head.key_ids() != [keyring.current.id]


def rewrap(path: str | os.PathLike, name: str, keyring: Keyring) -> bool:
    """Put the key of the file under the current store key and under no other. True when it changed.

    Done in two writes of one slot each, the first into the slot that did
    not open the file: whenever this stops, the file is readable with the old
    key or with the new one, and never with neither. The content is not
    touched.
    """
    with open(path, "r+b") as handle:
        head = parse_head(handle.read(HEADER))
        bound = _bound(name, head.chunk)
        opened, key = _open_slot(head, name, keyring)
        slots = list(head.slots)
        if slots[opened][:8] == keyring.current.id:
            mine = opened
            if not needs_rewrap(head, keyring):
                return False
        else:
            # The slot that opened the file stays as it is until the new one is on the disk.
            mine = next(number for number in range(SLOTS) if number != opened)
            handle.seek(PREFIX + mine * SLOT)
            handle.write(_wrap(keyring.current, key, bound))
            handle.flush()
            os.fsync(handle.fileno())
        for number, slot in enumerate(slots):
            if number != mine and slot[:8] != EMPTY_ID:
                handle.seek(PREFIX + number * SLOT)
                handle.write(b"\x00" * SLOT)
        handle.flush()
        os.fsync(handle.fileno())
    return True

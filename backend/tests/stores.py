"""The store of files as the automation worker sees it, and archives to unpack, for the tests.

``read_only`` makes the store refuse every write, as the read-only mount of the ``automation``
container does, except while the test plays the API process (``api()``), which takes the jobs the
worker asked for. The archives are built here, of harmless texts.
"""

from __future__ import annotations

import io
import os
import struct
import zipfile
import zlib

import pytest
import pyzipper

from app import artifact_jobs
from app.malware import samples
from app.routers import mails as mail_routes
from app.routers import samples as sample_routes


@pytest.fixture()
def read_only(monkeypatch):
    """Nothing can be written to the store, unless the API process does it: ``read_only()`` is that
    process taking what was asked of it (how many jobs it did)."""
    writable = {"now": False}

    def guarded(real):
        def write(sha256, data):
            if not writable["now"]:
                raise OSError(30, "Read-only file system")
            return real(sha256, data)

        return write

    monkeypatch.setattr(samples, "store_writable", lambda: writable["now"])
    monkeypatch.setattr(sample_routes, "write_sample", guarded(samples.write_sample))
    monkeypatch.setattr(mail_routes, "write_mail", guarded(samples.write_mail))

    def api() -> int:
        writable["now"] = True
        try:
            return artifact_jobs.run_due(threads=False)
        finally:
            writable["now"] = False

    return api


def zip_of(files: dict[str, bytes], password: str = "", links: tuple[str, ...] = ()) -> bytes:
    """A zip of these files; with a password, protected with WinZip AES. ``links`` are members
    written as symbolic links."""
    buffer = io.BytesIO()
    if password:
        archive = pyzipper.AESZipFile(buffer, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES)
        archive.setpassword(password.encode())
    else:
        archive = zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED)
    with archive:
        for name, data in files.items():
            if password:
                archive.writestr(name, data)
                continue
            info = zipfile.ZipInfo(name)
            info.compress_type = zipfile.ZIP_DEFLATED
            if name in links:
                info.external_attr = 0o120777 << 16
            archive.writestr(info, data)
    return buffer.getvalue()


def _crc(crc: int, byte: int) -> int:
    return ~zlib.crc32(bytes([byte]), ~crc & 0xFFFFFFFF) & 0xFFFFFFFF


def zipcrypto_of(name: str, data: bytes, password: str) -> bytes:
    """A zip with one stored member protected the classic way (ZipCrypto), written by hand: no
    library of Python writes one."""
    keys = [0x12345678, 0x23456789, 0x34567890]

    def update(byte: int) -> None:
        keys[0] = _crc(keys[0], byte)
        keys[1] = ((keys[1] + (keys[0] & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        keys[2] = _crc(keys[2], keys[1] >> 24)

    def encrypt(plain: bytes) -> bytes:
        out = bytearray()
        for byte in plain:
            temp = (keys[2] | 2) & 0xFFFF
            out.append(byte ^ (((temp * (temp ^ 1)) >> 8) & 0xFF))
            update(byte)
        return bytes(out)

    for byte in password.encode():
        update(byte)
    crc = zlib.crc32(data) & 0xFFFFFFFF
    body = encrypt(os.urandom(11) + bytes([crc >> 24])) + encrypt(data)
    raw = name.encode()
    sizes = struct.pack("<LLL", crc, len(body), len(data))
    local = struct.pack("<4sHHHHH", b"PK\x03\x04", 20, 1, 0, 0, 0x21) + sizes + struct.pack("<HH", len(raw), 0) + raw
    central = (
        struct.pack("<4sHHHHHH", b"PK\x01\x02", 20, 20, 1, 0, 0, 0x21)
        + sizes
        + struct.pack("<HHHHHLL", len(raw), 0, 0, 0, 0, 0, 0)
        + raw
    )
    end = struct.pack("<4sHHHHLLH", b"PK\x05\x06", 0, 0, 1, 1, len(central), len(local) + len(body), 0)
    return local + body + central + end

"""Sample store: the raw malware files, on disk, named by SHA-256.

Files are written once (deduplicated by hash), without execute permission and
with a neutral ``.bin`` extension, under ``settings.SAMPLE_STORE``. They are
never opened by anything that interprets their format; the only consumers are
the static analysis (bytes in, JSON out) and the download endpoint, which
wraps them in a password-protected zip so mail filters and antivirus do not
intercept them in transit.
"""

from __future__ import annotations

import io
import os
import re
from pathlib import Path

import pyzipper

from .config import settings

DEFAULT_ZIP_PASSWORD = "infected"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def store_dir() -> Path:
    path = Path(settings.SAMPLE_STORE)
    path.mkdir(parents=True, exist_ok=True)
    return path


def is_sha256(value: str) -> bool:
    return bool(_SHA256_RE.match(value or ""))


def sample_path(sha256: str) -> Path:
    if not is_sha256(sha256):
        raise ValueError("Not a SHA-256 digest.")
    return store_dir() / f"{sha256}.bin"


def write_sample(sha256: str, data: bytes) -> Path:
    """Store the bytes if not already present; the file is read-only (0o440)."""
    path = sample_path(sha256)
    if not path.exists():
        tmp = path.with_suffix(".part")
        tmp.write_bytes(data)
        os.chmod(tmp, 0o440)
        tmp.replace(path)
    return path


def read_sample(sha256: str) -> bytes:
    return sample_path(sha256).read_bytes()


def delete_sample(sha256: str) -> None:
    path = sample_path(sha256)
    if path.exists():
        os.chmod(path, 0o640)
        path.unlink()


def zip_sample(data: bytes, inner_name: str, password: str = DEFAULT_ZIP_PASSWORD) -> bytes:
    """AES-256 encrypted zip holding the sample as ``inner_name``."""
    buffer = io.BytesIO()
    with pyzipper.AESZipFile(buffer, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as archive:
        archive.setpassword(password.encode("utf-8"))
        archive.writestr(inner_name, data)
    return buffer.getvalue()

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
import logging
import os
import re
import stat
from pathlib import Path

import pyzipper

from .config import settings

DEFAULT_ZIP_PASSWORD = "infected"
STORE_MODE = 0o444  # readable by every worker user, never writable or executable
logger = logging.getLogger("nik.samples")
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
    """Store the bytes if not already present; the file is read-only for everyone (0o444).

    World-readable so the analyzer worker, which runs as another user and sees
    the store through a read-only mount, can open it. Never executable.
    """
    path = sample_path(sha256)
    if not path.exists():
        tmp = path.with_suffix(".part")
        tmp.write_bytes(data)
        os.chmod(tmp, STORE_MODE)
        tmp.replace(path)
    else:
        # Uploaded again: the file may predate 2.7.0, when samples were stored 0o440.
        ensure_store_mode(path)
    return path


def ensure_store_mode(path: Path) -> bool:
    """Give a stored sample the store mode (0o444); True when it had to change."""
    if stat.S_IMODE(path.stat().st_mode) == STORE_MODE:
        return False
    os.chmod(path, STORE_MODE)
    return True


def repair_store_permissions() -> int:
    """Startup pass: every sample readable by the workers (older releases stored them 0o440).

    Returns the number of files changed; files that cannot be changed are
    logged and skipped, so a bad file never stops the API from starting.
    """
    directory = Path(settings.SAMPLE_STORE)
    if not directory.is_dir():
        return 0
    changed = 0
    for path in directory.glob("*.bin"):
        try:
            changed += ensure_store_mode(path)
        except OSError as exc:
            logger.warning("Cannot set the permissions of %s: %s", path.name, exc)
    if changed:
        logger.info("Made %d stored sample(s) readable by the analysis workers", changed)
    return changed


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

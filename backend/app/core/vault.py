"""Encryption of the threat-intelligence API keys stored in the database.

The keys are encrypted with Fernet (AES-128-CBC + HMAC-SHA256) under a key
derived from ``SECRET_KEY`` with HKDF, so a database dump or a backup alone
does not reveal them. Changing ``SECRET_KEY`` makes the stored keys
unreadable: they must be entered again (Settings -> Threat intelligence).
"""

from __future__ import annotations

import base64

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .config import settings


def _fernet() -> Fernet:
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"nik integration keys").derive(
        settings.SECRET_KEY.encode("utf-8")
    )
    return Fernet(base64.urlsafe_b64encode(key))


def encrypt(secret: str) -> str:
    return _fernet().encrypt(secret.encode("utf-8")).decode("ascii")


def decrypt(token: str) -> str | None:
    """The secret, or None when it cannot be read (``SECRET_KEY`` changed)."""
    try:
        return _fernet().decrypt(token.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError):
        return None

"""Encryption of the secrets stored in the database.

The threat-intelligence API keys and the TLS key logs of captures are
encrypted with Fernet (AES-128-CBC + HMAC-SHA256) under a key derived from
``SECRET_KEY`` with HKDF, so a database dump or a backup alone does not reveal
them. ``SECRET_KEY`` must therefore be kept with the backups: without it the
stored secrets are unreadable and have to be entered again.

To change ``SECRET_KEY`` without losing them, set ``SECRET_KEY_PREVIOUS`` to
the old value (several, separated by commas) for one start: everything stored
is still read with the old key and is re-encrypted with the new one
(``reencrypt``), after which ``SECRET_KEY_PREVIOUS`` can be removed.
"""

from __future__ import annotations

import base64
import logging

from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from sqlalchemy import select

from .config import settings

_logger = logging.getLogger("nik.vault")


def _key(secret: str) -> Fernet:
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"nik integration keys").derive(
        secret.encode("utf-8")
    )
    return Fernet(base64.urlsafe_b64encode(key))


def _fernet() -> MultiFernet:
    """Encrypts with ``SECRET_KEY``; decrypts with it or with a previous one."""
    return MultiFernet([_key(secret) for secret in (settings.SECRET_KEY, *settings.SECRET_KEY_PREVIOUS)])


def encrypt(secret: str) -> str:
    return _fernet().encrypt(secret.encode("utf-8")).decode("ascii")


def decrypt(token: str) -> str | None:
    """The secret, or None when it cannot be read (``SECRET_KEY`` changed)."""
    try:
        return _fernet().decrypt(token.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError):
        return None


def _rotated(token: str | None) -> str | None:
    """The token under the current key; None when it needs no change or cannot be read."""
    if not token:
        return None
    try:
        _key(settings.SECRET_KEY).decrypt(token.encode("ascii"))
        return None
    except (InvalidToken, ValueError):
        pass
    try:
        return _fernet().rotate(token.encode("ascii")).decode("ascii")
    except (InvalidToken, ValueError):
        return None


def reencrypt(session_factory) -> int:
    """Re-encrypt what is stored under a previous key with the current one.

    Runs at start-up while ``SECRET_KEY_PREVIOUS`` is set; returns how many
    secrets were moved. What neither key can read is left as it is.
    """
    if not settings.SECRET_KEY_PREVIOUS:
        return 0
    from .models import IntegrationKey, NetworkCapture

    moved = 0
    with session_factory() as db:
        for row in db.scalars(select(IntegrationKey)):
            token = _rotated(row.secret)
            if token:
                row.secret = token
                moved += 1
        for row in db.scalars(select(NetworkCapture).where(NetworkCapture.keylog.is_not(None))):
            token = _rotated(row.keylog)
            if token:
                row.keylog = token
                moved += 1
        db.commit()
    if moved:
        _logger.info("re-encrypted %d stored secret(s) with the current SECRET_KEY", moved)
    return moved

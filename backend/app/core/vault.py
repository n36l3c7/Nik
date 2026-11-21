"""Encryption of the secrets stored in the database.

The threat-intelligence API keys, the TLS key logs of captures and the
secrets of the second factors of accounts are encrypted with Fernet (AES-128-CBC + HMAC-SHA256) under a key derived from
``SECRET_KEY`` with HKDF, so a database dump or a backup alone does not reveal
them. ``SECRET_KEY`` must therefore be kept with the backups: without it the
stored secrets are unreadable and have to be entered again.

To change ``SECRET_KEY`` without losing them, the old value is kept as
``SECRET_KEY_PREVIOUS`` (several, separated by commas) while the change
lasts: everything stored is still read with the old key and is re-encrypted
with the new one (``reencrypt``), then read back under the new key alone
(``app/key_rotation.py``, which guides the whole change and says when the old
key can go). ``inventory`` lists every place a secret is stored: what
``reencrypt`` moves and what the check reads back.
"""

from __future__ import annotations

import base64
import logging
import os

from cryptography.exceptions import InvalidTag
from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from sqlalchemy import select

from .config import settings

logger = logging.getLogger("nik.vault")


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


# --------------------------------------------------------------------------- #
# Bytes that cross the database between two processes of the server           #
# --------------------------------------------------------------------------- #
TRANSIT = b"NKT1"


def _transit_key(secret: str, purpose: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"nik transit " + purpose).derive(
        secret.encode("utf-8")
    )


def seal_bytes(data: bytes, purpose: bytes, bound: bytes = b"") -> bytes:
    """Encrypt bytes one process of the server leaves in the database for another (the parts of a
    file the automation worker hands to the API process): AES-256-GCM under a key derived from
    ``SECRET_KEY`` for this ``purpose``, bound to ``bound`` (which row they are). So the rows, the
    write-ahead log and a dump taken at that moment hold no file in clear."""
    nonce = os.urandom(12)
    return TRANSIT + nonce + AESGCM(_transit_key(settings.SECRET_KEY, purpose)).encrypt(nonce, data, bound)


def open_bytes(blob: bytes, purpose: bytes, bound: bytes = b"") -> bytes:
    """What ``seal_bytes`` encrypted, under the current key or an earlier one. Bytes that were not
    sealed (written by a process of the version before, during an upgrade) are returned as they
    are. Raises ``ValueError`` when they cannot be read."""
    blob = bytes(blob)
    if not blob.startswith(TRANSIT):
        return blob
    nonce, sealed = blob[len(TRANSIT) : len(TRANSIT) + 12], blob[len(TRANSIT) + 12 :]
    for secret in (settings.SECRET_KEY, *settings.SECRET_KEY_PREVIOUS):
        try:
            return AESGCM(_transit_key(secret, purpose)).decrypt(nonce, sealed, bound)
        except InvalidTag:
            continue
    raise ValueError("The bytes handed over cannot be read: they were changed, or SECRET_KEY is another")


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


def _rotate_automation(db) -> int:
    """The secrets of automation: the credentials of connections (their first key and the others), the
    stored credentials they name, the SMTP password."""
    from sqlalchemy.orm.attributes import flag_modified

    from .models import Connection, Credential, Setting

    moved = 0
    for row in db.scalars(select(Connection)):
        for column in ("secrets", "extra_keys"):
            token = _rotated(getattr(row, column))
            if token:
                setattr(row, column, token)
                moved += 1
    for row in db.scalars(select(Credential)):
        token = _rotated(row.secret)
        if token:
            row.secret = token
            moved += 1
    from ..automation.state import SETTINGS_ID as AUTOMATION_ROW

    settings_row = db.get(Setting, AUTOMATION_ROW)
    smtp = ((settings_row.doc if settings_row else None) or {}).get("smtp") or {}
    token = _rotated(smtp["password"]) if smtp.get("password") else None
    if token:
        settings_row.doc = {**settings_row.doc, "smtp": {**smtp, "password": token}}
        flag_modified(settings_row, "doc")
        moved += 1
    return moved


def _rotate_backups(db) -> int:
    """The secrets of the backups (backups/config.py): the passphrase, the earlier ones, the key of the destination."""
    from sqlalchemy.orm.attributes import flag_modified

    from ..backups.config import SETTINGS_ID as BACKUPS_ROW
    from .models import Setting

    row = db.get(Setting, BACKUPS_ROW)
    doc = dict((row.doc if row else None) or {})
    moved = 0
    token = _rotated(doc.get("passphrase"))
    if token:
        doc["passphrase"] = token
        moved += 1
    previous = list(doc.get("previous") or [])
    for index, kept in enumerate(previous):
        token = _rotated(kept)
        if token:
            previous[index] = token
            moved += 1
    if previous:
        doc["previous"] = previous
    destination = dict(doc.get("destination") or {})
    secret = str(destination.get("secret") or "")
    token = _rotated(secret[len("vault:") :]) if secret.startswith("vault:") else None
    if token:
        doc["destination"] = {**destination, "secret": "vault:" + token}
        moved += 1
    if moved:
        row.doc = doc
        flag_modified(row, "doc")
    return moved


# The rows of the forwarding of the audit log (auditlog/forward.py): the settings as an
# administrator set them, and the settings in force, which the sender writes. Each keeps the key
# of the client certificate under ``clientKey``, as ``vault:<token>``.
FORWARDING_ROWS = ((40, "settings"), (41, "active"))


def _forwarding_tokens(db, lock: bool = False):
    """``(row, part, held, token)`` for each key of a client certificate the forwarding keeps."""
    from .models import Setting

    for row_id, part in FORWARDING_ROWS:
        row = db.get(Setting, row_id, with_for_update=True) if lock else db.get(Setting, row_id)
        held = ((row.doc if row else None) or {}).get(part)
        kept = str(held.get("clientKey") or "") if isinstance(held, dict) else ""
        if kept.startswith("vault:"):
            yield row, part, held, kept[len("vault:") :]


def _rotate_forwarding(db) -> int:
    """The key of the client certificate the audit log is forwarded with. The row in force is the
    sender's (the automation worker), which also puts it under the new key when it starts
    (``forward.rekey``): the row is locked here while it is read and written, so that nothing the
    sender committed meanwhile is written over."""
    from sqlalchemy.orm.attributes import flag_modified

    moved = 0
    for row, part, held, kept in list(_forwarding_tokens(db, lock=True)):
        token = _rotated(kept)
        if token:
            row.doc = {**row.doc, part: {**held, "clientKey": "vault:" + token}}
            flag_modified(row, "doc")
            moved += 1
    return moved


def _rotate_factors(db) -> int:
    """The secrets of the second factors: without this, a changed key would lock their owners out."""
    from .models import UserFactor

    moved = 0
    for row in db.scalars(select(UserFactor)):
        token = _rotated(row.secret)
        if token:
            row.secret = token
            moved += 1
    return moved


def inventory(db) -> list[tuple[str, str]]:
    """Every secret the database stores under ``SECRET_KEY``, as ``(what it is, its token)``: the
    same places ``reencrypt`` moves. A place added to one must be added to the other (a test
    compares them)."""
    from .models import Connection, Credential, IntegrationKey, NetworkCapture, Setting, UserFactor

    found: list[tuple[str, str]] = []
    for row in db.scalars(select(IntegrationKey)):
        found.append(("look-up key", row.secret))
    for row in db.scalars(select(NetworkCapture).where(NetworkCapture.keylog.is_not(None))):
        found.append(("TLS key log of a capture", row.keylog))
    for row in db.scalars(select(Connection)):
        found += [("secret of a connector instance", getattr(row, column)) for column in ("secrets", "extra_keys")]
    for row in db.scalars(select(Credential)):
        found.append(("credential", row.secret))
    from ..automation.state import SETTINGS_ID as AUTOMATION_ROW
    from ..backups.config import SETTINGS_ID as BACKUPS_ROW

    automation = db.get(Setting, AUTOMATION_ROW)
    smtp = ((automation.doc if automation else None) or {}).get("smtp") or {}
    found.append(("SMTP password", smtp.get("password")))
    backups = db.get(Setting, BACKUPS_ROW)
    doc = (backups.doc if backups else None) or {}
    found.append(("backup passphrase", doc.get("passphrase")))
    found += [("earlier backup passphrase", kept) for kept in doc.get("previous") or []]
    secret = str((doc.get("destination") or {}).get("secret") or "")
    if secret.startswith("vault:"):
        found.append(("key of the backup destination", secret[len("vault:") :]))
    for row in db.scalars(select(UserFactor)):
        found.append(("second factor of an account", row.secret))
    for _row, _part, _held, token in _forwarding_tokens(db):
        found.append(("key of the certificate the audit log is forwarded with", token))
    return [(what, token) for what, token in found if token]


def reads_alone(token: str) -> bool:
    """Whether the current ``SECRET_KEY`` reads the token by itself, without an earlier key."""
    try:
        _key(settings.SECRET_KEY).decrypt(token.encode("ascii"))
        return True
    except (InvalidToken, ValueError):
        return False


def key_id(secret: str) -> bytes:
    """What tells one ``SECRET_KEY`` from another without being a part of it (for its fingerprint)."""
    import hashlib

    derived = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"nik secret key id").derive(
        secret.encode("utf-8")
    )
    return hashlib.sha256(derived).digest()[:8]


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
        moved += _rotate_automation(db)
        moved += _rotate_backups(db)
        moved += _rotate_factors(db)
        moved += _rotate_forwarding(db)
        db.commit()
    if moved:
        logger.info("Re-encrypted %d stored secret(s) with the current SECRET_KEY", moved)
    return moved

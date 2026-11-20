"""The key the audit log is signed with: the one thing of the chain that is not in the database.

Every entry carries, beside its hash, an HMAC-SHA-256 of that hash made with
this key (``verifier.sign``). Whoever can write to the database can compute
hashes again; without the key they cannot make the signatures again.

**Where the key comes from**, in this order:

1. ``AUDIT_KEY``, or the file ``AUDIT_KEY_FILE`` names: a secret of its own.
   A text is taken as its UTF-8 bytes; ``hex:…`` as the bytes it spells.
2. When neither is set, a key **derived from** ``SECRET_KEY`` (HKDF-SHA-256,
   the label ``nik audit log signature``): a server that was upgraded is
   protected without anybody doing anything.

**The id of a key** names it without giving it away: ``set-<12 hex>`` or
``derived-<12 hex>``, the digits being the start of a SHA-256 of the key. A
key that changes therefore has another id by itself. Entries keep the id of
the key that signed them, and the messages sent to syslog carry it.

**When the key changes** the new one signs from the next entry on. The
entries before it stay verifiable for as long as this server can still make
their key: the earlier keys named in ``AUDIT_KEY_PREVIOUS`` (or the file
``AUDIT_KEY_PREVIOUS_FILE``; several separated by commas or line breaks), and
the keys derived from ``SECRET_KEY`` and from every ``SECRET_KEY_PREVIOUS``.
So:

- setting ``AUDIT_KEY`` on a server that used the derived key loses nothing:
  the derived one is still made from ``SECRET_KEY``;
- changing ``SECRET_KEY`` (with the derived key) starts a new derived key;
  the old entries verify while ``SECRET_KEY_PREVIOUS`` holds the old value.
  To take that value away and still verify them, put the old derived key in
  ``AUDIT_KEY_PREVIOUS`` first: ``python -m app.auditlog key --derived``
  prints it;
- an entry whose key this server can no longer make is reported as one that
  **cannot be checked**, never as tampering: its place in the chain of
  hashes is still verified.

Everything here goes through ``current`` and ``known``: a provider of
secrets (keys from files, a rotation screen) plugs in by replacing what
``_configured`` and ``_previous`` read.
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import verifier

LABEL = b"nik audit log signature"


def _read(name: str) -> str:
    """A secret of the environment: ``NAME``, or the content of the file ``NAME_FILE`` names."""
    value = os.environ.get(name, "")
    path = os.environ.get(f"{name}_FILE", "")
    if not value and path:
        try:
            with open(path, encoding="utf-8") as source:
                value = source.read()
        except OSError:
            value = ""
    return value.strip()


def _configured() -> str:
    return _read("AUDIT_KEY")


def _previous() -> list[str]:
    return [part.strip() for part in _read("AUDIT_KEY_PREVIOUS").replace("\n", ",").split(",") if part.strip()]


def derived(secret: str) -> bytes:
    """The key made from a ``SECRET_KEY``."""
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=LABEL).derive(secret.encode("utf-8"))


def current() -> tuple[str, bytes]:
    """The id and the bytes of the key that signs the entries written now."""
    from ..core.config import settings

    text = _configured()
    if text:
        key = verifier.key_bytes(text)
        return f"set-{verifier.fingerprint(key)}", key
    key = derived(settings.SECRET_KEY)
    return f"derived-{verifier.fingerprint(key)}", key


def known() -> dict[str, bytes]:
    """Every key this server can still make, by fingerprint (the digits of its id)."""
    from ..core.config import settings

    keys = [current()[1], *(verifier.key_bytes(text) for text in _previous())]
    keys += [derived(secret) for secret in (settings.SECRET_KEY, *settings.SECRET_KEY_PREVIOUS)]
    return {verifier.fingerprint(key): key for key in keys}

"""Time-based one-time passwords (RFC 6238 over RFC 4226), as authenticator apps compute them.

A secret shared once (the QR code of the enrolment) and the time give a code
of six digits that changes every thirty seconds. The server accepts the code
of the current step and of one step either way, for a clock that is a little
off, and never the same step twice: ``verify`` returns the step it matched,
the caller remembers it and passes it back as ``after``.

Only what every authenticator app understands is used: SHA-1, six digits,
thirty seconds. SHA-1 is not a weakness here: HMAC does not need collision
resistance, and the other algorithms of the RFC are ignored by several apps.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
from urllib.parse import quote

DIGITS = 6
PERIOD = 30
# Steps accepted before and after the current one.
WINDOW = 1
SECRET_BYTES = 20  # 160 bits, the size RFC 4226 recommends


def new_secret() -> str:
    """A new secret, in the base32 an authenticator app takes (no padding)."""
    return base64.b32encode(secrets.token_bytes(SECRET_BYTES)).decode("ascii").rstrip("=")


def _key(secret: str) -> bytes:
    cleaned = "".join(secret.split()).upper()
    return base64.b32decode(cleaned + "=" * (-len(cleaned) % 8))


def step_at(at: float, period: int = PERIOD) -> int:
    """The time step a moment (seconds since 1970) falls in."""
    return int(at // period)


def code_at(secret: str, step: int, digits: int = DIGITS, algorithm: str = "sha1") -> str:
    """The code of one time step."""
    digest = hmac.new(_key(secret), struct.pack(">Q", step), getattr(hashlib, algorithm)).digest()
    offset = digest[-1] & 0x0F
    number = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(number % 10**digits).zfill(digits)


def clean_code(typed: object) -> str:
    """What was typed, without the spaces and dashes people and apps put in a code."""
    return "".join(ch for ch in str(typed or "") if not ch.isspace() and ch != "-")


def verify(secret: str, typed: object, at: float, after: int | None = None) -> int | None:
    """The time step whose code was typed, or None.

    ``after`` is the last step already accepted: it and every older one are
    refused, so a code read over a shoulder cannot be used a second time.
    Every step of the window is compared, in constant time each, whatever
    the outcome of the others.
    """
    code = clean_code(typed)
    if len(code) != DIGITS or not code.isascii() or not code.isdigit():
        code = ""  # still compared below, and never equal
    current = step_at(at)
    matched: int | None = None
    for step in range(current - WINDOW, current + WINDOW + 1):
        same = hmac.compare_digest(code_at(secret, step).encode("ascii"), code.encode("ascii"))
        if same and (after is None or step > after) and matched is None:
            matched = step
    return matched


def uri(secret: str, account: str, issuer: str = "Nik") -> str:
    """The ``otpauth://`` address an authenticator app reads from the QR code."""
    label = quote(f"{issuer}:{account}", safe="")
    return f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer, safe='')}&digits={DIGITS}&period={PERIOD}"

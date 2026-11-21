"""The id of a new row: 32 hexadecimal characters of a random UUID."""

from __future__ import annotations

import uuid


def new_id() -> str:
    return uuid.uuid4().hex

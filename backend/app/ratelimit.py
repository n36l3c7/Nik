"""Shared rate limiter (slowapi).

A blanket per-IP default protects every endpoint; sensitive routes (login) add
a stricter explicit limit via ``@limiter.limit(...)``. In-memory storage is
fine for a single-node deploy; point ``RATE_LIMIT_STORAGE_URI`` at Redis for a
multi-worker/multi-host setup.
"""

from __future__ import annotations

import os

from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[os.getenv("RATE_LIMIT_DEFAULT", "600/minute")],
    storage_uri=os.getenv("RATE_LIMIT_STORAGE_URI", "memory://"),
    headers_enabled=True,
)

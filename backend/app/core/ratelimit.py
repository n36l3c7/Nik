"""Shared rate limiter (slowapi).

A blanket per-IP default protects every endpoint; sensitive routes (login) add
a stricter explicit limit via ``@limiter.limit(...)``. In-memory storage is
fine for a single-node deploy; point ``RATE_LIMIT_STORAGE_URI`` at Redis for a
multi-worker/multi-host setup.
"""

from __future__ import annotations

import os

from slowapi import Limiter

from .client_address import limiter_key

# Counted by the client's address as the server knows it: the one a trusted
# proxy names, the connection's own otherwise (core/client_address.py).
limiter = Limiter(
    key_func=limiter_key,
    default_limits=[os.getenv("RATE_LIMIT_DEFAULT", "600/minute")],
    storage_uri=os.getenv("RATE_LIMIT_STORAGE_URI", "memory://"),
    headers_enabled=True,
)

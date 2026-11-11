"""Start-up check of the container: refuse to serve with secrets everybody knows.

``SECRET_KEY`` protects the provider API keys and the TLS key logs stored in
the database, and each worker token is all that stands between the analysis
network and a worker. The values printed in ``.env.example`` and in older
Compose files are public: a deployment that still uses them is not protected
at all, and nothing shows it. So the image's entrypoint runs this check before
anything else and stops, saying what to set, instead of starting.

Development (``uvicorn app.main:app`` on SQLite) does not go through it.

Only the NAME of a variable and one of the fixed reasons below are ever
reported: a value is looked at, never copied into a message.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping

# Values that have been printed in this repository at some point.
KNOWN_SECRET_KEYS = {
    "dev-insecure-change-me",
    "please-change-this-secret",
    "change-this-to-a-long-random-string",
}
PLACEHOLDER_PREFIXES = ("please-change-this", "change-this")
MIN_SECRET_LENGTH = 16
WORKERS = ("ANALYZER", "CAPA", "DOCVIEW", "BROWSER", "PCAP")

MISSING, EXAMPLE, SHORT = "missing", "example", "short"
REASONS = {
    MISSING: "is not set",
    EXAMPLE: "is still the value of the example file, which is public",
    SHORT: f"is shorter than {MIN_SECRET_LENGTH} characters",
}
HOW = "Run deploy/init-env.sh, or set it in .env to a long random value (openssl rand -hex 32)."
KEEP_STORED = (
    "If the server already stores provider API keys or TLS key logs, also set "
    "SECRET_KEY_PREVIOUS to the old value so they are re-encrypted, not lost."
)


def is_placeholder(value: str) -> bool:
    """True for a value copied from an example file instead of generated."""
    return value in KNOWN_SECRET_KEYS or value.startswith(PLACEHOLDER_PREFIXES)


def _weakness(value: str, min_length: int = 0) -> str | None:
    """Why a secret cannot be used (one of the reason constants), or None."""
    if not value:
        return MISSING
    if is_placeholder(value):
        return EXAMPLE
    if len(value) < min_length:
        return SHORT
    return None


def problems(env: Mapping[str, str] | None = None) -> list[tuple[str, str]]:
    """What must be fixed before the server may start: ``(variable name, reason)`` pairs."""
    env = os.environ if env is None else env
    found = []
    reason = _weakness(env.get("SECRET_KEY", ""), MIN_SECRET_LENGTH)
    if reason:
        found.append(("SECRET_KEY", reason))
    for worker in WORKERS:
        # A worker that is not configured needs no token.
        if not env.get(f"{worker}_URL", ""):
            continue
        reason = _weakness(env.get(f"{worker}_TOKEN", ""))
        if reason:
            found.append((f"{worker}_TOKEN", reason))
    return found


def describe(name: str, reason: str) -> str:
    """The line shown to the operator for one problem."""
    text = f"{name} {REASONS[reason]}. {HOW}"
    if name == "SECRET_KEY" and reason == EXAMPLE:
        text += f" {KEEP_STORED}"
    return text


def main() -> None:
    found = problems()
    if not found:
        return
    sys.stderr.write("Nik refuses to start with secrets that are missing or publicly known:\n")
    for name, reason in found:
        sys.stderr.write(f"  - {describe(name, reason)}\n")
    raise SystemExit(1)


if __name__ == "__main__":
    main()

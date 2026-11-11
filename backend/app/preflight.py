"""Start-up check of the container: refuse to serve with secrets everybody knows.

``SECRET_KEY`` protects the provider API keys and the TLS key logs stored in
the database, and each worker token is all that stands between the analysis
network and a worker. The values printed in ``.env.example`` and in older
Compose files are public: a deployment that still uses them is not protected
at all, and nothing shows it. So the image's entrypoint runs this check before
anything else and stops, saying what to set, instead of starting.

Development (``uvicorn app.main:app`` on SQLite) does not go through it.
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
HOW = "run deploy/init-env.sh, or set it in .env to a long random value (openssl rand -hex 32)"


def is_placeholder(value: str) -> bool:
    """True for a value copied from an example file instead of generated."""
    return value in KNOWN_SECRET_KEYS or value.startswith(PLACEHOLDER_PREFIXES)


def problems(env: Mapping[str, str] | None = None) -> list[str]:
    """What must be fixed before the server may start (empty when nothing)."""
    env = os.environ if env is None else env
    found = []
    secret = env.get("SECRET_KEY", "")
    if not secret:
        found.append(f"SECRET_KEY is not set: {HOW}.")
    elif is_placeholder(secret):
        found.append(
            f"SECRET_KEY is still the value of the example file, which is public: {HOW}. "
            "If the server already stores provider API keys or TLS key logs, also set "
            "SECRET_KEY_PREVIOUS to the old value so they are re-encrypted, not lost."
        )
    elif len(secret) < MIN_SECRET_LENGTH:
        found.append(f"SECRET_KEY is shorter than {MIN_SECRET_LENGTH} characters: {HOW}.")
    for worker in WORKERS:
        if not env.get(f"{worker}_URL", ""):
            continue
        token = env.get(f"{worker}_TOKEN", "")
        if not token or is_placeholder(token):
            found.append(f"{worker}_TOKEN is {'not set' if not token else 'still the example value'}: {HOW}.")
    return found


def main() -> None:
    found = problems()
    if not found:
        return
    print("Nik refuses to start with secrets that are missing or publicly known:", file=sys.stderr)
    for line in found:
        print(f"  - {line}", file=sys.stderr)
    raise SystemExit(1)


if __name__ == "__main__":
    main()

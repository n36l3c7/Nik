"""Start-up check of the container: refuse to serve with secrets everybody knows.

``SECRET_KEY`` protects the provider API keys and the TLS key logs stored in
the database, ``STORE_KEY`` seals every file of the store, and each worker
token is all that stands between the analysis network and a worker. The
values printed in ``.env.example`` and in older
Compose files are public: a deployment that still uses them is not protected
at all, and nothing shows it. So the image's entrypoint runs this check before
anything else and stops, saying what to set, instead of starting.

A secret is taken from a file (``<NAME>_FILE``, a mounted secret) or from the
environment (``core/keys.py``); one that is given in both, or whose file
cannot be read, is a problem too.

``python -m app.preflight`` prints the problems and exits; with ``--serve``
(what the entrypoint of the API container runs) it stays up instead and
answers every request with them (``app/stopped.py``): a container that
exits only restarts, and the page shows nothing. Then it checks the store
key against the store (``--store``, once the database is migrated).

Development (``uvicorn app.main:app`` on SQLite) does not go through it.

Only the NAME of a variable and one of the fixed reasons below are ever
reported: a value is looked at, never copied into a message.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping

from .core import keys

# Values that have been printed in this repository at some point.
KNOWN_SECRET_KEYS = {
    "dev-insecure-change-me",
    "please-change-this-secret",
    "change-this-to-a-long-random-string",
}
PLACEHOLDER_PREFIXES = ("please-change-this", "change-this")
MIN_SECRET_LENGTH = 16
MIN_STORE_KEY_LENGTH = 32
DEV_STORE_KEY = "dev-insecure-store-key-change-me"
WORKERS = ("ANALYZER", "CAPA", "DOCVIEW", "BROWSER", "PCAP", "SANDBOX")

MISSING, EXAMPLE, SHORT = "missing", "example", "short"
REASONS = {
    MISSING: "is not set",
    EXAMPLE: "is still the value of the example file, which is public",
    SHORT: f"is shorter than {MIN_SECRET_LENGTH} characters",
}
HOW = "Run deploy/init-env.sh, or set it in .env to a long random value (openssl rand -hex 32)."
STORE_KEY_NEW = (
    "It is new in 6.8: every file of the store is sealed under it. deploy/init-env.sh writes one beside the "
    "other secrets and changes nothing else; keep a copy of it away from the server, apart from the backups."
)
KEEP_STORED = (
    "If the server already stores provider API keys or TLS key logs, also set "
    "SECRET_KEY_PREVIOUS to the old value so they are re-encrypted, not lost."
)


def is_placeholder(value: str) -> bool:
    """True for a value copied from an example file instead of generated."""
    return value in KNOWN_SECRET_KEYS or value == DEV_STORE_KEY or value.startswith(PLACEHOLDER_PREFIXES)


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

    def check(name: str, min_length: int = 0) -> None:
        try:
            reason = _weakness(keys.value(name, "", env), min_length)
        except keys.KeyProblem as problem:
            # Given twice, or in a file that cannot be read: the sentence says which.
            reason = problem.message
        if reason:
            found.append((name, reason))

    check("SECRET_KEY", MIN_SECRET_LENGTH)
    # A process that is told it holds no store key (the automation worker) needs none.
    if env.get("NIK_NO_STORE_KEY", "").strip().lower() not in ("1", "true", "yes", "on"):
        check("STORE_KEY", MIN_STORE_KEY_LENGTH)
    for name in ("SECRET_KEY_PREVIOUS", "STORE_KEY_PREVIOUS", "DB_PASSWORD"):
        # Not required here, but a file that cannot be read is never taken for an empty one.
        try:
            keys.find(name, env)
        except keys.KeyProblem as problem:
            found.append((name, problem.message))
    for worker in WORKERS:
        # A worker that is not configured needs no token.
        if not env.get(f"{worker}_URL", ""):
            continue
        check(f"{worker}_TOKEN")
    return found


def describe(name: str, reason: str) -> str:
    """The line shown to the operator for one problem."""
    if reason not in REASONS:
        return reason if reason.endswith(".") else reason + "."
    length = MIN_STORE_KEY_LENGTH if name == "STORE_KEY" else MIN_SECRET_LENGTH
    why = f"is shorter than {length} characters" if reason == SHORT else REASONS[reason]
    text = f"{name} {why}. {HOW}"
    if name == "SECRET_KEY" and reason == EXAMPLE:
        text += f" {KEEP_STORED}"
    if name == "STORE_KEY" and reason == MISSING:
        text += f" {STORE_KEY_NEW}"
    return text


def main(argv: list[str] | None = None) -> None:
    argv = sys.argv[1:] if argv is None else argv
    if "--store" in argv:
        # The store key against the store it is given: asked once the database can be read.
        from . import store_seal

        wrong = store_seal.key_problem()
        if wrong is None:
            return
        from . import stopped

        stopped.serve([wrong + "."])
        return
    found = problems()
    if not found:
        return
    if "--serve" in argv:
        from . import stopped

        stopped.serve([describe(name, reason) for name, reason in found])
        return
    sys.stderr.write("Nik refuses to start with secrets that are missing or publicly known:\n")
    for name, reason in found:
        sys.stderr.write(f"  - {describe(name, reason)}\n")
    raise SystemExit(1)


if __name__ == "__main__":
    main()

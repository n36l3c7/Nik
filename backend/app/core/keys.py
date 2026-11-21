"""Where the secrets of the server come from.

A secret has a name (``SECRET_KEY``, ``STORE_KEY``, ``DB_PASSWORD``, a worker
token) and is asked of the providers below, in order:

- a **file**: the variable ``<NAME>_FILE`` names it (``/run/secrets/secret_key``,
  what ``secrets:`` of Compose, ``podman secret`` and ``docker secret`` mount).
  This is the recommended place: the value is then not in the environment of
  the container, so it is not in ``podman inspect``, not in
  ``/proc/<pid>/environ`` and not handed to every process the server starts;
- the **environment**: the variable ``<NAME>`` itself, as a ``.env`` file gives it.

A file that is empty counts as not given: the Compose file mounts an empty
one in the place of each secret a server still keeps in ``.env``. A secret
given in both places is refused (``Conflict``): one of the two is stale, and
nothing says which. A file that is named and cannot be read is refused too
(``Unreadable``), never taken for a missing one.

Nothing here writes a value anywhere: not into the environment, not into a
log, not into a message. A message names the variable and says what is wrong
with it.

Another provider (the client of a secrets manager) is one more class with a
``name`` and a ``read``, added to ``PROVIDERS``: nothing that asks for a
secret knows where it came from.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol

FILE, ENVIRONMENT, DEFAULT = "file", "environment", "default"
# A key is a line of text; anything larger is not one.
MAX_BYTES = 64 * 1024


class KeyProblem(Exception):
    """A secret that cannot be taken: the name of its variable and a sentence to act on."""

    def __init__(self, name: str, message: str) -> None:
        super().__init__(message)
        self.name, self.message = name, message


class Conflict(KeyProblem):
    """Given both as a file and in the environment."""


class Unreadable(KeyProblem):
    """Its file is named and cannot be read."""


class Provider(Protocol):
    name: str

    def read(self, secret: str, env: Mapping[str, str]) -> str | None:
        """The value of the secret, or None when this provider does not have it."""


class FileProvider:
    name = FILE

    def path(self, secret: str, env: Mapping[str, str]) -> str:
        return (env.get(f"{secret}_FILE") or "").strip()

    def read(self, secret: str, env: Mapping[str, str]) -> str | None:
        path = self.path(secret, env)
        if not path:
            return None
        try:
            with open(path, "rb") as handle:
                raw = handle.read(MAX_BYTES + 1)
        except OSError as error:
            raise Unreadable(
                secret,
                f"{secret}_FILE names {path}, which cannot be read ({error.strerror or type(error).__name__}): "
                "check that the file exists and that the user of the container may read it",
            ) from None
        if len(raw) > MAX_BYTES:
            raise Unreadable(secret, f"{secret}_FILE names {path}, which is too large to be a secret")
        try:
            # The newline an editor or `echo` leaves at the end is not part of the secret.
            value = raw.decode("utf-8").strip("\r\n")
        except UnicodeDecodeError:
            raise Unreadable(secret, f"{secret}_FILE names {path}, which is not text") from None
        return value or None


class EnvironmentProvider:
    name = ENVIRONMENT

    def read(self, secret: str, env: Mapping[str, str]) -> str | None:
        return env.get(secret) or None


PROVIDERS: tuple[Provider, ...] = (FileProvider(), EnvironmentProvider())


@dataclass(frozen=True)
class Found:
    value: str
    source: str  # the name of the provider it came from


def find(secret: str, env: Mapping[str, str] | None = None) -> Found | None:
    """The secret and where it came from; None when no provider has it."""
    env = os.environ if env is None else env
    found = [Found(value, provider.name) for provider in PROVIDERS if (value := provider.read(secret, env))]
    if len(found) > 1:
        raise Conflict(
            secret,
            f"{secret} is given twice: in the file named by {secret}_FILE and in the environment. "
            "Keep one (deploy/secrets.sh move takes the values out of .env)",
        )
    return found[0] if found else None


def value(secret: str, default: str = "", env: Mapping[str, str] | None = None) -> str:
    found = find(secret, env)
    return found.value if found else default


def source(secret: str, env: Mapping[str, str] | None = None) -> str:
    """``file``, ``environment``, or ``default`` when no provider has it."""
    try:
        found = find(secret, env)
    except KeyProblem:
        return DEFAULT
    return found.source if found else DEFAULT


def several(secret: str, env: Mapping[str, str] | None = None) -> list[str]:
    """A secret that holds several values, separated by commas or new lines (the earlier keys)."""
    raw = value(secret, "", env)
    return [part.strip() for part in raw.replace("\n", ",").split(",") if part.strip()]


def to_a_terminal(what: str, out=None, err=None) -> bool:
    """Whether standard output is a terminal, said on standard error when it is.

    A few commands write a key on standard output, for the script that pipes it into the place keys
    are kept. Run by hand in a terminal they would put the key on a screen, and in the scrollback of
    whoever looks next: they ask this first, and write nothing when it answers True."""
    import sys

    out = sys.stdout if out is None else out
    try:
        shown = bool(out.isatty())
    except (AttributeError, ValueError):
        shown = False
    if shown:
        (sys.stderr if err is None else err).write(
            f"{what} is a secret and is not written to a terminal. Send it where it goes: into a file only you "
            "can read (> file, with umask 077), or through a pipe to the command that stores it.\n"
        )
    return shown

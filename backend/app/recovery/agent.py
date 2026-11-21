"""Asking the recovery service, and reading what it answers.

The backend cannot run the tools of PostgreSQL and the recovery service takes
no command over a network: it has none. The two share the archive volume and
nothing else. A request is a small file in ``requests/`` (its name says what
is asked, its lines are ``key=value``); the answer is ``<name>.result`` in
``results/``, written by the service when the work is over
(``deploy/db/recovery-agent.sh`` is the other side).

A request is written beside its name and moved there, so the service never
reads half of one. Values are checked here against what they may be before
they are written: the service checks them again.
"""

from __future__ import annotations

import os
import re
import time
from pathlib import Path

from . import layout

_NAME = re.compile(r"^(base-\d{8}-\d{6}|test-[a-z0-9]{1,40}|prune-[a-z0-9]{1,40})$")
_VALUE = re.compile(r"^[A-Za-z0-9 :+.,_-]{0,200}$")
ALIVE_WITHIN = 120


class AgentError(Exception):
    """The recovery service cannot be asked: a sentence a person can act on."""


def _requests() -> Path:
    return layout.folder("requests")


def _results() -> Path:
    return layout.folder("results")


def alive(now: float | None = None) -> float | None:
    """How many seconds ago the recovery service last said it was there; None when it never did."""
    try:
        said = float((_results() / "alive").read_text(encoding="ascii").strip() or 0)
    except (OSError, ValueError):
        return None
    return max(0.0, (time.time() if now is None else now) - said)


def running(now: float | None = None) -> bool:
    age = alive(now)
    return age is not None and age <= ALIVE_WITHIN


def ask(name: str, lines: list[tuple[str, str]] | None = None) -> None:
    """Leave a request. Raises ``AgentError`` when it cannot be written."""
    if not _NAME.match(name):
        raise AgentError(f"{name!r} is not something the recovery service is asked")
    body = ""
    for key, value in lines or []:
        if not re.match(r"^[a-z_]{1,30}$", key) or not _VALUE.match(value):
            raise AgentError(f"The request {name} holds a value the recovery service would not read")
        body += f"{key}={value}\n"
    folder = _requests()
    part = folder / f".{name}.{os.getpid()}.part"
    try:
        part.write_text(body, encoding="ascii")
        part.chmod(0o644)
        part.replace(folder / f"{name}.req")
    except OSError as error:
        raise AgentError(f"The request {name} could not be left for the recovery service: {error}") from None


def asked(name: str) -> bool:
    """Whether the request is still waiting or being worked on."""
    try:
        return (_requests() / f"{name}.req").exists()
    except OSError:
        return False


def answer(name: str) -> dict[str, str] | None:
    """The answer to a request, or None while there is none. A name is asked once: a base backup
    is named by its second, a test and a pruning by a number of their own."""
    try:
        text = (_results() / f"{name}.result").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    found: dict[str, str] = {}
    for line in text.splitlines():
        key, equals, value = line.partition("=")
        if equals:
            found[key.strip()] = value.strip()
    return found if found.get("state") else None

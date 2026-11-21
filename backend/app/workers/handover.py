"""Giving an analysis worker the files it works on.

The store is sealed and no worker sees it: a worker parses hostile files and
is the likeliest thing to be subverted, so it holds neither the store nor its
key. The API process, which holds both, decrypts the file a job needs and
sends it:

    PUT <worker>/files/<name>      the body is the file, streamed as it is decrypted

A worker keeps what it was given for as long as it uses it (``given.py`` in
each worker says where and for how long), so the file is not sent with every
request: a request is made as before, and when the worker answers ``409``
with the names it is ``missing``, those are sent and the request is made
again.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, TypeVar
from urllib.parse import quote

from ..core import store

T = TypeVar("T")
GIVE_TIMEOUT = 900


class NotGiven(Exception):
    """The worker did not take a file: what it answered."""


def give(base_url: str, header: str, token: str, name: str, path: Path, timeout: float = GIVE_TIMEOUT) -> None:
    """Send the file of the store at ``path`` to a worker, under ``name``."""
    size = store.size(path)
    with store.open(path) as handle:
        request = urllib.request.Request(  # noqa: S310 - operator-configured URL
            f"{base_url}/files/{quote(name)}",
            data=handle,
            method="PUT",
            headers={header: token, "Content-Type": "application/octet-stream", "Content-Length": str(size)},
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
                response.read()
        except urllib.error.HTTPError as error:
            try:
                detail = json.loads(error.read() or b"{}").get("detail")
            except (ValueError, AttributeError):
                detail = None
            raise NotGiven(str(detail or f"The worker answered {error.code}")) from None
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            raise NotGiven(f"The worker cannot be reached: {getattr(error, 'reason', error)}") from None


def missing_of(error: urllib.error.HTTPError, body: Any) -> list[str]:
    """The names a worker says it does not hold, from its ``409`` answer."""
    if error.code != 409 or not isinstance(body, dict):
        return []
    return [str(name) for name in body.get("missing") or [] if isinstance(name, str)]


def with_files(
    call: Callable[[], T],
    files: Mapping[str, Path],
    base_url: str,
    header: str,
    token: str,
    refused: Callable[[str], Exception],
) -> T:
    """Make ``call`` (a request to a worker). When the worker lacks files it names (the exception
    ``call`` raises carries them as ``missing``), send them and call once more. ``refused(sentence)``
    builds the exception raised when a file cannot be given."""
    try:
        return call()
    except Exception as error:  # noqa: BLE001 - only the ones that name missing files are handled
        missing = list(getattr(error, "missing", None) or [])
        if not missing:
            raise
    for name in missing:
        path = files.get(name)
        if path is None or not Path(path).is_file():
            raise refused(f"The file {name} is not in the store")
        try:
            give(base_url, header, token, name, Path(path))
        except NotGiven as error:
            raise refused(str(error)) from None
    return call()

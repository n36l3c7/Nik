"""The parsers of the forensics worker: one module per format.

A parser module has:

    NAME      its name ("evtx"): what ``evidence_sources.parser`` holds
    VERSION   a text that changes when what it gives for the same file changes ("1")
    KIND      the evidence section its records show in ("eventlog", "endpoint", "browser", "commands",
              "disk", "syslog")
    SOURCES   the sources it reads, as the section names them ("evtx", "windows.run_keys"…)

    sniff(path, name, head) -> str | None
        The source this file is, when the parser reads it, from its first bytes (``head``, 4096 of
        them) and its name; None when it is not one of its files. Cheap, and never raises.

    parse(path, ctx, source) -> None
        Read the file at ``path`` (a file of the worker's own folder, never a path of the caller) and
        say everything to ``ctx`` (``context.Context``): ``ctx.source`` first, then records, skips and
        notes, then ``ctx.end``. A parser that cannot go on raises: what it said so far is kept, and
        the file is reported as read in part.

A parser imports what it needs inside its functions where the library is heavy
or may be missing: ``load`` then fails for that parser alone.
"""

from __future__ import annotations

import importlib
from types import ModuleType

# In the order they are tried when a file comes without a source.
NAMES: tuple[str, ...] = ("evtx", "browser", "endpoint", "eventlog_json", "history")


class UnknownParser(Exception):
    """No parser of that name, or none that reads the file."""


def load(name: str) -> ModuleType:
    """The parser called ``name``: its module's name, or its ``NAME`` (``eventlog-json`` is the module
    ``eventlog_json``), which is what a source keeps and gives back to have its file read again."""
    module = name.replace("-", "_")
    if module not in NAMES:
        raise UnknownParser(f"No parser is called {name}")
    return importlib.import_module(f"{__name__}.{module}")


def recognise(path: str, file_name: str) -> tuple[ModuleType, str]:
    """The parser that reads the file and the source it is. Raises ``UnknownParser``."""
    with open(path, "rb") as handle:
        head = handle.read(4096)
    for name in NAMES:
        try:
            module = load(name)
            source = module.sniff(path, file_name, head)
        except Exception:  # noqa: BLE001, S112 - a parser that cannot even look is not the one
            continue
        if source:
            return module, source
    raise UnknownParser("No parser of Nik reads this file")

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

    view(path, source, loc) -> dict
        Show the piece of the file one record came from, from the ``loc`` the parser wrote for it
        (``ctx.record(loc=...)``). Read around the place the locator names: never the whole file when the
        format lets it be found otherwise. The answer is one of, always with a ``title`` (a short sentence
        that says what is shown) and ``where`` (an object that echoes the place: offset and length in bytes
        when the format has them, else what identifies it):

            {"kind": "xml",    "text": "<Event ...>...</Event>"}
            {"kind": "fields", "rows": [[name, value], ...]}      a row of a database, an entry of a list
            {"kind": "text",   "text": "...", "highlight": [first_line, last_line], "first": n}
            {"kind": "json",   "text": "<the element, pretty-printed>"}

        Every string of an answer is cut at 256 KiB in all (``viewing.fit``): ``cut`` is true when it was.
        A locator that names nothing in this file raises ``ViewError`` with a sentence for the analyst; one that
        lacks a member the parser needs raises ``BadLocator`` (a ``ViewError``), which is not about the file.

A parser imports what it needs inside its functions where the library is heavy
or may be missing: ``load`` then fails for that parser alone.
"""

from __future__ import annotations

import importlib
from types import ModuleType

# In the order they are tried when a file comes without a source.
NAMES: tuple[str, ...] = (
    "evtx",
    "browser",
    "endpoint",
    "eventlog_json",
    "history",
    # 7.0, stage 6: a module that is not there yet is simply not one that reads the file.
    "mft",
    "usnjrnl",
    "hive",
    "prefetch",
    "lnk",
    "jumplist",
    "srum",
    "syslog",
    "plaso",
)


class UnknownParser(Exception):
    """No parser of that name, or none that reads the file."""


class ViewError(Exception):
    """The locator names nothing in this file: the message says so, in a sentence the analyst can read."""


class BadLocator(ViewError):
    """The locator lacks a member the parser needs, or holds one of the wrong kind: not a place in any file
    (the server answers 422 for it, and 404 for a plain ``ViewError``)."""


def load(name: str) -> ModuleType:
    """The parser called ``name``: its module's name, or its ``NAME`` (``eventlog-json`` is the module
    ``eventlog_json``), which is what a source keeps and gives back to have its file read again."""
    module = name.replace("-", "_")
    if module not in NAMES:
        raise UnknownParser(f"No parser is called {name}")
    return importlib.import_module(f"{__name__}.{module}")


def by_source(kind: str, source: str) -> ModuleType | None:
    """The parser of a section that reads the source named: the one whose ``KIND`` is ``kind`` and whose
    ``SOURCES`` holds ``source``. None when no parser says so (the file is then recognised by what it is)."""
    for name in NAMES:
        try:
            module = load(name)
        except Exception:  # noqa: BLE001, S112 - a parser that cannot be loaded reads nothing
            continue
        if getattr(module, "KIND", None) == kind and source in getattr(module, "SOURCES", ()):
            return module
    return None


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

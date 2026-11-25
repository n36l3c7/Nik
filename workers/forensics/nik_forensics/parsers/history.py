"""Command histories: PowerShell (``ConsoleHost_history.txt``), bash, zsh and fish.

One record per command, in the order of the file. A PowerShell history holds
no time; bash holds one when ``HISTTIMEFORMAT`` was set (a ``#<epoch>`` line
before the command), zsh when ``EXTENDED_HISTORY`` was (``: <epoch>:<seconds>;``
before it), fish always (``- cmd: <command>`` then ``  when: <epoch>`` and an optional
``  paths:`` list; a newline in a command is written ``\\n``, a backslash ``\\\\``). A command written
over several lines is one record: PowerShell ends a line that goes on with a backtick, zsh with a
backslash.

The key of a record is its line and a hash of the command: the same file read
again gives the same keys, and a history that grew gives the old ones again
and new ones after them.

Bytes that are not UTF-8 are kept as replacement characters and said in a note:
nothing is skipped for them. Blank lines are notes. Standard library only.
"""

from __future__ import annotations

import hashlib
import os
import re

from nik_forensics import viewing

NAME = "history"
VERSION = "1"
KIND = "commands"
SOURCES = ("powershell", "bash", "zsh", "fish")

_ZSH = re.compile(r"^: (\d{9,11}):\d+;(.*)$", re.DOTALL)
_BASH_TIME = re.compile(r"^#(\d{9,11})$")
_FISH_CMD = re.compile(r"^- cmd:\s?(.*)$", re.DOTALL)
_FISH_WHEN = re.compile(r"^\s+when:\s*(\d{9,11})\b")
_FISH_PATH = re.compile(r"^\s+- (.*)$", re.DOTALL)
_FISH_ESCAPE = re.compile(r"\\(n|\\)")
_NAMES = {
    "consolehost_history.txt": "powershell",
    ".bash_history": "bash",
    "bash_history": "bash",
    ".zsh_history": "zsh",
    "zsh_history": "zsh",
    ".zhistory": "zsh",
    "fish_history": "fish",
}
MAX_LINE = 1024 * 1024


def sniff(path: str, name: str, head: bytes) -> str | None:
    source = _NAMES.get(os.path.basename(name.replace("\\", "/")).lower())
    if source is None or b"\x00" in head:
        return None
    return source


def _program(command: str) -> str:
    """The first word of a command, without its path: what the screens group by."""
    words = command.strip().split(None, 1)
    if not words:
        return ""
    first = words[0].strip("\"'&(")
    return re.split(r"[\\/]", first)[-1][:200]


def _unescape(text: str) -> str:
    """A fish history writes a newline as backslash-n and a backslash as two, read in one pass."""
    return _FISH_ESCAPE.sub(lambda found: "\n" if found.group(1) == "n" else "\\", text)


def parse(path: str, ctx, source: str) -> None:
    source = source if source in SOURCES else "bash"
    host = str(ctx.params.get("host") or "")
    username = str(ctx.params.get("username") or "")
    ctx.source(NAME, VERSION, KIND, source, host=host, username=username)
    blank = undecodable = 0
    stamp: int | None = None
    pending: list[str] = []
    started = (0, 0)  # the line and the offset the command being gathered began at
    offset = 0
    number = 0
    stray = 0
    block: dict | None = None  # the fish command being gathered: its text, line, offset, time and paths

    def give(command: str, line: int, at: int, length: int, when: int | None, extra: dict | None = None) -> None:
        digest = hashlib.sha256(command.encode("utf-8", "replace")).hexdigest()[:16]
        ctx.record(
            key=f"cmd:{source}:{host}:{username}:{line}:{digest}",
            type="command",
            ts=when * 1000 if when is not None else None,
            host=host,
            username=username,
            summary=command[:1000],
            data={"command": command, "program": _program(command), "shell": source, "line": line, **(extra or {})},
            loc={"line": line, "offset": at, "length": length},
        )

    def flush(end: int) -> None:
        nonlocal block, blank
        if block is None:
            return
        if block["command"].strip():
            extra = {"paths": block["paths"]} if block["paths"] else None
            give(block["command"], block["line"], block["at"], end - block["at"], block["when"], extra)
        else:
            blank += 1
        block = None

    with open(path, "rb") as handle:
        for raw in iter(lambda: handle.readline(MAX_LINE + 1), b""):
            number += 1
            at, offset = offset, offset + len(raw)
            if len(raw) > MAX_LINE:
                flush(at)
                ctx.skip("line longer than a megabyte", offset=at, length=len(raw), detail=f"line {number}")
                # The rest of that line, however long it is.
                while not raw.endswith(b"\n"):
                    raw = handle.readline(MAX_LINE)
                    if not raw:
                        break
                    offset += len(raw)
                continue
            try:
                text = raw.decode("utf-8-sig" if number == 1 else "utf-8")
            except UnicodeDecodeError:
                text = raw.decode("utf-8", "replace")
                undecodable += 1
            text = text.rstrip("\r\n")
            if source == "fish":
                found = _FISH_CMD.match(text)
                if found:
                    flush(at)
                    block = {"command": _unescape(found.group(1)), "line": number, "at": at, "when": None, "paths": []}
                    continue
                if not text.strip():
                    blank += 1
                    continue
                found = _FISH_WHEN.match(text)
                if found and block is not None:
                    block["when"] = int(found.group(1))
                elif block is not None and (found := _FISH_PATH.match(text)):
                    block["paths"].append(_unescape(found.group(1)))
                elif not (block is not None and text.strip() == "paths:"):
                    stray += 1
                continue
            if not pending:
                started = (number, at)
                if source == "bash":
                    found = _BASH_TIME.fullmatch(text)
                    if found:
                        stamp = int(found.group(1))
                        continue
                if not text.strip():
                    blank += 1
                    continue
            if (source == "powershell" and text.endswith("`")) or (source == "zsh" and text.endswith("\\")):
                pending.append(text[:-1] if source == "zsh" else text)
                continue
            command = "\n".join([*pending, text])
            pending = []
            when = stamp
            if source == "zsh":
                found = _ZSH.fullmatch(command)
                if found:
                    when, command = int(found.group(1)), found.group(2)
            give(command, started[0], started[1], offset - started[1], when)
            stamp = None
    flush(offset)
    if pending:
        give("\n".join(pending), started[0], started[1], offset - started[1], stamp)
    if blank:
        ctx.note("blank line", count=blank)
    if stray:
        ctx.note(
            "line that belongs to no command", count=stray, detail="a fish history line that is not cmd, when or paths"
        )
    if undecodable:
        ctx.note("line with bytes that are not UTF-8", count=undecodable, detail="kept with replacement characters")
    if source == "powershell" and ctx.read:
        ctx.note("no time", count=ctx.read, detail="a PowerShell history keeps none: the commands are in file order")
    ctx.end()


def view(path: str, source: str, loc: dict) -> dict:
    """The lines of the command (``loc`` has its line, offset and length), with five lines before and after."""
    return viewing.text_around(
        path, viewing.loc_int(loc, "offset"), viewing.loc_int(loc, "length"), viewing.loc_int(loc, "line")
    )

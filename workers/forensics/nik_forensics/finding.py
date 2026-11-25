"""Whole-file search for the source viewer: where a text or some bytes sit in an original of any size.

``find(path, needle, how, start, limit, deadline)`` reads the file from ``start`` in blocks of ``BLOCK`` bytes,
never more than one block and a short tail of the one before in memory (an original may be 20 GB). A match is
told by where it starts; the tail kept between two blocks is as long as the longest match minus one byte, so a
match across the edge of two blocks is found once, and every start is judged when it has all its bytes in view.

    how == "text"   the needle as UTF-8 and as UTF-16LE (the strings of an EVTX), a letter in either case
    how == "hex"    the needle is bytes, written as hex digits (spaces allowed), exact

The answer is ``{"matches": [{"offset", "length", "encoding"}], "next", "scanned", "cut"}``: ``next`` is where a
following call goes on (None at the end of the file) and ``cut`` says the limit or the clock stopped it before
the end. Nothing is run and nothing but the file is read. Standard library only.
"""

from __future__ import annotations

import re
import time
from typing import Any

BLOCK = 1024 * 1024
MIN_TEXT, MAX_TEXT = 2, 256
MAX_HEX_BYTES = 128
MAX_LIMIT = 200
ENCODINGS = (("utf-8", "utf-8"), ("utf-16le", "utf-16-le"))


class BadNeedle(ValueError):
    """The needle cannot be searched for; the message says why, in a sentence."""


def hex_needle(text: str) -> bytes:
    digits = "".join(text.split())
    if not digits or len(digits) % 2 or any(c not in "0123456789abcdefABCDEF" for c in digits):
        raise BadNeedle("The needle must be whole bytes written as hex digits (spaces allowed)")
    if len(digits) // 2 > MAX_HEX_BYTES:
        raise BadNeedle(f"The needle may be at most {MAX_HEX_BYTES} bytes")
    return bytes.fromhex(digits)


def _variants(char: str) -> set[str]:
    """The characters that count as ``char`` when the case does not: itself, and its lower and upper case when
    that is one character too (a letter that becomes two, as the German sharp s does, is left as it is)."""
    return {v for v in (char, char.lower(), char.upper()) if len(v) == 1}


def _pattern(text: str, codec: str) -> tuple[re.Pattern[bytes], int]:
    """A regular expression over bytes for the text in one encoding, and the length of its longest match."""
    parts: list[bytes] = []
    longest = 0
    for char in text:
        coded = sorted({v.encode(codec) for v in _variants(char)})
        longest += max(len(c) for c in coded)
        parts.append(re.escape(coded[0]) if len(coded) == 1 else b"(?:" + b"|".join(re.escape(c) for c in coded) + b")")
    # A lookahead, so that matches which overlap (``aa`` in ``aaa``) are all told.
    return re.compile(b"(?=(" + b"".join(parts) + b"))", re.DOTALL), longest


def patterns(needle: str, how: str) -> list[tuple[str, re.Pattern[bytes], int]]:
    """``(encoding, pattern, longest match)`` for each way the needle is looked for; ``BadNeedle`` when it is bad."""
    if how == "hex":
        raw = hex_needle(needle)
        return [("hex", re.compile(b"(?=(" + re.escape(raw) + b"))", re.DOTALL), len(raw))]
    if how != "text":
        raise BadNeedle('"as" must be "text" or "hex"')
    if not MIN_TEXT <= len(needle) <= MAX_TEXT:
        raise BadNeedle(f"The needle must be {MIN_TEXT} to {MAX_TEXT} characters")
    try:
        needle.encode("utf-16-le")
    except UnicodeEncodeError:
        raise BadNeedle("The needle holds a character that cannot be written in UTF-8") from None
    return [(name, *_pattern(needle, codec)) for name, codec in ENCODINGS]


def check(needle: Any, how: Any, start: Any, limit: Any) -> None:
    """The shape of the request: ``BadNeedle`` with a sentence when it is not one."""
    if not isinstance(needle, str):
        raise BadNeedle("The needle must be a text")
    if isinstance(start, bool) or not isinstance(start, int) or start < 0:
        raise BadNeedle('"from" must be a whole number of at least 0')
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_LIMIT:
        raise BadNeedle(f'"limit" must be a whole number from 1 to {MAX_LIMIT}')
    patterns(needle, str(how))


def find(
    path: str,
    needle: str,
    how: str,
    start: int = 0,
    limit: int = 100,
    deadline: float | None = None,
    block: int = BLOCK,
) -> dict[str, Any]:
    """Where the needle is in the file from ``start`` on. ``deadline`` is a ``time.monotonic()`` value after
    which no further block is begun (the answer then carries ``next``); one block is always read."""
    found = patterns(needle, how)
    keep = max(length for _name, _re, length in found) - 1  # the tail a match of the longest kind may straddle
    block = max(block, keep + 1)  # a block shorter than the tail would never get past its start
    matches: list[dict[str, Any]] = []
    carry = b""
    position = start  # the file offset of the next byte to read
    with open(path, "rb") as handle:
        handle.seek(start)
        while True:
            fresh = handle.read(block)
            data = carry + fresh
            base = position - len(carry)  # the file offset of data[0]
            position += len(fresh)
            at_end = len(fresh) < block  # a regular file gives a whole block until its end
            # Starts below this have every byte a match can have in view; at the end all of them do.
            safe = len(data) if at_end else len(data) - keep
            batch: list[dict[str, Any]] = []
            for name, pattern, _length in found:
                taken = 0
                for hit in pattern.finditer(data):
                    if hit.start() >= safe:
                        break
                    batch.append({"offset": base + hit.start(), "length": len(hit.group(1)), "encoding": name})
                    taken += 1
                    if taken > limit:
                        break
            batch.sort(key=lambda m: (m["offset"], m["length"]))
            matches.extend(batch[: limit + 1 - len(matches)])
            if len(matches) > limit:
                return {
                    "matches": matches[:limit],
                    "next": matches[limit]["offset"],
                    "scanned": position - start,
                    "cut": True,
                }
            if at_end:
                return {"matches": matches, "next": None, "scanned": position - start, "cut": False}
            carry = data[max(safe, 0) :]  # the starts not judged yet
            if deadline is not None and time.monotonic() >= deadline:
                return {"matches": matches, "next": position - len(carry), "scanned": position - start, "cut": True}

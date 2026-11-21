"""Checking the chain of an audit log: format 1.

This module needs Python 3.10 and nothing else, and nothing of Nik: it can be
copied out and run alone, on another machine, against what left the server::

    python verifier.py EXPORT                      an export of the log
    python verifier.py EXPORT --syslog CAPTURE     ... held against what the receiver got
    python verifier.py --syslog CAPTURE            what the receiver got, alone
    python verifier.py EXPORT --head SEQ:HASH      ... held against a head noted elsewhere
    python verifier.py EXPORT --keys FILE          ... and the signatures checked with the keys of FILE

``EXPORT`` is what ``python -m app.auditlog export`` prints (one JSON object
a line) or what ``GET /api/audit`` answers. ``CAPTURE`` is a file of the
syslog receiver: one message a line, with anything before the JSON object
Nik sent (the receiver's own prefix is skipped). It exits 0 when everything
holds, 1 when something does not, 2 when it was called wrongly.

**An entry** has eight fields, each a text or nothing: ``id``, ``at``,
``actor``, ``action``, ``target``, ``details``, ``incident_id``,
``incident_name`` (``incidentId`` and ``incidentName`` in the API and in the
messages). The chain adds three: ``seq``, the number of the entry, counted
from 1 with no gap; ``prev``, the hash of the entry numbered ``seq - 1``
(sixty-four zeros for the entry numbered 1); ``hash``, its own.

**The canonical form** of an entry is this sequence of bytes, and its hash is
the SHA-256 of them, written as 64 lower-case hexadecimal digits::

    nik-audit-1\\n
    seq <the number in decimal, no sign, no leading zero>\\n
    prev <the 64 digits>\\n
    id <length>:<bytes>\\n
    at <length>:<bytes>\\n
    actor <length>:<bytes>\\n
    action <length>:<bytes>\\n
    target <length>:<bytes>\\n
    details <length>:<bytes>\\n
    incident_id <length>:<bytes>\\n
    incident_name <length>:<bytes>\\n

and, **only for an entry that has an origin**, one more line after them::

    origin <length>:<bytes>\\n

``\\n`` is one byte, 0x0A. ``<bytes>`` is the text in UTF-8, exactly as
stored (no trimming, no normalisation), and ``<length>`` the number of those
bytes in decimal. A field that holds nothing (null, not the empty text) is
written ``<name> -\\n`` instead. Nothing else goes in: the lengths make the
form unambiguous whatever a text contains.

**The origin.** An entry the server wrote itself has none, and its form
ends at ``incident_name``. An entry that came in a file of content from
another server has ``origin`` ``import``: its time, its author and its
sentence are what that file said, and the server vouches only for the moment
it joined the chain (its number). The origin is hashed, so the mark cannot be
taken off unseen.

**The signature.** Beside its hash every entry carries ``mac`` and ``key_id``
(``keyId`` in the API and in the messages). ``mac`` is HMAC-SHA-256, in
hexadecimal, of the bytes ``nik-audit-mac-1\\n<the 64 digits of the hash>\\n``
under a key that is not in the database. ``key_id`` names the key without
giving it away: ``set-`` or ``derived-`` and the first twelve hexadecimal
digits of SHA-256 of ``nik audit key id\\n`` followed by the key. The hashes
are checked by anybody; the signatures only by who holds the key. Give the
keys in a file (``--keys FILE``, one a line) or in the environment variable
``NIK_AUDIT_KEYS`` (separated by commas or line breaks), never on the command
line: a key is a text, taken as its UTF-8 bytes, or ``hex:`` and the bytes
spelled out. Without a key the signatures are **not checked**, and the output
says so. With keys, an entry signed by a key that was not given **cannot be
checked** (said, and not a problem); one that has no signature is
``unsigned``; one whose signature the key it names did not make is ``forged``:
that is what a chain computed again by somebody without the key looks like.

**An entry written outside the server.** The server signs what its own
transactions wrote. An entry it finds in the table without a number (the one
a restore leaves, written with plain SQL; one somebody inserted by hand; one
whose number somebody took away to have it linked again) is linked and
signed too, but marked: its ``origin`` is ``outside``.

**What a chain may contain besides ordinary entries.** They are entries like
the others, told apart by their ``action``:

- ``audit.chain`` says that the entries before it were written before the
  log was chained (Nik before 6.8) and were linked as they were found;
- ``audit.trim`` says that old entries were removed by a rule: its details
  read ``... sequence A to B, up to hash H ...``. A log may then start at
  the entry numbered ``B + 1``, whose ``prev`` must be ``H``;
- ``audit.restore`` says the database was put back from a backup: the
  entries the server wrote between that backup and the restore are not in
  its log any more. A receiver that has them sees the same number arrive
  twice with different content; the second must be this entry.

**What the walk finds**, by name: ``edited`` (the content of an entry is not
what its hash was made of), ``missing`` (numbers that are not there),
``reordered`` (an entry stands at a number it was not written as),
``relinked`` (an entry does not follow the one before it: one of the two was
replaced), ``start`` (the log begins after its first entry and nothing in it
says why), ``cut`` (a head known elsewhere is past the end of the log),
``rewritten`` (an entry known elsewhere has another hash here), ``unsigned``
and ``forged`` (the signature, when keys are given).

A hash chain alone proves that what is there is linked. It cannot show that
the newest entries were removed, nor that the whole log was computed again
from some point: only a head (a number and its hash) kept somewhere else
does, which is what ``--syslog`` and ``--head`` are for.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import sys
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

FORMAT = 1
ZERO = "0" * 64
FIELDS = ("id", "at", "actor", "action", "target", "details", "incident_id", "incident_name")
IMPORTED = "import"
OUTSIDE = "outside"
MAC_LABEL = b"nik-audit-mac-1\n"
KEY_ID_LABEL = b"nik audit key id\n"
# The names the API and the syslog messages use for the two that differ.
_API = {"incident_id": "incidentId", "incident_name": "incidentName"}
CHAINED = "audit.chain"
TRIM = "audit.trim"
RESTORE = "audit.restore"
_HASH = re.compile(r"^[0-9a-f]{64}$")
_TRIMMED = re.compile(r"sequence (\d+) to (\d+), up to hash ([0-9a-f]{64})")


def canonical(seq: int, prev: str, entry: Mapping[str, Any]) -> bytes:
    """The bytes an entry is hashed as (the module docstring is their specification)."""
    lines = [b"nik-audit-1\n", f"seq {int(seq)}\n".encode("ascii"), f"prev {prev}\n".encode("ascii")]
    for name in FIELDS:
        value = entry.get(name)
        if value is None:
            lines.append(f"{name} -\n".encode("ascii"))
            continue
        data = str(value).encode("utf-8", "surrogatepass")
        lines.append(f"{name} {len(data)}:".encode("ascii") + data + b"\n")
    origin = entry.get("origin")
    if origin is not None:
        data = str(origin).encode("utf-8", "surrogatepass")
        lines.append(f"origin {len(data)}:".encode("ascii") + data + b"\n")
    return b"".join(lines)


def entry_hash(seq: int, prev: str, entry: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical(seq, prev, entry)).hexdigest()


def key_bytes(text: str) -> bytes:
    """A key as it is written down: a text (its UTF-8 bytes), or ``hex:`` and the bytes spelled out."""
    text = text.strip()
    if text.startswith("hex:"):
        return bytes.fromhex(text[4:])
    return text.encode("utf-8")


def fingerprint(key: bytes) -> str:
    """The twelve digits that name a key in its id."""
    return hashlib.sha256(KEY_ID_LABEL + key).hexdigest()[:12]


def sign(key: bytes, hashed: str) -> str:
    """The signature of an entry: an HMAC of its hash."""
    return hmac.new(key, MAC_LABEL + hashed.encode("ascii") + b"\n", hashlib.sha256).hexdigest()


def keyring(texts: Iterable[str]) -> dict[str, bytes]:
    """Keys as written down, by fingerprint."""
    keys = [key_bytes(text) for text in texts if text.strip()]
    return {fingerprint(key): key for key in keys}


def signature(entry: Mapping[str, Any], keys: Mapping[str, bytes]) -> str:
    """How the signature of an entry stands against the keys given: ``ok``, ``unknown`` (its key
    is not among them: it cannot be checked), ``unsigned`` or ``forged``."""
    mac, key_id = str(entry.get("mac") or ""), str(entry.get("key_id") or "")
    if not mac:
        return "unsigned"
    key = keys.get(key_id.rsplit("-", 1)[-1])
    if key is None:
        return "unknown"
    return "ok" if hmac.compare_digest(sign(key, str(entry.get("hash") or "")), mac) else "forged"


def _signature_problem(state: str, seq: int) -> Problem:
    if state == "unsigned":
        return Problem(
            "unsigned", seq, f"Entry {seq} carries no signature: it was not written, or was rewritten, without the key"
        )
    return Problem(
        "forged",
        seq,
        f"The signature of entry {seq} was not made with the key it names: it was rewritten without the key",
    )


def normal(raw: Mapping[str, Any]) -> dict[str, Any]:
    """An entry as read from an export, the API or a message, with the names used here."""
    entry: dict[str, Any] = {name: raw.get(name, raw.get(_API.get(name, name))) for name in FIELDS}
    entry["seq"] = raw.get("seq")
    entry["prev"] = raw.get("prev", raw.get("prev_hash"))
    entry["hash"] = raw.get("hash")
    entry["mac"] = raw.get("mac")
    entry["key_id"] = raw.get("key_id", raw.get("keyId"))
    if raw.get("origin") is not None:
        entry["origin"] = raw["origin"]
    if raw.get("truncated"):
        entry["truncated"] = True
    return entry


def trim_details(count: int, first: int, last: int, upto: str, rule: str) -> str:
    """The sentence of an ``audit.trim`` entry: what ``trimmed`` reads back."""
    return f"Removed {count} entries, sequence {first} to {last}, up to hash {upto}, {rule}"


def trimmed(entry: Mapping[str, Any]) -> tuple[int, int, str] | None:
    """What an ``audit.trim`` entry says was removed: first number, last number, the hash of the last."""
    if entry.get("action") != TRIM:
        return None
    found = _TRIMMED.search(str(entry.get("details") or ""))
    return (int(found.group(1)), int(found.group(2)), found.group(3)) if found else None


@dataclass
class Problem:
    kind: str
    seq: int
    text: str

    def out(self) -> dict[str, Any]:
        return {"kind": self.kind, "seq": self.seq, "text": self.text}


class Walk:
    """A chain, fed one entry at a time in the order of its numbers.

    ``after`` resumes after an entry already checked (its number and hash).
    ``locate`` answers the number of the entry that carries a hash, or None:
    it is only asked when something is wrong, to tell a reordering from an edit.
    ``keys`` are the keys the signatures are checked with, by fingerprint; None leaves them
    unchecked. ``signed`` counts the signatures that held, ``unchecked`` the entries whose key
    was not given, by key id.
    The walk stops at the first problem: ``problem`` keeps it.
    """

    def __init__(
        self,
        after: tuple[int, str] | None = None,
        locate: Callable[[str], int | None] | None = None,
        keys: Mapping[str, bytes] | None = None,
    ) -> None:
        self.keys = keys
        self.signed = 0
        self.unchecked: dict[str, int] = {}
        self.count = 0
        self.first_seq: int | None = None
        self.last_seq, self.last_hash = after if after else (0, ZERO)
        self.problem: Problem | None = None
        self._resumed = after is not None
        self._locate = locate
        self._anchor: tuple[int, str] | None = None
        self._trims: set[tuple[int, str]] = set()

    def _fail(self, kind: str, seq: int, text: str) -> Problem:
        self.problem = Problem(kind, seq, text)
        return self.problem

    def feed(self, entry: Mapping[str, Any]) -> Problem | None:
        if self.problem is not None:
            return self.problem
        seq, prev, held = entry.get("seq"), str(entry.get("prev") or ""), str(entry.get("hash") or "")
        if not isinstance(seq, int) or isinstance(seq, bool) or seq < 1:
            return self._fail("edited", int(self.last_seq) + 1, "An entry has no number in the chain")
        first = self.first_seq is None
        if first and not self._resumed:
            if seq == 1:
                if prev != ZERO:
                    return self._fail("relinked", 1, "Entry 1 does not start the chain: it names an entry before it")
            else:
                # To be accounted for by an audit.trim entry further on.
                self._anchor = (seq, prev)
        elif seq != self.last_seq + 1:
            if seq > self.last_seq + 1:
                gone = seq - self.last_seq - 1
                return self._fail(
                    "missing",
                    self.last_seq + 1,
                    f"{gone} {'entry is' if gone == 1 else 'entries are'} missing: "
                    f"{self.last_seq + 1}{'' if gone == 1 else f' to {seq - 1}'} "
                    f"(after entry {self.last_seq} comes entry {seq})",
                )
            return self._fail("reordered", seq, f"Entry {seq} comes after entry {self.last_seq}")
        linked = first and not self._resumed or prev == self.last_hash
        whole = bool(entry.get("truncated")) or entry_hash(seq, prev, entry) == held
        if not whole or not linked:
            was = self._written_as(entry, seq, prev, held)
            if was is not None:
                return self._fail(
                    "reordered", seq, f"Entry {seq} was written as entry {was}: the order of the log was changed"
                )
        if not whole:
            return self._fail("edited", seq, f"The content of entry {seq} was changed after it was written")
        if not linked:
            return self._fail(
                "relinked",
                seq,
                f"Entry {seq} does not follow entry {seq - 1}: one of the two was replaced",
            )
        if self.keys is not None:
            state = signature(entry, self.keys)
            if state in ("unsigned", "forged"):
                self.problem = _signature_problem(state, seq)
                return self.problem
            if state == "ok":
                self.signed += 1
            else:
                name = str(entry.get("key_id") or "")
                self.unchecked[name] = self.unchecked.get(name, 0) + 1
        if first:
            self.first_seq = seq
        found = trimmed(entry)
        if found is not None:
            self._trims.add((found[1], found[2]))
        self.last_seq, self.last_hash = seq, held
        self.count += 1
        return None

    def _written_as(self, entry: Mapping[str, Any], seq: int, prev: str, held: str) -> int | None:
        """The number an entry was written as, when it is not the one it stands at."""
        if self._locate is None or not _HASH.match(prev):
            return None
        before = self._locate(prev)
        if before is None or before + 1 == seq:
            return None
        return before + 1 if entry_hash(before + 1, prev, entry) == held else None

    def finish(self) -> Problem | None:
        """Call once everything was fed: a log that starts after its first entry must say why."""
        if self.problem is None and self._anchor is not None:
            seq, prev = self._anchor
            if (seq - 1, prev) not in self._trims:
                self._fail(
                    "start",
                    1,
                    f"The log starts at entry {seq} and no entry says that the {seq - 1} before it were removed",
                )
        return self.problem


def check(entries: Iterable[Mapping[str, Any]], keys: Mapping[str, bytes] | None = None) -> Walk:
    """Walk a whole log, in any order: the entries that are not chained yet are left out."""
    chained = [entry for entry in map(normal, entries) if isinstance(entry.get("seq"), int)]
    chained.sort(key=lambda entry: entry["seq"])
    where: dict[str, int] = {}
    for entry in chained:
        where.setdefault(str(entry.get("hash") or ""), entry["seq"])
    walk = Walk(locate=where.get, keys=keys)
    for entry in chained:
        if walk.feed(entry) is not None:
            break
    walk.finish()
    return walk


# --------------------------------------------------------------------------- #
# What a receiver got                                                         #
# --------------------------------------------------------------------------- #
_MARK = '{"nik":'


def message(line: str) -> dict[str, Any] | None:
    """The object Nik sent in a line of a receiver's file, or None when the line holds none."""
    start = line.find(_MARK)
    if start < 0:
        return None
    try:
        found, _end = json.JSONDecoder().raw_decode(line[start:])
    except ValueError:
        return None
    return found if isinstance(found, dict) else None


@dataclass
class Capture:
    """What a receiver holds, read in the order it arrived."""

    chain: dict[int, str] = field(default_factory=dict)  # number → hash, of what stands
    problems: list[Problem] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    gaps: list[tuple[int, int]] = field(default_factory=list)
    checkpoint: tuple[int, str] | None = None  # the latest head the server announced
    messages: int = 0
    repeated: int = 0
    signed: int = 0
    unchecked: dict[str, int] = field(default_factory=dict)

    @property
    def head(self) -> tuple[int, str] | None:
        if not self.chain:
            return None
        last = max(self.chain)
        return last, self.chain[last]


def read_capture(lines: Iterable[str], keys: Mapping[str, bytes] | None = None) -> Capture:
    """Check the messages of a receiver's file. A message that arrives twice is normal (the
    server sends again what it is not sure arrived); a number that arrives with another
    content is a rewriting, unless it is the entry a restore leaves."""
    found = Capture()
    trims: set[tuple[int, str]] = set()
    for line in lines:
        sent = message(line)
        if sent is None:
            continue
        if sent.get("nik") == "checkpoint":
            seq, held = sent.get("seq"), str(sent.get("hash") or "")
            if isinstance(seq, int) and _HASH.match(held):
                found.checkpoint = (seq, held)
                if seq in found.chain and found.chain[seq] != held:
                    found.problems.append(
                        Problem("rewritten", seq, f"A checkpoint names another hash for entry {seq} than the entry had")
                    )
            continue
        if sent.get("nik") != "audit":
            continue
        entry = normal(sent)
        seq, prev, held = entry.get("seq"), str(entry.get("prev") or ""), str(entry.get("hash") or "")
        if not isinstance(seq, int) or not _HASH.match(held):
            continue
        found.messages += 1
        if found.chain.get(seq) == held:
            found.repeated += 1
            continue
        if not entry.get("truncated") and entry_hash(seq, prev, entry) != held:
            found.problems.append(
                Problem("edited", seq, f"The content of entry {seq} is not what its hash was made of")
            )
            continue
        if keys is not None:
            state = signature(entry, keys)
            if state in ("unsigned", "forged"):
                found.problems.append(_signature_problem(state, seq))
                continue
            if state == "ok":
                found.signed += 1
            else:
                name = str(entry.get("key_id") or "")
                found.unchecked[name] = found.unchecked.get(name, 0) + 1
        if seq in found.chain:
            follows = found.chain.get(seq - 1) in (None, prev)
            if entry.get("action") == RESTORE and follows:
                lost = [number for number in found.chain if number >= seq]
                found.notes.append(
                    f"The server was restored from a backup at entry {seq}: the {len(lost)} "
                    f"{'entry' if len(lost) == 1 else 'entries'} it had sent from that number on exist only here"
                )
                for number in lost:
                    del found.chain[number]
            else:
                found.problems.append(Problem("rewritten", seq, f"Entry {seq} arrived twice with different content"))
                continue
        if seq - 1 in found.chain and found.chain[seq - 1] != prev:
            found.problems.append(
                Problem("relinked", seq, f"Entry {seq} does not follow the entry {seq - 1} that arrived before it")
            )
            continue
        cut = trimmed(entry)
        if cut is not None:
            trims.add((cut[1], cut[2]))
        found.chain[seq] = held
    numbers = sorted(found.chain)
    for before, after in zip(numbers, numbers[1:], strict=False):
        if after != before + 1:
            found.gaps.append((before + 1, after - 1))
    return found


def compare(walk: Walk, held: dict[int, str], capture: Capture) -> list[Problem]:
    """Hold a log (its walk, and the hash of each of its entries) against what a receiver got."""
    problems: list[Problem] = []
    for seq in sorted(capture.chain):
        here = held.get(seq)
        if here is not None and here != capture.chain[seq]:
            problems.append(
                Problem("rewritten", seq, f"Entry {seq} is not the entry the receiver got: the log was rewritten")
            )
            break
    heads = [head for head in (capture.head, capture.checkpoint) if head is not None]
    for seq, hashed in heads:
        if seq > walk.last_seq:
            problems.append(
                Problem(
                    "cut",
                    walk.last_seq + 1,
                    f"The receiver knows the log up to entry {seq} and it ends at entry {walk.last_seq}: "
                    f"the newest {seq - walk.last_seq} were removed",
                )
            )
            break
        if seq not in capture.chain and held.get(seq) not in (None, hashed):
            problems.append(
                Problem("rewritten", seq, f"Entry {seq} is not the head the server announced: the log was rewritten")
            )
            break
    return problems


def against_head(walk: Walk, held: Callable[[int], str | None], seq: int, hashed: str, where: str) -> Problem | None:
    """Hold a log against one head noted elsewhere (``where`` names the place, for the sentence)."""
    if seq > walk.last_seq:
        gone = seq - walk.last_seq
        return Problem(
            "cut",
            walk.last_seq + 1,
            f"{where} knows the log up to entry {seq} and it ends at entry {walk.last_seq}: the newest "
            f"{gone} {'entry was' if gone == 1 else 'entries were'} removed",
        )
    here = held(seq)
    if here is not None and here != hashed:
        return Problem(
            "rewritten", seq, f"Entry {seq} has another hash than the one {where} holds: the log was rewritten"
        )
    return None


# --------------------------------------------------------------------------- #
# The command                                                                 #
# --------------------------------------------------------------------------- #
def read_export(text: str) -> list[dict[str, Any]]:
    """The entries of an export: a JSON document (a list, or an object with ``entries``), or one object a line."""
    text = text.lstrip("﻿").strip()
    if not text:
        return []
    try:
        whole = json.loads(text)
    except ValueError:
        whole = [json.loads(line) for line in text.splitlines() if line.strip()]
    if isinstance(whole, dict):
        whole = whole.get("entries", [whole] if "seq" in whole else [])
    return [entry for entry in whole if isinstance(entry, dict)]


def _head(text: str) -> tuple[int, str]:
    seq, _, hashed = text.partition(":")
    if not seq.isdigit() or not _HASH.match(hashed):
        raise argparse.ArgumentTypeError("a head is written SEQ:HASH, the hash as 64 hexadecimal digits")
    return int(seq), hashed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="verifier.py", description="Check the chain of an audit log of Nik.")
    parser.add_argument("export", nargs="?", help="an export of the log (JSON, or one JSON object a line)")
    parser.add_argument("--syslog", help="a file of the syslog receiver, one message a line")
    parser.add_argument("--head", type=_head, help="a head noted elsewhere, as SEQ:HASH")
    parser.add_argument("--keys", help="a file of the keys the signatures are checked with, one a line")
    args = parser.parse_args(argv)
    if not args.export and not args.syslog:
        parser.error("give an export, a file of the receiver, or both")
    given = os.environ.get("NIK_AUDIT_KEYS", "").replace(",", "\n").splitlines()
    if args.keys:
        with open(args.keys, encoding="utf-8") as source:
            given += source.read().splitlines()
    keys = keyring(given) if any(text.strip() for text in given) else None

    def signatures(where: str, signed: int, unchecked: dict[str, int]) -> None:
        if keys is None:
            print(f"{where}: signatures not checked: no key")
            return
        print(f"{where}: {signed} signatures hold")
        for name, count in sorted(unchecked.items()):
            print(f"{where}: {count} cannot be checked: the key {name or '(none named)'} was not given")

    problems: list[Problem] = []
    walk, held = None, {}
    if args.export:
        with open(args.export, encoding="utf-8") as source:
            entries = [normal(entry) for entry in read_export(source.read())]
        waiting = sum(1 for entry in entries if not isinstance(entry.get("seq"), int))
        walk = check(entries, keys)
        held = {entry["seq"]: str(entry.get("hash") or "") for entry in entries if isinstance(entry.get("seq"), int)}
        print(
            f"export: {walk.count} entries hold together, from {walk.first_seq or 0} to {walk.last_seq}"
            + (f"; {waiting} not chained yet" if waiting else "")
        )
        if walk.last_seq:
            print(f"export: head {walk.last_seq}:{walk.last_hash}")
        signatures("export", walk.signed, walk.unchecked)
        if walk.problem is not None:
            problems.append(walk.problem)
    capture = None
    if args.syslog:
        with open(args.syslog, encoding="utf-8", errors="replace") as source:
            capture = read_capture(source, keys)
        print(
            f"syslog: {len(capture.chain)} entries, {capture.repeated} received more than once"
            + (f", head {capture.head[0]}:{capture.head[1]}" if capture.head else "")
        )
        if capture.checkpoint:
            print(f"syslog: last checkpoint {capture.checkpoint[0]}:{capture.checkpoint[1]}")
        for first, last in capture.gaps:
            print(f"syslog: entries {first} to {last} never arrived")
        for note in capture.notes:
            print(f"syslog: {note}")
        signatures("syslog", capture.signed, capture.unchecked)
        problems += capture.problems
    if walk is not None and walk.problem is None:
        if capture is not None:
            problems += compare(walk, held, capture)
        if args.head:
            found = against_head(walk, held.get, args.head[0], args.head[1], "The head given")
            if found is not None:
                problems.append(found)
    for problem in problems:
        print(f"PROBLEM ({problem.kind}, entry {problem.seq}): {problem.text}")
    if not problems:
        print("Everything holds.")
        if capture is None and not args.head:
            print(
                "Nothing outside the log was given to hold it against: entries removed from its end, "
                "or a log computed again from some point, would not show here."
            )
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())

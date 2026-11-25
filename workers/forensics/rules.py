"""The rule sets the backend gives the worker: ``PUT /rules/<sha256>``, the body one rule per line (NDJSON).

The backend holds the rules and the worker only evaluates them: a set is named by the SHA-256 of its bytes, kept
in a folder of the worker's own (``<work>/rules/<digest>.ndjson``) while it is used, and the least recently used
are deleted when there are more than ``keep`` (never one a job is running with). A request for a set the worker
does not hold is answered ``409`` with ``missingRules``; the backend sends it and asks again.

A line is ``{"id", "title", "level", "kind": "rule"|"correlation", "product", "category", "service", "source"}``;
the worker only checks here that each is a JSON object with an ``id`` and a ``source`` (what the YAML says is
read in a job: ``nik_forensics/sigma``). Standard library only.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading

import given

MAX_BYTES = 96 * 1024 * 1024
MAX_LINE = 2 * 1024 * 1024
DIGEST = re.compile(r"^[0-9a-f]{64}$")


class _Held:
    def __init__(self, sets: RuleSets, digest: str | None) -> None:
        self.sets, self.digest = sets, digest

    def __enter__(self) -> None:
        if self.digest:
            with self.sets._lock:
                self.sets._busy[self.digest] = self.sets._busy.get(self.digest, 0) + 1

    def __exit__(self, *_exc) -> None:
        if self.digest:
            with self.sets._lock:
                self.sets._busy[self.digest] -= 1
                if not self.sets._busy[self.digest]:
                    del self.sets._busy[self.digest]


class RuleSets:
    def __init__(self, folder: str, keep: int = 3) -> None:
        self.folder, self.keep = os.path.join(folder, "rules"), keep
        self._lock = threading.Lock()
        self._busy: dict[str, int] = {}

    def _file(self, digest: str) -> str:
        return os.path.join(self.folder, f"{digest}.ndjson")

    def clear(self) -> None:
        """What a stopped worker left is not kept."""
        if os.path.isdir(self.folder):
            for name in os.listdir(self.folder):
                try:
                    os.unlink(os.path.join(self.folder, name))
                except OSError:
                    continue

    def path(self, digest: str) -> str | None:
        """Where the set is, or None when the worker does not hold it. Asking marks it as used."""
        if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
            return None
        path = self._file(digest)
        try:
            os.utime(path)
        except OSError:
            return None
        return path

    def hold(self, digest: str | None) -> _Held:
        """While the block runs the set is not deleted to make room for another."""
        return _Held(self, digest)

    def put(self, digest: str, stream, length: int) -> int:
        """Take ``length`` bytes of ``stream`` as the set ``digest``; the number of rules. ``given.Refused``
        (400 for a body that is not what its name says or not a rule set, 413 for one too large)."""
        if not DIGEST.fullmatch(digest):
            raise given.Refused(400, "The name of a rule set is the SHA-256 of its content (64 hexadecimal digits)")
        if length < 0 or length > MAX_BYTES:
            raise given.Refused(413, "The rule set is larger than the worker takes")
        body = stream.read(length)
        if len(body) != length:
            raise given.Refused(400, "The rule set stopped before its end")
        if hashlib.sha256(body).hexdigest() != digest:
            raise given.Refused(400, "The rule set is not the one its name says: its SHA-256 is another")
        count = 0
        for number, line in enumerate(body.split(b"\n"), start=1):
            if not line.strip():
                continue
            if len(line) > MAX_LINE:
                raise given.Refused(400, f"Line {number} of the rule set is longer than {MAX_LINE} bytes")
            try:
                rule = json.loads(line)
            except ValueError:
                raise given.Refused(400, f"Line {number} of the rule set is not JSON") from None
            if (
                not isinstance(rule, dict)
                or not isinstance(rule.get("id"), str)
                or not isinstance(rule.get("source"), str)
            ):
                raise given.Refused(400, f"Line {number} of the rule set is not a rule: it needs an id and a source")
            count += 1
        os.makedirs(self.folder, exist_ok=True)
        part = os.path.join(self.folder, f"incoming-{os.getpid()}-{threading.get_ident()}")
        try:
            with open(part, "wb") as out:
                out.write(body)
            with self._lock:
                os.replace(part, self._file(digest))
                self._evict(digest)
        finally:
            if os.path.exists(part):
                os.unlink(part)
        return count

    def _evict(self, keep_digest: str) -> None:
        held = []
        for name in os.listdir(self.folder):
            if name.endswith(".ndjson"):
                path = os.path.join(self.folder, name)
                try:
                    held.append((os.path.getmtime(path), name[: -len(".ndjson")], path))
                except OSError:
                    continue
        held.sort(reverse=True)
        for _used, digest, path in held[self.keep :]:
            if digest != keep_digest and digest not in self._busy:
                try:
                    os.unlink(path)
                except OSError:
                    continue

"""What the worker says a file matched becomes rows (``evidence_detections``).

While a file is read the worker follows the ``r`` line of a record with one ``det`` line for each rule
that matched it, and writes the correlations, which need the whole file, just before ``end``. A ``det``
names the record by its key. The rows are written after each batch of records is stored (a record that
another file of the incident held first is that file's row, and the detection goes to it), and the
highest level of a record's detections is kept on the record.

What the rule said of itself when it matched (title, author, level, tags) is copied to the row: a
rule changed or removed later does not change what was found.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import update
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.orm import Session as OrmSession

from ..core.models import LEVELS, EvidenceDetection, EvidenceRecord
from ..core.security import now_iso
from .checking import LEVEL_NAMES
from .ruleset import Set

CHUNK = 500
PENDING_MAX = 20_000  # det lines held before they are written, whatever the size of the batch
RECORDS_MAX = 50  # the keys of the records of a correlation that are kept
TOP = 20  # the rules a report and an event name


class Detected:
    """The detections of one reading: collected as they come, written when asked, counted for the report."""

    def __init__(self, found: Set | None, incident_id: str):
        self.set = found
        self.incident_id = incident_id
        self.pending: list[dict[str, Any]] = []
        self.counts: dict[str, int] = {}  # rule id → how many records it matched
        self.by_level = dict.fromkeys(range(1, 6), 0)
        self.unknown = 0
        self.unplaced = 0

    def __bool__(self) -> bool:
        return self.set is not None

    @property
    def total(self) -> int:
        return sum(self.counts.values())

    def add(self, event: dict[str, Any]) -> None:
        """A ``det`` line of the worker."""
        key, rule = event.get("key"), event.get("rule")
        if self.set is None or not isinstance(key, str) or not isinstance(rule, str):
            return
        records = [item for item in (event.get("records") or []) if isinstance(item, str)][:RECORDS_MAX]
        self.pending.append({"key": key, "rule": rule[:64], "records": records})

    def full(self) -> bool:
        return len(self.pending) >= PENDING_MAX

    def write(self, db: OrmSession) -> None:
        """Write what is held (the caller commits). The records they name are stored by now."""
        if not self.pending or self.set is None:
            self.pending = []
            return
        held, self.pending = self.pending, []
        placed = _ids(db, self.incident_id, {item["key"] for item in held})
        table = EvidenceDetection.__table__
        insert = postgresql.insert if db.get_bind().dialect.name == "postgresql" else sqlite.insert
        rows: list[dict[str, Any]] = []
        seen: set[tuple[int, str]] = set()
        now = now_iso()
        for item in held:
            record_id = placed.get(item["key"])
            meta = self.set.meta.get(item["rule"])
            if record_id is None:
                self.unplaced += 1
                continue
            if meta is None:
                self.unknown += 1
                continue
            if (record_id, item["rule"]) in seen:
                continue
            seen.add((record_id, item["rule"]))
            rows.append(
                {
                    "incident_id": self.incident_id,
                    "record_id": record_id,
                    "rule_id": item["rule"],
                    "rule_title": str(meta["title"])[:300],
                    "rule_author": str(meta["author"])[:300],
                    "level": int(meta["level"]),
                    "tags": meta["tags"],
                    "records": item["records"],
                    "created_at": now,
                }
            )
        if not rows:
            return
        stored: list[tuple[int, str, int]] = []
        for start in range(0, len(rows), CHUNK):
            answer = db.execute(
                insert(table)
                .on_conflict_do_nothing(index_elements=["record_id", "rule_id"])
                .returning(table.c.record_id, table.c.rule_id, table.c.level),
                rows[start : start + CHUNK],
            )
            stored.extend((record_id, rule_id, level) for record_id, rule_id, level in answer.all())
        top: dict[int, int] = {}
        for record_id, rule_id, level in stored:
            self.counts[rule_id] = self.counts.get(rule_id, 0) + 1
            self.by_level[level] = self.by_level.get(level, 0) + 1
            top[record_id] = max(top.get(record_id, 0), level)
        _raise(db, top)

    def report(self) -> dict[str, Any]:
        """The detections of a source's parse report: ``{"total", "byLevel", "rules"}``."""
        return {
            "total": self.total,
            "byLevel": {str(level): self.by_level.get(level, 0) for level in range(1, 6)},
            "rules": self.top(),
        }

    def top(self, most: int = TOP) -> list[dict[str, Any]]:
        """The rules that matched most, with their count: ``[{"id", "title", "level", "count"}]``."""
        meta = self.set.meta if self.set is not None else {}
        ranked = sorted(
            self.counts,
            key=lambda rule: (-self.counts[rule], -meta[rule]["level"], rule),
        )
        return [
            {
                "id": rule,
                "title": meta[rule]["title"],
                "level": meta[rule]["level"],
                "count": self.counts[rule],
            }
            for rule in ranked[:most]
        ]

    def highest(self) -> int:
        return max((level for level, n in self.by_level.items() if n), default=0)


def _ids(db: OrmSession, incident_id: str, keys: set[str]) -> dict[str, int]:
    """The ids of the records of the incident with these keys, whichever file of the incident holds them."""
    from sqlalchemy import select

    out: dict[str, int] = {}
    wanted = sorted(keys)
    for start in range(0, len(wanted), CHUNK):
        found = db.execute(
            select(EvidenceRecord.key, EvidenceRecord.id).where(
                EvidenceRecord.incident_id == incident_id,
                EvidenceRecord.key.in_(wanted[start : start + CHUNK]),
            )
        )
        out.update(found.all())
    return out


def _raise(db: OrmSession, top: dict[int, int]) -> None:
    """Keep on each record the highest level of its detections."""
    by_level: dict[int, list[int]] = {}
    for record_id, level in top.items():
        by_level.setdefault(level, []).append(record_id)
    record = EvidenceRecord
    for level, ids in by_level.items():
        for start in range(0, len(ids), CHUNK):
            db.execute(
                update(record)
                .where(
                    record.id.in_(ids[start : start + CHUNK]),
                    (record.level.is_(None)) | (record.level < level),
                )
                .values(level=level)
            )


def sentence(file_name: str, found: Detected) -> str | None:
    """The line the War Room keeps of a file with detections of level medium or more, or None."""
    shown = [(level, found.by_level.get(level, 0)) for level in (5, 4, 3)]
    total = sum(n for _level, n in shown)
    if not total:
        return None
    parts = ", ".join(f"{n} {LEVEL_NAMES[level]}" for level, n in shown if n)
    text = f"{file_name}: {total} detection{'' if total == 1 else 's'} ({parts})."
    loud = [rule for rule in found.top(len(found.counts)) if rule["level"] >= LEVELS["medium"]][:3]
    if loud:
        text += " The most frequent: " + "; ".join(f"{rule['title']} ({rule['count']})" for rule in loud) + "."
    return text

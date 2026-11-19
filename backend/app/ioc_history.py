"""The history of a watch list: what its checks found, and which verdicts changed.

When a bulk check is of a whole list (started from the library, or by the
playbook that checks the watched lists again), the verdict of each of its
indicators is noted as the check starts. When the check ends, each is
compared with what the sources say now: the list gets a line of history
(how many indicators, how many changed, how many of each verdict) and a row
for each indicator whose verdict changed.

``ioc.verdict_changed`` is published for a playbook where a verdict changes
(``enrichment/service._announce_verdict``): this module only keeps, for the
people who read a list, what a check of it changed.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.orm import Session as OrmSession

from .core.models import IocCheck, IocList, IocListHistory, IocVerdictChange
from .core.security import now_iso

HISTORY_KEPT = 200  # lines of history a list keeps
HISTORY_SHOWN = 20
CHANGES_SHOWN = 500
BAD = ("malicious", "suspicious")
RANK = {"": 0, "unknown": 0, "harmless": 1, "suspicious": 2, "malicious": 3}


def _key(kind: str, value: str) -> str:
    return f"{kind}|{value}"


def verdicts(db: OrmSession, pairs: list[tuple[str, str]]) -> dict[str, str]:
    """What the sources say of each indicator now, taken together ("" when nobody answered)."""
    from .enrichment import service

    found = service.summaries(db, pairs) if pairs else {}
    return {_key(kind, value): ((found.get((kind, value)) or {}).get("verdict") or "") for kind, value in pairs}


def begin(db: OrmSession, check: IocCheck, target: IocList) -> None:
    """Note that a check is of this list, and what each of its indicators is now (the caller commits)."""
    check.list_id = target.id
    check.baseline = verdicts(db, [(str(kind), str(value)) for kind, value in check.items or []])


def finish(db: OrmSession, check: IocCheck) -> IocListHistory | None:
    """A check of a list ended: write what it found and what changed (the caller commits). Nothing for a
    check that is not of a list, or whose list is gone, or that was written already."""
    if not check.list_id or check.baseline is None:
        return None
    target = db.get(IocList, check.list_id)
    if target is None:
        return None
    if db.scalar(select(IocListHistory.id).where(IocListHistory.check_id == check.id)) is not None:
        return None
    pairs = [(str(kind), str(value)) for kind, value in check.items or []]
    before = check.baseline if isinstance(check.baseline, dict) else {}
    after = verdicts(db, pairs)
    stamp = now_iso()
    by_verdict: dict[str, int] = {}
    changed = 0
    for kind, value in pairs:
        new = after.get(_key(kind, value), "")
        by_verdict[new or "none"] = by_verdict.get(new or "none", 0) + 1
        old = str(before.get(_key(kind, value), ""))
        # A first answer that says nothing is not a change: nobody knew, and nobody knows.
        if old == new or (RANK.get(old, 0) == 0 and RANK.get(new, 0) == 0):
            continue
        changed += 1
        db.add(
            IocVerdictChange(
                id=uuid.uuid4().hex,
                list_id=target.id,
                check_id=check.id,
                type=kind,
                value=value[:1024],
                old=old,
                new=new,
                at=stamp,
            )  # fmt: skip
        )
    row = IocListHistory(
        id=uuid.uuid4().hex,
        list_id=target.id,
        check_id=check.id,
        checked_at=stamp,
        total=len(pairs),
        changed=changed,
        by_verdict=by_verdict,
    )
    db.add(row)
    check.baseline = None  # written: it is not needed any more
    db.flush()
    # A list keeps its last lines; what the older checks changed goes with them.
    old_lines = db.scalars(
        select(IocListHistory)
        .where(IocListHistory.list_id == target.id)
        .order_by(IocListHistory.checked_at.desc())
        .offset(HISTORY_KEPT)
    ).all()
    for line in old_lines:
        db.execute(delete(IocVerdictChange).where(IocVerdictChange.check_id == line.check_id))
        db.delete(line)
    return row


def summary(changes: list[IocVerdictChange]) -> dict[str, Any]:
    """What a check changed, counted the way a person asks: how many became malicious or suspicious,
    how many cleared (were bad, are not any more)."""
    became = {"malicious": 0, "suspicious": 0}
    cleared = 0
    for change in changes:
        if change.new in BAD and RANK.get(change.new, 0) > RANK.get(change.old, 0):
            became[change.new] += 1
        elif change.old in BAD and change.new not in BAD:
            cleared += 1
    parts = [f"{count} became {verdict}" for verdict, count in became.items() if count]
    if cleared:
        parts.append(f"{cleared} cleared")
    other = len(changes) - sum(became.values()) - cleared
    if other:
        parts.append(f"{other} changed otherwise")
    return {"becameMalicious": became["malicious"], "becameSuspicious": became["suspicious"], "cleared": cleared,
            "text": ", ".join(parts) or "nothing changed"}  # fmt: skip


def out(db: OrmSession, target: IocList) -> dict[str, Any]:
    """The history of a list: its last checks, and what the last one changed."""
    lines = db.scalars(
        select(IocListHistory)
        .where(IocListHistory.list_id == target.id)
        .order_by(IocListHistory.checked_at.desc())
        .limit(HISTORY_SHOWN)
    ).all()
    last = lines[0] if lines else None
    changes = (
        db.scalars(
            select(IocVerdictChange)
            .where(IocVerdictChange.check_id == last.check_id)
            .order_by(IocVerdictChange.type, IocVerdictChange.value)
        ).all()
        if last is not None
        else []
    )
    return {
        "last": (
            {"checkedAt": last.checked_at, "total": last.total, "changed": last.changed, **summary(list(changes))}
            if last is not None
            else None
        ),
        "history": [
            {
                "checkId": line.check_id,
                "checkedAt": line.checked_at,
                "total": line.total,
                "changed": line.changed,
                "byVerdict": line.by_verdict or {},
            }
            for line in lines
        ],
        "changes": [
            {"type": change.type, "value": change.value, "old": change.old, "new": change.new, "at": change.at}
            for change in changes[:CHANGES_SHOWN]
        ],
    }

"""The rules Nik ships: the files of ``pack/`` (the pack ``nik``) and of ``pack_chains/`` (the pack
``nik-process-chains``, the rules of process chains), one rule each.

At start, a rule that is not here is added; one that is here and that nobody changed follows the file
(a release may improve it); one a person changed keeps their text, and ``original`` takes the file's, so
that Reset has it. A rule a release no longer ships goes, unless a person changed it. What Nik ships is
read by the worker like any other rule; without the worker the rules are stored as not checked, and
``recheck.py`` checks them when it answers.
"""

from __future__ import annotations

import logging
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from ..core.models import SigmaRule
from ..core.security import now_iso
from . import checking, rules, worker

logger = logging.getLogger("nik.sigma")
FOLDERS = {rules.NIK: Path(__file__).parent / "pack", "nik-process-chains": Path(__file__).parent / "pack_chains"}
CHECK_SECONDS = 20  # a worker that does not answer must not hold the start of the server


def shipped_by_pack() -> dict[str, tuple[str, str]]:
    """Every rule Nik ships, by id: the pack it is of, and its text."""
    found: dict[str, tuple[str, str]] = {}
    for pack, folder in FOLDERS.items():
        for path in sorted(folder.glob("*.yml")):
            text = path.read_text(encoding="utf-8").replace("\r\n", "\n")
            held = rules.quick(text)
            if held is None:
                logger.warning("The rule %s of the pack %s has no id: it is left out", path.name, pack)
                continue
            found[held["id"]] = (pack, text)
    return found


def shipped() -> dict[str, str]:
    """The rules Nik ships, by id, with their text."""
    return {rule_id: text for rule_id, (_pack, text) in shipped_by_pack().items()}


def seed(db: OrmSession) -> int:
    """Add and bring up to date the rules Nik ships (the caller commits). Returns how many changed."""
    by_pack = shipped_by_pack()
    wanted = {rule_id: text for rule_id, (_pack, text) in by_pack.items()}
    here = {row.id: row for row in db.scalars(select(SigmaRule).where(SigmaRule.id.in_(list(wanted) or [""])))}
    held = {row.id: row for row in db.scalars(select(SigmaRule).where(SigmaRule.pack.in_(list(FOLDERS))))}
    todo = [
        rule_id
        for rule_id, (pack, text) in by_pack.items()
        if rule_id not in here
        or (
            here[rule_id].pack == pack
            and here[rule_id].source.strip() != text.strip()
            and not rules.edited(here[rule_id])
        )
        or (
            here[rule_id].pack == pack
            and rules.edited(here[rule_id])
            and (here[rule_id].original or "").strip() != text.strip()
        )
    ]
    changed = 0
    infos: dict[str, dict] = {}
    engine = ""
    if todo and worker.configured():
        try:
            engine, answered = checking.check([wanted[rule_id] for rule_id in todo], timeout=CHECK_SECONDS)
            for rule_id, held_answer in zip(todo, answered, strict=True):
                found = next(
                    (rule for rule in held_answer["rules"] if str(rule.get("id")) == rule_id),
                    None,
                )
                if found is not None and isinstance(found.get("source"), str):
                    infos[rule_id] = found
        except checking.Unavailable as error:
            logger.warning("The rules of Nik were stored without being checked: %s", error.message)
            engine = ""
    for rule_id in todo:
        text = wanted[rule_id]
        info = infos.get(rule_id)
        used = engine if info is not None else ""
        info = info or rules.quick(text)
        row = here.get(rule_id)
        if row is None:
            rules.add(db, info, used, "nik", pack=by_pack[rule_id][0])
        elif rules.edited(row):
            row.original = text  # what Reset puts back: the file as it is now
        else:
            cols = rules.columns(info, used)
            for key, value in cols.items():
                setattr(row, key, value)
            row.updated_at, row.updated_by, row.original = now_iso(), "nik", None
            if used and not row.supported:
                row.enabled = False
        changed += 1
    for rule_id, row in held.items():
        if rule_id not in wanted and not rules.edited(row):
            db.delete(row)
            changed += 1
    if changed:
        rules.bump(db)
        db.flush()
    return changed

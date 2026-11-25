"""Sigma rules in a content pack (kind ``sigma_rules``, folder ``sigma/``): what ``packs.py`` asks of the rules.

A pack may carry thousands of rules (a rule set of SigmaHQ is about 2,700), so nothing here does a
query or a call to the worker for each rule: the rules a pack names are read in chunks, checked by the
worker 200 at a time, and written with one statement for each chunk.

An item is one rule, named by its ``id``; its data is the text of the file, as written. What a pack's
rule becomes is decided in ``rules.py`` (enabled when supported, stable or test, and medium or more).
A rule a person changed keeps their text when the pack is applied again and takes the pack's new text
as ``original`` (Reset puts it back); a rule written here with the same id is a conflict.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from sqlalchemy import delete, func, insert, select, update
from sqlalchemy.orm import Session as OrmSession

from ..core.models import PackItem, SigmaRule
from ..core.security import now_iso
from . import checking, rules

KIND = "sigma_rules"
FOLDER = "sigma"
TEXT_MAX = 100_000  # characters of one rule in a pack
CHUNK = 500
_ID = re.compile(r"^id:[ \t]*['\"]?([^\s'\"#]+)", re.MULTILINE)
_SEPARATOR = re.compile(r"^---[ \t]*$", re.MULTILINE)


def name_of(text: str) -> str:
    """The id of the rule a file holds, found by a scan of its lines (the worker reads the YAML, at the
    time the pack is applied). Raises ``ValueError`` with a sentence."""
    if len(text) > TEXT_MAX:
        raise ValueError(f"is longer than {TEXT_MAX} characters: a file holds one rule")
    if sum(1 for part in _SEPARATOR.split(text.lstrip("﻿")) if part.strip()) > 1:
        raise ValueError("holds more than one document: a file holds one rule")
    found = _ID.search(text)
    if found is None:
        raise ValueError("is not a rule: a rule needs an id (a UUID)")
    held = found.group(1)
    if len(held) > rules.ID_MAX or not re.fullmatch(r"[A-Za-z0-9._:-]+", held):
        raise ValueError(f"has the id {held[:40]!r}: an id is {rules.ID_MAX} letters, digits and . _ : - at most")
    return held


def digest(text: str) -> str:
    return hashlib.sha256(text.strip().encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- #
# What is here                                                                 #
# --------------------------------------------------------------------------- #
def held(db: OrmSession, ids: list[str]) -> dict[str, Any]:
    """The rules of these ids that are here, with what the plan needs to judge them (no JSON, no search):
    ``{id: row}`` where a row has ``source``, ``pack``, ``updated_by``, ``original``, ``enabled``, ``supported``,
    ``engine``."""
    row = SigmaRule
    out: dict[str, Any] = {}
    for start in range(0, len(ids), CHUNK):
        found = db.execute(
            select(
                row.id,
                row.source,
                row.pack,
                row.updated_by,
                row.original,
                row.enabled,
                row.supported,
                row.engine,
            ).where(row.id.in_(ids[start : start + CHUNK]))
        )
        out.update({item.id: item for item in found})
    return out


def kept_by_hand(item: Any) -> bool:
    """Whether a person changed a rule of a pack (``rules.edited``, for a row read by ``held``)."""
    return bool(item.pack) and item.updated_by != rules.marker(item.pack)


def digests(db: OrmSession, ids: list[str]) -> dict[str, str]:
    """What each of these rules is now, as ``PackItem.digest`` says it: the fingerprint of its text."""
    return {rule_id: digest(item.source) for rule_id, item in held(db, ids).items()}


def texts(db: OrmSession, ids: list[str]) -> dict[str, str]:
    return {rule_id: item.source for rule_id, item in held(db, ids).items()}


# --------------------------------------------------------------------------- #
# Applying                                                                     #
# --------------------------------------------------------------------------- #
def _plain(rule_id: str, text: str, reason: str) -> dict[str, Any]:
    """What a rule is when the worker did not say: read by a plain scan, not supported, with the reason."""
    base = rules.quick(text) or {"id": rule_id, "title": rule_id, "source": text}
    return {**base, "id": rule_id, "supported": False, "reason": reason[:400]}


def _checked(entries: list[tuple[str, str]]) -> tuple[str, dict[str, dict[str, Any]]]:
    """``(engine, {id: RuleInfo})`` for the texts, 200 at a time. A text that is not a rule gets a row of
    its own saying why (not supported); a worker that cannot be asked gives no engine, and every rule is
    stored not checked."""
    if not entries:
        return "", {}
    try:
        engine, answered = checking.check([text for _id, text in entries])
    except checking.Unavailable:
        return "", {rule_id: _plain(rule_id, text, rules.NOT_CHECKED) for rule_id, text in entries}
    infos: dict[str, dict[str, Any]] = {}
    for (rule_id, text), answer in zip(entries, answered, strict=True):
        found = next(
            (
                item
                for item in answer["rules"]
                if str(item.get("id")) == rule_id and isinstance(item.get("source"), str)
            ),
            None,
        )
        if found is not None:
            infos[rule_id] = found
            continue
        first = answer["errors"][0] if answer["errors"] else {}
        where = f" (line {first['line']})" if isinstance(first.get("line"), int) else ""
        why = first.get("message") or "the worker found no rule with this id"
        infos[rule_id] = _plain(rule_id, text, f"Not a valid rule: {why}{where}")
    return engine, infos


def apply(db: OrmSession, pack_id: str, entries: list[tuple[str, str, str]], actor: str) -> dict[str, int]:
    """Write the rules of a pack (the caller commits). ``entries`` are ``(id, text, action)`` as the plan
    judged them (``add``, ``update``, ``same``). Returns ``{"added", "updated"}``."""
    ids = [rule_id for rule_id, _text, _action in entries]
    here = held(db, ids)
    marker = rules.marker(pack_id)

    def needs_check(rule_id: str, text: str) -> bool:
        item = here.get(rule_id)
        if item is None:
            return True
        if kept_by_hand(item):
            return False  # their text stays
        return item.source.strip() != text.strip() or item.pack != pack_id

    to_check = [(rule_id, text) for rule_id, text, _action in entries if needs_check(rule_id, text)]
    engine, infos = _checked(to_check)
    now = now_iso()
    new_rows: list[dict[str, Any]] = []
    changed: list[dict[str, Any]] = []
    refreshed: list[dict[str, Any]] = []
    added = updated = 0
    for rule_id, text, _action in entries:
        item = here.get(rule_id)
        if item is not None and kept_by_hand(item):
            refreshed.append({"id": rule_id, "original": text})  # theirs stays; Reset puts this back
            continue
        if item is not None and item.source.strip() == text.strip() and item.pack == pack_id:
            continue
        info = infos[rule_id]
        cols = rules.columns(info, engine)
        if item is None:
            known = cols["supported"] or not engine
            new_rows.append(
                {
                    "id": rule_id,
                    "pack": pack_id,
                    "enabled": rules.default_enabled(info, engine, pack_id) and known,
                    "original": None,
                    "created_at": now,
                    "created_by": actor[:200],
                    "updated_at": now,
                    "updated_by": marker,
                    **cols,
                }
            )
            added += 1
        else:
            enabled = bool(item.enabled) and (cols["supported"] or not engine)
            changed.append(
                {
                    "id": rule_id,
                    "pack": pack_id,
                    "enabled": enabled,
                    "original": None,
                    "updated_at": now,
                    "updated_by": marker,
                    **cols,
                }
            )
            updated += 1
    for start in range(0, len(new_rows), CHUNK):
        db.execute(insert(SigmaRule), new_rows[start : start + CHUNK])
    for group in (changed, refreshed):
        for start in range(0, len(group), CHUNK):
            db.execute(update(SigmaRule), group[start : start + CHUNK])
    if new_rows or changed or refreshed:
        rules.bump(db)
        if engine:
            rules.keep_setting(db, "engine", engine)
    return {"added": added, "updated": updated}


def remember(db: OrmSession, pack_id: str, wanted: dict[str, str]) -> None:
    """Write down that these rules (id → the fingerprint of the pack's text) are of the pack."""
    names = sorted(wanted)
    for start in range(0, len(names), CHUNK):
        chunk = names[start : start + CHUNK]
        db.execute(
            delete(PackItem).where(
                PackItem.kind == KIND,
                func.lower(PackItem.name).in_([n.lower() for n in chunk]),
            )
        )
        db.execute(
            insert(PackItem),
            [{"kind": KIND, "name": name, "pack_id": pack_id, "digest": wanted[name]} for name in chunk],
        )


def release(db: OrmSession, pack_id: str) -> None:
    """The rules a pack gave that stay when it goes are no pack's any more: written here, as their own."""
    db.execute(update(SigmaRule).where(SigmaRule.pack == pack_id).values(pack="", original=None))
    rules.bump(db)


def remove(db: OrmSession, ids: list[str]) -> None:
    """Delete the rules an uninstalled pack gave (the caller commits)."""
    for start in range(0, len(ids), CHUNK):
        db.execute(delete(SigmaRule).where(SigmaRule.id.in_(ids[start : start + CHUNK])))
    if ids:
        rules.bump(db)

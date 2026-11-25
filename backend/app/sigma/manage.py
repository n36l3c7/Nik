"""Saving rules a person wrote: the worker reads the text, then the rows are written.

A save is all or nothing: a text with a document that is not a rule saves none of its rules and says,
with the lines, what is wrong. The version of the evaluator that read them is kept with each rule.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from ..core.models import SigmaRule
from . import checking, rules
from .rules import SigmaError

SOURCE_MAX = checking.TEXT_MAX


def read(text: str) -> tuple[str, list[dict[str, Any]], list[dict[str, Any]]]:
    """Ask the worker what a text is: ``(engine, rules, errors)``. Raises ``SigmaError`` for a text that
    cannot be sent and for a worker that cannot answer."""
    if not text.strip():
        raise SigmaError("The text of the rule is empty")
    if len(text) > SOURCE_MAX:
        raise SigmaError(f"A text of rules is {SOURCE_MAX} characters at most")
    try:
        engine, answered = checking.check([text])
    except checking.Unavailable as error:
        raise SigmaError(error.message, error.status) from None
    held = answered[0]
    for info in held["rules"]:
        if not isinstance(info.get("source"), str) or not str(info.get("id") or ""):
            raise SigmaError("The forensics worker answered a rule without its id or its text", 502)
    return engine, held["rules"], checking.errors_of(held)


def _valid(text: str) -> tuple[str, list[dict[str, Any]]]:
    engine, found, errors = read(text)
    if errors:
        first = errors[0]
        where = f" (line {first['line']})" if first["line"] else ""
        raise SigmaError(f"This is not a Sigma rule: {first['message']}{where}", 400, errors)
    if not found:
        raise SigmaError("The text holds no rule")
    ids = [str(info["id"]) for info in found]
    if len(set(ids)) != len(ids):
        raise SigmaError("The text holds two rules with the same id")
    for rule_id in ids:
        rules.check_id(rule_id)
    return engine, found


def validate(db: OrmSession, text: str) -> dict[str, Any]:
    """What the editor shows while a rule is written: nothing is saved. ``rules`` are the rules the text
    holds, each with ``exists`` (a rule with its id is here, and saving replaces nothing: it is refused)."""
    engine, found, errors = read(text)
    ids = [str(info["id"]) for info in found]
    here = set(db.scalars(select(SigmaRule.id).where(SigmaRule.id.in_(ids)))) if ids else set()
    return {
        "ok": not errors and bool(found),
        "engine": engine,
        "errors": errors,
        "rules": [shown(info) | {"exists": str(info["id"]) in here} for info in found],
    }


def shown(info: dict[str, Any]) -> dict[str, Any]:
    level = checking.level_of(info.get("level"))
    return {
        "id": str(info.get("id") or ""),
        "name": str(info.get("name") or ""),
        "title": str(info.get("title") or ""),
        "author": str(info.get("author") or ""),
        "level": level,
        "levelName": checking.LEVEL_NAMES.get(level, ""),
        "status": str(info.get("status") or ""),
        "kind": "correlation" if info.get("kind") == "correlation" else "rule",
        "product": str(info.get("product") or ""),
        "category": str(info.get("category") or ""),
        "service": str(info.get("service") or ""),
        "tags": [str(tag) for tag in info.get("tags") or []],
        "supported": bool(info.get("supported", True)),
        "reason": str(info.get("reason") or ""),
        "line": info.get("line") if isinstance(info.get("line"), int) else None,
    }


def create(db: OrmSession, text: str, actor: str, enabled: bool | None) -> list[SigmaRule]:
    """Save the rules of a text that are not here yet (the caller commits)."""
    engine, found = _valid(text)
    ids = [str(info["id"]) for info in found]
    here = sorted(db.scalars(select(SigmaRule.id).where(SigmaRule.id.in_(ids))))
    if here:
        raise SigmaError(
            f"A rule with the id {here[0]} is here already: change that rule instead",
            409,
        )
    made = [rules.add(db, info, engine, actor, enabled=enabled) for info in found]
    rules.keep_setting(db, "engine", engine)
    return made


def change(db: OrmSession, row: SigmaRule, text: str, actor: str, enabled: bool | None) -> SigmaRule:
    """Put a new text in a rule: it holds that rule alone, with the same id (the caller commits)."""
    engine, found = _valid(text)
    if len(found) != 1 or str(found[0]["id"]) != row.id:
        raise SigmaError(f"The text must hold the rule {row.id}, and no other: the id of a rule does not change")
    rules.replace(db, row, found[0], engine, actor, enabled)
    rules.keep_setting(db, "engine", engine)
    return row


def reset(db: OrmSession, row: SigmaRule, actor: str) -> SigmaRule:
    """Put back the text the pack gave (the caller commits)."""
    if not row.pack:
        raise SigmaError("A rule written here has no pack to go back to", 409)
    if not rules.edited(row) or row.original is None:
        raise SigmaError("This rule is as its pack says it", 409)
    return change(db, row, row.original, actor, None)

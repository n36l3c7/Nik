"""Scripts: Python with typed arguments and outputs, run in the sandbox.

A script is ``def main(args): return <something JSON can hold>``. It is
edited as a draft; it enters the library, and becomes a node of the canvas,
when a **version** is saved, which needs its stored test to pass in the
sandbox. A playbook stays on the version of a script it was saved with.

Scripts never receive secrets, connections, the database or Nik's files:
only the arguments a node gives them. What they return carries the classes of
everything that went in (engine.py), so a script cannot launder data past the
guard.
"""

from __future__ import annotations

import difflib
import re
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy import func, select
from sqlalchemy.orm import Session as OrmSession

from ..core.config import settings
from ..core.models import Script, ScriptVersion
from ..core.security import now_iso
from . import egress, engine

NAME_RE = re.compile(r"^[A-Z][A-Za-z0-9]{2,48}$")
FIELD_RE = re.compile(r"^[a-z][a-z0-9_]{0,39}$")
TYPES = ("text", "number", "bool", "list", "object", "any")
MAX_CODE = 100_000
MAX_FIELDS = 30
SEED_DIR = Path(__file__).parent / "seed" / "scripts"


class ScriptError(ValueError):
    """A script that cannot be saved: a sentence safe to show."""


# --------------------------------------------------------------------------- #
# The shape of a script                                                       #
# --------------------------------------------------------------------------- #
def _fields(items: Any, what: str, *, arguments: bool) -> list[dict]:
    if items is None:
        return []
    if not isinstance(items, list) or len(items) > MAX_FIELDS:
        raise ScriptError(f"The {what} are a list of at most {MAX_FIELDS}")
    out, seen = [], set()
    for item in items:
        if not isinstance(item, dict) or not FIELD_RE.match(str(item.get("name") or "")):
            raise ScriptError(f"Each of the {what} needs a name: a lower-case letter, then letters, digits or _")
        if item["name"] in seen:
            raise ScriptError(f'Two of the {what} are called "{item["name"]}"')
        seen.add(item["name"])
        kind = item.get("type") or "any"
        if kind not in TYPES:
            raise ScriptError(f'"{item["name"]}" has an unknown type: ' + ", ".join(TYPES))
        field = {"name": item["name"], "type": kind, "description": str(item.get("description") or "")[:300]}
        if arguments:
            field["required"] = bool(item.get("required"))
            if item.get("default") is not None:
                field["default"] = item["default"]
        out.append(field)
    return out


def clean(source: dict[str, Any]) -> dict[str, Any]:
    """A draft as it is stored: code, arguments, outputs and the test. Raises ``ScriptError``."""
    code = source.get("code")
    if not isinstance(code, str) or not code.strip():
        raise ScriptError("The script has no code")
    if len(code) > MAX_CODE:
        raise ScriptError("The script is longer than 100 000 characters")
    test = source.get("test") if isinstance(source.get("test"), dict) else {}
    args = test.get("args") if isinstance(test.get("args"), dict) else {}
    stored_test: dict[str, Any] = {"args": args}
    if "expect" in test:
        stored_test["expect"] = test["expect"]
    return {
        "code": code,
        "arguments": _fields(source.get("arguments"), "arguments", arguments=True),
        "outputs": _fields(source.get("outputs"), "outputs", arguments=False),
        "test": stored_test,
    }


# --------------------------------------------------------------------------- #
# Running                                                                     #
# --------------------------------------------------------------------------- #
def execute(code: str, args: dict, timeout: int | None = None) -> dict:
    """Run code in the sandbox: ``{ok, result | error, stdout, duration_ms}``.
    A sandbox that cannot be reached is an answer too, not an exception."""
    if not settings.SANDBOX_URL:
        return {"ok": False, "error": "The sandbox is not configured (SANDBOX_URL)", "stdout": "", "duration_ms": 0}
    seconds = max(1, min(int(timeout or settings.SANDBOX_TIMEOUT), settings.SANDBOX_MAX_TIMEOUT))
    try:
        return egress.sandbox_run(settings.SANDBOX_URL, settings.SANDBOX_TOKEN, code, args, seconds)
    except egress.EgressError as error:
        return {"ok": False, "error": error.message, "stdout": "", "duration_ms": 0, "unreachable": True}


def run_test(draft: dict[str, Any]) -> dict[str, Any]:
    """Run the stored test of a draft. It passes when the script returns without an
    error and, if the test says what to expect, returns exactly that."""
    test = draft.get("test") or {}
    answer = execute(draft["code"], test.get("args") or {})
    passed = bool(answer.get("ok"))
    if passed and "expect" in test:
        passed = answer.get("result") == test["expect"]
        if not passed:
            answer = {**answer, "error": "The script ran, but did not return what the test expects"}
    return {
        "passed": passed,
        "result": answer.get("result"),
        "error": answer.get("error"),
        "stdout": answer.get("stdout", ""),
        "durationMs": answer.get("duration_ms", 0),
        "at": now_iso(),
    }


def run_for_step(db: OrmSession, name: str, version: Any, args: dict, _run: Any) -> tuple[Any, str]:
    """What a script node does (``engine.script_runner``): the result and the script's log."""
    script = db.scalars(select(Script).where(Script.name == name)).first()
    row = db.get(ScriptVersion, (script.id, version)) if script and isinstance(version, int) else None
    if row is None:
        raise engine.StepFailed("This script, or this version of it, does not exist any more", retry=False)
    answer = execute(row.code, args)
    log = answer.get("stdout") or ""
    if not answer.get("ok"):
        # A sandbox that is down may be back; a script that raised will raise again.
        raise engine.StepFailed(str(answer.get("error")), retry=bool(answer.get("unreachable")), log=log)
    result = answer.get("result")
    missing = [out["name"] for out in row.outputs or [] if not (isinstance(result, dict) and out["name"] in result)]
    if missing and row.outputs:
        log += f"\n[nik] the script did not return its declared output(s): {', '.join(missing)}"
    return result, log


engine.script_runner = run_for_step


# --------------------------------------------------------------------------- #
# Versions                                                                    #
# --------------------------------------------------------------------------- #
def code_diff(before: str, after: str, limit: int = 6000) -> str:
    """A unified diff of two versions of the code, for the audit log."""
    lines = difflib.unified_diff(before.splitlines(), after.splitlines(), "before", "after", lineterm="", n=2)
    text = "\n".join(lines)
    return text if len(text) <= limit else text[:limit] + "\n… (cut)"


def current(db: OrmSession, script: Script) -> ScriptVersion | None:
    return db.get(ScriptVersion, (script.id, script.current_version)) if script.current_version else None


def add_version(
    db: OrmSession, script: Script, draft: dict[str, Any], result: dict[str, Any], actor: str
) -> ScriptVersion:
    number = (db.scalar(select(func.max(ScriptVersion.version)).where(ScriptVersion.script_id == script.id)) or 0) + 1
    row = ScriptVersion(
        script_id=script.id,
        version=number,
        code=draft["code"],
        arguments=draft["arguments"],
        outputs=draft["outputs"],
        test=draft["test"],
        test_result=result,
        created_at=now_iso(),
        created_by=actor,
    )
    db.add(row)
    script.current_version = number
    script.draft = None
    script.updated_at = row.created_at
    script.updated_by = actor
    return row


# --------------------------------------------------------------------------- #
# The scripts Nik ships                                                       #
# --------------------------------------------------------------------------- #
def shipped() -> list[dict[str, Any]]:
    """The built-in scripts (``seed/scripts/*.yml``), cleaned like any draft."""
    found = []
    for path in sorted(SEED_DIR.glob("*.yml")):
        source = yaml.safe_load(path.read_text(encoding="utf-8"))
        found.append({"name": source["name"], "description": str(source.get("description") or ""), **clean(source)})
    return found


def seed(db: OrmSession) -> int:
    """Add the built-in scripts that are missing, and a new version of those a release
    changed (the caller commits). Their tests run in CI, not here: the sandbox may not be up."""
    changed = 0
    for item in shipped():
        script = db.scalars(select(Script).where(Script.name == item["name"])).first()
        if script is None:
            now = now_iso()
            script = Script(
                id=engine.new_id(),
                name=item["name"],
                description=item["description"],
                builtin=True,
                created_at=now,
                created_by="nik",
                updated_at=now,
                updated_by="nik",
            )
            db.add(script)
            db.flush()
        elif not script.builtin:
            continue  # someone made a script of their own with this name: it is theirs
        latest = current(db, script)
        if latest is not None and latest.code == item["code"] and latest.arguments == item["arguments"]:
            continue
        add_version(db, script, item, {"passed": True, "shipped": True, "at": now_iso()}, "nik")
        script.description = item["description"]
        changed += 1
    return changed

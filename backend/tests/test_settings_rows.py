"""The table ``settings`` holds one row for each thing that keeps a document, and each module says
which row is its own with a constant. Nothing but this test stops two modules from taking the same
number: the second would then read and overwrite the document of the first."""

from __future__ import annotations

import ast
from pathlib import Path

APP = Path(__file__).resolve().parent.parent / "app"

# A row read by more than one module: the module that owns it, then the ones that name it too.
SHARED = {
    1: {"routers/settings.py", "lists.py"},  # the analysts' settings; the lists are inside
    2: {"automation/state.py", "lists.py"},  # the state of automation; lists.py reads its part
}


def declared() -> dict[int, set[str]]:
    """Every row a module declares: a constant at the top of the module whose name ends in ``_ID``
    and speaks of settings (``SETTINGS_ID``, ``STATE_ID``, ``TEST_ID``, ``TEST_SETTINGS_ID``…),
    in a module that uses the model ``Setting``."""
    found: dict[int, set[str]] = {}
    for path in sorted(APP.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        if "Setting" not in text:
            continue
        for node in ast.parse(text).body:
            targets = (
                node.targets
                if isinstance(node, ast.Assign)
                else [node.target]
                if isinstance(node, ast.AnnAssign)
                else []
            )
            value = getattr(node, "value", None)
            if not (isinstance(value, ast.Constant) and type(value.value) is int):
                continue
            for target in targets:
                name = getattr(target, "id", "")
                if name.endswith("SETTINGS_ID") or name in ("STATE_ID", "TEST_ID"):
                    found.setdefault(value.value, set()).add(path.relative_to(APP).as_posix())
    return found


def test_no_two_modules_claim_the_same_settings_row():
    rows = declared()
    # What this test reads is what is there: the rows known when it was written are all found.
    known = {1, 2, 3, 4, 5, 20, 21, 22, 23, 40, 41, 42, 43, 44, 45, 46, 50, 51, 60, 61, 62, 63, 64, 80}
    assert known <= set(rows), sorted(rows)
    twice = {row: sorted(owners) for row, owners in rows.items() if len(owners) > 1 and owners != SHARED.get(row)}
    assert twice == {}, f"the same row of settings is claimed by several modules: {twice}"


def test_a_module_does_not_claim_one_row_under_two_names():
    for path in sorted(APP.rglob("*.py")):
        seen: dict[int, str] = {}
        text = path.read_text(encoding="utf-8")
        if "Setting" not in text:
            continue
        for node in ast.parse(text).body:
            if not (isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant)):
                continue
            if type(node.value.value) is not int:
                continue
            for target in node.targets:
                name = getattr(target, "id", "")
                if name.endswith("SETTINGS_ID") or name in ("STATE_ID", "TEST_ID"):
                    assert node.value.value not in seen, (path.name, name, seen[node.value.value])
                    seen[node.value.value] = name


def test_the_rows_of_the_encryption_and_of_the_keys_are_their_own():
    from app import key_rotation, store_seal

    assert (store_seal.SETTINGS_ID, key_rotation.SETTINGS_ID) == (50, 51)

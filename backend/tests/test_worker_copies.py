"""What the backend and a worker each write down and must agree on.

Each image is built from its own folder, so a list both sides need is written twice. These tests
are what keeps the two the same: the worker's value is read from its source (the module itself is
not imported: it needs what only its image has).
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

import pytest

from app.enrichment import service
from app.workers import previews

WORKERS = Path(__file__).resolve().parents[2] / "workers"


def constant(path: Path, name: str) -> Any:
    if not path.is_file():
        pytest.skip("the workers are not beside the backend here")
    for node in ast.parse(path.read_text(encoding="utf-8")).body:
        if isinstance(node, ast.Assign) and any(isinstance(to, ast.Name) and to.id == name for to in node.targets):
            return ast.literal_eval(node.value)
    pytest.fail(f"{path} no longer says what {name} is")


def test_the_backend_offers_the_previews_the_document_worker_makes():
    worker = WORKERS / "docview" / "nik_docview.py"
    assert previews.OFFICE == constant(worker, "OFFICE")
    assert previews.IMAGES == constant(worker, "IMAGES")


def test_a_wordperfect_document_is_offered_a_preview():
    assert previews.kind("letter.wpd", "") == "document"
    assert previews.kind("letter.wpd.exe", "") is None


def test_the_names_the_isolated_browser_keeps_inside_are_those_the_lookups_keep_inside():
    assert service.INTERNAL_SUFFIXES == constant(WORKERS / "browser" / "egress.py", "INTERNAL_SUFFIXES")

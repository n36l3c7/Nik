"""The analyzer worker's HTTP front: every path it opens stays in the sample store."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import server  # noqa: E402


def test_in_store_keeps_paths_in_the_store(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "SAMPLE_DIR", str(tmp_path))
    sha = "a" * 64
    assert server.in_store(f"{sha}.bin") == str(tmp_path.resolve() / f"{sha}.bin")
    for escape in ("../etc/passwd", "/etc/passwd", f"{sha}/../../x"):
        with pytest.raises(ValueError):
            server.in_store(escape)


def test_digests_must_match_exactly():
    assert server.SHA256.fullmatch("a" * 64)
    assert not server.SHA256.fullmatch("a" * 64 + "\n")

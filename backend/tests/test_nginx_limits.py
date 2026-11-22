"""What nginx lets through and what the backend takes must agree.

The shipped nginx gives the upload of a mailbox a limit of its own. A mailbox the backend would
take and nginx refuses gets nginx's 413 and none of the backend's sentences, so the number in
``frontend/nginx/nginx.conf`` covers the defaults of ``MAILBOX_MAX_MB`` and ``PST_MAX_MB``; the
compose file gives the same defaults.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.core.config import Settings

ROOT = Path(__file__).resolve().parents[2]


def text_of(path: Path) -> str:
    if not path.is_file():
        pytest.skip("the rest of the repository is not beside the backend here")
    return path.read_text(encoding="utf-8")


def defaults(monkeypatch) -> dict[str, int]:
    for name in ("MAILBOX_MAX_MB", "PST_MAX_MB"):
        monkeypatch.delenv(name, raising=False)
    made = Settings()
    return {"MAILBOX_MAX_MB": made.MAILBOX_MAX_MB, "PST_MAX_MB": made.PST_MAX_MB}


def test_nginx_lets_through_the_largest_mailbox_the_backend_takes_by_default(monkeypatch):
    conf = text_of(ROOT / "frontend" / "nginx" / "nginx.conf")
    block = re.search(r"location = /api/artifacts/mailboxes \{(.*?)\}", conf, re.S)
    assert block, "nginx.conf no longer has the location of the mailbox upload"
    limit = re.search(r"client_max_body_size (\d+)m;", block.group(1))
    assert limit, "the mailbox upload no longer has a limit of its own, in MB"
    assert int(limit.group(1)) >= max(defaults(monkeypatch).values())


def test_the_compose_file_gives_the_defaults_of_the_backend(monkeypatch):
    compose = text_of(ROOT / "docker-compose.yml")
    for name, value in defaults(monkeypatch).items():
        written = set(re.findall(rf"\$\{{{name}:-(\d+)\}}", compose))
        assert written == {str(value)}, name

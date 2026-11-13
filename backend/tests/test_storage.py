"""The Storage page: the disk of the file store and what Nik keeps on it."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from app import storage
from app.core.config import settings
from tests.conftest import make_key
from tests.test_mailboxes import _upload


def test_storage_says_how_full_the_disk_is_and_with_what(admin: TestClient, monkeypatch):
    monkeypatch.setattr(storage, "LARGEST", 10_000)  # the store is shared with the other tests
    box = _upload(admin)
    store = Path(settings.SAMPLE_STORE)
    (store / ("a" * 64 + ".bin")).write_bytes(b"x" * 300)
    (store / "_previews").mkdir(exist_ok=True)
    (store / "_previews" / "page.png").write_bytes(b"y" * 50)
    (store / "stray.txt").write_bytes(b"z" * 7)

    usage = admin.get("/api/storage").json()
    disk = usage["disk"]
    assert disk["total"] >= disk["used"] > 0 and disk["free"] > 0
    groups = {group["id"]: group for group in usage["groups"]}
    assert groups["mailboxes"]["bytes"] > 0 and groups["mailboxes"]["files"] >= 1
    assert groups["samples"]["bytes"] >= 300
    assert groups["previews"]["bytes"] >= 50
    assert groups["other"]["bytes"] >= 7
    assert "database" in groups
    assert usage["nik"] == sum(group["bytes"] for group in usage["groups"])
    assert usage["elsewhere"] == max(0, disk["used"] - usage["nik"])

    # The largest objects are named and lead to their artifact when they have one.
    named = {item["name"]: item for item in usage["largest"]}
    assert named["finance.mbox"]["artifactId"] == box["artifactId"]
    assert named["a" * 64]["artifactId"] is None
    assert [item["bytes"] for item in usage["largest"]] == sorted((i["bytes"] for i in usage["largest"]), reverse=True)


def test_storage_is_for_admins(admin: TestClient):
    reader = make_key(admin, scopes=["read"])
    assert TestClient(admin.app).get("/api/storage", headers=reader).status_code == 403

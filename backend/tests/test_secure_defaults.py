"""Secrets the container refuses, changing SECRET_KEY without losing what it encrypts, and the metrics endpoint."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app import preflight
from app.core import vault
from app.core.config import settings
from app.core.db import SessionLocal
from app.core.models import IntegrationKey

GOOD = {"SECRET_KEY": "k" * 40}


def test_preflight_accepts_generated_secrets():
    assert preflight.problems(GOOD) == []
    workers = {f"{name}_URL": "http://w" for name in preflight.WORKERS}
    tokens = {f"{name}_TOKEN": "t" * 64 for name in preflight.WORKERS}
    assert preflight.problems({**GOOD, **workers, **tokens}) == []
    # A worker that is not configured needs no token.
    assert preflight.problems({**GOOD, "CAPA_URL": "", "CAPA_TOKEN": ""}) == []


@pytest.mark.parametrize(
    "secret",
    ["", "dev-insecure-change-me", "please-change-this-secret", "change-this-to-a-long-random-string", "short"],
)
def test_preflight_refuses_missing_public_and_short_secret_keys(secret):
    found = preflight.problems({"SECRET_KEY": secret})
    assert len(found) == 1 and found[0].startswith("SECRET_KEY")


def test_preflight_refuses_example_worker_tokens_and_says_which():
    env = {
        **GOOD,
        "ANALYZER_URL": "http://analyzer:8700",
        "ANALYZER_TOKEN": "please-change-this-analyzer-token",
        "PCAP_URL": "http://pcap:8740",
    }
    found = preflight.problems(env)
    assert [line.split(" ")[0] for line in found] == ["ANALYZER_TOKEN", "PCAP_TOKEN"]
    assert "still the example value" in found[0] and "not set" in found[1]


def test_preflight_main_exits_with_the_list(monkeypatch, capsys):
    monkeypatch.setenv("SECRET_KEY", "please-change-this-secret")
    for name in preflight.WORKERS:
        monkeypatch.delenv(f"{name}_URL", raising=False)
    with pytest.raises(SystemExit) as stop:
        preflight.main()
    assert stop.value.code == 1
    err = capsys.readouterr().err
    assert "refuses to start" in err and "SECRET_KEY_PREVIOUS" in err
    monkeypatch.setenv("SECRET_KEY", "k" * 40)
    preflight.main()


def test_a_changed_secret_key_keeps_the_stored_secrets(admin: TestClient, monkeypatch):
    """SECRET_KEY_PREVIOUS reads what the old key encrypted, and start-up moves it to the new one."""
    monkeypatch.setattr(settings, "SECRET_KEY", "the-old-default")
    old_token = vault.encrypt("vt-api-key")
    with SessionLocal() as db:
        db.add(IntegrationKey(provider="virustotal", secret=old_token, hint="-key", updated_at="", updated_by=""))
        db.commit()

    # The key changes and nothing says what it was: the secret is unreadable.
    monkeypatch.setattr(settings, "SECRET_KEY", "a-new-random-key")
    assert vault.decrypt(old_token) is None
    assert vault.reencrypt(SessionLocal) == 0

    monkeypatch.setattr(settings, "SECRET_KEY_PREVIOUS", ["a-wrong-guess", "the-old-default"])
    assert vault.decrypt(old_token) == "vt-api-key"
    assert vault.reencrypt(SessionLocal) == 1
    # A second start has nothing left to move.
    assert vault.reencrypt(SessionLocal) == 0

    # The previous key is no longer needed.
    monkeypatch.setattr(settings, "SECRET_KEY_PREVIOUS", [])
    with SessionLocal() as db:
        stored = db.get(IntegrationKey, "virustotal").secret
    assert stored != old_token and vault.decrypt(stored) == "vt-api-key"


def test_metrics_can_require_a_token_and_count_unknown_paths_under_one_label(client: TestClient, monkeypatch):
    for path in ("/api/no-such-thing-1", "/api/no-such-thing-2", "/wp-login.php"):
        assert client.get(path).status_code == 404
    body = client.get("/api/metrics").text
    assert 'path="unmatched"' in body
    assert "no-such-thing" not in body and "wp-login" not in body

    monkeypatch.setattr(settings, "METRICS_TOKEN", "scrape-me")
    assert client.get("/api/metrics").status_code == 401
    assert client.get("/api/metrics", headers={"Authorization": "Bearer nope"}).status_code == 401
    assert client.get("/api/metrics", headers={"Authorization": "Bearer scrape-me"}).status_code == 200

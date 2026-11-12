"""Test fixtures.

Each test runs against a fresh SQLite database in a temp dir. Rate limiting is
effectively disabled so the suite can make many requests.
"""

from __future__ import annotations

import os
import tempfile

# Configure the app BEFORE importing it.
os.environ.setdefault("DATABASE_URL", "sqlite:///" + os.path.join(tempfile.mkdtemp(), "test.db").replace("\\", "/"))
os.environ.setdefault("COOKIE_SECURE", "false")
os.environ.setdefault("RATE_LIMIT_DEFAULT", "100000/minute")
os.environ.setdefault("SAMPLE_STORE", os.path.join(tempfile.mkdtemp(), "samples"))
os.environ.setdefault("ENRICHMENT_WORKER", "false")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.core import security  # noqa: E402
from app.core.db import Base, engine  # noqa: E402
from app.main import app  # noqa: E402

# bcrypt's lowest cost: hashing in tests needs to be correct, not slow.
security.BCRYPT_ROUNDS = 4

ADMIN = {"username": "admin", "password": "supersecret"}


@pytest.fixture()
def client():
    """A TestClient on a freshly-created schema and empty rate-limit counters."""
    app.state.limiter.reset()
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    return TestClient(app)


@pytest.fixture()
def admin(client):
    """A client signed in as the first-run admin (session cookie set)."""
    created = client.post("/api/users", json=ADMIN)
    assert created.status_code == 201, f"first-run admin not created: {created.status_code} {created.text}"
    login = client.post("/api/auth/login", json=ADMIN)
    assert login.status_code == 200, f"admin login failed: {login.status_code} {login.text}"
    assert client.cookies.get("nik_session"), f"no session cookie after login: {login.headers}"
    return client


def make_key(admin_client, **body):
    """Create an API key and return its X-API-Key header dict."""
    body.setdefault("label", "test")
    res = admin_client.post("/api/keys", json=body)
    assert res.status_code == 201, res.text
    return {"X-API-Key": res.json()["key"]}


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """No test reaches a threat-intelligence provider or a registry: a lookup
    that is not faked by the test fails at once instead of going out."""
    from app.enrichment import providers, registration

    def refuse(*args, **kwargs):
        raise providers.ProviderError("network", "no network in tests")

    monkeypatch.setattr(providers, "_request", refuse)
    monkeypatch.setattr(registration, "_whois", refuse)
    registration.reset_cache()

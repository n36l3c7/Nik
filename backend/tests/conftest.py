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

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.db import Base, engine  # noqa: E402
from app.main import app  # noqa: E402

ADMIN = {"username": "admin", "password": "supersecret"}


@pytest.fixture()
def client():
    """A TestClient on a freshly-created schema."""
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    return TestClient(app)


@pytest.fixture()
def admin(client):
    """A client signed in as the first-run admin (session cookie set)."""
    client.post("/api/users", json=ADMIN)
    client.post("/api/auth/login", json=ADMIN)
    return client


def make_key(admin_client, **body):
    """Create an API key and return its X-API-Key header dict."""
    body.setdefault("label", "test")
    res = admin_client.post("/api/keys", json=body)
    assert res.status_code == 201, res.text
    return {"X-API-Key": res.json()["key"]}

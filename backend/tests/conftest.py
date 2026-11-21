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
# Nor the threads of the API process (the check of the workers, the scans playbooks ask for): a test calls them itself.
os.environ.setdefault("API_BACKGROUND", "false")
# No catalogue of packs unless a test gives one (the `published` fixture of test_pack_catalogue.py).
os.environ.setdefault("NIK_PACKS_CATALOGUE", "")
# The script sandbox is "configured"; what answers is the `sandbox` fixture (or nothing).
os.environ.setdefault("SANDBOX_URL", "http://sandbox.test:8750")
os.environ.setdefault("SANDBOX_TOKEN", "test-sandbox-token")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import lists
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
    lists.clear_cache()  # what the last test's lists held is not this one's
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
def store_as_new():
    """What a process remembers of the encryption of the store (whether files in clear are still
    allowed, how far the conversion walked) is of the database of the test before."""
    from app import store_seal

    store_seal.forget()
    store_seal._cursor[0] = 0


@pytest.fixture(autouse=True)
def a_process_that_runs():
    """A test that closes a client stops the application, as a server that is asked to stop does:
    its loops take no more work (main.on_shutdown). The next test is another process."""
    from app import work
    from app.automation import worker
    from app.core import leases
    from app.recovery import role

    work.starting()
    leases.starting()
    role.forget_may_work()
    worker._stopping.clear()
    worker._in_flight.clear()
    worker._fetching.clear()


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """No test reaches a source of threat intelligence, nor anything else: a look-up is a connector
    command, and the way out of every command and every playbook (app/automation/egress.py) is closed
    unless a test opens it with answers of its own (the `outside` fixture below)."""
    from app.automation import egress
    from app.enrichment import sources

    # What the look-ups remember of the connectors and of a source that refused its key is per process.
    sources.forget()
    sources.reset()

    def closed(*args, **kwargs):
        raise AssertionError("a test tried to reach the network through the automation egress")

    monkeypatch.setattr(egress, "_send", closed)
    monkeypatch.setattr(egress, "resolve", closed)
    monkeypatch.setattr(egress, "sandbox_run", closed)
    monkeypatch.setattr(egress.smtplib, "SMTP", closed)
    monkeypatch.setattr(egress.smtplib, "SMTP_SSL", closed)


class Outside:
    """The world outside for a test: names that resolve, and what answers there."""

    def __init__(self):
        self.names: dict[str, list[str]] = {}
        self.answers: list = []  # callables (method, host, path, headers, body) -> (status, headers, body) | None
        self.requests: list[dict] = []
        self.mails: list[dict] = []

    def host(self, name: str, *addresses: str) -> None:
        self.names[name] = list(addresses) or ["93.184.215.10"]

    def answer(
        self, host: str, status: int = 200, json=None, body: bytes = b"", headers: dict | None = None, path=None
    ):
        import json as jsonlib

        payload = jsonlib.dumps(json).encode() if json is not None else body
        sent = {"content-type": "application/json"} if json is not None else {}

        def reply(method, to, target, _headers, _body):
            if to != host or (path is not None and target.split("?")[0] != path):
                return None
            return status, {**sent, **(headers or {})}, payload

        self.answers.append(reply)


@pytest.fixture()
def outside(monkeypatch):
    """Open the automation egress onto a fake outside: `outside.host(...)`, `outside.answer(...)`."""
    from app.automation import egress

    world = Outside()

    def resolve(host, port):
        if host not in world.names:
            raise OSError("unknown host")
        return world.names[host]

    def send(scheme, host, port, path, address, method, headers, body, timeout, ca_pem, max_body):
        world.requests.append(
            {"scheme": scheme, "host": host, "port": port, "path": path, "address": address, "method": method,
             "headers": dict(headers), "body": body}
        )  # fmt: skip
        for reply in reversed(world.answers):
            found = reply(method, host, path, headers, body)
            if found is not None:
                return found
        return 404, {}, b""

    class Smtp:
        def __init__(self, host, port, timeout=None, context=None):
            self.host, self.port = host, port

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def starttls(self, context=None):
            self.tls = True

        def login(self, username, password):
            self.login_as = (username, password)

        def send_message(self, message):
            world.mails.append(
                {"host": self.host, "port": self.port, "from": message["From"], "to": message["To"],
                 "subject": message["Subject"], "text": message.get_content(), "login": getattr(self, "login_as", None)}
            )  # fmt: skip
            return {}

    monkeypatch.setattr(egress, "resolve", resolve)
    monkeypatch.setattr(egress, "_send", send)
    monkeypatch.setattr(egress.smtplib, "SMTP", Smtp)
    monkeypatch.setattr(egress.smtplib, "SMTP_SSL", Smtp)
    return world


@pytest.fixture()
def sandbox(monkeypatch):
    """The script sandbox for a test: the real runner of workers/sandbox, called in
    place of the HTTP request to its container. Returns the list of what was run."""
    import sys
    from pathlib import Path

    folder = Path(__file__).resolve().parents[2] / "workers" / "sandbox"
    if not folder.is_dir() or sys.platform == "win32":
        pytest.skip("the sandbox runner needs Linux and the workers/sandbox sources")
    sys.path.insert(0, str(folder))
    import runner

    from app.automation import egress

    calls: list[dict] = []

    def run(url, token, code, args, timeout):
        calls.append({"url": url, "token": token, "args": args, "timeout": timeout})
        return runner.run(code, args, timeout)

    monkeypatch.setattr(egress, "sandbox_run", run)
    yield calls
    sys.path.remove(str(folder))

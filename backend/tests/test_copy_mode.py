"""A copy of a server (NIK_COPY=true, 7.0) reaches nothing outside itself."""

from __future__ import annotations

import pytest

from app import events
from app.automation import egress, triggers
from app.backups import offsite
from app.core import copy
from app.core.config import settings
from app.recovery import ship as recovery_ship


@pytest.fixture
def a_copy(monkeypatch):
    monkeypatch.setattr(settings, "NIK_COPY", True)
    monkeypatch.setattr(settings, "NIK_COPY_OF", "nik.example.org")


def test_a_server_is_not_a_copy_unless_told():
    assert copy.is_copy() is False
    assert copy.describe() == {"copy": False, "copyOf": ""}
    copy.refuse("send anything")  # nothing raised


def test_every_way_out_is_shut_on_a_copy(a_copy, monkeypatch):
    assert copy.describe() == {"copy": True, "copyOf": "nik.example.org"}
    with pytest.raises(copy.CopyRefused, match="copy of nik.example.org"):
        copy.refuse("send a webhook")

    # Requests, mail and mailboxes of playbooks and connectors: refused, never retried.
    with pytest.raises(egress.EgressError) as refused:
        egress.request(egress.Policy(), "GET", "https://example.org/")
    assert refused.value.refused and "copy" in str(refused.value)
    with pytest.raises(egress.EgressError):
        server = {"host": "smtp.example.org", "sender": "a@example.org"}
        egress.send_mail(server, to=["b@example.org"], subject="s", text="t")
    with pytest.raises(egress.EgressError):
        egress.smtp_client("smtp.example.org", 587, "starttls")
    with pytest.raises(egress.EgressError):
        egress.imap_client("imap.example.org", 993, "tls")

    # Webhooks: not sent.
    opened = []
    monkeypatch.setattr(events.urllib.request, "urlopen", lambda *a, **k: opened.append(a))
    events._deliver("https://hooks.example.org/x", "secret", "incident.created", {})
    assert opened == []

    # The off-site destination of the backups (its retention would delete the real server's copies).
    with pytest.raises(offsite.OffsiteError, match="copy"):
        offsite.Sftp({"host": "backup.example.org", "user": "nik"}, "").connect()
    assert offsite.ship() == []
    assert recovery_ship.ship() == []


def test_no_playbook_starts_by_itself_on_a_copy(a_copy, monkeypatch):
    from app.core.db import SessionLocal

    with SessionLocal() as db:
        assert triggers.fire_schedules(db, 10**12) == []

        class Event:
            kind, payload = "incident.created", {"data": {}}

        assert triggers.handle_event(db, Event(), 10**12) == []


def test_the_screens_are_told_the_server_is_a_copy(admin, a_copy):
    shown = admin.get("/api/auth/me").json()
    assert shown["server"] == {"copy": True, "copyOf": "nik.example.org"}


def test_the_answer_to_a_login_says_what_the_server_is(client):
    from tests.conftest import ADMIN

    assert client.post("/api/users", json=ADMIN).status_code == 201
    answered = client.post("/api/auth/login", json=ADMIN).json()
    assert answered["server"] == {"copy": False, "copyOf": ""}


def test_the_answer_to_a_login_says_the_server_is_a_copy(client, a_copy):
    from tests.conftest import ADMIN

    assert client.post("/api/users", json=ADMIN).status_code == 201
    answered = client.post("/api/auth/login", json=ADMIN).json()
    assert answered["server"] == {"copy": True, "copyOf": "nik.example.org"}

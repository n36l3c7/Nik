"""Mirroring: an incident and a ticket of another product kept in step, both ways."""

from __future__ import annotations

import json
import textwrap
from urllib.parse import urlsplit

from fastapi.testclient import TestClient
from sqlalchemy import select

from app import mirror
from app.automation import worker
from app.core.db import SessionLocal
from app.core.models import Incident, MirrorJob
from tests.conftest import make_key
from tests.test_automation_engine import T0, test_actions  # noqa: F401 - test_actions is a fixture
from tests.test_fields import incident
from tests.test_tasks import person

BASE = "/api/automation"

DESK = textwrap.dedent(
    """\
    name: Desk
    id: desk
    version: 1
    description: Tickets of Desk.
    configuration:
      - { name: url, type: url, required: true }
      - { name: token, type: bearer }
    base_url: "{{ config.url }}"
    test:
      request: { method: GET, path: /me }
    commands:
      - name: get-ticket
        arguments: [{ name: id, type: text, required: true }]
        request: { method: GET, path: "/tickets/{{ args.id }}" }
        outputs: { ticket: "{{ response }}" }
      - name: update-ticket
        changes_outside: true
        arguments:
          - { name: id, type: text, required: true }
          - { name: fields, type: object }
        request: { method: PATCH, path: "/tickets/{{ args.id }}", json: "{{ args.fields }}" }
        outputs: { ticket: "{{ response }}" }
      - name: get-comments
        arguments: [{ name: id, type: text, required: true }]
        request: { method: GET, path: "/tickets/{{ args.id }}/comments" }
        outputs: { comments: "{{ response.comments }}" }
      - name: add-comment
        changes_outside: true
        arguments:
          - { name: id, type: text, required: true }
          - { name: text, type: text, required: true }
        request: { method: POST, path: "/tickets/{{ args.id }}/comments", json: { body: "{{ args.text }}" } }
        success: { status: [200, 201] }
    mirror:
      interval_seconds: 120
      get: { command: get-ticket }
      item: "{{ result.ticket }}"
      update:
        command: update-ticket
        args: { id: "{{ mirror.id }}", fields: "{{ fields }}" }
      comments:
        list: { command: get-comments }
        items: "{{ result.comments }}"
        id: "{{ item.id }}"
        text: "{{ item.body }}"
        author: "{{ item.by }}"
        at: "{{ item.at }}"
        add:
          command: add-comment
          args: { id: "{{ mirror.id }}", text: "{{ comment.text }}" }
    """
)

INCOMING = [
    {"to": "name", "from": "{{ item.title }}"},
    {"to": "severity", "from": "{{ item.priority | severity('inverse') }}"},
    {
        "to": "status",
        "from": "{{ item.state | map(new='open', work='in_progress', closed='closed') }}",
        "authoritative": True,
    },
    {"to": "ticket", "from": "{{ item.number }}"},
]
OUTGOING = [
    {"to": "title", "from": "{{ incident.name }}"},
    {"to": "priority", "from": "{{ incident.severity | map(critical=1, high=2, medium=3, low=4) }}"},
]


class Desk:
    """A fake Desk: one ticket, its comments, and everything it was sent."""

    def __init__(self):
        self.ticket = {"id": "T-9", "number": "DSK-9", "title": "Laptop of finance", "priority": 3, "state": "new"}
        self.comments: list[dict] = []
        self.patches: list[dict] = []
        self.posted: list[str] = []
        self.down = False

    def reply(self, method, host, target, _headers, body):
        path = urlsplit(target).path
        if host != "desk.example.com":
            return None
        if self.down:
            return 503, {}, b"down"
        ok = {"content-type": "application/json"}
        if path == "/api/tickets/T-9" and method == "GET":
            return 200, ok, json.dumps(self.ticket).encode()
        if path == "/api/tickets/T-9" and method == "PATCH":
            sent = json.loads(body or b"{}")
            self.patches.append(sent)
            self.ticket.update(sent)
            return 200, ok, json.dumps(self.ticket).encode()
        if path == "/api/tickets/T-9/comments" and method == "GET":
            return 200, ok, json.dumps({"comments": self.comments}).encode()
        if path == "/api/tickets/T-9/comments" and method == "POST":
            text = json.loads(body or b"{}")["body"]
            self.posted.append(text)
            self.comments.append(
                {"id": f"c{len(self.comments) + 1}", "body": text, "by": "nik", "at": "2026-11-17T10:00:00Z"}
            )
            return 201, ok, b"{}"
        return 404, {}, b""


def desk(admin: TestClient, outside) -> tuple[dict, Desk]:
    assert admin.post(f"{BASE}/connectors", json={"source": DESK}).status_code == 201
    made = admin.post(
        f"{BASE}/connections",
        json={
            "name": "Desk prod",
            "connector": "desk",
            "config": {"url": "https://desk.example.com/api"},
            "secrets": {"token": "s3cret-token"},
        },
    )
    assert made.status_code == 201, made.text
    for direction, rules in (("incoming", INCOMING), ("outgoing", OUTGOING)):
        saved = admin.put("/api/mappers", json={"connectorId": "desk", "direction": direction, "rules": rules})
        assert saved.status_code == 200, saved.text
    world = Desk()
    outside.host("desk.example.com")
    outside.answers.append(world.reply)
    return made.json(), world


def start(admin: TestClient, connection: dict, direction: str = "both", **more):
    return admin.post(
        "/api/incidents/i1/mirror",
        json={"connectionId": connection["id"], "mirrorId": "T-9", "direction": direction, **more},
    )


def sync(admin: TestClient) -> dict:
    answer = admin.post("/api/incidents/i1/mirror/sync")
    assert answer.status_code == 200, answer.text
    return answer.json()


def fields_of(admin: TestClient) -> dict:
    return admin.get("/api/incidents/i1/fields").json()["fields"]


def push_all(now: float = T0) -> None:
    with SessionLocal() as db:
        ids = [job.id for job in db.scalars(select(MirrorJob).where(MirrorJob.status == "pending"))]
    for job_id in ids:
        mirror.run_push(job_id, now)


def test_what_the_other_side_says_comes_in_and_what_a_person_set_stays(admin: TestClient, outside):
    connection, world = desk(admin, outside)
    incident(admin)
    assert admin.get("/api/incidents/i1/mirror").json() == {
        "mirrored": False,
        "connections": [
            {"id": connection["id"], "name": "Desk prod", "connector": "Desk", "out": True, "comments": True}
        ],
    }
    started = start(admin, connection, "in")
    assert started.status_code == 201, started.text
    shown = started.json()
    assert (shown["mirrored"], shown["connection"], shown["id"], shown["direction"]) == (True, "Desk prod", "T-9", "in")
    assert fields_of(admin)["mirror_id"] == "T-9" and fields_of(admin)["mirror_direction"] == "in"

    # The first read: the ticket fills the incident.
    done = sync(admin)
    assert sorted(done["changed"]) == ["severity", "ticket"] and done["kept"] == [] and done["problems"] == []
    held = fields_of(admin)
    assert (held["severity"], held["ticket"], held["name"]) == ("medium", "DSK-9", "Laptop of finance")
    assert done["mirror"]["lastSync"] and held["mirror_last_sync"]

    # A person changes the severity in Nik; the other side changes its priority and its title.
    assert admin.patch("/api/incidents/i1/fields", json={"changes": {"severity": "critical"}}).status_code == 200
    world.ticket.update(priority=4, title="Laptop of finance (stolen)", state="work")
    done = sync(admin)
    # The name follows; the severity stays what the person set; the status, authoritative, follows anyway.
    assert sorted(done["changed"]) == ["name", "status"] and done["kept"] == ["severity"]
    held = fields_of(admin)
    assert (held["severity"], held["name"], held["status"]) == ("critical", "Laptop of finance (stolen)", "in_progress")
    # A person sets the status; the other side closes: authoritative wins over the edit.
    assert admin.patch("/api/incidents/i1", json={"status": "open"}).status_code == 200
    world.ticket["state"] = "closed"
    assert sync(admin)["changed"] == ["status"] and fields_of(admin)["status"] == "closed"

    # Comments not seen before become lines of the War Room, once.
    world.comments += [
        {"id": "c1", "body": "User called back.", "by": "helpdesk", "at": "2026-11-17T09:00:00Z"},
        {"id": "c2", "body": "Disk sent to the lab.", "by": "lab", "at": "2026-11-17T09:30:00Z"},
    ]
    assert sync(admin)["comments"] == 2 and sync(admin)["comments"] == 0
    room = [entry for entry in admin.get("/api/incidents/i1/war-room").json()["entries"] if entry["kind"] == "mirror"]
    assert [(entry["body"]["text"], entry["body"]["from"], entry["author"]) for entry in room] == [
        ("User called back.", "helpdesk", "connector:desk"),
        ("Disk sent to the lab.", "lab", "connector:desk"),
    ]
    # Mirrored in only: nothing was ever sent.
    assert world.patches == [] and world.posted == []

    # Stopped: nothing is read any more.
    assert admin.delete("/api/incidents/i1/mirror").status_code == 204
    assert admin.get("/api/incidents/i1/mirror").json()["mirrored"] is False
    assert "mirror_id" not in fields_of(admin)
    assert admin.post("/api/incidents/i1/mirror/sync").status_code == 409


def test_what_changes_in_nik_goes_out_and_nothing_comes_back_in_a_loop(admin: TestClient, outside):
    connection, world = desk(admin, outside)
    incident(admin, severity="high")
    assert start(admin, connection, "both").status_code == 201
    sync(admin)  # the ticket says medium; the severity a person gave when creating... was set by the document
    with SessionLocal() as db:
        assert db.scalars(select(MirrorJob)).all() == []  # what came from the other side is not sent back

    # A field the outgoing mapper reads changes in Nik: one update waits, and sends the incident as it is.
    assert admin.patch("/api/incidents/i1/fields", json={"changes": {"severity": "critical"}}).status_code == 200
    assert admin.patch("/api/incidents/i1", json={"name": "Laptop of finance: stolen"}).status_code == 200
    assert admin.patch("/api/incidents/i1/fields", json={"changes": {"host": "WKS-9"}}).status_code == 200  # not read
    with SessionLocal() as db:
        jobs = db.scalars(select(MirrorJob)).all()
        assert [(job.kind, job.status) for job in jobs] == [("update", "pending")]
    assert admin.get("/api/incidents/i1/mirror").json()["waiting"] == 1
    push_all()
    assert world.patches == [{"title": "Laptop of finance: stolen", "priority": 1}]
    assert admin.get("/api/mirror/queue").json()["jobs"] == []

    # A note tagged "mirror" goes out as a comment, and is not said twice when it comes back.
    noted = admin.post("/api/incidents/i1/war-room", json={"text": "Disk imaged.", "tags": ["mirror"]})
    assert noted.status_code == 201
    assert admin.post("/api/incidents/i1/war-room", json={"text": "Only for us."}).status_code == 201
    push_all()
    assert world.posted == ["Disk imaged."]
    assert sync(admin)["comments"] == 0
    kinds = [
        entry["body"].get("direction")
        for entry in admin.get("/api/incidents/i1/war-room").json()["entries"]
        if entry["kind"] == "mirror"
    ]
    assert kinds == ["out"]

    # The other side is down: the send is tried again later, and listed with why.
    world.down = True
    assert admin.patch("/api/incidents/i1/fields", json={"changes": {"severity": "low"}}).status_code == 200
    push_all(T0)
    (job,) = admin.get("/api/mirror/queue").json()["jobs"]
    assert (job["kind"], job["status"], job["attempts"], job["incident"]) == (
        "update",
        "pending",
        1,
        "Laptop of finance: stolen",
    )
    assert "503" in job["error"] and job["nextAt"] > T0
    with SessionLocal() as db:
        assert mirror.jobs_due(db, T0) == [] and mirror.jobs_due(db, T0 + 600) == [job["id"]]
    world.down = False
    retried = admin.post(f"/api/mirror/queue/{job['id']}/retry")
    assert retried.status_code == 200
    push_all()
    assert world.patches[-1] == {"title": "Laptop of finance: stolen", "priority": 4}
    assert admin.get("/api/mirror/queue").json()["jobs"] == []


def test_who_may_start_a_mirror_and_what_it_may_send(admin: TestClient, outside):
    connection, world = desk(admin, outside)
    incident(admin)
    anna = person(admin, "anna", ["analyst"])
    reader = make_key(admin, label="v", roles=["viewer"])
    writer = make_key(admin, label="w", roles=["viewer", "rules"])  # reads, and nothing of playbooks
    body = {"connectionId": connection["id"], "mirrorId": "T-9", "direction": "both"}
    assert admin.post("/api/incidents/i1/mirror", headers=reader, json=body).status_code == 403
    assert admin.get("/api/incidents/i1/mirror", headers=reader).status_code == 200
    # An analyst writes incidents and runs playbooks: she may start a mirror that sends, with no class opened.
    opened = anna.post("/api/incidents/i1/mirror", json={**body, "dataAllow": ["email_address"]})
    assert (opened.status_code, opened.json()["detail"]) == (
        403,
        "Opening a class of data needs the permission that opens them",
    )
    assert anna.post("/api/incidents/i1/mirror", json=body).status_code == 201
    del writer

    def refused(**changes) -> str:
        answer = admin.post("/api/incidents/i1/mirror", json={**body, **changes})
        assert answer.status_code in (400, 404), answer.text
        return answer.json()["detail"]

    assert refused(connectionId="nope") == "Connection not found"
    assert refused(mirrorId="  ").startswith("Say which object of the other side")
    # A connector that only reads cannot be mirrored out.
    reading = DESK.replace("id: desk", "id: readonly").replace("name: Desk", "name: Read only")
    reading = (
        reading[: reading.index("  update:\n    command: update-ticket")]
        + "  comments:\n    list: { command: get-comments }\n"
    )
    assert admin.post(f"{BASE}/connectors", json={"source": reading}).status_code == 201, reading
    only = admin.post(
        f"{BASE}/connections",
        json={"name": "Read only", "connector": "readonly", "config": {"url": "https://desk.example.com/api"}},
    ).json()
    assert refused(connectionId=only["id"]) == "This connector reads the other side but does not write to it: mirror in"

    # What leaves passes the data guard: an e-mail address in the name is held until its class is opened.
    assert admin.patch("/api/incidents/i1", json={"name": "Phish from eve@evil.example"}).status_code == 200
    push_all()
    (job,) = admin.get("/api/mirror/queue").json()["jobs"]
    assert job["attempts"] == 1 and "e-mail" in job["error"].lower() and world.patches == []
    assert admin.post("/api/incidents/i1/mirror", json={**body, "dataAllow": ["email_address"]}).status_code == 201
    assert admin.get("/api/incidents/i1/mirror").json()["dataAllow"] == ["email_address"]
    admin.post(f"/api/mirror/queue/{job['id']}/retry")
    push_all()
    assert world.patches == [{"title": "Phish from eve@evil.example"}]
    # Starting and what it may send are in the audit log.
    audit = admin.get("/api/audit", params={"limit": 50}).json()
    entries = audit["entries"] if isinstance(audit, dict) else audit
    assert any("sending email_address" in str(entry.get("details")) for entry in entries)


def test_the_worker_reads_mirrored_incidents_at_their_interval_and_sends_what_waits(admin: TestClient, outside):
    connection, world = desk(admin, outside)
    incident(admin)
    assert start(admin, connection, "both").status_code == 201
    with SessionLocal() as db:
        row = db.get(Incident, "i1")
        row.mirror = {**row.mirror, "nextAt": T0 + 50}
        db.commit()
    worker.tick(T0)
    assert fields_of(admin).get("ticket") is None  # not its time yet
    worker.tick(T0 + 51)
    assert fields_of(admin)["ticket"] == "DSK-9"
    with SessionLocal() as db:
        assert db.get(Incident, "i1").mirror["nextAt"] == T0 + 51 + 120
        assert mirror.due(db, T0 + 100) == [] and mirror.due(db, T0 + 200) == ["i1"]
    # What waits is sent by the worker too.
    assert admin.patch("/api/incidents/i1/fields", json={"changes": {"severity": "high"}}).status_code == 200
    with SessionLocal() as db:
        for job in db.scalars(select(MirrorJob)):
            job.next_at = T0
        db.commit()
    worker.tick(T0 + 60)
    assert world.patches == [{"title": "Laptop of finance", "priority": 2}]

    # The other side fails: the incident says so, and is read again later and later.
    world.down = True
    worker.tick(T0 + 200)
    shown = admin.get("/api/incidents/i1/mirror").json()
    assert "503" in shown["error"]
    with SessionLocal() as db:
        assert db.get(Incident, "i1").mirror["nextAt"] > T0 + 200 + 120
    # A closed incident is read for a day more, then left alone.
    world.down = False
    assert admin.patch("/api/incidents/i1", json={"status": "closed"}).status_code == 200
    with SessionLocal() as db:
        row = db.get(Incident, "i1")
        row.mirror = {**row.mirror, "nextAt": 0}
        closed_at = row.closed_at
        db.commit()
        assert closed_at
        from datetime import datetime

        closed = datetime.fromisoformat(closed_at.replace("Z", "+00:00")).timestamp()
        assert mirror.due(db, closed + 3600) == ["i1"]
        assert mirror.due(db, closed + 2 * 86400) == []

"""Mirroring as an instance says it: the direction of the incidents its fetch makes.

The other half of test_mirror.py, which starts mirrors by hand: here an instance is told None,
In, Out or In-out, its fetch starts the mirrors, and a mapper that names the object and the
direction itself is still obeyed first. Also what the format gained for it (the id of the object in
a fetched item, kinds of objects, a connector that says why it does not mirror), what happens to an
object that is gone on the other side, and giving the choice to what was fetched before.
"""

from __future__ import annotations

import json
import textwrap
from urllib.parse import urlsplit

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import mirror, packs
from app.automation import connectors as cn
from app.core.db import SessionLocal
from app.core.models import AuditEntry, Connection, Incident, MirrorJob, Notification
from tests import vendor
from tests.conftest import make_key
from tests.test_automation_engine import T0, test_actions  # noqa: F401 - test_actions is a fixture
from tests.test_fields import incident
from tests.test_shipped_connectors import DATA
from tests.test_tasks import person

BASE = "/api/automation"

HELPDESK = textwrap.dedent(
    """\
    name: Helpdesk
    id: helpdesk
    version: 1
    description: Tickets and tasks of Helpdesk.
    configuration:
      - { name: url, type: url, required: true }
      - { name: token, type: bearer }
    base_url: "{{ config.url }}"
    commands:
      - name: get-ticket
        arguments: [{ name: key, type: text, required: true }]
        request: { method: GET, path: "/tickets/{{ args.key }}" }
        outputs: { ticket: "{{ response }}" }
      - name: update-ticket
        changes_outside: true
        arguments:
          - { name: key, type: text, required: true }
          - { name: fields, type: object }
        request: { method: PATCH, path: "/tickets/{{ args.key }}", json: "{{ args.fields }}" }
      - name: get-comments
        arguments: [{ name: key, type: text, required: true }]
        request: { method: GET, path: "/tickets/{{ args.key }}/comments" }
        outputs: { comments: "{{ response.comments }}" }
      - name: add-comment
        changes_outside: true
        idempotent: false
        arguments:
          - { name: key, type: text, required: true }
          - { name: text, type: text, required: true }
        request: { method: POST, path: "/tickets/{{ args.key }}/comments", json: { body: "{{ args.text }}" } }
        success: { status: [200, 201] }
      - name: find-tasks
        arguments: [{ name: ids, type: text, required: true }]
        request: { method: GET, path: /tasks, query: { ids: "{{ args.ids }}" } }
        outputs: { tasks: "{{ response.tasks }}" }
      - name: update-task
        changes_outside: true
        arguments:
          - { name: id, type: text, required: true }
          - { name: kind, type: text }
          - { name: state, type: text }
        request:
          method: PUT
          path: "/tasks/{{ args.id }}"
          json: { state: "{{ args.state }}", of: "{{ args.kind }}" }
    fetch:
      interval_seconds: 120
      request: { method: GET, path: /tickets }
      items: "{{ response.tickets }}"
      item_id: "{{ item.id }}"
    mirror:
      interval_seconds: 120
      id: "{{ item.key }}"
      get: { command: get-ticket }
      item: "{{ result.ticket }}"
      update:
        command: update-ticket
        args: { key: "{{ mirror.id }}", fields: "{{ fields }}" }
      comments:
        list: { command: get-comments }
        items: "{{ result.comments }}"
        text: "{{ item.body }}"
        author: "{{ item.by }}"
        at: "{{ item.at }}"
        add:
          command: add-comment
          args: { key: "{{ mirror.id }}", text: "{{ comment.text }}" }
      kinds:
        task:
          get: { command: find-tasks, args: { ids: "{{ mirror.id }}" } }
          item: "{{ result.tasks | first }}"
          update:
            command: update-task
            args: { id: "{{ mirror.id }}", kind: "{{ mirror.kind }}", state: "{{ fields.state }}" }
    """
)

INCOMING = [
    {"to": "name", "from": "{{ item.title }}"},
    {"to": "status", "from": "{{ item.state | map(new='open', work='in_progress', closed='closed', else='') }}"},
    {"to": "ticket", "from": "{{ item.key }}"},
]
OUTGOING = [
    {"to": "title", "from": "{{ incident.name }}"},
    {"to": "state", "from": "{{ incident.status | map(open='new', in_progress='work', closed='closed') }}"},
]
JSON = {"content-type": "application/json"}


class World:
    """A fake Helpdesk: its tickets by key, its tasks by id, and everything it was sent."""

    def __init__(self):
        self.tickets = {
            "T-101": {"id": "101", "key": "T-101", "title": "Laptop of finance", "state": "new"},
            "T-102": {"id": "102", "key": "T-102", "title": "Badge lost", "state": "new"},
        }
        self.tasks = {"K-1": {"id": "K-1", "key": "K-1", "title": "Wipe the laptop", "state": "new"}}
        self.comments: dict[str, list[dict]] = {}
        self.sent: list[tuple[str, str, dict]] = []

    def reply(self, method, host, target, _headers, body):
        if host != "helpdesk.example.com":
            return None
        parts = urlsplit(target)
        path = parts.path.removeprefix("/api")
        given = json.loads(body or b"{}") if method != "GET" else {}
        if method != "GET":
            self.sent.append((method, path, given))
        if path == "/tickets":
            return 200, JSON, json.dumps({"tickets": list(self.tickets.values())}).encode()
        if path == "/tasks":
            wanted = parts.query.removeprefix("ids=")
            return (
                200,
                JSON,
                json.dumps({"tasks": [task for key, task in self.tasks.items() if key == wanted]}).encode(),
            )
        kind, _, rest = path.strip("/").partition("/")
        key, _, more = rest.partition("/")
        if kind == "tasks" and key in self.tasks and method == "PUT":
            self.tasks[key]["state"] = given["state"]
            return 200, JSON, b"{}"
        if kind != "tickets" or key not in self.tickets:
            return 404, JSON, b'{"error": "no such ticket"}'
        if more == "comments":
            if method == "POST":
                listed = self.comments.setdefault(key, [])
                listed.append(
                    {"id": f"c{len(listed) + 1}", "body": given["body"], "by": "nik", "at": "2026-11-21T10:00:00Z"}
                )
                return 201, JSON, b"{}"
            return 200, JSON, json.dumps({"comments": self.comments.get(key, [])}).encode()
        if method == "PATCH":
            self.tickets[key].update(given)
        return 200, JSON, json.dumps(self.tickets[key]).encode()

    def updates(self) -> list[dict]:
        return [given for method, _path, given in self.sent if method == "PATCH"]


def helpdesk(
    admin: TestClient, outside, source: str = HELPDESK, name: str = "Helpdesk prod", world: World | None = None
) -> tuple[dict, World]:
    """A connector, an instance of it and its mappers; a fake Helpdesk behind it, or the one given."""
    assert admin.post(f"{BASE}/connectors", json={"source": source}).status_code == 201
    made = admin.post(
        f"{BASE}/instances",
        json={
            "name": name,
            "connector": cn.load(source).id,
            "config": {"url": "https://helpdesk.example.com/api"},
            "secrets": {"token": "s3cret-token"},
        },
    )
    assert made.status_code == 201, made.text
    for direction, rules in (("incoming", INCOMING), ("outgoing", OUTGOING)):
        body = {"connectorId": cn.load(source).id, "direction": direction, "rules": rules}
        assert admin.put("/api/mappers", json=body).status_code == 200
    if world is None:
        world = World()
        outside.host("helpdesk.example.com")
        outside.answers.append(world.reply)
    return made.json(), world


def held_by(admin: TestClient, connection: dict) -> dict:
    """The instance as its form reads it."""
    listed = admin.get(f"{BASE}/instances").json()["instances"]
    return next(item for item in listed if item["id"] == connection["id"])


def choose(client: TestClient, connection: dict, **fetch):
    return client.put(f"{BASE}/instances/{connection['id']}", json={"fetch": {"enabled": True, **fetch}})


def fetch_now(admin: TestClient, connection: dict) -> dict:
    answer = admin.post(f"/api/fetch/{connection['id']}/run")
    assert answer.status_code == 200, answer.text
    return answer.json()["result"]


def fetched(source_id: str) -> str:
    """The id of the incident an item became."""
    with SessionLocal() as db:
        return db.scalars(select(Incident.id).where(Incident.source_id == source_id)).one()


def shown(admin: TestClient, incident_id: str) -> dict:
    return admin.get(f"/api/incidents/{incident_id}/mirror").json()


def sync(admin: TestClient, incident_id: str) -> dict:
    answer = admin.post(f"/api/incidents/{incident_id}/mirror/sync")
    assert answer.status_code == 200, answer.text
    return answer.json()


def jobs() -> list[tuple[str, str]]:
    with SessionLocal() as db:
        return [(job.kind, job.status) for job in db.scalars(select(MirrorJob).order_by(MirrorJob.created_at))]


def push_all(now: float = T0) -> None:
    with SessionLocal() as db:
        ids = [job.id for job in db.scalars(select(MirrorJob).where(MirrorJob.status == "pending"))]
    for job_id in ids:
        mirror.run_push(job_id, now, "test")


def audited(db, action: str) -> list[AuditEntry]:
    """The entries of the audit log for one action, in the order they were written."""
    return list(db.scalars(select(AuditEntry).where(AuditEntry.action == action).order_by(AuditEntry.seq)))


def status_of(admin: TestClient, incident_id: str) -> str:
    return admin.get(f"/api/incidents/{incident_id}/fields").json()["fields"]["status"]


# --------------------------------------------------------------------------- #
# The format                                                                  #
# --------------------------------------------------------------------------- #
def problems(source: str) -> list[str]:
    with pytest.raises(cn.ConnectorError) as caught:
        cn.load(source)
    return [problem.message for problem in caught.value.problems]


def test_the_format_says_which_object_an_item_is_what_kinds_there_are_and_why_not():
    connector = cn.load(HELPDESK)
    spec = connector.mirror
    assert spec.id == "{{ item.key }}" and sorted(spec.kinds) == ["task"]
    # An id names its kind before a colon; one with no kind, or a kind the file does not have, is the object itself.
    assert spec.of("task:K-1")[:2] == ("task", "K-1") and spec.of("task:K-1")[2] is spec.kinds["task"]
    assert spec.of("T-101") == ("", "T-101", spec) and spec.of("urn:x") == ("", "urn:x", spec)
    assert [where for where, _call in connector.mirror_calls()] == [
        "mirror.get",
        "mirror.update",
        "mirror.comments.list",
        "mirror.comments.add",
        "mirror.kinds.task.get",
        "mirror.kinds.task.update",
    ]
    said = cn.summary(connector)["mirror"]
    assert (said["out"], said["fieldsIn"], said["fieldsOut"], said["commentsOut"], said["fed"], said["kinds"]) == (
        True, True, True, True, False, ["task"]
    )  # fmt: skip

    # A kind is checked as the mirror is: its commands exist, take what they are given, and say they change.
    wrong = HELPDESK.replace("get: { command: find-tasks, args: { ids:", "get: { command: find-task, args: { ids:")
    assert problems(wrong) == ['mirror.kinds.task.get names "find-task", which is not a command']
    wrong = HELPDESK.replace('kind: "{{ mirror.kind }}"', 'sort: "{{ mirror.kind }}"')
    assert problems(wrong) == ['mirror.kinds.task.update gives "sort", which "update-task" does not take']
    quiet = HELPDESK.replace("  - name: update-task\n    changes_outside: true\n", "  - name: update-task\n")
    assert problems(quiet) == [
        "mirror.kinds.task.update changes the other side: its command says changes_outside: true"
    ]
    assert problems(HELPDESK.replace('id: "{{ item.key }}"', "id: key")) == [
        '"id" is a template over the fetched item: "{{ item.id }}"'
    ]
    assert problems(HELPDESK.replace('id: "{{ item.key }}"', 'id: "{{ result.key }}"'))[0].startswith(
        '"result" cannot be read'
    )

    # A mirror says how the other side is read: by a command, or by its fetch.
    cut = HELPDESK[: HELPDESK.index("mirror:")]
    assert problems(cut + "mirror:\n  interval_seconds: 120\n") == [
        'a mirror says how the other side is read: "get", or "thread" when the fetch feeds it'
    ]
    fed = cut + 'mirror:\n  thread: { ids: "{{ item.parents }}" }\n'
    loaded = cn.load(fed)
    assert loaded.mirror.get is None and cn.summary(loaded)["mirror"]["fed"] is True
    assert cn.summary(loaded)["mirror"]["out"] is False and cn.summary(loaded)["mirror"]["comments"] is True
    assert problems(fed + "  update: { command: update-ticket }\n") == [
        'a mirror with no "get" is fed by the fetch: it has no "update", "comments" nor "kinds"'
    ]

    # A connector that fetches and cannot mirror says why, in a sentence; not both, and not without a fetch.
    why = "The product keeps no object for an alert: there is nothing to read again."
    silent = cn.load(cut + f'no_mirror: "{why}"\n')
    assert silent.mirror is None and cn.summary(silent)["noMirror"] == why
    assert problems(HELPDESK + f'no_mirror: "{why}"\n') == [
        '"no_mirror" says why a connector that fetches does not mirror: with "fetch", no "mirror"'
    ]
    assert "at least 20 characters" in problems(cut + "no_mirror: too short\n")[0]


def test_a_file_that_fetches_and_says_nothing_of_mirroring_loads_with_a_warning(admin: TestClient):
    """The rule of the shipped connectors, for the files people write: a warning with its line, never
    a refusal. Their connectors load and are installed as before."""
    cut = HELPDESK[: HELPDESK.index("mirror:")]
    (warning,) = cn.warnings(cut)
    assert warning.message == cn.NO_MIRROR_SAID and warning.where == "fetch"
    assert cut.splitlines()[warning.line - 1].startswith("fetch:")
    why = "The product keeps no object for an alert: there is nothing to read again."
    assert cn.warnings(HELPDESK) == [] and cn.warnings(cut + f'no_mirror: "{why}"\n') == []
    # One that does not fetch has nothing to say of it; one that does not load has its problems.
    assert cn.warnings(cut[: cut.index("fetch:")]) == [] and cn.warnings("name: x\n") == []

    checked = admin.post(f"{BASE}/connectors/check", json={"source": cut}).json()
    assert checked["problems"] == [] and checked["connector"]["mirror"] is None
    assert checked["warnings"] == [{"line": warning.line, "message": cn.NO_MIRROR_SAID, "where": "fetch"}]
    assert admin.post(f"{BASE}/connectors/check", json={"source": HELPDESK}).json()["warnings"] == []
    broken = admin.post(f"{BASE}/connectors/check", json={"source": "name: x\n"}).json()
    assert broken["problems"] and broken["warnings"] == []
    made = admin.post(f"{BASE}/connectors", json={"source": cut})
    assert made.status_code == 201 and made.json()["warnings"] == checked["warnings"]
    assert admin.post(f"{BASE}/connectors", json={"source": HELPDESK}).json()["warnings"] == []


def test_a_native_connector_mirrors_by_its_fetch_and_never_by_a_command():
    text, mail = next((text, connector) for text, connector in vendor.connectors() if connector.id == "mail")
    assert mail.native == "mail" and mail.mirror.get is None and mail.mirror.thread is not None
    assert mail.mirror.id == "{{ item.message_id }}"
    said = cn.summary(mail)["mirror"]
    assert (said["out"], said["fed"], said["fieldsIn"], said["comments"]) == (False, True, False, True)
    with_get = text.replace("mirror:\n", "mirror:\n  get: { command: get-message }\n", 1)
    assert problems(with_get) == ['the "mirror" of a native connector is fed by its fetch: "thread", and no "get"']


# --------------------------------------------------------------------------- #
# The choice of an instance                                                   #
# --------------------------------------------------------------------------- #
def test_an_instance_that_says_nothing_mirrors_nothing_and_says_what_it_could(admin: TestClient, outside):
    connection, world = helpdesk(admin, outside)
    said = held_by(admin, connection)["fetch"]["mirror"]
    assert (said["direction"], said["allow"], said["offered"]) == ("none", [], ["none", "in", "out", "both"])
    assert said["can"] == {"fieldsIn": True, "commentsIn": True, "fieldsOut": True, "commentsOut": True}
    assert said["fed"] is False and said["noMirror"] == ""
    assert "incident_text" in [item["id"] for item in said["classes"]]
    assert choose(admin, connection).status_code == 200
    assert fetch_now(admin, connection)["created"] == 2
    one = fetched("101")
    assert shown(admin, one)["mirrored"] is False and jobs() == []
    with SessionLocal() as db:
        # Nothing is written to the instance for a choice it did not make.
        assert db.get(Connection, connection["id"]).fetch_settings is None
        assert mirror.due(db, T0 + 9e9) == []
    del world


def test_in_out_the_incident_follows_the_other_side_and_the_other_side_follows_it_once(admin: TestClient, outside):
    connection, world = helpdesk(admin, outside)
    changed = choose(admin, connection, mirror="both")
    assert changed.status_code == 200, changed.text
    assert changed.json()["fetch"]["mirror"]["direction"] == "both"
    with SessionLocal() as db:
        assert db.get(Connection, connection["id"]).fetch_settings == {"mirror": "both"}
        entry = audited(db, "connection.update")[-1]
        assert "mirroring None → In-out" in entry.details
    assert fetch_now(admin, connection)["created"] == 2
    one = fetched("101")
    said = shown(admin, one)
    # The object is what the connector says of the item (its key), not the id the fetch tells it apart by.
    assert (said["id"], said["direction"], said["origin"], said["dataAllow"]) == ("T-101", "both", "instance", [])
    assert (said["startedBy"], said["gone"], said["fed"]) == ("connector:helpdesk", False, False)
    assert said["lastPull"] is None and said["lastPush"] is None

    # In: the other side moves, the incident follows.
    world.tickets["T-101"].update(state="work", title="Laptop of finance (stolen)")
    world.comments["T-101"] = [{"id": "c1", "body": "User called.", "by": "desk", "at": "2026-11-21T09:00:00Z"}]
    done = sync(admin, one)
    assert sorted(done["changed"]) == ["name", "status"] and done["comments"] == 1
    assert status_of(admin, one) == "in_progress" and done["mirror"]["lastPull"]
    assert jobs() == []  # what came from there is not sent back

    # Out: a person changes the status here; the other side receives exactly one update.
    assert admin.patch(f"/api/incidents/{one}", json={"status": "open"}).status_code == 200
    assert jobs() == [("update", "pending")]
    push_all()
    assert world.updates() == [{"title": "Laptop of finance (stolen)", "state": "new"}]
    assert shown(admin, one)["lastPush"]
    # Reading again finds what was just written: nothing changes, nothing is queued, nothing is sent twice.
    again = sync(admin, one)
    assert again["changed"] == [] and jobs() == [("update", "done")]
    push_all()
    assert len(world.updates()) == 1

    # A note tagged "mirror" goes out once and is known when it comes back.
    assert admin.post(f"/api/incidents/{one}/war-room", json={"text": "Wiped.", "tags": ["mirror"]}).status_code == 201
    push_all()
    assert [comment["body"] for comment in world.comments["T-101"]] == ["User called.", "Wiped."]
    assert sync(admin, one)["comments"] == 0

    # The other incident of the same fetch is mirrored on its own, with its own object.
    assert shown(admin, fetched("102"))["id"] == "T-102"


def test_in_only_reads_and_out_only_writes(admin: TestClient, outside):
    connection, world = helpdesk(admin, outside)
    assert choose(admin, connection, mirror="in").status_code == 200
    world.tickets.pop("T-102")
    fetch_now(admin, connection)
    one = fetched("101")
    assert shown(admin, one)["direction"] == "in"
    assert admin.patch(f"/api/incidents/{one}", json={"status": "in_progress"}).status_code == 200
    assert admin.post(f"/api/incidents/{one}/war-room", json={"text": "x", "tags": ["mirror"]}).status_code == 201
    assert jobs() == [] and world.sent == []
    with SessionLocal() as db:
        assert mirror.due(db, T0 + 9e9) == [one]

    # The choice is for what is fetched from then on: the incident there keeps its direction.
    assert choose(admin, connection, mirror="out").status_code == 200
    world.tickets["T-103"] = {"id": "103", "key": "T-103", "title": "Phone lost", "state": "new"}
    fetch_now(admin, connection)
    other = fetched("103")
    assert (shown(admin, one)["direction"], shown(admin, other)["direction"]) == ("in", "out")
    world.tickets["T-103"]["state"] = "closed"
    with SessionLocal() as db:
        assert mirror.due(db, T0 + 9e9) == [one]  # out only: the other side is not read
    assert admin.patch(f"/api/incidents/{other}", json={"status": "in_progress"}).status_code == 200
    push_all()
    assert world.updates() == [{"title": "Phone lost", "state": "work"}]


def test_a_mapper_that_names_the_object_and_the_direction_wins_over_the_instance(admin: TestClient, outside):
    connection, world = helpdesk(admin, outside)
    rules = [*INCOMING, {"to": "mirror_id", "from": "{{ item.key }}"}, {"to": "mirror_direction", "from": "in"}]
    saved = admin.put("/api/mappers", json={"connectorId": "helpdesk", "direction": "incoming", "rules": rules})
    assert saved.status_code == 200, saved.text
    # The instance says nothing: the mapper starts the mirror, as it did before instances had a choice.
    assert choose(admin, connection).status_code == 200
    world.tickets.pop("T-102")
    fetch_now(admin, connection)
    said = shown(admin, fetched("101"))
    assert (said["id"], said["direction"], said["origin"]) == ("T-101", "in", "mapper")
    # The instance says In-out: the mapper is still obeyed.
    assert choose(admin, connection, mirror="both").status_code == 200
    world.tickets["T-102"] = {"id": "102", "key": "T-102", "title": "Badge lost", "state": "new"}
    fetch_now(admin, connection)
    said = shown(admin, fetched("102"))
    assert (said["direction"], said["origin"]) == ("in", "mapper")

    # A mapper that names the object only: its id, in the direction of the instance.
    only_id = [*INCOMING, {"to": "mirror_id", "from": "{{ item.key }}"}]
    saved = admin.put("/api/mappers", json={"connectorId": "helpdesk", "direction": "incoming", "rules": only_id})
    assert saved.status_code == 200, saved.text
    world.tickets["T-104"] = {"id": "104", "key": "T-104", "title": "Screen broken", "state": "new"}
    fetch_now(admin, connection)
    said = shown(admin, fetched("104"))
    assert (said["id"], said["direction"], said["origin"]) == ("T-104", "both", "instance")
    # And with an instance that says nothing, an id alone starts nothing: as before.
    assert choose(admin, connection, mirror="none").status_code == 200
    world.tickets["T-105"] = {"id": "105", "key": "T-105", "title": "Mouse lost", "state": "new"}
    fetch_now(admin, connection)
    assert shown(admin, fetched("105"))["mirrored"] is False


# The two rules the incoming mappers of Jira and ServiceNow had until 6.10 (packs 1.0.1).
FORCED_IN = [{"to": "mirror_id", "from": "{{ item.sys_id }}"}, {"to": "mirror_direction", "from": "in"}]


def test_an_instance_as_6_9_left_it_goes_on_exactly_as_it_did(admin: TestClient, outside):
    """ServiceNow with the mappers 6.9 shipped (the incoming one names the object and says "in"),
    and an instance whose document is what 6.9 wrote: how it fetches, and nothing of mirroring."""
    text = next(text for text, connector in vendor.connectors() if connector.id == "servicenow")
    held = json.loads((DATA / "servicenow" / "connection.json").read_text(encoding="utf-8"))
    recorded = json.loads((DATA / "servicenow" / "fetch.json").read_text(encoding="utf-8"))
    assert admin.post(f"{BASE}/connectors", json={"source": text}).status_code == 201
    made = admin.post(
        f"{BASE}/instances",
        json={"name": "ServiceNow", "connector": "servicenow", "config": held["config"], "secrets": held["secrets"]},
    )
    assert made.status_code == 201, made.text
    connection = made.json()
    shipped = dict(vendor.mappers()["servicenow"])
    # The pack of 6.10 leaves the direction to the instance: these are the two rules it had until then.
    assert not {"mirror_id", "mirror_direction"} & {rule["to"] for rule in shipped["incoming"]}
    shipped["incoming"] = [*shipped["incoming"], *FORCED_IN]
    for direction in ("incoming", "outgoing"):
        body = {"connectorId": "servicenow", "direction": direction, "rules": shipped[direction]}
        assert admin.put("/api/mappers", json=body).status_code == 200
    host = urlsplit(held["config"]["url"]).hostname
    outside.host(host)
    answer = recorded["exchanges"][0]["response"]["json"]
    outside.answers.append(
        lambda method, to, target, _headers, _body: (
            (200, JSON, json.dumps(answer if "sysparm_offset=0" in target else {"result": []}).encode())
            if to == host and urlsplit(target).path == "/api/now/table/incident"
            else None
        )
    )
    with SessionLocal() as db:
        row = db.get(Connection, connection["id"])
        row.fetch_enabled = True
        row.fetch_settings = {"intervalSeconds": 300, "lookbackMinutes": 5}  # a 6.9 document
        db.commit()
    assert fetch_now(admin, connection)["new"] == len(recorded["item_ids"])
    with SessionLocal() as db:
        row = db.get(Connection, connection["id"])
        assert row.fetch_settings == {"intervalSeconds": 300, "lookbackMinutes": 5}
        assert mirror.choice_of(row) == ("none", [])
        incident_row = db.scalars(select(Incident).where(Incident.source_id == recorded["item_ids"][0])).one()
        state = incident_row.mirror
        # What 6.9 kept of a mirror, and one thing more: where its direction came from.
        assert {key: state[key] for key in ("connection", "id", "direction", "allow", "startedBy", "seen", "sent")} == {
            "connection": connection["id"],
            "id": recorded["item_ids"][0],
            "direction": "in",
            "allow": [],
            "startedBy": "connector:servicenow",
            "seen": [],
            "sent": [],
        }
        assert state["origin"] == "mapper" and "fed" not in state and "gone" not in state
        # A mirror 6.9 started has no origin written: it is read from who started it.
        assert mirror.origin_of({"startedBy": "connector:servicenow"}) == "mapper"
        assert mirror.origin_of({"startedBy": "anna"}) == "here"
        assert incident_row.fields["mirror_direction"] == "in"
    said = held_by(admin, connection)["fetch"]
    assert (said["intervalSeconds"], said["lookbackMinutes"], said["mirror"]["direction"]) == (300, 5, "none")


def servicenow_pack(*, before: bool) -> packs.PackFile:
    """The ServiceNow pack of the repository; or, with ``before``, as it was at 1.0.1: its mapper
    names the object and says "in", and its connector is a version older."""
    pack = packs.read(packs.folder_bytes(vendor.REPO_PACKS / "servicenow"))
    if not before:
        return pack
    items = []
    for item in pack.items:
        data = item.data
        if item.kind == "mappers":
            data = {**data, "incoming": [*data["incoming"], *FORCED_IN]}
        elif item.kind == "connectors":
            now = cn.load(data).version
            data = data.replace(f"\nversion: {now}\n", f"\nversion: {now - 1}\n", 1)
            assert cn.load(data).version == now - 1
        items.append(packs.Item(item.kind, item.name, data, item.extras))
    return packs.read(packs.write({**pack.manifest, "version": "1.0.1", "nik": ">=6.0"}, items, pack.logo))


def servicenow_world(outside, held: dict) -> list[dict]:
    """A ServiceNow that answers the fetch with the records it holds."""
    host = urlsplit(held["config"]["url"]).hostname
    outside.host(host)
    records: list[dict] = []
    outside.answers.append(
        lambda method, to, target, _headers, _body: (
            (200, JSON, json.dumps({"result": records if "sysparm_offset=0" in target else []}).encode())
            if to == host and urlsplit(target).path == "/api/now/table/incident"
            else None
        )
    )
    return records


def servicenow_held() -> tuple[dict, list[dict]]:
    """The settings of an instance, and the records the recorded fetch brings."""
    held = json.loads((DATA / "servicenow" / "connection.json").read_text(encoding="utf-8"))
    recorded = json.loads((DATA / "servicenow" / "fetch.json").read_text(encoding="utf-8"))
    return held, recorded["exchanges"][0]["response"]["json"]["result"]


def test_a_pack_that_stops_naming_the_direction_leaves_every_instance_mirroring_as_it_did(admin: TestClient, outside):
    """An install updated from the pack of before: its instances said None and mirrored In because the
    mapper said so. The new mapper says nothing, so the update writes In in those instances, says so
    in the audit log and in what it reports, and nobody has to touch anything. An instance a person
    gave a direction is left alone."""
    held, (first, *_rest) = servicenow_held()
    with SessionLocal() as db:
        done = packs.apply(db, servicenow_pack(before=True), {}, "admin")
        db.commit()
    assert done["added"] >= 2 and done["mirroring"] == []
    made = {}
    for name in ("SN prod", "SN test", "SN set by hand"):
        body = {"name": name, "connector": "servicenow", "config": held["config"], "secrets": held["secrets"]}
        made[name] = admin.post(f"{BASE}/instances", json=body).json()
    assert choose(admin, made["SN set by hand"], enabled=False, mirror="both").status_code == 200
    records = servicenow_world(outside, held)
    records.append(first)
    assert choose(admin, made["SN prod"]).status_code == 200
    assert fetch_now(admin, made["SN prod"])["created"] == 1
    old = fetched(first["sys_id"])
    before = shown(admin, old)
    assert (before["direction"], before["origin"], before["id"]) == ("in", "mapper", first["sys_id"])
    assert held_by(admin, made["SN prod"])["fetch"]["mirror"]["direction"] == "none"

    # The update, as the Packs page applies it: nothing is asked about mirroring.
    with SessionLocal() as db:
        plan = packs.plan(db, servicenow_pack(before=False))
        assert {entry["kind"]: entry["action"] for entry in plan["items"]}["mappers"] == "update"
        done = packs.apply(db, servicenow_pack(before=False), {}, "admin")
        db.commit()
    assert done["mirroring"] == [{"connector": "servicenow", "direction": "in", "instances": ["SN prod", "SN test"]}]
    said = {name: held_by(admin, one)["fetch"]["mirror"]["direction"] for name, one in made.items()}
    assert said == {"SN prod": "in", "SN test": "in", "SN set by hand": "both"}
    with SessionLocal() as db:
        (entry,) = audited(db, "mirror.kept")
        assert entry.target == "servicenow"
        assert "Mirroring was set to In in the instances that said None" in entry.details
        assert entry.details.endswith("so that they mirror as before: SN prod, SN test")
        # How it fetches is as it was: only the direction was written.
        assert db.get(Connection, made["SN prod"]["id"]).fetch_settings["mirror"] == "in"
    # The mirror that was there is untouched, and what is fetched from now on is mirrored In, by the instance.
    assert shown(admin, old) == before
    second = {**first, "sys_id": "0" * 31 + "7", "number": "INC0099999"}
    records.append(second)
    assert fetch_now(admin, made["SN prod"])["created"] == 1
    after = shown(admin, fetched(second["sys_id"]))
    assert (after["direction"], after["origin"], after["id"]) == ("in", "instance", second["sys_id"])
    # The same pack again changes nothing more, and writes nothing more.
    with SessionLocal() as db:
        assert packs.apply(db, servicenow_pack(before=False), {}, "admin")["mirroring"] == []
        db.commit()
        assert len(audited(db, "mirror.kept")) == 1


def test_a_mapper_someone_kept_goes_on_naming_the_direction_and_no_instance_is_changed(admin: TestClient, outside):
    """The update with the mapper left out (it was changed here and the person keeps it): it still
    names the object and the direction, it is still obeyed first, and no instance is written to."""
    held, (first, *_rest) = servicenow_held()
    with SessionLocal() as db:
        packs.apply(db, servicenow_pack(before=True), {}, "admin")
        db.commit()
    body = {"name": "SN prod", "connector": "servicenow", "config": held["config"], "secrets": held["secrets"]}
    connection = admin.post(f"{BASE}/instances", json=body).json()
    with SessionLocal() as db:
        done = packs.apply(db, servicenow_pack(before=False), {"mappers/servicenow": "skip"}, "admin")
        db.commit()
        assert done["mirroring"] == [] and done["skipped"] == 1 and audited(db, "mirror.kept") == []
    assert held_by(admin, connection)["fetch"]["mirror"]["direction"] == "none"
    records = servicenow_world(outside, held)
    records.append(first)
    assert choose(admin, connection).status_code == 200
    fetch_now(admin, connection)
    said = shown(admin, fetched(first["sys_id"]))
    assert (said["direction"], said["origin"]) == ("in", "mapper")


def test_a_new_install_of_the_pack_starts_at_none(admin: TestClient, outside):
    held, found = servicenow_held()
    with SessionLocal() as db:
        assert packs.apply(db, servicenow_pack(before=False), {}, "admin")["mirroring"] == []
        db.commit()
    body = {"name": "SN new", "connector": "servicenow", "config": held["config"], "secrets": held["secrets"]}
    connection = admin.post(f"{BASE}/instances", json=body).json()
    records = servicenow_world(outside, held)
    records.extend(found)
    assert choose(admin, connection).status_code == 200
    assert held_by(admin, connection)["fetch"]["mirror"]["direction"] == "none"
    assert fetch_now(admin, connection)["created"] == len(found)
    assert shown(admin, fetched(found[0]["sys_id"]))["mirrored"] is False
    with SessionLocal() as db:
        assert audited(db, "mirror.kept") == []


def test_the_choice_is_given_to_what_was_fetched_before_only_when_asked(admin: TestClient, outside):
    connection, world = helpdesk(admin, outside)
    aside = HELPDESK.replace("helpdesk", "sidedesk").replace("Helpdesk", "Sidedesk")
    other, _world = helpdesk(admin, outside, aside, "Side desk", world)
    world.tickets["T-103"] = {"id": "103", "key": "T-103", "title": "Phone lost", "state": "new"}
    world.tickets["T-104"] = {"id": "104", "key": "T-104", "title": "Screen broken", "state": "new"}
    assert choose(admin, connection).status_code == 200
    assert fetch_now(admin, connection)["created"] == 4
    ids = {key: fetched(key) for key in ("101", "102", "103", "104")}
    # One is closed; one a person mirrored with another instance.
    assert admin.patch(f"/api/incidents/{ids['104']}", json={"status": "closed"}).status_code == 200
    by_hand = {"instanceId": other["id"], "mirrorId": "T-103", "direction": "in"}
    assert admin.post(f"/api/incidents/{ids['103']}/mirror", json=by_hand).status_code == 201

    assert choose(admin, connection, mirror="in").status_code == 200
    # Saving the choice touched nothing that was there.
    assert [shown(admin, ids[key])["mirrored"] for key in ("101", "102", "103")] == [False, False, True]
    path = f"/api/fetch/{connection['id']}/mirror"
    assert admin.get(path).json() == {"open": 3, "mirrored": 0, "direction": "in", "most": mirror.APPLY_MAX}
    assert admin.post(f"{path}/apply").json() == {
        "started": 2, "changed": 0, "stopped": 0, "unchanged": 0, "skipped": 1
    }  # fmt: skip
    said = shown(admin, ids["101"])
    assert (said["id"], said["direction"], said["origin"], said["startedBy"]) == ("T-101", "in", "instance", "admin")
    assert shown(admin, ids["103"])["connection"] == "Side desk"  # left as the person set it
    assert shown(admin, ids["104"])["mirrored"] is False  # closed: not among the open ones
    assert admin.get(path).json()["mirrored"] == 2

    # Another direction changes them and keeps what they saw; the same one again changes nothing.
    assert choose(admin, connection, mirror="both").status_code == 200
    assert admin.post(f"{path}/apply").json()["changed"] == 2
    assert admin.post(f"{path}/apply").json() == {
        "started": 0, "changed": 0, "stopped": 0, "unchanged": 2, "skipped": 1
    }  # fmt: skip
    assert shown(admin, ids["102"])["direction"] == "both"
    # None stops them, and what waited to be sent is dropped.
    assert admin.patch(f"/api/incidents/{ids['101']}", json={"status": "in_progress"}).status_code == 200
    assert jobs() == [("update", "pending")]
    assert choose(admin, connection, mirror="none").status_code == 200
    assert admin.post(f"{path}/apply").json()["stopped"] == 2
    assert shown(admin, ids["101"])["mirrored"] is False and jobs() == [("update", "failed")]
    assert shown(admin, ids["103"])["mirrored"] is True
    with SessionLocal() as db:
        applied = [entry.details for entry in audited(db, "mirror.apply")]
    assert len(applied) == 4 and applied[0] == (
        'Applied mirroring In of "Helpdesk prod" to the open incidents it fetched: 2 started, 1 skipped'
    )
    assert applied[-1].endswith("2 stopped, 1 skipped")
    # Managing connectors is what it takes; reading is not enough.
    reader = make_key(admin, label="v", roles=["viewer"])
    assert admin.get(path, headers=reader).status_code == 403
    assert admin.post(f"{path}/apply", headers=reader).status_code == 403


def test_what_an_instance_lets_its_mirrors_send(admin: TestClient, outside):
    connection, world = helpdesk(admin, outside)
    world.tickets.pop("T-102")
    world.tickets["T-101"]["title"] = "Phish from eve@evil.example"
    # Who manages connectors chooses None or In. A direction that sends takes the permission to run
    # playbooks as well, as starting such a mirror on an incident does; opening a class of data takes
    # the permission that opens them.
    manager = person(admin, "carla", ["connectors"])
    assert choose(manager, connection, mirror="in").status_code == 200
    for sending in ("out", "both"):
        refused = choose(manager, connection, mirror=sending)
        assert (refused.status_code, refused.json()["detail"]) == (
            403,
            "Sending to another system needs the permission to run playbooks",
        )
    assert held_by(admin, connection)["fetch"]["mirror"]["direction"] == "in"
    sender = person(admin, "dora", ["connectors", "analyst"])
    assert choose(sender, connection, mirror="both").status_code == 200
    # What is saved already is saved again with the rest of the form, and taken back, by who manages connectors.
    assert choose(manager, connection, mirror="both", intervalSeconds=300).status_code == 200
    apply = f"/api/fetch/{connection['id']}/mirror/apply"
    assert manager.post(apply).status_code == 403 and sender.post(apply).status_code == 200
    assert choose(manager, connection, mirror="none").status_code == 200
    assert manager.post(apply).status_code == 200
    assert choose(sender, connection, mirror="both").status_code == 200
    refused = choose(manager, connection, mirrorAllow=["email_address"])
    assert (refused.status_code, refused.json()["detail"]) == (
        403,
        "Opening a class of data needs the permission that opens them",
    )
    wrong = choose(admin, connection, mirrorAllow=["whole_message"])
    assert wrong.status_code == 400 and "is not a class of data an instance can open" in wrong.json()["detail"]
    assert choose(admin, connection, mirror="sideways").json()["detail"] == "Mirroring is none, in, out or both"

    # No class opened: what holds an e-mail address is held back, and the queue says why.
    fetch_now(admin, connection)
    one = fetched("101")
    assert admin.patch(f"/api/incidents/{one}", json={"status": "in_progress"}).status_code == 200
    push_all()
    (job,) = admin.get("/api/mirror/queue").json()["jobs"]
    assert job["attempts"] == 1 and "e-mail" in job["error"].lower() and world.updates() == []

    # The class opened in the instance is what the mirrors of the incidents fetched from then on may send.
    opened = choose(admin, connection, mirrorAllow=["email_address", "incident_text"])
    assert opened.status_code == 200 and opened.json()["fetch"]["mirror"]["allow"] == ["email_address", "incident_text"]
    with SessionLocal() as db:
        entry = audited(db, "connection.update")[-1]
        assert "its mirrors may send: email_address, incident_text" in entry.details
    assert shown(admin, one)["dataAllow"] == []
    world.tickets["T-106"] = {"id": "106", "key": "T-106", "title": "Phish from bob@evil.example", "state": "new"}
    fetch_now(admin, connection)
    other = fetched("106")
    assert shown(admin, other)["dataAllow"] == ["email_address", "incident_text"]
    assert admin.patch(f"/api/incidents/{other}", json={"status": "in_progress"}).status_code == 200
    push_all(T0 + 10)
    assert world.updates() == [{"title": "Phish from bob@evil.example", "state": "work"}]
    # A direction that sends nothing holds no class.
    assert choose(admin, connection, mirror="in").json()["fetch"]["mirror"]["allow"] == []


def test_a_connector_is_offered_only_what_it_can_do(admin: TestClient, outside):
    reading = HELPDESK[: HELPDESK.index("  update:\n    command: update-ticket")]
    reading += '  comments:\n    list: { command: get-comments }\n    text: "{{ item.body }}"\n'
    connection, world = helpdesk(admin, outside, reading)
    said = held_by(admin, connection)["fetch"]["mirror"]
    assert (
        said["offered"] == ["none", "in"] and said["can"]["fieldsOut"] is False and said["can"]["commentsOut"] is False
    )
    refused = choose(admin, connection, mirror="both")
    assert (refused.status_code, refused.json()["detail"]) == (
        400,
        "Helpdesk is read and never written to: mirroring with it is None or In",
    )
    assert choose(admin, connection, mirror="in").status_code == 200

    why = "Radar keeps no object for an alert: there is nothing to read again."
    silent = HELPDESK[: HELPDESK.index("mirror:")].replace("helpdesk", "radar").replace("Helpdesk", "Radar")
    radar, _world = helpdesk(admin, outside, silent + f'no_mirror: "{why}"\n', "Radar", world)
    said = held_by(admin, radar)["fetch"]["mirror"]
    assert (said["offered"], said["can"], said["noMirror"]) == (["none"], None, why)
    refused = choose(admin, radar, mirror="in")
    assert (refused.status_code, refused.json()["detail"]) == (400, f"Radar does not mirror: {why}")
    assert choose(admin, radar, mirror="none").status_code == 200


# --------------------------------------------------------------------------- #
# On the incident                                                             #
# --------------------------------------------------------------------------- #
def test_the_direction_is_changed_on_one_incident_and_is_then_set_here(admin: TestClient, outside):
    connection, world = helpdesk(admin, outside)
    world.tickets.pop("T-102")
    assert choose(admin, connection, mirror="both").status_code == 200
    fetch_now(admin, connection)
    one = fetched("101")
    anna = person(admin, "anna", ["analyst"])
    reader = make_key(admin, label="v", roles=["viewer"])
    writer = make_key(admin, label="w", roles=["viewer", "rules"])
    path = f"/api/incidents/{one}/mirror"
    assert admin.patch(path, headers=reader, json={"direction": "in"}).status_code == 403
    # Who writes incidents and runs no playbook may turn a mirror to In, and not back to one that sends.
    assert admin.patch(f"/api/incidents/{one}", json={"status": "in_progress"}).status_code == 200
    assert jobs() == [("update", "pending")]
    turned = anna.patch(path, json={"direction": "in"})
    assert turned.status_code == 200 and (turned.json()["direction"], turned.json()["origin"]) == ("in", "here")
    assert jobs() == [("update", "failed")]  # what waited is not sent by a mirror that only reads
    assert anna.patch(path, json={"direction": "both", "dataAllow": ["email_address"]}).status_code == 403
    assert anna.patch(path, json={"direction": "both"}).status_code == 200
    assert admin.patch(path, json={"direction": "out", "dataAllow": ["email_address"]}).json()["dataAllow"] == [
        "email_address"
    ]
    assert admin.patch(path, json={"direction": "sideways"}).status_code == 422
    with SessionLocal() as db:
        said = [entry.details for entry in audited(db, "mirror.direction")]
    assert said[0] == "Mirroring with Helpdesk prod, object T-101: direction both → in"
    assert said[-1].endswith("direction both → out, sending email_address")
    lines = [entry["body"].get("text", "") for entry in admin.get(f"/api/incidents/{one}/war-room").json()["entries"]]
    assert "anna changed mirroring with Helpdesk prod from both to in" in lines
    # An incident that is not mirrored has no direction to change.
    incident(admin)
    assert admin.patch("/api/incidents/i1/mirror", json={"direction": "in"}).status_code == 409
    del writer


def test_an_object_gone_on_the_other_side_is_said_once_and_read_no_more(admin: TestClient, outside):
    connection, world = helpdesk(admin, outside)
    assert choose(admin, connection, mirror="both").status_code == 200
    fetch_now(admin, connection)
    one = fetched("101")
    assert sync(admin, one)["problems"] == []
    kept = world.tickets.pop("T-101")
    with SessionLocal() as db:
        assert one in mirror.due(db, T0 + 9e9)
    mirror.run_pull(one, T0 + 500)  # the worker finds it gone
    said = shown(admin, one)
    assert said["gone"] is True and said["error"] == mirror.GONE and said["mirrored"] is True

    def said_once() -> tuple[int, int]:
        lines = admin.get(f"/api/incidents/{one}/war-room").json()["entries"]
        with SessionLocal() as db:
            told = db.scalars(select(Notification).where(Notification.kind == "mirror.gone")).all()
        return len([line for line in lines if "is gone from Helpdesk prod" in line["body"].get("text", "")]), len(told)

    assert said_once() == (1, 1)
    with SessionLocal() as db:
        # Not every two minutes for ever: it is not due again, however much time passes.
        assert one not in mirror.due(db, T0 + 9e9) and fetched("102") in mirror.due(db, T0 + 9e9)
    # Read by hand: still gone, and not said again. Nothing is queued for an object that is not there.
    again = sync(admin, one)
    assert again["gone"] is True and again["changed"] == [] and said_once() == (1, 1)
    assert admin.patch(f"/api/incidents/{one}", json={"status": "in_progress"}).status_code == 200
    assert jobs() == []
    # It is back (restored there): reading by hand finds it, and the worker reads it again.
    world.tickets["T-101"] = {**kept, "state": "closed"}
    back = sync(admin, one)
    assert "gone" not in back and back["mirror"]["gone"] is False and back["mirror"]["error"] == ""
    with SessionLocal() as db:
        assert one in mirror.due(db, T0 + 9e9)


def test_a_kind_of_object_is_read_and_written_by_its_own_commands(admin: TestClient, outside):
    connection, world = helpdesk(admin, outside)
    incident(admin)
    started = admin.post(
        "/api/incidents/i1/mirror", json={"instanceId": connection["id"], "mirrorId": "task:K-1", "direction": "both"}
    )
    assert started.status_code == 201, started.text
    assert (started.json()["id"], started.json()["origin"]) == ("task:K-1", "here")
    # A task has no comments in this connector: what it can do is said of the kind.
    assert started.json()["can"] == {"fieldsIn": True, "commentsIn": False, "fieldsOut": True, "commentsOut": False}
    assert sorted(sync(admin, "i1")["changed"]) == ["name", "ticket"]
    assert admin.get("/api/incidents/i1/fields").json()["fields"]["name"] == "Wipe the laptop"
    assert admin.patch("/api/incidents/i1", json={"status": "in_progress"}).status_code == 200
    push_all()
    # Its own command, given the id without the kind, and the kind where the file asks for it.
    assert world.sent == [("PUT", "/tasks/K-1", {"state": "work", "of": "task"})]
    # A task that is not in the list any more: the list comes back empty, and the object is gone.
    world.tasks.clear()
    assert sync(admin, "i1")["gone"] is True


def test_a_restart_sends_an_update_again_and_never_a_comment(admin: TestClient, outside):
    """The rule of 6.9 holds for a mirror an instance started."""
    connection, world = helpdesk(admin, outside)
    world.tickets.pop("T-102")
    assert choose(admin, connection, mirror="both").status_code == 200
    fetch_now(admin, connection)
    one = fetched("101")
    assert admin.patch(f"/api/incidents/{one}", json={"status": "in_progress"}).status_code == 200
    assert admin.post(f"/api/incidents/{one}/war-room", json={"text": "Wiped.", "tags": ["mirror"]}).status_code == 201
    with SessionLocal() as db:
        for job in db.scalars(select(MirrorJob)):
            job.status, job.holder = "sending", "a-worker-that-died"
        db.commit()
        assert mirror.take_back(db, T0, "me") == 2
    assert sorted(jobs()) == [("comment", "failed"), ("update", "pending")]
    push_all()
    assert world.updates() == [{"title": "Laptop of finance", "state": "work"}] and world.comments == {}

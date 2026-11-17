"""Tasks and questions: what a playbook waits a person for, and tasks added by hand."""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy import select

from app import tasks
from app.automation import worker
from app.core.db import SessionLocal
from app.core.models import Notification, Run, RunStep, Task
from app.main import app
from tests.conftest import make_key
from tests.test_automation_engine import (  # noqa: F401 - test_actions is a fixture
    T0,
    echo,
    edge,
    go,
    node,
    playbook,
    run_of,
    steps,
    test_actions,
)
from tests.test_fields import field, incident

PASSWORD = "Correct-horse-battery-9"


def person(admin: TestClient, name: str, roles: list[str]) -> TestClient:
    """An account, signed in on a client of its own."""
    made = admin.post("/api/users", json={"username": name, "password": PASSWORD, "roles": roles})
    assert made.status_code == 201, made.text
    client = TestClient(app)
    assert client.post("/api/auth/login", json={"username": name, "password": PASSWORD}).status_code == 200
    return client


def later(now: float) -> None:
    """Let the worker do what is due at ``now``: the pending steps, and what time does to tasks."""
    with SessionLocal() as db:
        for step in db.scalars(select(RunStep).where(RunStep.status == "pending")):
            step.next_at = now
        db.commit()
        tasks.tick(db, now)
    with SessionLocal() as db:
        for step in db.scalars(select(RunStep).where(RunStep.status == "pending")):
            step.next_at = now
        db.commit()
    worker.drain(now)


def the_tasks(client: TestClient, headers: dict | None = None, **params) -> list[dict]:
    answer = client.get("/api/tasks", params=params, headers=headers)
    assert answer.status_code == 200, answer.text
    return answer.json()["tasks"]


def test_a_task_holds_the_run_until_the_person_it_is_for_does_it(admin: TestClient):
    incident(admin)
    field(admin, "badge_number", "number")
    anna = person(admin, "anna", ["analyst"])
    bruno = person(admin, "bruno", ["analyst"])
    nodes = [
        node(
            "collect",
            "task",
            title="Collect the laptop of {{ incident.name }}",
            instructions="Bag it and **label** it.",
            assignee={"user": "anna"},
            fields=["badge_number"],
            phase="Containment",
        ),
        echo("after", "by {{ collect.by }}: {{ collect.fields.badge_number }} ({{ collect.comment }})"),
    ]
    pb = playbook(admin, "Collect", nodes, [edge("start", "collect"), edge("collect", "after", "done")])

    run = go(admin, pb, objectKind="incident", objectId="i1")
    assert run["status"] == "waiting" and steps(run)["collect"]["status"] == "waiting"
    (task,) = the_tasks(anna)
    assert task["title"] == "Collect the laptop of Laptop of finance" and task["for"] == "anna"
    assert (task["kind"], task["status"], task["incidentId"], task["mine"]) == ("task", "open", "i1", True)
    assert [item["name"] for item in task["fields"]] == ["badge_number"] and task["fields"][0]["type"] == "number"
    assert anna.get("/api/tasks/count").json() == {"mine": 1, "overdue": 0}
    # It is nobody else's: not in their list, and not theirs to complete.
    assert the_tasks(bruno) == [] and bruno.get("/api/tasks/count").json()["mine"] == 0
    assert the_tasks(bruno, which="all", incident="i1")[0]["mine"] is False
    refused = bruno.post(f"/api/tasks/{task['id']}/complete", json={})
    assert (refused.status_code, refused.json()["detail"]) == (403, "This task is for anna")
    # She was told.
    with SessionLocal() as db:
        (told,) = db.scalars(select(Notification).where(Notification.username == "anna")).all()
        assert (told.kind, told.link) == ("task", f"/tasks/{task['id']}")

    # The fields it asks for are needed, and are checked as the registry says.
    missing = anna.post(f"/api/tasks/{task['id']}/complete", json={"comment": "done"})
    assert (missing.status_code, missing.json()["detail"]) == (400, "Needed: badge_number")
    wrong = anna.post(f"/api/tasks/{task['id']}/complete", json={"fields": {"badge_number": "many"}})
    assert wrong.status_code == 400
    assert run_of(admin, run["id"])["status"] == "waiting"

    done = anna.post(
        f"/api/tasks/{task['id']}/complete", json={"fields": {"badge_number": 4471}, "comment": "In the safe"}
    )
    assert done.status_code == 200, done.text
    assert (done.json()["status"], done.json()["completedBy"]) == ("done", "anna")
    assert anna.post(f"/api/tasks/{task['id']}/complete", json={}).status_code == 409
    # The field is written to the incident, and the run goes on with the answer.
    assert admin.get("/api/incidents/i1").json()["fields"]["badge_number"] == 4471
    later(T0)
    run = run_of(admin, run["id"])
    assert run["status"] == "done"
    assert steps(run)["collect"]["port"] == "done"
    assert steps(run)["after"]["output"]["text"] == "by anna: 4471 (In the safe)"

    # The War Room of the incident tells it, and the page of the task shows that slice.
    shown = admin.get(f"/api/tasks/{task['id']}").json()
    assert [(entry["body"]["state"], entry["author"]) for entry in shown["entries"]] == [
        ("asked", "nik-automation"),
        ("done", "anna"),
    ]
    assert the_tasks(anna) == [] and the_tasks(admin, which="all", status="closed")[0]["id"] == task["id"]
    assert admin.get("/api/tasks/nope").status_code == 404


def test_a_task_is_for_a_role_or_for_whoever_owns_the_incident_when_it_is_done(admin: TestClient):
    incident(admin)
    anna = person(admin, "anna", ["analyst"])
    bruno = person(admin, "bruno", ["analyst"])
    reader = person(admin, "rita", ["viewer"])
    nodes = [
        node("review", "task", title="Review the rules", assignee={"role": "rules"}),
        node("call", "task", title="Call the user"),  # nobody named: the owner of the incident
    ]
    pb = playbook(admin, "Two", nodes, [edge("start", "review"), edge("start", "call")])
    run = go(admin, pb, objectKind="incident", objectId="i1")
    by_title = {task["title"]: task for task in the_tasks(admin, which="all")}
    review, call = by_title["Review the rules"], by_title["Call the user"]
    assert review["for"] == "the role rules" and call["for"] == "the owner of the incident"

    # A role: whoever holds it, and nobody else (an admin can always).
    assert anna.post(f"/api/tasks/{review['id']}/complete", json={}).status_code == 403
    carla = person(admin, "carla", ["viewer", "rules"])
    assert [task["id"] for task in the_tasks(carla)] == [review["id"]]
    assert carla.post(f"/api/tasks/{review['id']}/complete", json={}).status_code == 200

    # The owner: with nobody on the incident, whoever works incidents; then the one who has it.
    assert reader.post(f"/api/tasks/{call['id']}/complete", json={}).status_code == 403
    assert the_tasks(anna) == []  # not hers until the incident is
    assert admin.patch("/api/incidents/i1/fields", json={"changes": {"owner": "bruno"}}).status_code == 200
    assert [task["id"] for task in the_tasks(bruno)] == [call["id"]]
    assert anna.post(f"/api/tasks/{call['id']}/complete", json={}).status_code == 403
    assert bruno.post(f"/api/tasks/{call['id']}/complete", json={"comment": "No answer"}).status_code == 200
    later(T0)
    assert run_of(admin, run["id"])["status"] == "done"


def test_a_question_leaves_by_the_port_of_its_answer(admin: TestClient):
    incident(admin)
    anna = person(admin, "anna", ["analyst"])
    nodes = [
        node(
            "what",
            "ask",
            question="Is the laptop of {{ incident.name }} encrypted?",
            choices=["Yes", "No, not at all"],
            inputs=[
                {"name": "serial", "label": "Serial number", "type": "text", "required": True},
                {"name": "disks", "type": "number"},
                {"name": "docked", "type": "bool"},
            ],
        ),
        echo("fine", "encrypted {{ what.values.serial }}"),
        echo("wipe", "wipe {{ what.values.serial }} x{{ what.values.disks }} {{ what.choice }}"),
        echo("nobody", "nobody"),
    ]
    edges = [
        edge("start", "what"),
        edge("what", "fine", "yes"),
        edge("what", "wipe", "no_not_at_all"),
        edge("what", "nobody", "timeout"),
    ]
    pb = playbook(admin, "Ask", nodes, edges)
    run = go(admin, pb, objectKind="incident", objectId="i1")
    assert run["status"] == "waiting"
    # A question with nobody named is for anyone who works incidents.
    (task,) = the_tasks(anna, which="all")
    assert (task["kind"], task["for"], task["mine"]) == ("ask", "anyone", True)
    assert [item["id"] for item in the_tasks(anna)] == [task["id"]]  # asked of anyone: in everyone's list
    assert the_tasks(admin, headers=make_key(admin, label="r", roles=["viewer"])) == []
    assert task["choices"] == [{"label": "Yes", "port": "yes"}, {"label": "No, not at all", "port": "no_not_at_all"}]
    assert [item["name"] for item in task["inputs"]] == ["serial", "disks", "docked"]

    url = f"/api/tasks/{task['id']}/complete"
    assert anna.post(url, json={"values": {"serial": "X1"}}).json()["detail"] == "Choose one of: Yes, No, not at all"
    assert anna.post(url, json={"choice": "Yes"}).json()["detail"] == "Needed: Serial number"
    bad = anna.post(url, json={"choice": "Yes", "values": {"serial": "X1", "disks": "two"}})
    assert (bad.status_code, bad.json()["detail"]) == (400, "disks is a number")
    answered = anna.post(
        url, json={"choice": "no_not_at_all", "values": {"serial": "X1", "disks": "2", "docked": "no"}}
    )
    assert answered.status_code == 200, answered.text
    assert answered.json()["answer"]["values"] == {"serial": "X1", "disks": 2, "docked": False}
    later(T0)
    run = run_of(admin, run["id"])
    assert run["status"] == "done" and steps(run)["what"]["port"] == "no_not_at_all"
    assert steps(run)["wipe"]["output"]["text"] == "wipe X1 x2 No, not at all"
    assert "fine" not in steps(run) and "nobody" not in steps(run)  # branches not taken

    # A dry run asks nobody and shows the path of the first answer.
    dry = go(admin, pb, objectKind="incident", objectId="i1", dryRun=True)
    assert dry["status"] == "done" and steps(dry)["what"]["port"] == "yes"
    assert len(the_tasks(admin, which="all", status="all")) == 1


def test_time_reminds_marks_overdue_and_gives_a_question_up(admin: TestClient):
    incident(admin)
    anna = person(admin, "anna", ["analyst"])
    nodes = [
        node("do", "task", title="Pull the disk", assignee={"user": "anna"}, due="2h", reminder_seconds=1800),
        echo("chase", "late: {{ do.overdue }}"),
        echo("after", "done by {{ do.by }}"),
        node("ask", "ask", question="Still there?", assignee={"user": "anna"}, timeout_seconds=3600),
        echo("gone", "nobody answered"),
        echo("here", "here"),
    ]
    edges = [
        edge("start", "do"),
        edge("do", "after", "done"),
        edge("do", "chase", "overdue"),
        edge("start", "ask"),
        edge("ask", "here", "answered"),
        edge("ask", "gone", "timeout"),
    ]
    pb = playbook(admin, "Timed", nodes, edges)
    run = go(admin, pb, objectKind="incident", objectId="i1")
    by_kind = {task["kind"]: task for task in the_tasks(admin, which="all")}
    assert by_kind["task"]["dueAt"] == T0 + 7200

    def told(kind: str) -> int:
        with SessionLocal() as db:
            return len(db.scalars(select(Notification).where(Notification.kind == kind)).all())

    # A reminder at its interval, and again at the next.
    later(T0 + 1700)
    assert told("task.reminder") == 0
    later(T0 + 1801)
    later(T0 + 1900)
    assert told("task.reminder") == 1
    # The question nobody answered is given up: the run leaves it by "timeout".
    later(T0 + 3601)
    run = run_of(admin, run["id"])
    assert steps(run)["ask"]["port"] == "timeout" and steps(run)["gone"]["status"] == "done"
    assert "here" not in steps(run)
    assert run["status"] == "waiting"  # the task is still to do

    # Past its due time the task is overdue and stays to do; the run also leaves by "overdue".
    later(T0 + 7201)
    run = run_of(admin, run["id"])
    assert steps(run)["do"]["status"] == "waiting" and steps(run)["chase"]["output"]["text"] == "late: true"
    assert run["status"] == "waiting" and "after" not in steps(run)
    (task,) = the_tasks(admin, which="all")
    assert task["status"] == "overdue" and told("task.overdue") == 1
    later(T0 + 7300)  # once: not again at the next look
    assert told("task.overdue") == 1
    assert anna.get("/api/tasks/count").json() == {"mine": 1, "overdue": 1}
    assert admin.get("/api/tasks/count").json()["mine"] == 0  # an admin may do it; it is not theirs

    # Done late, the run goes on by "done" as well.
    assert admin.post(f"/api/tasks/{task['id']}/complete", json={}).status_code == 200
    later(T0 + 7400)
    run = run_of(admin, run["id"])
    assert run["status"] == "done" and steps(run)["after"]["output"]["text"] == "done by admin"
    # The time spent waiting for a person is not the playbook's (here, the hour the question waited).
    with SessionLocal() as db:
        assert db.get(Run, run["id"]).waited_seconds >= 3600


def test_a_run_that_ends_takes_its_open_tasks_with_it_and_a_task_can_be_skipped(admin: TestClient):
    incident(admin)
    nodes = [node("do", "task", title="Pull the disk"), echo("after", "skipped: {{ do.skipped }}")]
    pb = playbook(admin, "Stops", nodes, [edge("start", "do"), edge("do", "after", "done")])
    run = go(admin, pb, objectKind="incident", objectId="i1")
    assert admin.post(f"/api/automation/runs/{run['id']}/stop").status_code == 200
    (task,) = the_tasks(admin, which="all", status="all")
    assert task["status"] == "skipped" and task["answer"]["skipped"] == "The run ended (stopped)"

    run = go(admin, pb, objectKind="incident", objectId="i1")
    (task,) = the_tasks(admin, which="all")
    viewer = make_key(admin, label="v", roles=["viewer"])
    assert admin.post(f"/api/tasks/{task['id']}/skip", headers=viewer, json={}).status_code == 403
    assert admin.post(f"/api/tasks/{task['id']}/skip", json={"why": "The disk is gone"}).status_code == 200
    assert admin.post(f"/api/tasks/{task['id']}/skip", json={}).status_code == 409
    later(T0)
    run = run_of(admin, run["id"])
    assert run["status"] == "done" and steps(run)["after"]["output"]["text"] == "skipped: The disk is gone"


def test_a_task_is_added_by_hand_given_to_someone_else_and_typed_in_the_war_room(admin: TestClient):
    incident(admin)
    anna = person(admin, "anna", ["analyst"])
    made = admin.post(
        "/api/incidents/i1/tasks",
        json={"title": "  Write the report ", "instructions": "For legal.", "assignee": {"user": "ANNA"}, "due": "3d"},
    )
    assert made.status_code == 201, made.text
    task = made.json()
    assert (task["title"], task["for"], task["runId"], task["createdBy"]) == ("Write the report", "anna", None, "admin")
    assert task["dueAt"] > 0

    assert admin.post("/api/incidents/i1/tasks", json={"title": "x", "assignee": {"user": "nobody"}}).status_code == 400
    assert admin.post("/api/incidents/i1/tasks", json={"title": "x", "assignee": {"role": "kings"}}).status_code == 400
    assert admin.post("/api/incidents/i1/tasks", json={"title": "x", "due": "soon"}).status_code == 400
    both = {"title": "x", "assignee": {"user": "anna", "role": "analyst"}}
    assert admin.post("/api/incidents/i1/tasks", json=both).status_code == 400
    assert admin.post("/api/incidents/nope/tasks", json={"title": "x"}).status_code == 404
    viewer = make_key(admin, label="v", roles=["viewer"])
    assert admin.post("/api/incidents/i1/tasks", headers=viewer, json={"title": "x"}).status_code == 403

    # Given to a role instead.
    given = admin.put(f"/api/tasks/{task['id']}/assignee", json={"role": "analyst"})
    assert given.status_code == 200 and given.json()["for"] == "the role analyst"
    assert admin.put(f"/api/tasks/{task['id']}/assignee", json={}).status_code == 400
    assert anna.post(f"/api/tasks/{task['id']}/complete", json={"comment": "Sent"}).status_code == 200

    # Typed in the War Room.
    typed = admin.post("/api/incidents/i1/war-room/command", json={"line": "/task Call the user @anna due=2h"})
    assert typed.status_code == 201 and typed.json()["action"] == "task"
    (call,) = the_tasks(anna)
    assert (call["title"], call["for"]) == ("Call the user", "anna")
    assert admin.post("/api/incidents/i1/war-room/command", json={"line": "/task @anna"}).status_code == 400
    with SessionLocal() as db:
        assert db.get(Task, call["id"]).due_at is not None


def test_a_graph_with_tasks_and_questions_is_checked(admin: TestClient):
    created = admin.post("/api/automation/playbooks", json={"name": "Checked"}).json()["id"]

    def problems(nodes, edges) -> list[str]:
        shape = {"nodes": [node("start", "trigger", manual=True), *nodes], "edges": edges}
        answer = admin.post(f"/api/automation/playbooks/{created}/versions", json={"graph": shape})
        if answer.status_code == 201:
            return []
        return [item["message"] for item in answer.json()["problems"]]

    assert problems([node("t", "task")], [edge("start", "t")]) == ["What to do is needed"]
    wrong = node(
        "t",
        "task",
        title="x",
        assignee={"user": "a", "role": "analyst"},
        due="soon",
        reminder_seconds=5,
        fields=["nope"],
        phase="p" * 41,
    )
    assert problems([wrong], [edge("start", "t")]) == [
        "A phase is a name of 40 characters at most",
        "It is for one user, for one role, or for the owner of the incident",
        "Due in 1 minute to 90 days: seconds, or 30m, 2h, 3d",
        "A reminder every 5 minutes to 30 days",
        '"nope" is not a field of incidents that can be filled',
    ]
    assert problems([node("t", "task", title="x", assignee={"role": "kings"})], [edge("start", "t")])[0].startswith(
        "This role does not exist"
    )
    # A due time can be an expression: it is read when the task is made.
    assert problems([node("t", "task", title="x", due="{{ trigger.hours }}h")], [edge("start", "t")]) == []

    ask = node("q", "ask", question="Which?", choices=["A b", "a-b"])
    assert problems([ask], [edge("start", "q")]) == [
        'The choices are different from one another, and none is "timeout"'
    ]
    ask = node(
        "q", "ask", question="Which?", choices=["Go"], inputs=[{"name": "Bad name"}, {"name": "n", "type": "date"}]
    )
    assert problems([ask], [edge("start", "q")]) == [
        "What is asked for needs a name: lower-case letters, digits, _",
        "What is asked for is text, a number or yes/no",
    ]
    # The ports of a question are its choices.
    ask = node("q", "ask", question="Which?", choices=["Go", "Stop"])
    after = node("e", "end")
    assert problems([ask, after], [edge("start", "q"), edge("q", "e", "answered")]) == [
        'A ask node has no "answered" port'
    ]
    assert problems([ask, after], [edge("start", "q"), edge("q", "e")]) == [
        "An edge from a question says which answer it follows"
    ]
    assert problems([ask, after], [edge("start", "q"), edge("q", "e", "stop"), edge("q", "e", "timeout")]) == []
    # Not inside a "for each".
    loop = node("each", "for_each", items="{{ trigger.items }}")
    inside = node("t", "task", title="x")
    assert problems([loop, inside], [edge("start", "each"), edge("each", "t", "each")]) == [
        'A task or a question inside a "for each" is not supported: ask before the loop'
    ]

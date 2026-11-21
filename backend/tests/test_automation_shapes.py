"""What the editor offers inside a value is true: every path it lists is there when a playbook runs.

The catalog says what is inside an incident, its fields and its context
(``shapes``), and an output of an action that is an object or a list says what
is inside it (``shape``). The editor lists those paths as values to pick. Here
each of them is read by a run, real and dry: a path that led nowhere would
fail the step that reads it.
"""

# ruff: noqa: E501 (graphs of test playbooks read better on one line)

from __future__ import annotations

from fastapi.testclient import TestClient

from app import fields as registry
from app.automation import actions, payloads
from app.core.db import SessionLocal
from app.core.models import Incident, IocList, IocListItem
from tests.test_automation_engine import edge, go, incident, node, playbook, steps

# The actions of Nik that say what is inside an output, each run below. A new one is added here
# with a run that reads its paths: a test below fails until it is.
SHAPED = {
    "nik.get-incident",
    "nik.set-status",
    "nik.set-assignee",
    "nik.set-incident-field",
    "nik.create-incident",
    "nik.get-ioc-lists",
    "nik.make-indicators",
    "nik.recheck-list",
    "nik.reputation",
}


def act(node_id, action, **args):
    return node(node_id, "action", action=action, args=args)


def catalog(admin: TestClient) -> dict:
    found = admin.get("/api/automation/catalog")
    assert found.status_code == 200, found.text
    return found.json()


def paths_of(entry: dict, shapes: dict, node_id: str) -> list[str]:
    """Every path the editor lists under the outputs of a node of this action."""
    found = []
    for output in entry["outputs"]:
        found.append(f"{node_id}.{output['name']}")
        shape = output.get("shape")
        inside = shapes[shape] if isinstance(shape, str) else (shape or [])
        for item in inside:
            joint = "" if item["name"].startswith("[") else "."
            found.append(f"{node_id}.{output['name']}{joint}{item['name']}")
    return found


def reads(paths: list[str]) -> dict:
    """A node that reads every path: one that is not there fails it, and says which."""
    return node(
        "reads", "action", action="nik.add-note", args={"text": " ".join(f"{{{{ {path} | json }}}}" for path in paths)}
    )


def fill(incident_id: str, custom: dict) -> None:
    """Give the incident a value for every field of the registry, where each field lives."""
    with SessionLocal() as db:
        row = db.get(Incident, incident_id)
        doc, stored = dict(row.doc or {}), dict(row.fields or {})
        for name, spec in registry.SYSTEM_FIELDS.items():
            where, _, key = spec.where.partition(":")
            value = (
                "2026-11-19T09:00:00Z" if spec.type in ("date", "timer") else ["one"] if spec.type == "tags" else "x"
            )
            if where == "doc" and not doc.get(key):
                doc[key] = value
            elif where == "column" and not getattr(row, key):
                setattr(row, key, value)
            elif where == "json":
                stored[name] = True if spec.type == "bool" else value
        stored.update(custom)
        row.doc, row.fields = doc, stored
        db.commit()


def test_the_catalog_says_what_is_inside_an_incident_its_fields_and_its_context(admin: TestClient):
    made = admin.post(
        "/api/fields", json={"name": "business_unit", "label": "Business unit", "type": "text", "allTypes": True}
    )
    assert made.status_code == 201, made.text
    admin.post("/api/fields", json={"name": "first_seen_at", "type": "indicator", "allTypes": True})
    columns = [{"name": "who", "type": "text"}, {"name": "hours", "type": "number", "label": "Hours"}]
    admin.post(
        "/api/fields", json={"name": "effort", "type": "list", "allTypes": True, "options": {"columns": columns}}
    )
    # A field of indicators or of tasks is not a field of incidents.
    admin.post("/api/fields", json={"name": "seen_by", "type": "text", "appliesTo": "indicator"})

    shapes = catalog(admin)["shapes"]
    # The incident an event carries and a node gives: exactly what is built for one.
    incident(admin, "i1")
    with SessionLocal() as db:
        assert [item["name"] for item in shapes["incident"]] == list(payloads.incident_data(db.get(Incident, "i1")))
    assert all(item["type"] and item["description"] for item in shapes["incident"])

    by_name = {item["name"]: item for item in shapes["fields"]}
    assert set(registry.SYSTEM_FIELDS) <= set(by_name) and "seen_by" not in by_name
    assert by_name["owner"] == {"name": "owner", "type": "user", "description": "Owner. The analyst who has it."}
    assert by_name["business_unit"] == {
        "name": "business_unit",
        "type": "text",
        "description": "Business unit (a field of yours)",
    }
    assert {"first_seen_at.type", "first_seen_at.value", "effort[0].who", "effort[0].hours"} <= set(by_name)
    assert by_name["effort[0].hours"]["type"] == "number"

    assert shapes["context"]["Ticket"] == ["ID", "Number", "System", "URL", "Status"]

    # The outputs that are incidents name the shape, once, and not a list of their own.
    nodes = {entry["id"]: entry for entry in catalog(admin)["nodes"]}
    for name in ("nik.get-incident", "nik.create-incident", "nik.set-status"):
        assert nodes[name]["outputs"][0]["shape"] == "incident"
    assert nodes["nik.get-incident"]["outputs"][1]["shape"] == "fields"


def test_every_path_offered_under_an_incident_is_there_when_a_playbook_runs(admin: TestClient):
    admin.post("/api/users", json={"username": "anna", "password": "password1"})
    admin.post("/api/fields", json={"name": "business_unit", "type": "text", "allTypes": True})
    admin.post("/api/fields", json={"name": "first_seen_at", "type": "indicator", "allTypes": True})
    columns = [{"name": "who", "type": "text"}, {"name": "hours", "type": "number"}]
    admin.post(
        "/api/fields", json={"name": "effort", "type": "list", "allTypes": True, "options": {"columns": columns}}
    )
    incident(admin, "i1", severity="low", host="WKS-1")
    fill(
        "i1",
        {
            "business_unit": "Retail",
            "first_seen_at": {"type": "ip", "value": "185.220.101.47"},
            "effort": [{"who": "anna", "hours": 2}],
        },
    )

    found = catalog(admin)
    shapes, entries = found["shapes"], {entry["id"]: entry for entry in found["nodes"]}
    order = ["got", "status", "owner", "sev", "made", "again"]
    nodes = [
        act("got", "nik.get-incident"),
        # Closed, so that "closed" has a value: a field is there when it has one.
        act("status", "nik.set-status", status="closed"),
        act("owner", "nik.set-assignee", assignee="anna"),
        act("sev", "nik.set-incident-field", field="severity", value="high"),
        act("made", "nik.create-incident", title="Second one", ticketId="INC-2", severity="low"),
        # The incident a node gave is taken whole where an id is asked.
        act("again", "nik.get-incident", incident="{{ made.incident }}"),
    ]
    wanted = [
        *(f"trigger.incident.{item['name']}" for item in shapes["incident"]),
        *(f"incident.{item['name']}" for item in shapes["fields"]),
        *(path for item in nodes for path in paths_of(entries[item["config"]["action"]], shapes, item["id"])),
    ]
    # The fields of the incident just made that have no value are not there, as the editor says:
    # of "again", the incident and the fields every new incident has.
    blank = {f"again.fields.{item['name']}" for item in shapes["fields"]} - {
        f"again.fields.{name}" for name in ("id", "name", "type", "status", "severity", "ticket", "created", "modified")
    }
    wanted = [path for path in wanted if path not in blank]
    assert "got.fields.business_unit" in wanted and "got.fields.effort[0].hours" in wanted
    assert "made.incident.id" in wanted and "incident.first_seen_at.value" in wanted

    edges = [
        edge("start", order[0]),
        *(edge(a, b) for a, b in zip(order, order[1:], strict=False)),
        edge(order[-1], "reads"),
    ]
    pb = playbook(admin, "Reads it all", [*nodes, reads(wanted)], edges)

    run = go(admin, pb, objectKind="incident", objectId="i1")
    assert run["status"] == "done", run["error"]
    out = steps(run)
    assert out["again"]["output"]["incident"]["id"] == out["made"]["output"]["incident"]["id"] != "i1"
    assert out["got"]["output"]["fields"]["business_unit"] == "Retail"
    assert out["again"]["output"]["fields"]["ticket"] == "INC-2"

    # A dry run makes and changes nothing, and what is read after is there all the same.
    dry = go(admin, pb, objectKind="incident", objectId="i1", dryRun=True)
    assert dry["status"] == "failed"  # "again" reads an incident a dry run did not make…
    assert steps(dry)["again"]["error"] == "The incident does not exist"
    assert steps(dry)["made"]["output"]["incident"] == {
        **steps(dry)["made"]["output"]["incident"],
        "id": "dry-run",
        "name": "INC-2 · Second one",
        "ticket": "INC-2",
        "status": "open",
        "severity": "low",
    }
    # …so the same playbook without it: every path of the others is there.
    kept = [path for path in wanted if not path.startswith("again.")]
    edges = [
        edge("start", "got"),
        *(edge(a, b) for a, b in zip(order[:-1], order[1:-1], strict=False)),
        edge("made", "reads"),
    ]
    dry = go(
        admin,
        playbook(admin, "Reads it dry", [*nodes[:-1], reads(kept)], edges),
        objectKind="incident",
        objectId="i1",
        dryRun=True,
    )
    assert dry["status"] == "done", dry["error"]


def test_what_is_inside_a_list_an_action_gives_is_there(admin: TestClient):
    with SessionLocal() as db:
        db.add(
            IocList(
                id="l1", name="Blocklist", description="", watch=True, created_at="", created_by="admin", updated_at=""
            )
        )
        db.add(IocListItem(list_id="l1", type="ip", value="185.220.101.47", added_at="", added_by="admin"))
        db.commit()
    found = catalog(admin)
    shapes, entries = found["shapes"], {entry["id"]: entry for entry in found["nodes"]}
    nodes = [
        act("lists", "nik.get-ioc-lists"),
        act("check", "nik.recheck-list", list="Blocklist"),
        act("known", "nik.get-indicator", value="185.220.101.47"),
        act("said", "nik.reputation", kind="ip", value="185.220.101.47"),
        act("made", "nik.make-indicators", text=["185.220.101.47", "nothing"]),
    ]
    wanted = [path for item in nodes for path in paths_of(entries[item["config"]["action"]], shapes, item["id"])]
    # A dry run asks no source: who answered and who was skipped are lists with nothing in them.
    wanted = [path for path in wanted if not path.startswith(("said.sources[0]", "said.skipped[0]"))]
    assert "lists.lists[0].count" in wanted and "check.after[0].verdict" in wanted and "known.value" in wanted
    order = [item["id"] for item in nodes]
    edges = [
        edge("start", order[0]),
        *(edge(a, b) for a, b in zip(order, order[1:], strict=False)),
        edge(order[-1], "reads"),
    ]
    reading = node(
        "reads",
        "action",
        action="nik.add-tags",
        args={"indicators": ["185.220.101.47"], "tags": [f"{{{{ {path} | json }}}}" for path in wanted]},
    )
    dry = go(admin, playbook(admin, "Reads the lists", [*nodes, reading], edges), dryRun=True)
    assert dry["status"] == "done", dry["error"]
    assert steps(dry)["lists"]["output"]["lists"][0]["name"] == "Blocklist"


def test_every_action_that_says_what_is_inside_an_output_is_held_to_it_here():
    shaped = {
        spec.id
        for spec in actions.all_specs()
        if spec.group == "Nik" and any(output.get("shape") for output in spec.outputs)
    }
    assert shaped == SHAPED
    for spec in actions.all_specs():
        for output in spec.outputs:
            shape = output.get("shape")
            assert (
                shape is None
                or shape in ("incident", "fields")
                or all(set(item) == {"name", "type", "description"} for item in shape)
            ), spec.id


def test_whole_messages_and_files_are_told_apart_and_opened_behind_the_double_check(admin: TestClient):
    # What the screen of a playbook reads: e-mail bodies, attachments and samples are offered apart
    # from the rest, and TLP:RED data is not offered.
    classes = admin.get("/api/automation/data-classes").json()["classes"]
    assert [item["id"] for item in classes if item.get("apart")] == ["mail_body", "attachment", "sample"]
    assert [item["id"] for item in classes if item["sensitive"] and not item.get("apart")] == ["tlp_red"]

    made = admin.post("/api/automation/playbooks", json={"name": "Forwards"})
    url = f"/api/automation/playbooks/{made.json()['id']}/data-allow"
    # The box and the name, exactly as it is written: without both nothing is opened.
    assert admin.put(url, json={"class": "attachment"}).status_code == 400
    assert (
        admin.put(url, json={"class": "attachment", "acknowledged": True, "confirmName": "forwards"}).status_code == 400
    )
    opened = admin.put(url, json={"class": "attachment", "acknowledged": True, "confirmName": "Forwards"})
    assert opened.status_code == 200 and opened.json()["dataAllow"] == ["attachment"]
    both = admin.put(url, json={"class": "mail_body", "acknowledged": True, "confirmName": "Forwards"})
    assert both.json()["dataAllow"] == ["mail_body", "attachment"]
    assert admin.put(url, json={"class": "mail_body", "allow": False}).json()["dataAllow"] == ["attachment"]
    assert admin.put(url, json={"class": "attachment", "allow": False}).json()["dataAllow"] == []

    entries = admin.get("/api/audit?q=action:automation.data.*").json()["entries"]
    assert [(entry["action"], entry["actor"]) for entry in reversed(entries)] == [
        ("automation.data.open", "admin"),
        ("automation.data.open", "admin"),
        ("automation.data.close", "admin"),
        ("automation.data.close", "admin"),
    ]
    assert entries[2]["details"].startswith('Playbook "Forwards" may send e-mail bodies to: ')
    assert entries[-1]["details"].startswith('Playbook "Forwards" may send attachments to: ')
    assert entries[0]["details"] == 'Playbook "Forwards" may no longer send attachments'


def test_the_route_tidy_up_gives_a_line_is_kept_with_the_graph_and_checked(admin: TestClient):
    made = admin.post("/api/automation/playbooks", json={"name": "Tidied"}).json()["id"]
    url = f"/api/automation/playbooks/{made}"

    def shape(route):
        nodes = [node("start", "trigger", manual=True), act("note", "nik.add-note", text="seen")]
        return {"nodes": nodes, "edges": [{"from": "start", "to": "note", "route": route}]}

    route = {"points": [{"x": 135, "y": 102}, {"x": 135, "y": 158}], "label": {"x": 135, "y": 130}}
    saved = admin.post(f"{url}/versions", json={"graph": shape(route)})
    assert saved.status_code == 201, saved.text
    assert admin.get(url).json()["graph"]["edges"][0]["route"] == route
    # It is a drawing, and is held to being one.
    for bad in ({"points": [{"x": 1, "y": 2}]}, {"points": "no"}, [], {"points": route["points"], "more": 1}):
        refused = admin.post(f"{url}/versions", json={"graph": shape(bad)})
        assert refused.status_code == 422, bad
        assert refused.json()["problems"][0]["message"].startswith("The route of an edge is 2 to 60 points")

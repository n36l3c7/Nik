"""The tags of an incident: the field ``labels`` under the name a person reads, the rules of a
tag, ``tag:`` in a query (in SQL and on rows, which must agree), and the two actions of a
playbook that put tags on an incident and take them off."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import fields as registry
from app import incident_tags, query
from app.core.db import SessionLocal
from app.core.models import Field, Incident
from app.query.fields import Entity
from tests.test_automation_engine import edge, go, incident, node, playbook, steps


def act(node_id, action, **args):
    return node(node_id, "action", action=action, args=args)


def tags_of(admin: TestClient, incident_id: str) -> list[str]:
    return admin.get(f"/api/incidents/{incident_id}/fields").json()["fields"].get("labels", [])


def set_tags(admin: TestClient, incident_id: str, tags):
    return admin.patch(f"/api/incidents/{incident_id}/fields", json={"changes": {"labels": tags}})


# --------------------------------------------------------------------------- #
# The rules of a tag                                                          #
# --------------------------------------------------------------------------- #
def test_a_tag_is_what_a_tag_of_an_indicator_is():
    from app import artifacts
    from app import ioc_library as lib

    # One rule for the three: a tag means the same on an incident, an indicator and an artifact.
    assert incident_tags.TAG_RE.pattern == lib.TAG_RE.pattern == artifacts.TAG_RE.pattern
    assert incident_tags.TAGS_MAX == lib.TAGS_MAX == artifacts.TAGS_MAX

    assert incident_tags.clean_tag("  Phish ") == "phish"
    assert incident_tags.clean_tag("#Campaign:Q4") == "campaign:q4"
    assert incident_tags.clean_tag("data   leak") == "data-leak"
    assert incident_tags.clean_tag("a" * 40) == "a" * 40
    for wrong in ("", "   ", "-x", "a" * 41, "né", "a,b", "a/b", "two\nlines!"):
        with pytest.raises(registry.FieldError) as refused:
            incident_tags.clean_tag(wrong)
        assert "is not a tag" in refused.value.message and refused.value.field == "labels"


def test_tags_are_kept_once_in_their_order_and_twelve_at_most():
    assert incident_tags.clean(["Phish", "vip", "#phish", " VIP "]) == ["phish", "vip"]
    assert incident_tags.clean("phish, vip,,") == ["phish", "vip"]
    assert incident_tags.clean(None) == [] and incident_tags.clean([]) == []
    twelve = [f"t{n}" for n in range(12)]
    assert incident_tags.clean(twelve) == twelve
    with pytest.raises(registry.FieldError) as refused:
        incident_tags.clean([*twelve, "one-more"])
    assert refused.value.message == "An incident holds 12 tags at most"


def test_what_an_incident_held_before_the_rules_is_kept_until_it_is_taken_off():
    held = ["Suspicious Login", "VIP", *(f"old {n}" for n in range(12))]
    # Sent back as it is, in any case: kept as it was written, and still fourteen of them.
    assert incident_tags.clean([*held], held) == held
    assert incident_tags.clean(["vip", "suspicious login"], held) == ["VIP", "Suspicious Login"]
    # A new one is held to the rules, and to the limit.
    with pytest.raises(registry.FieldError):
        incident_tags.clean([*held, "new"], held)
    assert incident_tags.added(["VIP"], ["vip", "Phish"]) == ["VIP", "phish"]
    assert incident_tags.added(["VIP"], "a, b") == ["VIP", "a", "b"]
    assert incident_tags.removed(held[:2], ["vip"]) == ["Suspicious Login"]
    assert incident_tags.removed(held[:2], ["SUSPICIOUS LOGIN", "nothing"]) == ["VIP"]
    assert incident_tags.removed(["data-leak", "x"], "Data Leak, #X") == []


# --------------------------------------------------------------------------- #
# The field                                                                   #
# --------------------------------------------------------------------------- #
def test_the_field_is_called_tags_and_stays_labels_where_it_is_stored(admin: TestClient):
    listed = {field["name"]: field for field in admin.get("/api/fields").json()["fields"]}
    assert listed["labels"]["label"] == "Tags" and listed["labels"]["type"] == "tags" and listed["labels"]["system"]
    assert "tags" not in listed and "tag" not in listed

    incident(admin, "i1")
    saved = set_tags(admin, "i1", ["Phish", "#VIP", "phish", "data leak"])
    assert saved.status_code == 200, saved.text
    assert saved.json()["fields"]["labels"] == ["phish", "vip", "data-leak"] and saved.json()["changed"] == ["labels"]
    with SessionLocal() as db:
        assert db.get(Incident, "i1").fields["labels"] == ["phish", "vip", "data-leak"]
    # The same tags again change nothing; one that is not a tag refuses the change, and says why.
    assert set_tags(admin, "i1", "PHISH, vip, data-leak").json()["changed"] == []
    refused = set_tags(admin, "i1", ["phish", "no/slash"])
    assert refused.status_code == 400 and refused.json()["detail"].startswith('"no/slash" is not a tag. A tag is')
    many = set_tags(admin, "i1", [f"t{n}" for n in range(13)])
    assert many.status_code == 400 and many.json()["detail"] == "An incident holds 12 tags at most"
    assert tags_of(admin, "i1") == ["phish", "vip", "data-leak"]

    # The trace a field change leaves, under the name a person reads.
    entries = admin.get("/api/audit?q=action:incident.field").json()["entries"]
    assert entries[0]["details"] == 'Set Tags: empty → ["phish", "vip", "data-leak"]'
    # The whole document is another way in, and is held to the same rules.
    assert admin.patch("/api/incidents/i1", json={"fields": {"labels": ["Only"]}}).status_code == 200
    assert tags_of(admin, "i1") == ["only"]
    assert set_tags(admin, "i1", None).json()["fields"].get("labels") is None

    # The other fields of the same type are not tags: they keep what they are given.
    hosts = admin.patch("/api/incidents/i1/fields", json={"changes": {"affected_hosts": ["WKS 01", "Srv/02"]}})
    assert hosts.status_code == 200 and hosts.json()["fields"]["affected_hosts"] == ["WKS 01", "Srv/02"]


def test_a_label_from_before_the_rules_stays_and_can_be_taken_off(admin: TestClient):
    incident(admin, "i1")
    with SessionLocal() as db:
        row = db.get(Incident, "i1")
        row.fields = {"labels": ["Suspicious Login", "VIP"]}
        db.commit()
    assert set_tags(admin, "i1", ["Suspicious Login", "VIP", "New One"]).json()["fields"]["labels"] == [
        "Suspicious Login",
        "VIP",
        "new-one",
    ]
    assert set_tags(admin, "i1", ["VIP", "new-one"]).json()["fields"]["labels"] == ["VIP", "new-one"]
    # Once it is off, it comes back only as a tag.
    assert set_tags(admin, "i1", ["new-one"]).status_code == 200
    assert set_tags(admin, "i1", ["new-one", "VIP"]).json()["fields"]["labels"] == ["new-one", "vip"]


def test_a_database_of_an_older_release_takes_the_new_name_unless_it_was_renamed(admin: TestClient):
    assert admin.get("/api/fields").status_code == 200  # the system fields are there from now on
    with SessionLocal() as db:
        row = db.scalars(select(Field).where(Field.name == "labels")).one()
        row.label, row.description = "Labels", ""
        db.commit()
    with SessionLocal() as db:
        assert registry.registry(db)["labels"].label == "Tags"
        db.commit()
    assert admin.patch("/api/fields/labels", json={"label": "Keywords"}).status_code == 200
    with SessionLocal() as db:
        assert registry.seed(db) == 0 and registry.registry(db)["labels"].label == "Keywords"


def test_the_list_carries_the_tags_of_each_incident(admin: TestClient):
    incident(admin, "i1")
    incident(admin, "i2")
    set_tags(admin, "i1", ["phish", "vip"])
    rows = {row["id"]: row for row in admin.get("/api/incidents?view=summary").json()["incidents"]}
    assert rows["i1"]["tags"] == ["phish", "vip"] and rows["i2"]["tags"] == []
    with_fields = admin.get("/api/incidents?view=summary&fields=labels,tlp").json()["incidents"]
    assert {row["id"]: (row["tags"], row["fields"]) for row in with_fields} == {
        "i1": (["phish", "vip"], {"labels": ["phish", "vip"]}),
        "i2": ([], {}),
    }
    # The whole documents keep the shape they had: the tags are under fields, by the name of the field.
    full = {row["id"]: row for row in admin.get("/api/incidents").json()["incidents"]}
    assert full["i1"]["fields"]["labels"] == ["phish", "vip"] and "tags" not in full["i1"]


# --------------------------------------------------------------------------- #
# tag: in a query                                                             #
# --------------------------------------------------------------------------- #
TAGGED = {
    "a": {"labels": ["phish", "vip"]},
    "b": {"labels": ["Phishing Campaign", "campaign:q4"]},
    "c": {"labels": []},
    "d": {},
    "e": {"labels": "phish"},  # not a list: written by a hand before the field was what it is
}
TAG_CASES = {
    "tag:phish": "a",
    "tags:phish": "a",
    "labels:phish": "a",
    "TAG:PHISH": "a",
    # A whole tag, as on an artifact and on an indicator: a part of one is not it.
    "tag:phi": "",
    "tag:phi*": "ab",
    "tag:vip tag:phish": "a",
    "tag:vip or tag:campaign:q4": "ab",
    'tag:"phishing campaign"': "b",
    "!tag:phish": "bcde",
    "-tags:vip": "bcde",
    "not tag:phish not tag:campaign:q4": "cde",
    'tag:""': "cde",
    "tag:*": "ab",
}


def _rows_entity(db) -> Entity:
    held = tuple(spec for spec in query.entity_of("incidents", db).fields if spec.getter is not None)
    return Entity(name="rowincidents", label="Incidents", permission="read", fields=held, text_fields=())


def test_tag_asks_the_tags_of_an_incident_in_sql_and_on_rows(client, monkeypatch):
    with SessionLocal() as db:
        for key, held in TAGGED.items():
            db.add(Incident(id=key, name=f"incident {key}", doc={}, fields=held))
        db.commit()
    rows = [{"id": key, "fields": held} for key, held in TAGGED.items()]
    wrong = {}
    with SessionLocal() as db:
        monkeypatch.setitem(query.ENTITIES, "rowincidents", _rows_entity(db))
        for text, expected in TAG_CASES.items():
            found = db.scalars(select(Incident.id).where(*query.sql("incidents", text, db=db)))
            keep = query.rows("rowincidents", text)
            got = "".join(sorted(found)), "".join(row["id"] for row in rows if keep(row))
            if got != (expected, expected):
                wrong[text] = {"expected": expected, "sql": got[0], "rows": got[1]}
    assert wrong == {}


def test_the_schema_says_tag_and_tags_are_the_field_labels(admin: TestClient):
    incident(admin, "i1")
    incident(admin, "i2")
    set_tags(admin, "i1", ["phish", "vip"])
    set_tags(admin, "i2", ["phish"])
    plain = query.entity_of("incidents")
    assert plain.field("tag") is plain.field("tags") is plain.field("labels") and plain.field("tag").kind == "tags"

    fields = {f["name"]: f for f in admin.get("/api/query/schema?entity=incidents").json()["entities"][0]["fields"]}
    assert fields["labels"]["aliases"] == ["tag", "tags"] and fields["labels"]["label"] == "Tags"
    assert "tags" not in fields and "tag" not in fields

    def ids(q: str) -> list[str]:
        found = admin.get("/api/incidents", params={"view": "summary", "q": q})
        assert found.status_code == 200, found.text
        return sorted(row["id"] for row in found.json()["incidents"])

    assert ids("tag:phish") == ["i1", "i2"] and ids("tags:vip") == ["i1"] and ids("tag:phish -tag:vip") == ["i2"]
    assert admin.post("/api/query", json={"entity": "incidents", "query": "tag:VIP"}).json()["total"] == 1
    # How many incidents carry each tag: counted like any other group.
    counted = admin.post("/api/query/aggregate", json={"entity": "incidents", "groupBy": ["tag"]}).json()
    assert sorted(map(tuple, counted["rows"])) == [("phish", 2), ("vip", 1)]


def test_a_field_of_yours_called_tags_keeps_its_name(admin: TestClient):
    made = admin.post("/api/fields", json={"name": "tags", "type": "tags", "allTypes": True})
    assert made.status_code == 201, made.text
    incident(admin, "i1")
    incident(admin, "i2")
    set_tags(admin, "i1", ["phish"])
    assert admin.patch("/api/incidents/i2/fields", json={"changes": {"tags": ["Mine"]}}).status_code == 200

    def ids(q: str) -> list[str]:
        found = admin.get("/api/incidents", params={"view": "summary", "q": q})
        assert found.status_code == 200, found.text
        return sorted(row["id"] for row in found.json()["incidents"])

    # ``tags:`` asks the field that had the name first; the tags are still asked as tag: and labels:.
    assert ids("tags:mine") == ["i2"] and ids("tags:phish") == []
    assert ids("tag:phish") == ["i1"] and ids("labels:phish") == ["i1"] and ids("field.tags:mine") == ["i2"]
    fields = {f["name"]: f for f in admin.get("/api/query/schema?entity=incidents").json()["entities"][0]["fields"]}
    assert fields["labels"]["aliases"] == ["tag"] and fields["tags"]["aliases"] == ["field.tags"]
    # In an expression too: incident.tags is that field, and the catalog does not offer it twice.
    shapes = admin.get("/api/automation/catalog").json()["shapes"]["fields"]
    assert [item["name"] for item in shapes].count("tags") == 1
    with SessionLocal() as db:
        assert incident_tags.named(db, {"labels": ["phish"]}) == {"labels": ["phish"]}


# --------------------------------------------------------------------------- #
# The actions of a playbook                                                   #
# --------------------------------------------------------------------------- #
def test_a_playbook_puts_tags_on_its_incident_and_takes_them_off(admin: TestClient):
    incident(admin, "i1")
    incident(admin, "i2")
    set_tags(admin, "i1", ["vip"])
    nodes = [
        act("add", "nik.add-incident-tags", tags=["Phish", "vip", "data leak"]),
        act("again", "nik.add-incident-tags", tags="phish"),
        act("other", "nik.add-incident-tags", incident="i2", tags="{{ incident.tags }}"),
        act("off", "nik.remove-incident-tags", tags=["VIP", "never-there"]),
        act("off_again", "nik.remove-incident-tags", tags=["vip"]),
        act("note", "nik.add-note", text="{{ incident.tags | json }} {{ incident.labels | json }}"),
    ]
    order = [item["id"] for item in nodes]
    edges = [edge("start", order[0]), *(edge(a, b) for a, b in zip(order, order[1:], strict=False))]
    pb = playbook(admin, "Tags", nodes, edges)

    run = go(admin, pb, objectKind="incident", objectId="i1")
    assert run["status"] == "done", run["error"]
    out = {name: step["output"] for name, step in steps(run).items() if name != "start"}
    assert out["add"] == {"tags": ["vip", "phish", "data-leak"], "changed": True}
    # Done twice, it changes nothing the second time.
    assert out["again"] == {"tags": ["vip", "phish", "data-leak"], "changed": False}
    assert out["other"] == {"tags": ["vip", "phish", "data-leak"], "changed": True}
    assert out["off"] == {"tags": ["phish", "data-leak"], "changed": True}
    assert out["off_again"] == {"tags": ["phish", "data-leak"], "changed": False}
    assert tags_of(admin, "i1") == ["phish", "data-leak"] and tags_of(admin, "i2") == ["vip", "phish", "data-leak"]
    note = admin.get("/api/incidents/i1").json()["notes"][-1]["text"]
    assert note == '["phish","data-leak"] ["phish","data-leak"]'

    # Each change is in the audit log with the run that made it; what changed nothing left nothing.
    entries = [
        entry["details"]
        for entry in admin.get("/api/audit?q=action:incident.field").json()["entries"]
        if "playbook" in entry["details"]
    ]
    assert len(entries) == 3 and all(f'(playbook "Tags", run {run["id"]})' in text for text in entries)
    assert entries[0].startswith('Set Tags: ["vip", "phish", "data-leak"] → ["phish", "data-leak"]')
    with SessionLocal() as db:
        assert registry.source_of(db, db.get(Incident, "i1"), "labels") == f"run:{run['id']}"

    # A dry run says what the tags would be and changes nothing.
    dry = go(admin, pb, objectKind="incident", objectId="i1", dryRun=True)
    assert dry["status"] == "done", dry["error"]
    assert steps(dry)["add"]["output"] == {"tags": ["phish", "data-leak", "vip"], "changed": True}
    assert tags_of(admin, "i1") == ["phish", "data-leak"]


def test_the_tag_actions_say_what_is_missing(admin: TestClient):
    incident(admin, "i1")

    made = []

    def failed(action: str, **body) -> str:
        args = body.pop("args")
        made.append(action)
        pb = playbook(admin, f"Tags {len(made)}", [act("tag", action, **args)], [edge("start", "tag")])
        run = go(admin, pb, **body)
        assert run["status"] == "failed"
        return steps(run)["tag"]["error"]

    on_i1 = {"objectKind": "incident", "objectId": "i1"}
    for action in ("nik.add-incident-tags", "nik.remove-incident-tags"):
        assert failed(action, args={"tags": ["x"]}) == "No incident was given"
        assert failed(action, args={"tags": ["x"], "incident": "nowhere"}) == "The incident does not exist"
        assert failed(action, args={"tags": []}, **on_i1) == "At least one tag is needed"
    assert failed("nik.add-incident-tags", args={"tags": ["no/slash"]}, **on_i1).startswith('"no/slash" is not a tag')
    assert tags_of(admin, "i1") == []

    nodes = {entry["id"]: entry for entry in admin.get("/api/automation/catalog").json()["nodes"]}
    for action in ("nik.add-incident-tags", "nik.remove-incident-tags"):
        assert [argument["name"] for argument in nodes[action]["arguments"]] == ["incident", "tags"]
        assert [output["name"] for output in nodes[action]["outputs"]] == ["tags", "changed"]
    # "Tag indicators" is still what it was.
    assert nodes["nik.add-tags"]["name"] == "Tag indicators"

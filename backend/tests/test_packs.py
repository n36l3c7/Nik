"""Content packs: the file, the plan of an import, applying it, and what Nik ships as packs."""

from __future__ import annotations

import io
import json
import zipfile

import pytest
import yaml
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import packs
from app.core.db import SessionLocal
from app.core.models import Pack, PackItem, Playbook, PlaybookVersion, Script, ScriptVersion
from app.main import app
from tests.conftest import make_key
from tests.test_connectors_api import ACME

MANIFEST = {"id": "acme-soc", "name": "Acme SOC", "version": "1.2.0", "description": "Ours", "author": "Acme"}
SCRIPT = {
    "name": "CountWords",
    "description": "How many words a text has.",
    "code": "def main(args):\n    return {'count': len(str(args.get('text', '')).split())}\n",
    "arguments": [{"name": "text", "type": "text", "required": True}],
    "outputs": [{"name": "count", "type": "number"}],
    "test": {"args": {"text": "a b c"}, "expect": {"count": 3}},
}


def node(node_id: str, kind: str, **config) -> dict:
    return {"id": node_id, "kind": kind, "name": node_id, "config": config}


def playbook(name: str = "Count the words", script: str = "CountWords") -> dict:
    graph = {
        "nodes": [
            node("start", "trigger", manual=True),
            node("count", "script", script=script, args={"text": "one two three"}),
        ],
        "edges": [{"from": "start", "to": "count"}],
    }
    return {"app": "Nik", "type": "playbook", "version": 1, "playbook": {"name": name, "graph": graph}}


FIELD = {"name": "customer", "label": "Customer", "type": "text", "options": {}, "appliesTo": "incident"}
TYPE = {
    "name": "Customer case",
    "description": "Something a customer reported.",
    "colour": "cyan",
    "fields": [{"name": "customer", "required": True, "requiredOnClose": False}],
    "closeReasons": ["Solved", "Not ours"],
    "defaultPlaybook": "Count the words",
    "autoRun": False,
}
LIST = {"name": "vip_users", "label": "VIP users", "kind": "values", "itemType": "text", "entries": [{"key": "ceo"}]}
WIDGET = {"id": "n", "type": "number", "title": "Cases", "entity": "incidents", "query": 'type:"Customer case"'}
DASHBOARD = {"nik": "dashboard", "version": 1, "name": "Customer cases", "timeRange": "30d", "widgets": [WIDGET]}
RULE = {
    "name": "Drop tests",
    "enabled": True,
    "action": "drop",
    "when": {"all": [{"left": "{{ incident.name }}", "op": "contains", "right": "[test]"}]},
    "params": {},
}


def items(*more: packs.Item) -> list[packs.Item]:
    return [
        packs.Item("scripts", "CountWords", SCRIPT),
        packs.Item("playbooks", "Count the words", playbook()),
        packs.Item("fields", "customer", FIELD),
        packs.Item("incident_types", "Customer case", TYPE),
        packs.Item("lists", "vip_users", LIST),
        packs.Item("dashboards", "Customer cases", DASHBOARD),
        packs.Item("preprocess_rules", "Drop tests", RULE),
        packs.Item("connectors", "acme", ACME),
        *more,
    ]


def inspect(client: TestClient, data: bytes, headers=None) -> dict:
    answer = client.post("/api/packs/inspect", files={"file": ("x.nikpack", data, "application/zip")}, headers=headers)
    assert answer.status_code == 200, answer.text
    return answer.json()


def actions(found: dict) -> dict[str, str]:
    return {f"{item['kind']}/{item['name']}": item["action"] for item in found["items"]}


def raw_zip(files: dict[str, str | bytes], manifest: dict | None = MANIFEST) -> bytes:
    held = io.BytesIO()
    with zipfile.ZipFile(held, "w") as archive:
        if manifest is not None:
            archive.writestr("pack.yml", yaml.safe_dump(manifest))
        for path, text in files.items():
            archive.writestr(path, text)
    return held.getvalue()


def test_a_pack_is_a_file_that_reads_back_as_it_was_written():
    data = packs.write(MANIFEST, items())
    assert data == packs.write(MANIFEST, list(reversed(items())))  # the same pack, the same bytes
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        listed = archive.namelist()
    assert listed[0] == "pack.yml" and "scripts/CountWords.yml" in listed and "connectors/acme.yml" in listed
    assert "playbooks/count-the-words.json" in listed and "incident_types/customer-case.json" in listed
    back = packs.read(data)
    assert back.manifest["id"] == "acme-soc" and back.manifest["version"] == "1.2.0"
    assert [(item.kind, item.name) for item in back.items] == [
        ("fields", "customer"), ("lists", "vip_users"), ("scripts", "CountWords"), ("connectors", "acme"),
        ("playbooks", "Count the words"), ("incident_types", "Customer case"), ("preprocess_rules", "Drop tests"),
        ("dashboards", "Customer cases"),
    ]  # fmt: skip
    assert next(item for item in back.items if item.kind == "connectors").data == ACME
    assert next(item for item in back.items if item.kind == "scripts").data == SCRIPT


def test_a_file_that_is_not_a_safe_pack_is_refused():
    def refused(data: bytes) -> str:
        with pytest.raises(packs.PackError) as caught:
            packs.read(data)
        return caught.value.message

    assert "not a content pack" in refused(b"not a zip")
    assert "no pack.yml" in refused(raw_zip({"README.md": "hello"}, manifest=None))
    assert "id of a pack" in refused(raw_zip({}, manifest={**MANIFEST, "id": "Bad Id"}))
    assert "three numbers" in refused(raw_zip({}, manifest={**MANIFEST, "version": "1.2"}))
    # A path that would leave the pack, in each of the ways a zip can say it.
    for path in ("../evil.json", "fields/../../evil.json", "/etc/passwd", "fields\\\\x.json", "C:/x.json"):
        assert "not allowed" in refused(raw_zip({path: "{}"})), path
    assert "does not know" in refused(raw_zip({"secrets/token.json": "{}"}))
    assert "does not know" in refused(raw_zip({"fields/deep/x.json": "{}"}))
    assert "not a .json file" in refused(raw_zip({"fields/x.yml": "a: 1"}))
    assert "cannot be read" in refused(raw_zip({"fields/x.json": "{nope"}))
    assert "has no name" in refused(raw_zip({"fields/x.json": "{}"}))
    assert "twice" in refused(raw_zip({"fields/a.json": json.dumps(FIELD), "fields/b.json": json.dumps(FIELD)}))
    # YAML is read safely: a tag that would build an object is not followed.
    assert "cannot be read" in refused(raw_zip({"scripts/X.yml": "!!python/object/apply:os.system ['id']"}))
    # A link is not a file of a pack.
    held = io.BytesIO()
    with zipfile.ZipFile(held, "w") as archive:
        archive.writestr("pack.yml", yaml.safe_dump(MANIFEST))
        link = zipfile.ZipInfo("fields/link.json")
        link.external_attr = 0o120777 << 16
        archive.writestr(link, "/etc/passwd")
    assert "a link" in refused(held.getvalue())
    # Too many files, and too much once unpacked.
    assert "2000 files at most" in refused(raw_zip({f"fields/f{index}.json": "{}" for index in range(2001)}))
    big = io.BytesIO()
    with zipfile.ZipFile(big, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("pack.yml", yaml.safe_dump(MANIFEST))
        archive.writestr("fields/bomb.json", b" " * (packs.MAX_ITEM + 1))
    assert "too large" in refused(big.getvalue())
    assert "20 MB at most" in refused(b"x" * (packs.MAX_BYTES + 1))
    # What does not travel alone is left where it is, without failing the pack.
    assert packs.read(raw_zip({"classifiers/x.json": "{}", "README.md": "hello"})).items == []


def test_a_pack_is_inspected_then_applied_all_or_nothing(admin: TestClient):
    data = packs.write(MANIFEST, items())
    found = inspect(admin, data)
    assert found["pack"]["name"] == "Acme SOC" and found["installed"] is None and found["problems"] == []
    assert set(actions(found).values()) == {"add"} and found["counts"]["add"] == 8
    # Nothing was written by looking.
    assert admin.get("/api/fields").json()["fields"] and "customer" not in admin.get("/api/fields").text
    done = admin.post("/api/packs/import", json={"token": found["token"]})
    assert done.status_code == 200, done.text
    assert (done.json()["added"], done.json()["updated"], done.json()["skipped"]) == (8, 0, 0)
    assert [item["name"] for item in done.json()["installed"]["items"] if item["there"]] and all(
        item["there"] for item in done.json()["installed"]["items"]
    )
    # Each item is where its kind lives.
    assert any(field["name"] == "customer" for field in admin.get("/api/fields").json()["fields"])
    kinds = {row["name"]: row for row in admin.get("/api/incident-types").json()["types"]}
    assert kinds["Customer case"]["fields"][0] == {"name": "customer", "required": True, "requiredOnClose": False}
    assert kinds["Customer case"]["closeReasons"] == ["Solved", "Not ours"]
    assert admin.get("/api/lists/vip_users").json()["entries"][0]["key"] == "ceo"
    assert admin.get("/api/automation/connectors/acme").status_code == 200
    with SessionLocal() as db:
        script = db.scalars(select(Script).where(Script.name == "CountWords")).one()
        assert script.current_version == 1 and not script.builtin
        book = db.scalars(select(Playbook).where(Playbook.name == "Count the words")).one()
        # Off, reaching nothing it was not opened to, with the script at the version it has here.
        assert not book.enabled and book.egress_mode == "listed" and book.data_allow == [] and book.current_version == 1
        graph = db.get(PlaybookVersion, (book.id, 1)).graph
        assert next(n for n in graph["nodes"] if n["kind"] == "script")["config"]["script_version"] == 1
        assert kinds["Customer case"]["defaultPlaybookId"] == book.id
    boards = {row["name"]: row for row in admin.get("/api/dashboards").json()["dashboards"]}
    assert boards["Customer cases"]["sharedWith"]["everyone"] is True  # a pack's dashboard is everyone's
    assert [rule["name"] for rule in admin.get("/api/preprocess-rules").json()["rules"]] == ["Drop tests"]
    # The token is spent, and the import is in the audit log.
    assert admin.post("/api/packs/import", json={"token": found["token"]}).status_code == 410
    audit = admin.get("/api/audit", params={"q": "action:pack.import"}).json()["entries"]
    assert "8 added" in audit[0]["details"]
    # The pack is listed with what came from it.
    listed = {row["id"]: row for row in admin.get("/api/packs").json()["packs"]}
    assert listed["acme-soc"]["version"] == "1.2.0" and len(listed["acme-soc"]["items"]) == 8
    # The same pack again: nothing to do.
    again = inspect(admin, data)
    assert set(actions(again).values()) == {"same"} and again["installed"] == "1.2.0"


def test_an_update_shows_the_difference_and_makes_a_new_version(admin: TestClient):
    first = inspect(admin, packs.write(MANIFEST, items()))
    assert admin.post("/api/packs/import", json={"token": first["token"]}).status_code == 200
    changed_script = {**SCRIPT, "code": SCRIPT["code"].replace("split()", "split(' ')")}
    changed_book = playbook()
    changed_book["playbook"]["description"] = "Counts, now with a description."
    changed_list = {**LIST, "entries": [{"key": "ceo"}, {"key": "cfo"}]}
    newer = [
        packs.Item("scripts", "CountWords", changed_script),
        packs.Item("playbooks", "Count the words", changed_book),
        packs.Item("lists", "vip_users", changed_list),
        packs.Item("fields", "customer", {**FIELD, "label": "Customer name"}),
        packs.Item("dashboards", "Customer cases", DASHBOARD),
    ]
    found = inspect(admin, packs.write({**MANIFEST, "version": "1.3.0"}, newer))
    assert actions(found) == {
        "fields/customer": "update", "lists/vip_users": "update", "scripts/CountWords": "update",
        "playbooks/Count the words": "update", "dashboards/Customer cases": "same",
    }  # fmt: skip
    by_name = {item["name"]: item for item in found["items"]}
    lines = by_name["CountWords"]["diff"].splitlines()
    # The code is compared line by line, as it is written.
    assert any(line.startswith("-") and line.endswith(".split())}") for line in lines)
    assert any(line.startswith("+") and line.endswith(".split(' '))}") for line in lines)
    assert "new version" in by_name["CountWords"]["note"] and "cfo" in by_name["vip_users"]["diff"]
    # Skipping one item: the others are applied, that one stays as it was.
    done = admin.post("/api/packs/import", json={"token": found["token"], "choices": {"lists/vip_users": "skip"}})
    assert done.status_code == 200, done.text
    assert (done.json()["updated"], done.json()["same"], done.json()["skipped"]) == (3, 1, 1)
    assert [entry["key"] for entry in admin.get("/api/lists/vip_users").json()["entries"]] == ["ceo"]
    with SessionLocal() as db:
        script = db.scalars(select(Script).where(Script.name == "CountWords")).one()
        versions = db.scalars(select(ScriptVersion).where(ScriptVersion.script_id == script.id)).all()
        assert script.current_version == 2 and len(versions) == 2  # the first one is still there
        book = db.scalars(select(Playbook).where(Playbook.name == "Count the words")).one()
        assert book.current_version == 2 and book.description == "Counts, now with a description."
        assert db.get(PlaybookVersion, (book.id, 1)) is not None
        assert db.get(Pack, "acme-soc").version == "1.3.0"
        # What was skipped is not of the pack any more; what stayed the same still is.
        owned = {(row.kind, row.name) for row in db.scalars(select(PackItem).where(PackItem.pack_id == "acme-soc"))}
        assert ("lists", "vip_users") not in owned and ("dashboards", "Customer cases") in owned


def test_a_conflict_stops_everything_unless_it_is_skipped(admin: TestClient):
    made = admin.post("/api/fields", json={"name": "customer", "type": "number", "allTypes": True})
    assert made.status_code == 201
    orphan = packs.Item("mappers", "zendesk", {"connector": "zendesk", "incoming": [{"to": "name", "from": "x"}]})
    found = inspect(admin, packs.write(MANIFEST, items(orphan)))
    by_name = {item["name"]: item for item in found["items"]}
    assert by_name["customer"]["action"] == "conflict" and "keeps its type" in by_name["customer"]["why"]
    assert by_name["zendesk"]["action"] == "conflict" and "neither here nor in the pack" in by_name["zendesk"]["why"]
    assert found["counts"] == {"add": 7, "update": 0, "same": 0, "conflict": 2}
    # As it is: refused, and nothing of the pack is here.
    refused = admin.post("/api/packs/import", json={"token": found["token"]})
    assert refused.status_code == 409 and "Skip it, or settle it first" in refused.json()["detail"]
    assert admin.get("/api/lists/vip_users").status_code == 404
    assert admin.get("/api/automation/connectors/acme").status_code == 404
    assert "acme-soc" not in [row["id"] for row in admin.get("/api/packs").json()["packs"]]
    # With the two skipped, the type that needs the field of the pack now finds one of another kind: still whole.
    choices = {"fields/customer": "skip", "mappers/zendesk": "skip"}
    done = admin.post("/api/packs/import", json={"token": found["token"], "choices": choices})
    assert done.status_code == 200, done.text
    assert (done.json()["added"], done.json()["skipped"]) == (7, 2)
    # A connector older than the one installed never replaces it.
    old = ACME.replace("version: 1\n", "version: 0\n") if "version: 1\n" in ACME else None
    if old is not None:
        stale = inspect(admin, packs.write({**MANIFEST, "id": "old-pack"}, [packs.Item("connectors", "acme", old)]))
        assert stale["items"][0]["action"] == "conflict" and "versions only go up" in stale["items"][0]["why"]


def test_what_a_pack_requires_is_checked(admin: TestClient):
    needy = {**MANIFEST, "id": "needy", "requires": [{"pack": "acme-soc", "version": "2.0.0"}], "nik": ">=4.6"}
    data = packs.write(needy, [packs.Item("fields", "customer", FIELD)])
    found = inspect(admin, data)
    assert found["problems"] == ['It requires the pack "acme-soc", which is not installed']
    assert admin.post("/api/packs/import", json={"token": found["token"]}).status_code == 409
    base = inspect(admin, packs.write(MANIFEST, [packs.Item("lists", "vip_users", LIST)]))
    assert admin.post("/api/packs/import", json={"token": base["token"]}).status_code == 200
    assert inspect(admin, data)["problems"] == ['It requires version 2.0.0 of the pack "acme-soc": 1.2.0 is installed']
    future = packs.write({**MANIFEST, "id": "future", "nik": ">=9.0"}, [packs.Item("fields", "customer", FIELD)])
    assert inspect(admin, future)["problems"] == ["The pack is for Nik 9.0 or later"]
    # A pack another one requires is not taken off the list; one nothing requires is, and its items stay.
    ok = inspect(
        admin, packs.write({**needy, "requires": [{"pack": "acme-soc"}]}, [packs.Item("fields", "customer", FIELD)])
    )
    assert admin.post("/api/packs/import", json={"token": ok["token"]}).status_code == 200
    assert admin.delete("/api/packs/acme-soc").status_code == 409
    assert admin.delete("/api/packs/needy").status_code == 204
    assert admin.delete("/api/packs/acme-soc").status_code == 204
    assert admin.get("/api/lists/vip_users").status_code == 200
    assert any(field["name"] == "customer" for field in admin.get("/api/fields").json()["fields"])


def test_a_pack_is_exported_with_what_its_items_need(admin: TestClient):
    first = inspect(admin, packs.write(MANIFEST, items()))
    assert admin.post("/api/packs/import", json={"token": first["token"]}).status_code == 200
    install_mapper = admin.put(
        "/api/mappers",
        json={"connectorId": "acme", "direction": "incoming",
              "rules": [{"to": "name", "from": "{{ item.title }}"}, {"to": "customer", "from": "{{ item.org }}"}]},
    )  # fmt: skip
    assert install_mapper.status_code == 200, install_mapper.text
    # Asking for the type brings its field, its playbook, and the script of that playbook.
    needed = admin.post(
        "/api/packs/dependencies", json={"items": [{"kind": "incident_types", "name": "Customer case"}]}
    )
    assert [(item["kind"], item["name"], item["asked"]) for item in needed.json()["items"]] == [
        ("fields", "customer", False), ("scripts", "CountWords", False), ("playbooks", "Count the words", False),
        ("incident_types", "Customer case", True),
    ]  # fmt: skip
    kinds = {
        group["kind"]: [item["name"] for item in group["items"]]
        for group in admin.get("/api/packs/items").json()["kinds"]
    }
    assert "customer" in kinds["fields"] and "acme" in kinds["mappers"] and "vip_users" in kinds["lists"]
    body = {"id": "customer-cases", "name": "Customer cases", "version": "0.1.0",
            "items": [{"kind": "incident_types", "name": "Customer case"}, {"kind": "mappers", "name": "acme"},
                      {"kind": "lists", "name": "vip_users"}]}  # fmt: skip
    made = admin.post("/api/packs/export", json=body)
    assert made.status_code == 200 and "customer-cases-0.1.0.nikpack" in made.headers["content-disposition"]
    back = packs.read(made.content)
    assert [(item.kind, item.name) for item in back.items] == [
        ("fields", "customer"), ("lists", "vip_users"), ("scripts", "CountWords"), ("connectors", "acme"),
        ("playbooks", "Count the words"), ("incident_types", "Customer case"), ("mappers", "acme"),
    ]  # fmt: skip
    # No connection, no secret, and a list goes without what it holds unless asked.
    with zipfile.ZipFile(io.BytesIO(made.content)) as archive:
        everything = b"".join(archive.read(name) for name in archive.namelist()).decode()
    assert "s3cret" not in everything and "entries" not in next(i for i in back.items if i.kind == "lists").data
    with_items = admin.post("/api/packs/export", json={**body, "listItems": True})
    assert next(i for i in packs.read(with_items.content).items if i.kind == "lists").data["entries"] == [
        {"key": "ceo"}
    ]
    # Here, what was just exported is what is here.
    assert set(actions(inspect(admin, made.content)).values()) == {"same"}
    assert admin.post("/api/packs/export", json={**body, "items": []}).status_code == 400
    assert admin.post("/api/packs/export", json={**body, "id": "Bad"}).status_code == 400
    gone = admin.post("/api/packs/export", json={**body, "items": [{"kind": "lists", "name": "nothing"}]})
    assert gone.status_code == 404
    # An installed pack comes out as a file again.
    again = admin.get("/api/packs/acme-soc/download")
    assert again.status_code == 200 and len(packs.read(again.content).items) == 8


def test_packs_are_for_who_manages_content_and_a_token_is_its_owners(admin: TestClient):
    analyst = make_key(admin, label="a", roles=["analyst", "playbooks", "connectors"])
    other = TestClient(app)
    data = packs.write(MANIFEST, [packs.Item("fields", "customer", FIELD)])
    file = {"file": ("x.nikpack", data, "application/zip")}
    assert other.post("/api/packs/inspect", files=file, headers=analyst).status_code == 403
    assert other.get("/api/packs", headers=analyst).status_code == 403
    found = inspect(admin, data)
    second_admin = make_key(admin, label="b", roles=["admin"])
    stolen = other.post("/api/packs/import", json={"token": found["token"]}, headers=second_admin)
    assert stolen.status_code == 410
    assert admin.post("/api/packs/import", json={"token": "x" * 20}).status_code == 410
    assert admin.post("/api/packs/inspect", files={"file": ("x", b"junk", "application/zip")}).status_code == 400
    # After an hour the file is forgotten.
    with SessionLocal() as db:
        with pytest.raises(packs.PackError):
            packs.take_upload(db, found["token"], "admin", now=__import__("time").time() + 3601)


def test_what_nik_ships_is_listed_as_packs_and_reads_back_as_it_is(admin: TestClient):
    from app import dashboards, fields, incident_types, lists, mapping
    from app.automation import connector_actions, shipped
    from app.automation import scripts as automation_scripts

    with SessionLocal() as db:
        fields.seed(db)
        incident_types.seed(db)
        lists.seed(db)
        dashboards.seed(db)
        automation_scripts.seed(db)
        connector_actions.seed(db)
        db.flush()
        mapping.seed(db)
        shipped.seed(db)
        db.commit()
        assert packs.register_builtin(db) > 4
        db.commit()
        assert packs.register_builtin(db) == 0
    listed = admin.get("/api/packs").json()["packs"]
    assert [row["id"] for row in listed] == ["nik"] and listed[0]["source"] == "nik"
    assert all(row["builtin"] and row["author"] == "Nik" for row in listed)
    for row in listed:
        missing = [f"{item['kind']}/{item['name']}" for item in row["items"] if not item["there"]]
        assert missing == [], row["id"]
        assert admin.delete(f"/api/packs/{row['id']}").status_code == 409
        # Each comes out as a file, and that file says of this Nik: nothing to do.
        file = admin.get(f"/api/packs/{row['id']}/download")
        assert file.status_code == 200, file.text
        found = inspect(admin, file.content)
        assert set(actions(found).values()) == {"same"}, (
            row["id"],
            [i for i in found["items"] if i["action"] != "same"],
        )
        assert len(found["items"]) == len(row["items"])
    kinds = {item["kind"] for row in listed for item in row["items"]}
    assert kinds == {"incident_types", "lists", "scripts", "playbooks", "connectors", "mappers", "dashboards"}
    # An item a pack someone installed gave last stays of that pack when Nik starts again.
    changed = dict(packs.current(SessionLocal(), "dashboards", "SOC overview"))
    assert changed["name"] == "SOC overview"
    with SessionLocal() as db:
        packs.remember(db, MANIFEST, [("scripts", "BusinessHours")], "admin")
        db.commit()
        assert packs.register_builtin(db) == 0
        assert db.get(PackItem, ("scripts", "BusinessHours")).pack_id == "acme-soc"


# --------------------------------------------------------------------------- #
# A connector with what it comes with (5.1)                                   #
# --------------------------------------------------------------------------- #
def test_a_connector_travels_in_a_pack_as_a_folder_with_its_logo_and_readme(admin: TestClient):
    from tests.test_connectors_api import SVG

    def archive(files: dict[str, bytes]) -> bytes:
        held = io.BytesIO()
        with zipfile.ZipFile(held, "w") as out:
            out.writestr("pack.yml", yaml.safe_dump(MANIFEST))
            for path, data in files.items():
                out.writestr(path, data)
        return held.getvalue()

    folder = {
        "connectors/acme/connector.yml": ACME.encode(),
        "connectors/acme/logo.svg": SVG,
        "connectors/acme/README.md": b"# Acme\n",
    }
    pack = packs.read(archive(folder))
    (item,) = pack.items
    assert (item.kind, item.name, item.data) == ("connectors", "acme", ACME)
    assert item.extras == {"logo": SVG, "readme": "# Acme\n"}
    # Written again, it is a folder again; without what it comes with, a file as before.
    again = packs.read(packs.write(pack.manifest, pack.items))
    assert again.items[0].extras == item.extras
    with zipfile.ZipFile(io.BytesIO(packs.write(pack.manifest, [packs.Item("connectors", "acme", ACME)]))) as plain:
        assert plain.namelist() == ["pack.yml", "connectors/acme.yml"]

    # A logo that is not a drawing, a stray file and the connector twice are refused as the file is read.
    for files, why in (
        ({**folder, "connectors/acme/logo.svg": SVG.replace(b"<rect", b"<script/><rect")}, "The logo of the connector"),
        ({**folder, "connectors/acme/run.sh": b"#!/bin/sh"}, "does not know"),
        ({**folder, "connectors/acme.yml": ACME.encode()}, "twice"),
    ):
        with pytest.raises(packs.PackError) as caught:
            packs.read(archive(files))
        assert why in caught.value.message, caught.value.message

    with SessionLocal() as db:
        packs.apply(db, pack, None, "admin")
        db.commit()
    shown = admin.get("/api/automation/connectors/acme").json()
    assert shown["readme"] == "# Acme\n" and shown["logo"].startswith("/automation/connectors/acme/logo?v=")
    assert admin.get("/api" + shown["logo"]).content == SVG
    # Exported from here, the connector takes its logo and its README with it.
    with SessionLocal() as db:
        exported = packs.read(packs.export(db, MANIFEST, [("connectors", "acme")]))
    assert exported.items[0].extras == {"logo": SVG, "readme": "# Acme\n"}
